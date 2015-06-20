#include <stdio.h>
#include <string.h>
#include <libconfig.h>

#include "policy_engine.h"
#include "configuration.h"
#include "plugins.h"
#include "addons.h"

#define CONFIG_FILE_NAME	"policy-engine/trusthub.cfg"

static int parse_plugin(config_setting_t* plugin_data, plugin_t* plugin);
static int parse_addon(config_setting_t* plugin_data, addon_t* addon);

int load_config(policy_context_t* policy_context) {
	plugin_t* plugins;
	addon_t* addons;
	config_t cfg;
	config_setting_t* setting;
	config_setting_t* cfg_data;
	int i;
	int plugin_count;
	int addon_count;

	plugin_count = 0;
	addon_count = 0;
	plugins = NULL;
	addons = NULL;
	
	// Read config file and store data
	config_init(&cfg);
	if (config_read_file(&cfg, CONFIG_FILE_NAME) == 0) {
		fprintf(stderr, "%s:%d - %s\n", 
			config_error_file(&cfg),
			config_error_line(&cfg),
			config_error_text(&cfg));	
		config_destroy(&cfg);
		return 1;
	}

	// Addon parsing
	setting = config_lookup(&cfg, "addons");
	if (setting == NULL) {
		fprintf(stderr, "addons setting not found\n");	
		config_destroy(&cfg);
		return 1;
	}
	addon_count = config_setting_length(setting);
	addons = (addon_t*)calloc(addon_count, sizeof(addon_t));
	for (i = 0; i < addon_count; i++) {
		cfg_data = config_setting_get_elem(setting, i);
		parse_addon(cfg_data, &addons[i]);
	}

	// Plugin parsing
	setting = config_lookup(&cfg, "plugins");
	if (setting == NULL) {
		fprintf(stderr, "plugins setting not found\n");	
		config_destroy(&cfg);
		return 1;
	}
	plugin_count = config_setting_length(setting);
	plugins = (plugin_t*)calloc(plugin_count, sizeof(plugin_t));
	for (i = 0; i < plugin_count; i++) {
		cfg_data = config_setting_get_elem(setting, i);
		parse_plugin(cfg_data, &plugins[i]);
	}

	// Free up config data
	config_destroy(&cfg);

	// Save parsed data
	policy_context->plugins = plugins;
	policy_context->plugin_count = plugin_count;
	policy_context->addons = addons;
	policy_context->addon_count = addon_count;

	return 0;
}

int parse_addon(config_setting_t* plugin_data, addon_t* addon) {
	const char* name;
	const char* desc;
	const char* version;
	const char* path;
	const char* type_handled;
	if (!(config_setting_lookup_string(plugin_data, "name", &name) &&
	    config_setting_lookup_string(plugin_data, "description", &desc) &&
	    config_setting_lookup_string(plugin_data, "version", &version) &&
	    config_setting_lookup_string(plugin_data, "type", &type_handled) &&
	    config_setting_lookup_string(plugin_data, "path", &path))) {
		fprintf(stderr, "Syntax error in configuration file: section addons\n");
		return 1;
	}
	snprintf(addon->name, ADDON_NAME_MAX, "%s", name);
	snprintf(addon->desc, ADDON_DESC_MAX, "%s", desc);
	snprintf(addon->ver, ADDON_VERSION_STR_MAX, "%s", version);
	snprintf(addon->type_handled, ADDON_TYPE_HANDLED_MAX, "%s", type_handled);
	if (load_addon(path, addon) != 0) {
		fprintf(stderr, "Syntax error in configuration file: section addons\n");
		return 1;
	}
	return 0;
}

int parse_plugin(config_setting_t* plugin_data, plugin_t* plugin) {
	const char* name;
	const char* desc;
	const char* version;
	const char* type;
	const char* path;
	const char* hostname;
	int port;
	int openSSL;
	if (!(config_setting_lookup_string(plugin_data, "name", &name) &&
	    config_setting_lookup_string(plugin_data, "description", &desc) &&
	    config_setting_lookup_string(plugin_data, "version", &version) &&
	    config_setting_lookup_string(plugin_data, "type", &type))) {
		fprintf(stderr, "Syntax error in configuration file: section plugins\n");
		return 1;
	}
	snprintf(plugin->name, PLUGIN_NAME_MAX, "%s", name);
	snprintf(plugin->desc, PLUGIN_DESC_MAX, "%s", desc);
	snprintf(plugin->ver, PLUGIN_VERSION_STR_MAX, "%s", version);
	snprintf(plugin->type_str, PLUGIN_TYPE_STR_MAX, "%s", type);

	if (strncmp(type, "internal", sizeof("internal")) == 0) {
		if (!(config_setting_lookup_string(plugin_data, "path", &path) &&
			config_setting_lookup_int(plugin_data, "openssl", &openSSL))) {
			fprintf(stderr, "Syntax error in configuration file: section plugins\n");
			return 2;
		}
		snprintf(plugin->path, PLUGIN_PATH_MAX, "%s", path);
		if (openSSL) {
			plugin->type = PLUGIN_TYPE_INTERNAL_OPENSSL;
		}
		else {
			plugin->type = PLUGIN_TYPE_INTERNAL_RAW;
		}
	}
	else if (strncmp(type, "external", sizeof("external")) == 0) {
		if (!(config_setting_lookup_string(plugin_data, "hostname", &hostname) &&
			config_setting_lookup_int(plugin_data, "port", &port))) {
			fprintf(stderr, "Syntax error in configuration file: section plugins\n");
			return 2;
		}
		plugin->port = port;
		snprintf(plugin->hostname, PLUGIN_HOSTNAME_MAX, "%s", hostname);
	}
	else {
		// Every unknown plugin should at least have a path (name, desc, ver, and type)
		// handled earlier
		if (!(config_setting_lookup_string(plugin_data, "path", &path))) {
			fprintf(stderr, "Syntax error in configuration file: section plugins\n");
			return 2;
		}
		snprintf(plugin->path, PLUGIN_PATH_MAX, "%s", path);
		plugin->type = PLUGIN_TYPE_UNKNOWN;
	}
	return 0;
}
