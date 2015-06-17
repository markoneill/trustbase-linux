#include <stdio.h>
#include <string.h>
#include <libconfig.h>

#include "configuration.h"
#include "plugins.h"
#include "addons.h"

#define CONFIG_FILE_NAME	"policy-engine/trusthub.cfg"

static int parse_plugin(config_setting_t* plugin_data, plugin_t* plugin);

int load_config(policy_context_t* policy_context) {
	plugin_t* plugins;
	config_t cfg;
	config_setting_t* setting;
	config_setting_t* plugin_data;
	int i;
	int plugin_count;

	config_init(&cfg);
	if (config_read_file(&cfg, CONFIG_FILE_NAME) == 0) {
		fprintf(stderr, "%s:%d - %s\n", 
			config_error_file(&cfg),
			config_error_line(&cfg),
			config_error_text(&cfg));	
		config_destroy(&cfg);
		return 0;
	}

	setting = config_lookup(&cfg, "plugins");
	if (setting == NULL) {
		fprintf(stderr, "plugins setting not found\n");	
		config_destroy(&cfg);
		return 0;
	}
	plugin_count = config_setting_length(setting);
	plugins = (plugin_t*)calloc(plugin_count, sizeof(plugin_t));
	for (i = 0; i < plugin_count; i++) {
		plugin_data = config_setting_get_elem(setting, i);
		parse_plugin(plugin_data, &plugins[i]);
	}
	config_destroy(&cfg);
	*plugins_ptr = plugins;
	return plugin_count;
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
		return 1;
	}
	memcpy(plugin->name, name, strlen(name));
	memcpy(plugin->desc, desc, strlen(desc));
	memcpy(plugin->ver, version, strlen(version));

	if (strncmp(type, "internal", sizeof("internal")) == 0) {
		if (!(config_setting_lookup_string(plugin_data, "path", &path) &&
			config_setting_lookup_int(plugin_data, "openssl", &openSSL))) {
			return 2;
		}
		if (openSSL) {
			plugin->type = PLUGIN_TYPE_INTERNAL_OPENSSL;
			load_query_func_openssl(path, plugin);
		}
		else {
			plugin->type = PLUGIN_TYPE_INTERNAL_RAW;
			load_query_func_raw(path, plugin);
		}
	}
	else if (strncmp(type, "external", sizeof("external")) == 0) {
		if (!(config_setting_lookup_string(plugin_data, "hostname", &hostname) &&
			config_setting_lookup_int(plugin_data, "port", &port))) {
			return 2;
		}
		plugin->port = port;
		memcpy(plugin->hostname, hostname, strlen(hostname));
	}
	else {
		return 3;
	}
	return 0;
}
