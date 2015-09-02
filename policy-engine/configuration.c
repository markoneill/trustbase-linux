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
static int parse_aggregation(config_setting_t* aggregation_data, double* congress_threshold, plugin_t* plugins, int plugin_count);
static int get_plugin_id(plugin_t* plugins, int plugin_count, const char* plugin_name);
static char* copy_string(const char* original);

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

	// Aggregation parsing
	setting = config_lookup(&cfg, "aggregation");
	if (setting == NULL) {
		fprintf(stderr, "aggregation setting not found\n");
		config_destroy(&cfg);
		return 1;
	}
	parse_aggregation(setting, &policy_context->congress_threshold, plugins, plugin_count);

	// Free up config data
	config_destroy(&cfg);

	// Save parsed data
	policy_context->plugins = plugins;
	policy_context->plugin_count = plugin_count;
	policy_context->addons = addons;
	policy_context->addon_count = addon_count;

	return 0;
}

int parse_aggregation(config_setting_t* aggregation_data, double* congress_threshold, plugin_t* plugins, int plugin_count) {
	config_setting_t* sufficient_groups;
	config_setting_t* group;
	const char* plugin_name;
	int plugin_id;
	int i;
	int group_count;
	if (!(config_setting_lookup_float(aggregation_data, "congress_threshold", congress_threshold))) {
		fprintf(stderr, "Syntax error in configuration file: section aggregation\n");
		return 1;
	}
	sufficient_groups = config_setting_get_member(aggregation_data, "sufficient");
	if (sufficient_groups == NULL) {
		fprintf(stderr, "aggregation->sufficient setting not found\n");
		return 1;
	}
	
	group = config_setting_get_member(sufficient_groups, "congress_group");
	if (group == NULL) {
		fprintf(stderr, "aggregation->sufficient->congress_group setting not found\n");
		return 1;
	}
	group_count = config_setting_length(group);
	for (i = 0; i < group_count; i++) {
		plugin_name = config_setting_get_string_elem(group, i);
		plugin_id = get_plugin_id(plugins, plugin_count, plugin_name);
		if (plugin_id >= 0) {
			plugins[plugin_id].aggregation = AGGREGATION_CONGRESS;
		}
		else {
			fprintf(stderr, "Plugin %s in congress list does not exist\n", plugin_name);
		}
	}

	group = config_setting_get_member(sufficient_groups, "necessary_group");
	if (group == NULL) {
		fprintf(stderr, "aggregation->sufficient->necessary_group setting not found\n");
		return 1;
	}
	group_count = config_setting_length(group);
	for (i = 0; i < group_count; i++) {
		plugin_name = config_setting_get_string_elem(group, i);
		plugin_id = get_plugin_id(plugins, plugin_count, plugin_name);
		if (plugin_id >= 0) {
			plugins[plugin_id].aggregation = AGGREGATION_NECESSARY;
		}
		else {
			fprintf(stderr, "Plugin %s in necessary list does not exist\n", plugin_name);
		}
	}
	return 0;
}

int get_plugin_id(plugin_t* plugins, int plugin_count, const char* plugin_name) {
	int i;
	for (i = 0; i < plugin_count; i++) {
		if (strcmp(plugins[i].name, plugin_name) == 0) {
			return i;
		}
	}
	/* -1 indicates plugin name is not found in list */
	return -1;
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
	addon->name = copy_string(name);
	addon->desc = copy_string(desc);
	addon->ver = copy_string(version);
	addon->type_handled = copy_string(type_handled);
	addon->so_path = copy_string(path);
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
	const char* handler;
	int openSSL;
	const char* path;
	if (!(config_setting_lookup_string(plugin_data, "name", &name) &&
	    config_setting_lookup_string(plugin_data, "description", &desc) &&
	    config_setting_lookup_string(plugin_data, "version", &version) &&
	    config_setting_lookup_string(plugin_data, "type", &type) &&
	    config_setting_lookup_string(plugin_data, "handler", &handler) &&
	    config_setting_lookup_int(plugin_data, "openssl", &openSSL) &&
	    config_setting_lookup_string(plugin_data, "path", &path))) {
		fprintf(stderr, "Syntax error in configuration file: section plugins\n");
		return 1;
	}

	plugin->aggregation = AGGREGATION_NONE;
	plugin->name = copy_string(name);
	plugin->desc = copy_string(desc);
	plugin->ver = copy_string(version);
	plugin->handler_str = copy_string(handler);
	plugin->path = copy_string(path);

	if (strncmp(type, "synchronous", sizeof("synchronous")) == 0) {
		plugin->type = PLUGIN_TYPE_SYNCHRONOUS;
	}
	else if (strncmp(type, "asynchronous", sizeof("asynchronous")) == 0) {
		plugin->type = PLUGIN_TYPE_ASYNCHRONOUS;
	}
	else {
		fprintf(stderr, "Unknown plugin type in configuration file\n");
		return 1;
	}

	if (strncmp(handler, "native", sizeof("native")) == 0) {
		if (openSSL) {
			plugin->handler_type = PLUGIN_HANDLER_TYPE_OPENSSL;
		}
		else {
			plugin->handler_type = PLUGIN_HANDLER_TYPE_RAW;
		}
	}
	else { /* This will (if possible) be resolved after addon loading */
		plugin->handler_type = PLUGIN_HANDLER_TYPE_UNKNOWN;
	}
	return 0;
}

char* copy_string(const char* original) {
	char* copy;
	int len;
	len = strlen(original)+1; /* +1 for null terminator */
	copy = (char*)malloc(len);
	if (copy == NULL) {
		fprintf(stderr, "Unable to allocate space for a string during configuration loading\n");
		return NULL;
	}
	memcpy(copy, original, len);
	return copy;
}

