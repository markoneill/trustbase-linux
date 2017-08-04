#include <stdio.h>
#include <string.h>
#include <libconfig.h>

#include "policy_engine.h"
#include "configuration.h"
#include "plugins.h"
#include "tb_logging.h"
#include "addons.h"
#include "trustbase_plugin.h"

#define CONFIG_FILE_NAME	"/etc/trustbase.cfg"

static int parse_plugin(config_setting_t* plugin_data, plugin_t* plugin, char* root_path);
static int parse_addon(config_setting_t* plugin_data, addon_t* addon, char* root_path);
static int parse_aggregation(config_setting_t* aggregation_data, policy_context_t* policy_context);
static int get_plugin_id(plugin_t* plugins, int plugin_count, const char* plugin_name);
static char* copy_string(const char* original);
static char* cat_path(char* a, const char* b);

int load_config(policy_context_t* policy_context, char* path, char* username) {
	plugin_t* plugins;
	addon_t* addons;
	config_t cfg;
	config_setting_t* setting;
	config_setting_t* cfg_data;
	int i;
	int plugin_count;
	int addon_count;
	const char* config_username;

	plugin_count = 0;
	addon_count = 0;
	plugins = NULL;
	addons = NULL;
	config_username = NULL;
	
	// Read config file and store data
	config_init(&cfg);
	if (config_read_file(&cfg, CONFIG_FILE_NAME) == 0) {
		tblog(LOG_ERROR, "%s:%d - %s", 
			config_error_file(&cfg),
			config_error_line(&cfg),
			config_error_text(&cfg));	
		config_destroy(&cfg);
		return 1;
	}

	// Addon parsing
	setting = config_lookup(&cfg, "addons");
	if (setting == NULL) {
		tblog(LOG_ERROR, "addons setting not found");	
		config_destroy(&cfg);
		return 1;
	}
	addon_count = config_setting_length(setting);
	addons = (addon_t*)calloc(addon_count, sizeof(addon_t));
	for (i = 0; i < addon_count; i++) {
		cfg_data = config_setting_get_elem(setting, i);
		parse_addon(cfg_data, &addons[i], path);
	}
	policy_context->addons = addons;
	policy_context->addon_count = addon_count;

	// Plugin parsing
	setting = config_lookup(&cfg, "plugins");
	if (setting == NULL) {
		tblog(LOG_ERROR, "plugins setting not found");	
		config_destroy(&cfg);
		return 1;
	}
	plugin_count = config_setting_length(setting);
	plugins = (plugin_t*)calloc(plugin_count, sizeof(plugin_t));
	for (i = 0; i < plugin_count; i++) {
		cfg_data = config_setting_get_elem(setting, i);
		parse_plugin(cfg_data, &plugins[i], path);
	}
	policy_context->plugins = plugins;
	policy_context->plugin_count = plugin_count;

	// Aggregation parsing
	setting = config_lookup(&cfg, "aggregation");
	if (setting == NULL) {
		tblog(LOG_ERROR, "aggregation setting not found");
		config_destroy(&cfg);
		return 1;
	}
	parse_aggregation(setting, policy_context);

	// Username parsing
	setting = config_lookup(&cfg, "username");
	if (setting == NULL) {
		tblog(LOG_ERROR, "username setting not found");
	} else {
		// Take the username and have the policy engine run as that user
		config_username = config_setting_get_string(setting);
		if (config_username != NULL) {
			// Set the username to be given back to the thing
			strncpy(username, config_username, MAX_USERNAME_LEN);
			username[MAX_USERNAME_LEN] = '\0';
		} else {
			username[0] = '\0';
		}
	}
		

	// Free up config data
	config_destroy(&cfg);


	return 0;
}

int parse_aggregation(config_setting_t* aggregation_data, policy_context_t* policy_context) {
	config_setting_t* sufficient_groups;
	config_setting_t* group;
	const char* plugin_name;
	int plugin_id;
	int i;
	int group_count;
	int plugin_count = policy_context->plugin_count;
	plugin_t* plugins = policy_context->plugins; 
	if (!(config_setting_lookup_float(aggregation_data, "congress_threshold", &policy_context->congress_threshold))) {
		tblog(LOG_ERROR, "Syntax error in configuration file: section aggregation");
		return 1;
	}
	sufficient_groups = config_setting_get_member(aggregation_data, "sufficient");
	if (sufficient_groups == NULL) {
		tblog(LOG_ERROR, "aggregation->sufficient setting not found");
		return 1;
	}
	
	group = config_setting_get_member(sufficient_groups, "congress_group");
	if (group == NULL) {
		tblog(LOG_ERROR, "aggregation->sufficient->congress_group setting not found");
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
			tblog(LOG_ERROR, "Plugin %s in congress list does not exist", plugin_name);
		}
	}

	group = config_setting_get_member(sufficient_groups, "necessary_group");
	if (group == NULL) {
		tblog(LOG_ERROR, "aggregation->sufficient->necessary_group setting not found");
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
			tblog(LOG_ERROR, "Plugin %s in necessary list does not exist", plugin_name);
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

int parse_addon(config_setting_t* plugin_data, addon_t* addon, char* root_path) {
	const char* name;
	const char* desc;
	const char* path;
	const char* type_handled;
	if (!(config_setting_lookup_string(plugin_data, "name", &name) &&
	    config_setting_lookup_string(plugin_data, "description", &desc) &&
	    config_setting_lookup_string(plugin_data, "type", &type_handled) &&
	    config_setting_lookup_string(plugin_data, "path", &path))) {
		tblog(LOG_ERROR, "Syntax error in configuration file: section addons");
		return 1;
	}
	addon->name = copy_string(name);
	addon->desc = copy_string(desc);
	addon->ver = NULL;
	addon->type_handled = copy_string(type_handled);
	addon->so_path = cat_path(root_path, path);
	if (load_addon(cat_path(root_path, path), addon) != 0) {
		tblog(LOG_ERROR, "Syntax error in configuration file: section addons");
		return 1;
	}
	return 0;
}

int parse_plugin(config_setting_t* plugin_data, plugin_t* plugin, char* root_path) {
	const char* name;
	const char* desc;
	const char* type;
	const char* handler;
	const char* abstain_map;
	const char* error_map;
	int openSSL;
	const char* path;
	if (!(config_setting_lookup_string(plugin_data, "name", &name) &&
	    config_setting_lookup_string(plugin_data, "description", &desc) &&
	    config_setting_lookup_string(plugin_data, "type", &type) &&
	    config_setting_lookup_string(plugin_data, "handler", &handler) &&
	    config_setting_lookup_int(plugin_data, "openssl", &openSSL) &&
	    config_setting_lookup_string(plugin_data, "map_abstain_to", &abstain_map) &&
	    config_setting_lookup_string(plugin_data, "map_error_to", &error_map) &&
	    config_setting_lookup_string(plugin_data, "path", &path))) {
		tblog(LOG_ERROR, "Syntax error in configuration file: section plugins");
		return 1;
	}

	plugin->aggregation = AGGREGATION_NONE;
	if (strncmp(abstain_map, "invalid", sizeof("invalid")) == 0) {
		plugin->abstain_map = PLUGIN_RESPONSE_INVALID;
	}
	else if (strncmp(abstain_map, "valid", sizeof("valid")) == 0) {
		plugin->abstain_map = PLUGIN_RESPONSE_VALID;
	}
	else {
		tblog(LOG_ERROR, "Unknown plugin abstain mapping in configuration file");
		return 1;
	}
	if (strncmp(error_map, "invalid", sizeof("invalid")) == 0) {
		plugin->error_map = PLUGIN_RESPONSE_INVALID;
	}
	else if (strncmp(error_map, "valid", sizeof("valid")) == 0) {
		plugin->error_map = PLUGIN_RESPONSE_VALID;
	}
	else {
		tblog(LOG_ERROR, "Unknown plugin error mapping in configuration file");
		return 1;
	}
	plugin->name = copy_string(name);
	plugin->desc = copy_string(desc);
	plugin->ver = NULL;
	plugin->handler_str = copy_string(handler);
	plugin->path = cat_path(root_path, path);

	if (strncmp(type, "synchronous", sizeof("synchronous")) == 0) {
		plugin->type = PLUGIN_TYPE_SYNCHRONOUS;
	}
	else if (strncmp(type, "asynchronous", sizeof("asynchronous")) == 0) {
		plugin->type = PLUGIN_TYPE_ASYNCHRONOUS;
	}
	else {
		tblog(LOG_ERROR, "Unknown plugin type in configuration file");
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
	len = strlen(original);
	copy = (char*)malloc(len+1); /* +1 for null terminator */
	if (copy == NULL) {
		tblog(LOG_ERROR, "Unable to allocate space for a string during configuration loading");
		return NULL;
	}
	memcpy(copy, original, len+1);
	return copy;
}

char* cat_path(char* a, const char* b) {
        char* concated;
        int len_a;
        int len_b;
                
        len_a = strlen(a);
        len_b = strlen(b);
        concated = (char*)malloc(len_a + 1 + len_b + 1); 
        if (concated == NULL) {
                tblog(LOG_ERROR, "Unable to allocate space for a string during configuration loading");
                return NULL;
        }
        memcpy(concated, a, len_a);
	concated[len_a] = '/';
        memcpy(concated + len_a + 1, b, len_b);
        concated[len_a + 1 + len_b] = 0;
        return concated;
}

