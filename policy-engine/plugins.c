#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dlfcn.h>
#include <string.h>
#include "query_queue.h"
#include "addons.h"
#include "trusthub_plugin.h"
#include "th_logging.h"
#include "plugins.h"

void print_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	thlog(LOG_INFO, "%zu loaded plugins:", plugin_count);
	for (i = 0; i < plugin_count; i++) {
		thlog(LOG_INFO, "\t[%02d] Plugin Name: %s", i, plugins[i].name);
		thlog(LOG_INFO, "\t\tDescription: %s", plugins[i].desc);
		if (plugins[i].aggregation == AGGREGATION_NONE) {
			thlog(LOG_INFO, "\t\tAggregation Group: None");
		}
		else if (plugins[i].aggregation == AGGREGATION_CONGRESS) {
			thlog(LOG_INFO, "\t\tAggregation Group: Congress");
		}
		else if (plugins[i].aggregation == AGGREGATION_NECESSARY) {
			thlog(LOG_INFO, "\t\tAggregation Group: Necessary");
		}
		else {
			thlog(LOG_INFO, "\t\tAggregation Group: Unknown");
		}
		thlog(LOG_INFO, "\t\tVersion: %s", plugins[i].ver);
		thlog(LOG_INFO, "\t\tPath: %s", plugins[i].path);
		if (plugins[i].type == PLUGIN_TYPE_ASYNCHRONOUS) {
			thlog(LOG_INFO, "\t\tType: Asynchronous");
		}
		else if (plugins[i].type == PLUGIN_TYPE_SYNCHRONOUS) {
			thlog(LOG_INFO,	"\t\tType: Synchronous");
		}
		else {
			thlog(LOG_INFO, "\t\tType: Unknown");
		}

		if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_RAW) {
			thlog(LOG_INFO, "\t\tHandler Type: Raw Data");
			thlog(LOG_INFO, "\t\tFunction: %p", plugins[i].generic_query_func);
		}
		else if(plugins[i].handler_type == PLUGIN_HANDLER_TYPE_OPENSSL) {
			thlog(LOG_INFO, "\t\tHandler Type: OpenSSL Data");
			thlog(LOG_INFO, "\t\tFunction: %p", plugins[i].generic_query_func);
		}
		else if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_ADDON) {
			thlog(LOG_INFO, "\t\tHandler Type: Addon-handled (%s)", plugins[i].handler_str);
			thlog(LOG_INFO, "\t\tAddon-supplied query function: %p", plugins[i].generic_query_func);
		}
		else {
			thlog(LOG_INFO, "\t\tType: Unknown");
		}
	}
	return;
}

int query_plugin(plugin_t* plugin, int id, query_t* query) {
	/* Make a copy of the data for the plugins */
	switch (plugin->handler_type) {
		case PLUGIN_HANDLER_TYPE_RAW:
		case PLUGIN_HANDLER_TYPE_OPENSSL:
			return plugin->query(query->data);
		case PLUGIN_HANDLER_TYPE_ADDON:
			if (plugin->query_by_addon == NULL) {
				return PLUGIN_RESPONSE_ERROR;
			}
			return plugin->query_by_addon(id, query->data);
	}
	return PLUGIN_RESPONSE_ABSTAIN;
}

void init_plugins(addon_t* addons, size_t addon_count, plugin_t* plugins, size_t plugin_count) {
	int i;
	int j;
	for (i = 0; i < plugin_count; i++) {
		if (plugins[i].handler_type != PLUGIN_HANDLER_TYPE_UNKNOWN) {
			load_plugin_functions(&plugins[i]);
		}
		else {
			for (j = 0; j < addon_count; j++) {
				if (strcmp(addons[j].type_handled, plugins[i].handler_str) == 0) {
					plugins[i].handler_type = PLUGIN_HANDLER_TYPE_ADDON;
					if (plugins[i].type == PLUGIN_TYPE_SYNCHRONOUS) {
						if (addons[j].addon_load_plugin(i, plugins[i].path, 0) == 0) {
							plugins[i].query_by_addon = addons[j].addon_query_plugin;
						} else {
							plugins[i].query_by_addon = NULL;
							thlog(LOG_WARNING, "Could not load plugin %s\n", plugins[i].name);
						}
					}
					else {
						if (addons[j].addon_load_plugin(i, plugins[i].path, 1) == 0) {
							plugins[i].query_by_addon = addons[j].addon_async_query_plugin;
						} else {
							plugins[i].query_by_addon = NULL;
							thlog(LOG_WARNING, "Could not load plugin %s\n", plugins[i].name);
						}
					}
					break;
				}
			}
		}
		if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_UNKNOWN) {
			thlog(LOG_WARNING, "Unhandled plugin type for plugin %02d\n", i);
		}
	}
	return;
}

void close_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	for (i = 0; i < plugin_count; i++) {
		/* addon-handled plugins do not need to be closed */
		/* addons themselves get closed instead in that case */
		if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_ADDON ||
			plugins[i].handler_type == PLUGIN_HANDLER_TYPE_UNKNOWN) {
			continue;
		}
		if (plugins[i].finalize != NULL) {
			plugins[i].finalize();
		}
		dlclose(plugins[i].so_handle);
		free(plugins[i].name);
		free(plugins[i].desc);
		free(plugins[i].ver);
		free(plugins[i].handler_str);
		free(plugins[i].path);
	}
	free(plugins);
	return;
}

int load_plugin_functions(plugin_t* plugin) {
	void* handle;
	handle = dlopen(plugin->path, RTLD_LAZY);
	if (!handle) {
		return 1;
	}
	plugin->so_handle = handle;
	dlerror(); // clear error (if any)
	plugin->generic_query_func = dlsym(handle, "query");
	if (dlerror() != NULL) {
		return 2;
	}
	/* dlsym returns null on failure and we use null to denote
 	 * that no function has been provided so we don't need to
 	 * error check here */
	plugin->generic_init_func = dlsym(handle, "initialize");
	plugin->finalize = dlsym(handle, "finalize");
	return 0;
}

