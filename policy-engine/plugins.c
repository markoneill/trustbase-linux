#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dlfcn.h>
#include <string.h>
#include "query_queue.h"
#include "plugins.h"
#include "plugin_response.h"
#include "addons.h"

void print_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	printf("%zu loaded plugins:\n", plugin_count);
	for (i = 0; i < plugin_count; i++) {
		printf("\t[%02d] Plugin Name: %s\n", i, plugins[i].name);
		printf("\t\tDescription: %s\n", plugins[i].desc);
		if (plugins[i].aggregation == AGGREGATION_NONE) {
			printf("\t\tAggregation Group: None\n");
		}
		else if (plugins[i].aggregation == AGGREGATION_CONGRESS) {
			printf("\t\tAggregation Group: Congress\n");
		}
		else if (plugins[i].aggregation == AGGREGATION_NECESSARY) {
			printf("\t\tAggregation Group: Necessary\n");
		}
		else {
			printf("\t\tAggregation Group: Unknown\n");
		}
		printf("\t\tVersion: %s\n", plugins[i].ver);
		printf("\t\tPath: %s\n", plugins[i].path);
		if (plugins[i].type == PLUGIN_TYPE_ASYNCHRONOUS) {
			printf("\t\tType: Asynchronous\n");
		}
		else if (plugins[i].type == PLUGIN_TYPE_SYNCHRONOUS) {
			printf("\t\tType: Synchronous\n");
		}
		else {
			printf("\t\tType: Unknown\n");
		}

		if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_RAW) {
			printf("\t\tHandler Type: Raw Data\n");
			printf("\t\tFunction: %p\n", plugins[i].generic_query_func);
		}
		else if(plugins[i].handler_type == PLUGIN_HANDLER_TYPE_OPENSSL) {
			printf("\t\tHandler Type: OpenSSL Data\n");
			printf("\t\tFunction: %p\n", plugins[i].generic_query_func);
		}
		else if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_ADDON) {
			printf("\t\tHandler Type: Addon-handled (%s)\n", plugins[i].handler_str);
			printf("\t\tAddon-supplied query function: %p\n", plugins[i].generic_query_func);
		}
		else {
			printf("\t\tType: Unknown\n");
		}
	}
	return;
}

int query_async_plugin(plugin_t* plugin, int id, query_t* query) {
	switch (plugin->handler_type) {
		case PLUGIN_HANDLER_TYPE_RAW:
			return plugin->query_async_raw(query->id, query->hostname, query->raw_chain, query->raw_chain_len);
		case PLUGIN_HANDLER_TYPE_OPENSSL:
			return plugin->query_async_openssl(query->id, query->hostname, query->chain);
		case PLUGIN_HANDLER_TYPE_ADDON:
			return plugin->query_async_by_addon(query->id, id, query->hostname, query->raw_chain, query->raw_chain_len);
	}
	return PLUGIN_RESPONSE_ABSTAIN;
}
int query_sync_plugin(plugin_t* plugin, int id, query_t* query) {
	switch (plugin->handler_type) {
		case PLUGIN_HANDLER_TYPE_RAW:
			return plugin->query_sync_raw(query->hostname, query->raw_chain, query->raw_chain_len);
		case PLUGIN_HANDLER_TYPE_OPENSSL:
			return plugin->query_sync_openssl(query->hostname, query->chain);
		case PLUGIN_HANDLER_TYPE_ADDON:
			return plugin->query_sync_by_addon(id, query->hostname, query->raw_chain, query->raw_chain_len);
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
					addons[j].addon_load_plugin(i, plugins[i].path);
					if (plugins[i].type == PLUGIN_TYPE_SYNCHRONOUS) {
						plugins[i].query_sync_by_addon = addons[j].addon_query_plugin;
					}
					else {
						// XXX see below
						fprintf(stderr, "Asynchronous addon-handled plugins are not current supported\n");
						// plugins[i].query_async_by_addon = addons[j].addon_async_query_plugin;
					}

					break;
				}
			}
		}
		if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_UNKNOWN) {
			fprintf(stderr, "Unhandled plugin type for plugin %02d\n", i);
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

