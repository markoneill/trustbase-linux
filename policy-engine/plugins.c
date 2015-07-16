#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dlfcn.h>
#include <string.h>
#include "query_queue.h"
#include "plugins.h"
#include "addons.h"

void print_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	printf("%zu loaded plugins:\n", plugin_count);
	for (i = 0; i < plugin_count; i++) {
		printf("\t[%02d] Plugin Name: %s\n", i, plugins[i].name);
		printf("\t\tDescription: %s\n", plugins[i].desc);
		printf("\t\tVersion: %s\n", plugins[i].ver);
		printf("\t\tPath: %s\n", plugins[i].path);
		if (plugins[i].type == PLUGIN_TYPE_ASYNCHRONOUS) {
			printf("\t\tType: Asynchronous\n");
		}
		else {
			printf("\t\tType: Synchronous\n");
		}

		if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_RAW) {
			printf("\t\tHandler Type: Raw Data\n");
			printf("\t\tFunction: %p\n", plugins[i].generic_func);
		}
		else if(plugins[i].handler_type == PLUGIN_HANDLER_TYPE_OPENSSL) {
			printf("\t\tHandler Type: OpenSSL Data\n");
			printf("\t\tFunction: %p\n", plugins[i].generic_func);
		}
		else if (plugins[i].handler_type == PLUGIN_HANDLER_TYPE_ADDON) {
			printf("\t\tHandler Type: Addon-handled (%s)\n", plugins[i].handler_str);
			printf("\t\tAddon-supplied query function: %p\n", plugins[i].generic_func);
		}
		else {
			printf("\t\tType: Unknown\n");
		}
	}
	return;
}

int query_plugin(plugin_t* plugin, int id, const char* hostname, STACK_OF(X509)* x509_certs, const unsigned char* certs, size_t certs_len) {
	if (plugin->type == PLUGIN_TYPE_ASYNCHRONOUS) {
		/*switch (plugin->handler_type) {
			case PLUGIN_HANDLER_TYPE_RAW:
				return plugin->query_async_raw();
		}*/
		return PLUGIN_RESPONSE_ABSTAIN; // XXX not implemented
	}
	else {
		switch (plugin->handler_type) {
			case PLUGIN_HANDLER_TYPE_RAW:
				return plugin->query_sync_raw(hostname, certs, certs_len);
			case PLUGIN_HANDLER_TYPE_OPENSSL:
				return plugin->query_sync_openssl(hostname, x509_certs);
			case PLUGIN_HANDLER_TYPE_ADDON:
				return plugin->query_sync_by_addon(id, hostname, certs, certs_len);
		}
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
						// XXX asynchronous addon-handled plugins are
						// currently unsupported
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
	plugin->generic_func = dlsym(handle, "query");
	if (dlerror() != NULL) {
		return 2;
	}
	return 0;
}

