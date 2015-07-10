#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dlfcn.h>
#include <string.h>
#include "plugins.h"
#include "addons.h"

static void close_internal_plugins(plugin_t* plugins, size_t plugin_count);

void print_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	printf("%zu loaded plugins:\n", plugin_count);
	for (i = 0; i < plugin_count; i++) {
		printf("\t[%02d] Plugin Name: %s\n", i, plugins[i].name);
		printf("\t\tDescription: %s\n", plugins[i].desc);
		printf("\t\tVersion: %s\n", plugins[i].ver);
		printf("\t\tPath: %s\n", plugins[i].path);
		if (plugins[i].type == PLUGIN_TYPE_EXTERNAL) {
			printf("\t\tType: External\n");
			printf("\t\tService: %s:%d\n", plugins[i].hostname, plugins[i].port);
		}
		else if (plugins[i].type == PLUGIN_TYPE_INTERNAL_RAW ||
			 plugins[i].type == PLUGIN_TYPE_INTERNAL_OPENSSL) {
			printf("\t\tType: Internal\n");
			printf("\t\tFunction: %p\n", plugins[i].query_func_openssl);
		}
		else if (plugins[i].type == PLUGIN_TYPE_ADDON_HANDLED) {
			printf("\t\tType: Addon-handled (%s)\n", plugins[i].type_str);
			printf("\t\tAddon-supplied query function: %p\n", plugins[i].query_func_by_addon);
		}
		else {
			printf("\t\tType: Unknown\n");
		}
	}
	return;
}

int query_plugin(plugin_t* plugin, int id, const char* hostname, STACK_OF(X509)* x509_certs, const unsigned char* certs, size_t certs_len) {
	switch (plugin->type) {
		case PLUGIN_TYPE_INTERNAL_RAW:
			return query_raw_plugin(plugin, hostname, certs, certs_len);
			break;
		case PLUGIN_TYPE_INTERNAL_OPENSSL:
			return query_openssl_plugin(plugin, hostname, x509_certs);
			break;
		case PLUGIN_TYPE_EXTERNAL:
			return PLUGIN_RESPONSE_ABSTAIN; // XXX not implemented
			break;
		case PLUGIN_TYPE_ADDON_HANDLED:
			return plugin->query_func_by_addon(id, hostname, certs, certs_len);
			break;
		default:
			return PLUGIN_RESPONSE_ABSTAIN;
			break;
	}
}

int query_openssl_plugin(plugin_t* plugin, const char* hostname, STACK_OF(X509)* certs) {
	query_func_openssl func;
	func = plugin->query_func_openssl;
	return (*func)(hostname, certs);
}

int query_raw_plugin(plugin_t* plugin, const char* hostname, const unsigned char* certs, size_t certs_length) {
	query_func_raw func;
	func = plugin->query_func_raw;
	return (*func)(hostname, certs, certs_length);
}

void init_plugins(addon_t* addons, size_t addon_count, plugin_t* plugins, size_t plugin_count) {
	int i;
	int j;
	for (i = 0; i < plugin_count; i++) {
		if (plugins[i].type == PLUGIN_TYPE_INTERNAL_OPENSSL) {
			load_query_func_openssl(&plugins[i]);
		}
		else if (plugins[i].type == PLUGIN_TYPE_INTERNAL_RAW) {
			load_query_func_raw(&plugins[i]);
		}
		// XXX external plugins
		else {
			for (j = 0; j < addon_count; j++) {
				if (strcmp(addons[j].type_handled, plugins[i].type_str) == 0) {
					plugins[i].type = PLUGIN_TYPE_ADDON_HANDLED;
					addons[j].addon_load_plugin(i, plugins[i].path);
					plugins[i].query_func_by_addon = addons[j].addon_query_plugin;
					break;
				}
			}
		}
		if (plugins[i].type == PLUGIN_TYPE_UNKNOWN) {
			fprintf(stderr, "Unhandled plugin type for plugin %02d\n", i);
		}
	}
	return;
}

void close_plugins(plugin_t* plugins, size_t plugin_count) {
	close_internal_plugins(plugins, plugin_count);
	//close_external_plugins(plugins, plugin_count); // XXX
	free(plugins);
	return;
}

void close_internal_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	for (i = 0; i < plugin_count; i++) {
		if (plugins[i].type == PLUGIN_TYPE_INTERNAL_OPENSSL ||
			plugins[i].type == PLUGIN_TYPE_INTERNAL_RAW) {
			dlclose(plugins[i].so_handle);
		}
	}
	return;
}

int load_query_func_raw(plugin_t* plugin) {
	query_func_raw func;
	void* handle;
	handle = dlopen(plugin->path, RTLD_LAZY);
	if (!handle) {
		return 1;
	}
	plugin->so_handle = handle;
	dlerror(); // clear error (if any)
	func = dlsym(handle, "query");
	plugin->query_func_raw = func;
	if (dlerror() != NULL) {
		return 2;
	}
	return 0;
}

int load_query_func_openssl(plugin_t* plugin) {
	query_func_openssl func;
	void* handle;
	handle = dlopen(plugin->path, RTLD_LAZY);
	if (!handle) {
		return 1;
	}
	plugin->so_handle = handle;
	dlerror(); // clear error (if any)
	func = dlsym(handle, "query");
	plugin->query_func_openssl = func;
	if (dlerror() != NULL) {
		return 2;
	}
	return 0;
}

