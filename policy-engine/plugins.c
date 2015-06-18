#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dlfcn.h>
#include "plugins.h"

static void close_internal_plugins(plugin_t* plugins, size_t plugin_count);

void print_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	printf("%zu loaded plugins:\n", plugin_count);
	for (i = 0; i < plugin_count; i++) {
		printf("\t[%02d] Plugin Name: %s\n", i, plugins[i].name);
		printf("\t\tDescription: %s\n", plugins[i].desc);
		printf("\t\tVersion: %s\n", plugins[i].ver);
		if (plugins[i].type == PLUGIN_TYPE_EXTERNAL) {
			printf("\t\tType: External\n");
			printf("\t\tService: %s:%d\n", plugins[i].hostname, plugins[i].port);
		}
		else if (plugins[i].type == PLUGIN_TYPE_INTERNAL_RAW ||
			 plugins[i].type == PLUGIN_TYPE_INTERNAL_OPENSSL) {
			printf("\t\tType: Internal\n");
			printf("\t\tFunction: %p\n", plugins[i].query_func_openssl);
		}
		else {
			printf("\t\tType: Unknown\n");
		}
	}
	return;
}

int query_openssl_plugin(plugin_t* plugin, const char* hostname, STACK_OF(X509)* certs) {
	query_func_openssl func;
	func = plugin->query_func_openssl;
	return (*func)(hostname, certs);
}

int query_raw_plugin(plugin_t* plugin, const char* hostname, unsigned char* certs, unsigned certs_length) {
	query_func_raw func;
	func = plugin->query_func_raw;
	return (*func)(hostname, certs, certs_length);
}

void init_plugins(plugin_t* plugins, size_t plugin_count) {
	int i;
	for (i = 0; i < plugin_count; i++) {
		if (plugins[i].type != PLUGIN_TYPE_INTERNAL_OPENSSL &&
			plugins[i].type != PLUGIN_TYPE_INTERNAL_RAW) {
			// init_external_plugins(); // XXX
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

int load_query_func_raw(const char* path, plugin_t* plugin) {
	query_func_raw func;
	void* handle;
	handle = dlopen(path, RTLD_LAZY);
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

int load_query_func_openssl(const char* path, plugin_t* plugin) {
	query_func_openssl func;
	void* handle;
	handle = dlopen(path, RTLD_LAZY);
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
