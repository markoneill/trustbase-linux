#include "addons.h"

#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>

int load_addon(const char* path, addon_t* addon) {
	addon_initialize init_func;
	addon_finalize fin_func;
	addon_load_plugin load_func;
	addon_query_plugin query_func;
	addon_async_query_plugin async_query_func;
	addon_finalize_plugin fin_plugin_func;
	void* handle;

	// Load shared object
	handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL) {
		tblog(LOG_ERROR, "Failed to load addon '%s': %s", path, dlerror());
		return 1;
	}
	addon->so_handle = handle;

	// Load functions within shared object
	init_func = dlsym(handle, "initialize");
	if (init_func == NULL) {
		tblog(LOG_ERROR, "Failed to load initialize function for addon '%s': %s", path, dlerror());
		return 1;
	}
	fin_func = dlsym(handle, "finalize");
	if (fin_func == NULL) {
		tblog(LOG_ERROR, "Failed to load finalize function for addon '%s': %s", path, dlerror());
		return 1;
	}
	load_func = dlsym(handle, "load_plugin");
	if (load_func == NULL) {
		tblog(LOG_ERROR, "Failed to load load_plugin function for addon '%s': %s", path, dlerror());
		return 1;
	}
	query_func = dlsym(handle, "query_plugin");
	if (query_func == NULL) {
		tblog(LOG_ERROR, "Failed to load query_plugin function for addon '%s': %s", path, dlerror());
		return 1;
	}
	async_query_func = dlsym(handle, "query_plugin_async");
	if (query_func == NULL) {
		tblog(LOG_ERROR, "Failed to load async_query_plugin function for addon '%s': %s", path, dlerror());
		return 1;
	}
	fin_plugin_func = dlsym(handle, "finalize_plugin");
	if (fin_plugin_func == NULL) {
		tblog(LOG_ERROR, "Failed to load finalize_plugin funciton for addon '%s': %s", path, dlerror());
		return 1;
	}

	addon->addon_initialize = init_func;
	addon->addon_finalize = fin_func;
	addon->addon_load_plugin = load_func;
	addon->addon_query_plugin = query_func;
	addon->addon_async_query_plugin = async_query_func;
	addon->addon_finalize_plugin = fin_plugin_func;

	return 0;
}

void init_addons(addon_t* addons, size_t addon_count, size_t plugin_count, int(*callback)(int, int, int)) {
	int i;
	for (i = 0; i < addon_count; i++) {
		addons[i].addon_initialize(plugin_count, ".", callback, addons[i].so_path, tblog);
	}
	return;
}

void close_addons(addon_t* addons, size_t addon_count) {
	int i;
	for (i = 0; i < addon_count; i++) {
		addons[i].addon_finalize();
		free(addons[i].name);
		free(addons[i].desc);
		free(addons[i].ver);
		free(addons[i].type_handled);
		
		dlclose(addons[i].so_handle);
	}
	free(addons);
	return;
}

void print_addons(addon_t* addons, size_t addon_count) {
	int i;
	tblog(LOG_INFO, "%zu loaded addons:", addon_count);
	for (i = 0; i < addon_count; i++) {
		tblog(LOG_INFO, "\t[%02d] Addon Name: %s", i, addons[i].name);
		tblog(LOG_INFO, "\t\tDescription: %s", addons[i].desc);
		tblog(LOG_INFO, "\t\tVersion: %s", addons[i].ver);
	}
	return;
}
