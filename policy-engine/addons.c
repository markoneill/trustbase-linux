#include "addons.h"

#include <stdio.h>
#include <dlfcn.h>

int load_addon(const char* path, addon_t* addon) {
	addon_initialize init_func;
	addon_finalize fin_func;
	addon_load_plugin load_func;
	addon_query_plugin query_func;
	void* handle;

	// Load shared object
	handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL) {
		fprintf(stderr, "Failed to load addon '%s': %s\n", path, dlerror());
		return 1;
	}
	addon->so_handle = handle;

	// Load functions within shared object
	init_func = dlsym(handle, "initialize");
	if (init_func == NULL) {
		fprintf(stderr, "Failed to load initialize function for addon '%s': %s\n", path, dlerror());
		return 1;
	}
	fin_func = dlsym(handle, "finalize");
	if (fin_func == NULL) {
		fprintf(stderr, "Failed to load finalize function for addon '%s': %s\n", path, dlerror());
		return 1;
	}
	load_func = dlsym(handle, "load_plugin");
	if (load_func == NULL) {
		fprintf(stderr, "Failed to load load_plugin function for addon '%s': %s\n", path, dlerror());
		return 1;
	}
	query_func = dlsym(handle, "query_plugin");
	if (query_func == NULL) {
		fprintf(stderr, "Failed to load query_plugin function for addon '%s': %s\n", path, dlerror());
		return 1;
	}
	addon->addon_initialize = init_func;
	addon->addon_finalize = fin_func;
	addon->addon_load_plugin = load_func;
	addon->addon_query_plugin = query_func;
	return 0;
}

void init_addons(addon_t* addons, size_t addon_count, size_t plugin_count) {
	int i;
	for (i = 0; i < addon_count; i++) {
		addons[i].addon_initialize(plugin_count, ".");
	}
	return;
}

void close_addons(addon_t* addons, size_t addon_count) {
	int i;
	for (i = 0; i < addon_count; i++) {
		addons[i].addon_finalize();
	}
	free(addons);
	return;
}

void print_addons(addon_t* addons, size_t addon_count) {
	int i;
	printf("%zu loaded addons:\n", addon_count);
	for (i = 0; i < addon_count; i++) {
		printf("\t[%02d] Addon Name: %s\n", i, addons[i].name);
		printf("\t\tDescription: %s\n", addons[i].desc);
		printf("\t\tVersion: %s\n", addons[i].ver);
	}
	return;
}
