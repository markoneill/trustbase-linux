#ifndef ADDONS_H_
#define ADDONS_H_

#include <stdlib.h>

#define ADDON_NAME_MAX		32
#define ADDON_DESC_MAX		256
#define ADDON_VERSION_STR_MAX	32

typedef int (*addon_initialize)(int, char*);
typedef int (*addon_finalize)();
typedef int (*addon_load_plugin)(int, char*);
typedef int (*addon_query_plugin)(int, char*, const unsigned char*, size_t);

typedef struct addon_t {
	char name[ADDON_NAME_MAX];
	char desc[ADDON_DESC_MAX];
	char ver[ADDON_VERSION_STR_MAX];
	int (*addon_initialize)(int, char*);
	int (*addon_finalize)();
	int (*addon_load_plugin)(int, char*);
	int (*addon_query_plugin)(int, char*, const unsigned char*, size_t);
	void* so_handle;
} addon_t;

int load_addon_functions(const char* path, addon_t* addon);

#endif
