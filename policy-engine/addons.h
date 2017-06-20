#ifndef ADDONS_H_
#define ADDONS_H_

#include <stdlib.h>
#include <stdint.h>
#include "trustbase_plugin.h"

typedef int (*addon_initialize)(int, char*, int(*callback)(int,int,int), const char*, int(*plog)(tblog_level_t, const char*, ... ));
typedef int (*addon_finalize)(void);
typedef int (*addon_load_plugin)(int, char*, int);
typedef int (*addon_query_plugin)(int, query_data_t*);
typedef int (*addon_async_query_plugin)(int, query_data_t*);
typedef int (*addon_finalize_plugin)(int);

typedef struct addon_t {
	char* name;
	char* desc;
	char* ver;
	char* type_handled;
	int (*addon_initialize)(int, char*, int(*callback)(int,int,int), const char*, int(*plog)(tblog_level_t, const char*, ... ));
	int (*addon_finalize)(void);
	int (*addon_load_plugin)(int, char*, int);
	int (*addon_query_plugin)(int, query_data_t*);
	int (*addon_async_query_plugin)(int, query_data_t*);
	int (*addon_finalize_plugin)(int);
	void* so_handle;
	char* so_path;
} addon_t;

int load_addon(const char* path, addon_t* addon);
void init_addons(addon_t* addons, size_t addon_count, size_t plugin_count, int(*callback)(int, int, int));
void close_addons(addon_t* addons, size_t addon_count);
void print_addons(addon_t* addons, size_t addon_count);

#endif
