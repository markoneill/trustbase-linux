#ifndef _PLUGINS_H
#define _PLUGINS_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define PLUGIN_HOSTNAME_MAX	256
#define PLUGIN_NAME_MAX		32
#define PLUGIN_DESC_MAX		256
#define PLUGIN_VERSION_STR_MAX	32

enum {
	PLUGIN_TYPE_NONE,
	PLUGIN_TYPE_EXTERNAL,
	PLUGIN_TYPE_INTERNAL_OPENSSL,
	PLUGIN_TYPE_INTERNAL_RAW,
};

enum {
	AGGREGATION_MAJORITY,
	AGGREGATION_UNANIMITY,
	AGGREGATION_CHAMPION,
	AGGREGATION_THRESHOLD,
};

typedef int (*query_func_raw)(const char*, unsigned char*, size_t);
typedef int (*query_func_openssl)(const char*, STACK_OF(X509)*);

typedef struct plugin_t {
	int type;
	char name[PLUGIN_NAME_MAX];
	char desc[PLUGIN_DESC_MAX];
	char ver[PLUGIN_VERSION_STR_MAX];
	void* so_handle;
	union {
		int (*query_func_openssl)(const char* hostname, STACK_OF(X509)* certs);
		int (*query_func_raw)(const char* hostname, unsigned char* certs, size_t certs_length);
	};
	char hostname[PLUGIN_HOSTNAME_MAX]; // null terminated
	int port;
} plugin_t;

void print_plugins(plugin_t* plugins, size_t plugin_count);
void close_plugins(plugin_t* plugins, size_t plugin_count);
int load_query_func_raw(const char* path, plugin_t* plugin);
int load_query_func_openssl(const char* path, plugin_t* plugin);

#endif
