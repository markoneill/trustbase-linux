#ifndef PLUGINS_H_
#define PLUGINS_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "query_queue.h"
#include "addons.h"

#define PLUGIN_HOSTNAME_MAX	256
#define PLUGIN_NAME_MAX		32
#define PLUGIN_DESC_MAX		256
#define PLUGIN_PATH_MAX		256
#define PLUGIN_VERSION_STR_MAX	32
#define PLUGIN_TYPE_STR_MAX	32

#define PLUGIN_RESPONSE_ERROR	-1
#define PLUGIN_RESPONSE_VALID	1
#define PLUGIN_RESPONSE_INVALID	0
#define PLUGIN_RESPONSE_ABSTAIN	2

enum {
	PLUGIN_TYPE_UNKNOWN,
	PLUGIN_TYPE_EXTERNAL,
	PLUGIN_TYPE_INTERNAL_OPENSSL,
	PLUGIN_TYPE_INTERNAL_RAW,
	PLUGIN_TYPE_ADDON_HANDLED,
};

typedef int (*query_func_raw)(const char*, const unsigned char*, size_t);
typedef int (*query_func_openssl)(const char*, STACK_OF(X509)*);

typedef struct plugin_t {
	int type;
	char type_str[PLUGIN_TYPE_STR_MAX];
	char name[PLUGIN_NAME_MAX];
	char desc[PLUGIN_DESC_MAX];
	char ver[PLUGIN_VERSION_STR_MAX];
	queue_t* queue;
	void* so_handle; // pointer to shared object or index into handler
	union {
		/* used for native plugins using OpenSSL */
		int (*query_func_openssl)(const char*, STACK_OF(X509)*);
		/* used for native plugins needing raw DER certificates */
		int (*query_func_raw)(const char*, const unsigned char*, size_t);
		/* used by plugins handled by addons */
		int (*query_func_by_addon)(int, const char*, const unsigned char*, size_t);
	};
	char hostname[PLUGIN_HOSTNAME_MAX]; // null terminated
	char path[PLUGIN_PATH_MAX]; // null-terminated path to plugin file
	int port;
} plugin_t;

void print_plugins(plugin_t* plugins, size_t plugin_count);
void close_plugins(plugin_t* plugins, size_t plugin_count);
int load_query_func_raw(plugin_t* plugin);
int load_query_func_openssl(plugin_t* plugin);
void init_plugins(addon_t* addons, size_t addon_count, plugin_t* plugins, size_t plugin_count);
int query_plugin(plugin_t* plugin, int id, const char* hostname, STACK_OF(X509)* x509_certs, const unsigned char* certs, size_t certs_len);
int query_openssl_plugin(plugin_t* plugin, const char* hostname, STACK_OF(X509)* certs);
int query_raw_plugin(plugin_t* plugin, const char* hostname, const unsigned char* certs, size_t certs_len);

#endif
