#ifndef PLUGINS_H_
#define PLUGINS_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "query_queue.h"
#include "addons.h"

#define PLUGIN_RESPONSE_ERROR	-1
#define PLUGIN_RESPONSE_VALID	1
#define PLUGIN_RESPONSE_INVALID	0
#define PLUGIN_RESPONSE_ABSTAIN	2

enum {
	PLUGIN_HANDLER_TYPE_UNKNOWN,
	PLUGIN_HANDLER_TYPE_OPENSSL,
	PLUGIN_HANDLER_TYPE_RAW,
	PLUGIN_HANDLER_TYPE_ADDON,
};

enum {
	PLUGIN_TYPE_SYNCHRONOUS,
	PLUGIN_TYPE_ASYNCHRONOUS,
};

typedef int (*query_func_raw)(const char*, const unsigned char*, size_t);
typedef int (*query_func_openssl)(const char*, STACK_OF(X509)*);

typedef struct plugin_t {
	int type;
	char* handler_str;
	int handler_type;
	char* name;
	char* desc;
	char* ver;
	queue_t* queue;
	void* so_handle; // pointer to shared object or index into handler
	union {
		/* used as a generic identifier for all these union members */
		int (*generic_func)(void);
		/* used for native plugins using OpenSSL */
		int (*query_sync_openssl)(const char*, STACK_OF(X509)*);
		/* used for native plugins needing raw DER certificates */
		int (*query_sync_raw)(const char*, const unsigned char*, size_t);
		/* used by plugins handled by addons */
		int (*query_sync_by_addon)(int, const char*, const unsigned char*, size_t);
		//int (*query_async_by_addon)(int, const char*, const unsigned char*, size_t);
	};
	char* path; // null-terminated path to plugin file
} plugin_t;

void print_plugins(plugin_t* plugins, size_t plugin_count);
void close_plugins(plugin_t* plugins, size_t plugin_count);
int load_plugin_functions(plugin_t* plugin);
void init_plugins(addon_t* addons, size_t addon_count, plugin_t* plugins, size_t plugin_count);
int query_plugin(plugin_t* plugin, int id, const char* hostname, STACK_OF(X509)* x509_certs, const unsigned char* certs, size_t certs_len);

#endif
