#ifndef PLUGINS_H_
#define PLUGINS_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "query_queue.h"
#include "query.h"
#include "addons.h"

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

enum {
	AGGREGATION_NONE,
	AGGREGATION_CONGRESS,
	AGGREGATION_NECESSARY,
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
		int (*generic_query_func)(void);
		/* used for native plugins using OpenSSL */
		int (*query_sync_openssl)(const char*, STACK_OF(X509)*);
		int (*query_async_openssl)(int, const char*, STACK_OF(X509)*);
		/* used for native plugins needing raw DER certificates */
		int (*query_sync_raw)(const char*, const unsigned char*, size_t);
		int (*query_async_raw)(int, const char*, const unsigned char*, size_t);
		/* used by plugins handled by addons */
		int (*query_sync_by_addon)(int, const char*, const unsigned char*, size_t);
		int (*query_async_by_addon)(int, int, const char*, const unsigned char*, size_t);
	};
	union {
		/* used as a generic identifier for all these union members */
		int (*generic_init_func)(void);
		/* used for synchronous plugins that want an init stage (optional) */
		int (*init_sync)(int);
		/* used for asynchronous plugins that want an init stage (optional) */
		int (*init_async)(int, int(*callback)(int, int, int));
	};
	/* used for plugins that want a finalize stage (optional) */
	int (*finalize)(void);
	char* path; // null-terminated path to plugin file
	/* Aggregation group this plugin belongs to */
	int aggregation;
} plugin_t;

void print_plugins(plugin_t* plugins, size_t plugin_count);
void close_plugins(plugin_t* plugins, size_t plugin_count);
int load_plugin_functions(plugin_t* plugin);
void init_plugins(addon_t* addons, size_t addon_count, plugin_t* plugins, size_t plugin_count);
int query_sync_plugin(plugin_t* plugin, int id, query_t* query);
int query_async_plugin(plugin_t* plugin, int id, query_t* query);

#endif
