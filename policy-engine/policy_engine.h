#ifndef POLICY_ENGINE_H_
#define POLICY_ENGINE_H_

#include "addons.h"
#include "plugins.h"
#include "query_queue.h"

enum {
	AGGREGATION_UNANIMITY,
	AGGREGATION_CHAMPION,
	AGGREGATION_THRESHOLD,
};

typedef struct policy_context_t {
	plugin_t* plugins;
	int plugin_count;
	addon_t* addons;
	int addon_count;
	/* new members here for aggregation policy */
} policy_context_t;

typedef struct thread_param_t {
	int plugin_id;
} thread_param_t;

int poll_schemes(uint64_t stptr, char* hostname, unsigned char* cert_data, size_t len);
#endif
