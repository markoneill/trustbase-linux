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
	queue_t* queue;
} thread_param_t;

int poll_schemes(char* hostname, unsigned char* data, size_t len, unsigned char** rcerts, int* rcerts_len);
#endif
