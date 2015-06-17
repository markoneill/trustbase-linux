#ifndef POLICY_ENGINE_H_
#define POLICY_ENGINE_H_

#include "addons.h"
#include "plugins.h"

enum {
	AGGREGATION_MAJORITY,
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

#endif
