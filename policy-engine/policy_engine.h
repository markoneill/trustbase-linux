#ifndef POLICY_ENGINE_H_
#define POLICY_ENGINE_H_

typedef struct policy_context_t {
	plugin_t* plugins;
	int plugin_count;
	addon_t* addons;
	int addon_count;
	/* new members here for aggregation policy */
} policy_context_t;

#endif
