#include <stdio.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <pthread.h>

#include "netlink.h"
#include "configuration.h"
#include "query.h"
#include "query_queue.h"
#include "plugins.h"


policy_context_t context;

void* plugin_thread_init(void* arg);

typedef struct { unsigned char b[3]; } be24, le24;


int poll_schemes(uint64_t stptr, char* hostname, unsigned char* cert_data, size_t len) {
	int i;
	query_t* query;
	/* Validation */
	query = create_query(context.plugin_count, stptr, hostname, cert_data, len);
	for (i = 0; i < context.plugin_count; i++) {
		printf("Enqueuing query\n");
		enqueue(context.plugins[i].queue, query);
		printf("query enqueued\n");
	}
	return 0;
}


int main() {
	int i;
	pthread_t* plugin_threads;
	thread_param_t* plugin_thread_params;

	load_config(&context);
	init_addons(context.addons, context.addon_count, context.plugin_count);
	init_plugins(context.addons, context.addon_count, context.plugins, context.plugin_count);
	print_addons(context.addons, context.addon_count);
	print_plugins(context.plugins, context.plugin_count);


	/* Plugin Threading */
	plugin_thread_params = (thread_param_t*)malloc(sizeof(thread_param_t) * context.plugin_count);
	plugin_threads = (pthread_t*)malloc(sizeof(pthread_t) * context.plugin_count);
	for (i = 0; i < context.plugin_count; i++) {
		context.plugins[i].queue = make_queue(context.plugins[i].name); // XXX relocate this
		plugin_thread_params[i].plugin_id = i;
		pthread_create(&plugin_threads[i], NULL, plugin_thread_init, &plugin_thread_params[i]);
	}

	listen_for_queries();

	// Cleanup
	for (i = 0; i < context.plugin_count; i++) {
		free_queue(context.plugins[i].queue); // XXX relocate this
		pthread_join(plugin_threads[i], NULL);
	}
	close_plugins(context.plugins, context.plugin_count);
	close_addons(context.addons, context.addon_count);
	free(plugin_thread_params);
	free(plugin_threads);
	return 0;
}

void* plugin_thread_init(void* arg) {
	queue_t* queue;
	int plugin_id;
	thread_param_t* params;
	plugin_t* plugin;
	query_t* query;
	int result;
	int report_sent;

	params = (thread_param_t*)arg;
	plugin_id = params->plugin_id;
	plugin = &context.plugins[plugin_id];
	queue = plugin->queue;
	
	//context.plugins[plugin_id].init(); // XXX set default
	while (1) {
		printf("Dequeuing query\n");
		query = dequeue(queue);
		report_sent = 0;
		printf("Query dequeued\n");
		if (plugin->type == PLUGIN_TYPE_INTERNAL_RAW || PLUGIN_TYPE_INTERNAL_OPENSSL ||
					PLUGIN_TYPE_ADDON_HANDLED) {
			result = query_plugin(plugin, plugin_id, query->hostname,
					query->chain, query->raw_chain, query->raw_chain_len);
			query->responses[plugin_id] = result;
			pthread_mutex_lock(&query->mutex);
			query->num_responses++;
			printf("%d plugins have submitted an answer\n", query->num_responses);
			if (query->num_responses == context.plugin_count) {
				printf("All plugins have submitted an answer\n");
				send_response(query->state_pointer, 1);
				report_sent = 1;
			}
			pthread_mutex_unlock(&query->mutex);
			if (report_sent == 1) {
				free_query(query);
			}
		}
		else if (plugin->type == PLUGIN_TYPE_EXTERNAL) {
			// XXX UNSUPPORTED STILL
		}
		// XXX MAKE this also send a callback for asynchronous plugins
		// Have the Master plugin thread (the one doing the CA plugin) also
		// wait for other plugins to finish with timeouts
		// Have callbacks check query/semaphore validity to handle eventual responses from timed out asychronous plugins
	}

	//context.plugins[plugin_id].finalize(); // XXX set default
	return NULL;
}

