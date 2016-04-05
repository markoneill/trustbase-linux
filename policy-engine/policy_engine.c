#include <stdio.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

#include "netlink.h"
#include "configuration.h"
#include "query.h"
#include "query_queue.h"
#include "linked_list.h"
#include "plugins.h"
#include "policy_response.h"
#include "plugin_response.h"
#include "check_root_store.h"
#include "th_logging.h"

#define TRUSTHUB_PLUGIN_TIMEOUT	(2) // in seconds

policy_context_t context;

static void* plugin_thread_init(void* arg);
static void* decider_thread_init(void* arg);
static int async_callback(int plugin_id, int query_id, int result);
static int aggregate_responses(query_t* query, int ca_system_response);

static volatile int keep_running;

typedef struct { unsigned char b[3]; } be24, le24;


int poll_schemes(uint64_t stptr, char* hostname, uint16_t port, unsigned char* cert_data, size_t len) {
	static int id = 0;
	int i;
	query_t* query;
	/* Validation */
	query = create_query(context.plugin_count, id++, stptr, hostname, port, cert_data, len);
	list_add(context.timeout_list, query);
	enqueue(context.decider_queue, query);
	for (i = 0; i < context.plugin_count; i++) {
		//printf("Enqueuing query\n");
		enqueue(context.plugins[i].queue, query);
		//printf("query enqueued\n");
	}
	return 0;
}


int main(int argc, char* argv[]) {
	int i;
	pthread_t logging_thread;
	pthread_t decider_thread;
	pthread_t* plugin_threads;
	thread_param_t decider_thread_params;
	thread_param_t* plugin_thread_params;
	
	keep_running = 1;
	
	/* Start Logging */
	thlog_init("/var/log/trusthub.log", LOG_DEBUG);
	pthread_create(&logging_thread, NULL, read_kthlog, NULL);
	
	load_config(&context, argv[1]);
	init_addons(context.addons, context.addon_count, context.plugin_count, async_callback);
	init_plugins(context.addons, context.addon_count, context.plugins, context.plugin_count);
	print_addons(context.addons, context.addon_count);
	printf("Congress Threshold is %2.1lf\n", context.congress_threshold);
	print_plugins(context.plugins, context.plugin_count);

	/* Decider thread (runs CA system and aggregates plugin verdicts */
	decider_thread_params.plugin_id = -1;
	context.decider_queue = make_queue("decider");
	context.timeout_list = list_create();
	pthread_create(&decider_thread, NULL, decider_thread_init, &decider_thread_params);


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
	keep_running = 0;
	for (i = 0; i < context.plugin_count; i++) {
		pthread_kill(plugin_threads[i], SIGTERM);
	}
	pthread_kill(decider_thread, SIGTERM);
	for (i = 0; i < context.plugin_count; i++) {
		pthread_join(plugin_threads[i], NULL);
		free_queue(context.plugins[i].queue); // XXX relocate this
	}
	pthread_join(decider_thread, NULL);
	free_queue(context.decider_queue);
	list_free(context.timeout_list);
	close_plugins(context.plugins, context.plugin_count);
	close_addons(context.addons, context.addon_count);
	free(plugin_thread_params);
	free(plugin_threads);
	pthread_kill(logging_thread, SIGTERM);
	thlog_close();
	return 0;
}

void* plugin_thread_init(void* arg) {
	queue_t* queue;
	int plugin_id;
	thread_param_t* params;
	plugin_t* plugin;
	query_t* query;
	int result;

	params = (thread_param_t*)arg;
	plugin_id = params->plugin_id;
	plugin = &context.plugins[plugin_id];
	queue = plugin->queue;
	
	if (plugin->generic_init_func != NULL) {
		if (plugin->type == PLUGIN_TYPE_SYNCHRONOUS) {
			plugin->init_sync(plugin_id);
		}
		else {
			plugin->init_async(plugin_id, async_callback);
		}
	}
	while (keep_running == 1) {
		//printf("Dequeuing query\n");
		query = dequeue(queue);
		//printf("Query dequeued\n");
		if (plugin->type == PLUGIN_TYPE_SYNCHRONOUS) {
			result = query_sync_plugin(plugin, plugin_id, query);
			query->responses[plugin_id] = result;
			pthread_mutex_lock(&query->mutex);
			query->num_responses++;
			//printf("%d plugins have submitted an answer\n", query->num_responses);
			if (query->num_responses == context.plugin_count) {
				pthread_cond_signal(&query->threshold_met);
			}
			pthread_mutex_unlock(&query->mutex);
		}
		else if (plugin->type == PLUGIN_TYPE_ASYNCHRONOUS) {
			query_async_plugin(plugin, plugin_id, query);
		}
	}
	return NULL;
}

void* decider_thread_init(void* arg) {
	queue_t* queue;
	query_t* query;
	int ca_system_response;
	struct timespec time_to_wait;
	struct timeval now;
	int err;
	int final_response;
	X509_STORE* root_store;
	queue = context.decider_queue;
	
	root_store = make_new_root_store();
	while (keep_running == 1) {
		query = dequeue(queue);
		ca_system_response =  query_store(query->hostname, query->chain, root_store);
		//printf("CA System response is %d\n", ca_system_response);
		gettimeofday(&now, NULL);
		time_to_wait.tv_sec = now.tv_sec + TRUSTHUB_PLUGIN_TIMEOUT;
		time_to_wait.tv_nsec = now.tv_usec*1000UL;
		pthread_mutex_lock(&query->mutex);
		while (query->num_responses < context.plugin_count) {
			err = pthread_cond_timedwait(&query->threshold_met, &query->mutex, &time_to_wait);
			if (err == ETIMEDOUT) {
				fprintf(stderr, "A plugin timed out!\n");
				break;
			}
		}
		pthread_mutex_unlock(&query->mutex);
		/* Either all plugins reported or some timed out.
 		 * either way, remove the query from the timeout storage */
		list_remove(context.timeout_list, query->id);
		
		//printf("All plugins have submitted an answer\n");
		final_response = aggregate_responses(query, ca_system_response);
		free_query(query);
		send_response(query->state_pointer, final_response);
	}
	return NULL;
}

int async_callback(int plugin_id, int query_id, int result) {
	query_t* query;

	query = list_get(context.timeout_list, query_id);
	if (query == NULL) {
		fprintf(stderr, "Plugin %d timed out on query %d but sent data anyway\n", plugin_id, query_id);
		return 0; /* let plugin know this result timed out */
	}
	query->responses[plugin_id] = result;
	pthread_mutex_lock(&query->mutex);
	query->num_responses++;
	if (query->num_responses == context.plugin_count) {
		//printf("%d plugins have submitted an answer\n", query->num_responses);
		pthread_cond_signal(&query->threshold_met);
	}
	pthread_mutex_unlock(&query->mutex);
	//printf("Asynchronous callback invoked by plugin %d!\n", plugin_id);
	return 1; /* let plugin know the callback was successful */
}

int aggregate_responses(query_t* query, int ca_system_response) {
	int i;
	double congress_approved_count;
	double congress_total;

	congress_approved_count = 0;
	congress_total = 0;
	for (i = 0; i < context.plugin_count; i++) {
		switch (context.plugins[i].aggregation) {
			case AGGREGATION_NECESSARY:
				/* We don't need to count necessary plugins' responses.
 				 * If any of them don't say yes we just say no immediately */
				if (query->responses[i] != PLUGIN_RESPONSE_VALID) {
					printf("Policy Engine reporting BAD cert for %s\n", query->hostname);
					return POLICY_RESPONSE_INVALID;
				}
				break;
			case AGGREGATION_CONGRESS:
				if (query->responses[i] == PLUGIN_RESPONSE_VALID) {
					congress_approved_count++;
				}
				congress_total++;
				break;
			case AGGREGATION_NONE:
			default:
				fprintf(stderr, "A plugin without an aggregation setting is running\n");
				break;
		}
	}
	/* At this point we know that all necessary plugins have indicate the certificates
 	 * found were valid, otherwise we'd have returned already.  Therefore the decision
 	 * is in the hands of the congress plugins */
	if (congress_total && (congress_approved_count / congress_total) < context.congress_threshold) {
		printf("Policy Engine reporting BAD cert for %s\n", query->hostname);
		return POLICY_RESPONSE_INVALID;
	}

	/* At this point we know the certificates are valid, but what we send back depends on
         * what the CA system said */
	if (ca_system_response == PLUGIN_RESPONSE_INVALID) {
		printf("Policy Engine reporting good cert for %s but it needs to be proxied\n", query->hostname);
		return POLICY_RESPONSE_VALID_PROXY;
	}
	printf("Policy Engine reporting good cert for %s\n", query->hostname);
	return POLICY_RESPONSE_VALID;
}
