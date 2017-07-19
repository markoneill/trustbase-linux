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
#include "trustbase_plugin.h"
#include "ca_validation.h"
#include "tb_logging.h"
#include "policy_engine.h"

#include <unistd.h>
#include <string.h>

#define TRUSTBASE_PLUGIN_TIMEOUT	(2) // in seconds

policy_context_t context;

static void* plugin_thread_init(void* arg);
static void* decider_thread_init(void* arg);
static int async_callback(int plugin_id, int query_id, int result);
static int aggregate_responses(query_t* query, int ca_system_response);

static volatile int keep_running;

typedef struct { unsigned char b[3]; } be24, le24;


int poll_schemes(uint32_t spid, uint64_t stptr, char* hostname, uint16_t port, unsigned char* cert_data, size_t len, char* client_hello, size_t client_hello_len, char* server_hello, size_t server_hello_len) {
	static int id = 0;
	int i;
	query_t* query;
	/* Validation */
	query = create_query(context.plugin_count, id++, spid, stptr, hostname, port, cert_data, len, client_hello, client_hello_len, server_hello, server_hello_len);
	list_add(context.timeout_list, query);
	enqueue(context.decider_queue, query);
	for (i = 0; i < context.plugin_count; i++) {
		enqueue(context.plugins[i].queue, query);
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
	char username[MAX_USERNAME_LEN + 1];
	char* plugin_name;
	
	keep_running = 1;
	
	/* Start Logging */
	tblog_init("/var/log/trustbase.log", LOG_DEBUG);
	tblog(LOG_INFO, "\n\n### Started Policy Engine ### Starting Logging ###\n");
	pthread_create(&logging_thread, NULL, read_ktblog, NULL);
	
	load_config(&context, argv[1], username);
	
	if (prep_communication(username) != 0) {
		tblog(LOG_ERROR, "Could not prepare the netlink socket, exiting...");
		pthread_kill(logging_thread, SIGTERM);
		tblog_close();
		return -1;
	}
	
	init_addons(context.addons, context.addon_count, context.plugin_count, async_callback);
	init_plugins(context.addons, context.addon_count, context.plugins, context.plugin_count);
	print_addons(context.addons, context.addon_count);
	tblog(LOG_DEBUG, "Congress Threshold is %2.1lf", context.congress_threshold);
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
	for (i = context.plugin_count - 1; i >= 0; i--) {
		plugin_name = (char*)calloc(strlen(context.plugins[i].name) + 1, 1);
		strcpy(plugin_name, context.plugins[i].name);
		tblog(LOG_INFO, "canceling plugin thread %d", i);
		pthread_cancel(plugin_threads[i]);
		pthread_join(plugin_threads[i], NULL);
		free_queue(context.plugins[i].queue, plugin_name);
		free(plugin_name);
	}
	pthread_cancel(decider_thread);
	pthread_join(decider_thread, NULL);
	free_queue(context.decider_queue, "decider");
	list_free(context.timeout_list);
	free(context.plugins);
	close_addons(context.addons, context.addon_count);
	free(plugin_thread_params);
	free(plugin_threads);

	tblog(LOG_INFO, "\n\n### Closing Policy Engine ### Closing Logging ###\n");
	pthread_kill(logging_thread, SIGTERM);
	tblog_close();
	return 0;
}

void* plugin_thread_init(void* arg) {
	queue_t* queue;
	int plugin_id;
	thread_param_t* params;
	plugin_t* plugin;
	query_t* query;
	int result;
	init_data_t* idata;

	params = (thread_param_t*)arg;
	plugin_id = params->plugin_id;
	plugin = &context.plugins[plugin_id];
	queue = plugin->queue;
	
	idata = NULL;
	if (plugin->generic_init_func != NULL) {
		idata = (init_data_t*)malloc(sizeof(init_data_t));
		if (idata == NULL) {
			tblog(LOG_WARNING, "Unable to acllocate memory");
		}
		idata->plugin_id = plugin_id;
		idata->plugin_path = plugin->path;
		idata->tblog = tblog;
		idata->callback = (plugin->type == PLUGIN_TYPE_SYNCHRONOUS) ? NULL : async_callback;
		plugin->init(idata);
	}
	// Set up our cleanup
	pthread_cleanup_push(cleanup_plugin, plugin);
	tblog(LOG_DEBUG, "Plugin %s ready", plugin->name);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	while (keep_running == 1) {
		query = dequeue(queue);
		if (plugin->type == PLUGIN_TYPE_SYNCHRONOUS) {
			tblog(LOG_DEBUG, "Querying synch plugin %s", plugin->name);
			result = query_plugin(plugin, plugin_id, query);
			query->responses[plugin_id] = result;
			pthread_mutex_lock(&query->mutex);
			query->num_responses++;
			if (query->num_responses == context.plugin_count) {
				pthread_cond_signal(&query->threshold_met);
			}
			pthread_mutex_unlock(&query->mutex);
		} else if (plugin->type == PLUGIN_TYPE_ASYNCHRONOUS) {
			tblog(LOG_DEBUG, "Querying asynch plugin %s", plugin->name);
			query_plugin(plugin, plugin_id, query);
		}
	}
	if (idata != NULL) {
		free(idata); // XXX this will not be called after a cancel
	}
	
	pthread_cleanup_pop(1);
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
		ca_system_response =  query_store(query->data->hostname, query->data->chain, root_store);
		gettimeofday(&now, NULL);
		time_to_wait.tv_sec = now.tv_sec + TRUSTBASE_PLUGIN_TIMEOUT;
		time_to_wait.tv_nsec = now.tv_usec*1000UL;
		pthread_mutex_lock(&query->mutex);
		while (query->num_responses < context.plugin_count) {
			err = pthread_cond_timedwait(&query->threshold_met, &query->mutex, &time_to_wait);
			if (err == ETIMEDOUT) {
				tblog(LOG_DEBUG, "A plugin timed out!\n");
				break;
			}
		}
		pthread_mutex_unlock(&query->mutex);
		/* Either all plugins reported or some timed out.
 		 * either way, remove the query from the timeout storage */
		list_remove(context.timeout_list, query->data->id);
		
		final_response = aggregate_responses(query, ca_system_response);
		send_response(query->spid, query->state_pointer, final_response);
		free_query(query);
	}
	return NULL;
}

int async_callback(int plugin_id, int query_id, int result) {
	query_t* query;

	query = list_get(context.timeout_list, query_id);
	if (query == NULL) {
		tblog(LOG_INFO, "Plugin %d timed out on query %d but sent data anyway", plugin_id, query_id);
		return 0; /* let plugin know this result timed out */
	}
	query->responses[plugin_id] = result;
	pthread_mutex_lock(&query->mutex);
	query->num_responses++;
	if (query->num_responses == context.plugin_count) {
		pthread_cond_signal(&query->threshold_met);
	}
	pthread_mutex_unlock(&query->mutex);
	return 1; /* let plugin know the callback was successful */
}

int aggregate_responses(query_t* query, int ca_system_response) {
	int i;
	double congress_approved_count;
	double congress_total;

	congress_approved_count = 0;
	congress_total = 0;
	for (i = 0; i < context.plugin_count; i++) {
		if (query->responses[i] == PLUGIN_RESPONSE_VALID) {
			tblog(LOG_INFO, "Plugin %s returned valid", context.plugins[i].name);
		} else if (query->responses[i] == PLUGIN_RESPONSE_ERROR) {
			tblog(LOG_INFO, "Plugin %s returned with an error", context.plugins[i].name);
		} else if (query->responses[i] == PLUGIN_RESPONSE_INVALID) {
			tblog(LOG_INFO, "Plugin %s returned invalid", context.plugins[i].name);
		} else if (query->responses[i] == PLUGIN_RESPONSE_ABSTAIN) {
			tblog(LOG_INFO, "Plugin %s abstained", context.plugins[i].name);
		}
		switch (context.plugins[i].aggregation) {
			case AGGREGATION_NECESSARY:
				/* We don't need to count necessary plugins' responses.
 				 * If any of them don't say yes we just say no immediately */
				if (query->responses[i] != PLUGIN_RESPONSE_VALID) {
					tblog(LOG_INFO, "Policy Engine reporting BAD cert for %s", query->data->hostname);
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
				tblog(LOG_WARNING, "A plugin without an aggregation setting is running");
				break;
		}
	}
	/* At this point we know that all necessary plugins have indicate the certificates
 	 * found were valid, otherwise we'd have returned already.  Therefore the decision
 	 * is in the hands of the congress plugins */
	if (congress_total && (congress_approved_count / congress_total) < context.congress_threshold) {
		tblog(LOG_INFO, "Policy Engine reporting BAD cert for %s", query->data->hostname);
		return POLICY_RESPONSE_INVALID;
	}

	/* At this point we know the certificates are valid, but what we send back depends on
         * what the CA system said */
	if (ca_system_response == PLUGIN_RESPONSE_INVALID) {
		tblog(LOG_INFO, "Policy Engine reporting good cert for %s but it needs to be proxied", query->data->hostname);
		return POLICY_RESPONSE_VALID_PROXY;
	}
	tblog(LOG_INFO, "Policy Engine reporting good cert for %s", query->data->hostname);
	return POLICY_RESPONSE_VALID;
}
