#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h> /* O_CREAT constant */
#include <sys/stat.h> /* S_IRWXU constant */
#include <semaphore.h>
#include <openssl/x509.h>
#include "../trusthub_plugin.h"

#define MAX_LENGTH	1024

typedef struct query_t {
	int id;
	const char* hostname;
	STACK_OF(X509)* chain;
} query_t;

/* Plugin functions */
int initialize(init_data_t* idata);
int finalize(void);
int query(query_data_t* data);
void* worker(void* arg);
void print_certificate(X509* cert);

/* Shared queue types and functions */
typedef struct queue_node_t {
	struct queue_node_t* next;
	query_t* query;
} queue_node_t;

typedef struct queue_t {
	queue_node_t* head;
	queue_node_t* tail;
	sem_t* fill_sem;
	pthread_mutex_t mutex;
} queue_t;

queue_t* make_queue(const char*);
void free_queue(queue_t* queue);
int enqueue(queue_t* queue, query_t* query);
query_t* dequeue(queue_t* queue);
queue_node_t* make_queue_node(query_t* query);

/* Globals */
int (*result_callback)(int plugin_id, int query_id, int result);
int plugin_id;
int running;
pthread_t worker_thread;
queue_t* queue;

int initialize(init_data_t* idata) {
	result_callback = idata->callback;
	plugin_id = idata->plugin_id;
	running = 1;
	queue = make_queue("async_test");
	pthread_create(&worker_thread, NULL, worker, (void*)NULL);
	printf("Initialized asynchronous test plugin\n");
	return 0;
}

int finalize(void) {
	running = 0;
	//pthread_join(worker_thread, NULL);
	free_queue(queue);
	return 0;
}

void* worker(void* arg) {
	//int i;
	//X509* cert;
	query_t* query;
	while (running) {
		query = dequeue(queue);
		//printf("Asynchronous Test Plugin checking cert for host: %s (query ID: %d)\n", query->hostname, query->id);
		/*printf("Certificate Data:\n");
		for (i = 0; i < sk_X509_num(query->chain); i++) {
			cert = sk_X509_value(query->chain, i);
			print_certificate(cert);
		}*/
		/* Send back a static accept result */
		result_callback(plugin_id, query->id, PLUGIN_RESPONSE_VALID);
		free(query);
	}
	return NULL;
}

/* TrustHub will not delete the data pointed to by these parameters until 
 * all plugins have reported or there is a timeout. In a real plugin you
 * should copy the source data to avoid bad dereferences in the case of a
 * timeout. */
int query(query_data_t* data) {
	query_t* query;
	query = (query_t*)malloc(sizeof(query_t));
	query->id = data->id;
	query->hostname = data->hostname;
	query->chain = data->chain;
	enqueue(queue, query);
	return 1;
}

void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("subject: %s\n", subj);
	printf("issuer: %s\n", issuer);
}


/**
 * Create a new empty queue
 * @returns queue pointer or NULL on failure
 */
queue_t* make_queue(const char* name) {
	queue_t* queue;
	sem_t* sem;
	sem = sem_open(name, O_CREAT, S_IRWXU, 0);
	if (sem == SEM_FAILED) {
		fprintf(stderr, "Failed to create queue semaphore %s: %s\n", name, strerror(errno));
		return NULL;
	}
	queue = (queue_t*)malloc(sizeof(queue_t));
	if (queue == NULL) {
		fprintf(stderr, "Failed to allocate space for queue %s\n", name);
		return NULL;
	}
	if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
		fprintf(stderr, "Failed to create mutex for queue %s\n", name);
		free(queue); /* free allocated memory since this happened after malloc */
		return NULL;
	}
	queue->head = NULL;
	queue->tail = NULL;
	queue->fill_sem = sem;
	return queue;
}

/**
 * Empties queue and frees all nodes
 * and queue itself
 */
void free_queue(queue_t* queue) {
	queue_node_t* current;
	queue_node_t* next;
	if (queue == NULL) {
		return;
	}
	current = queue->head;
	while (current != NULL) {
		next = current->next;
		/* We're not freeing the contents of nodes on purpose.
		   The query data still needs to be read by others */
		free(current);
		current = next;
	}
	if (sem_close(queue->fill_sem) == -1) {
		fprintf(stderr, "Failed to close semaphore: %s\n", strerror(errno));
	}
	if (pthread_mutex_destroy(&queue->mutex) != 0) {
		fprintf(stderr, "Failed to destroy queue mutex\n");
	}
	free(queue);
	return;
}

/**
 * Creates a queue node
 * @returns queue_node_t pointer or NULL on failure
 */
queue_node_t* make_queue_node(query_t* query) {
	queue_node_t* node;
	node = (queue_node_t*)malloc(sizeof(queue_node_t));
	if (node == NULL) {
		return NULL;
	}
	node->next = NULL;
	node->query = query;
	return node;
}

/**
 * Adds a query to the specified queue
 * @returns 1 on success, 0 on failure
 */
int enqueue(queue_t* queue, query_t* query) {
	queue_node_t* new_node;
	pthread_mutex_lock(&queue->mutex);
	new_node = make_queue_node(query);
	if (new_node == NULL) {
		pthread_mutex_unlock(&queue->mutex);
		return 0;
	}
	// If queue is empty
	if (queue->head == NULL) {
		assert(queue->tail == NULL);
		queue->head = new_node;
		queue->tail = new_node;
		pthread_mutex_unlock(&queue->mutex);
		sem_post(queue->fill_sem);
		return 1;
	}

	// If queue already has something in it
	assert(queue->tail->next == NULL);
	queue->tail->next = new_node;
	queue->tail = new_node;
	pthread_mutex_unlock(&queue->mutex);
	sem_post(queue->fill_sem);
	return 1;
}

/**
 * Returns the first element on the queue and
 * removes it
 * @returns pointer to first query or NULL on failure
 */
query_t* dequeue(queue_t* queue) {
	queue_node_t* node;
	query_t* query;
	sem_wait(queue->fill_sem);
	pthread_mutex_lock(&queue->mutex);
	if (queue->head == NULL) {
		pthread_mutex_unlock(&queue->mutex);
		return NULL;
	}
	// Get data
	node = queue->head;
	query = node->query;

	// If this was the last item in the queue
	if (queue->tail == node) {
		queue->tail = NULL;
	}

	// Make next element new head
	queue->head = node->next;
	free(node);
	pthread_mutex_unlock(&queue->mutex);
	return query;
}

