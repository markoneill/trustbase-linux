#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h> /* O_CREAT constant */
#include <sys/stat.h> /* S_IRWXU constant */
#include <semaphore.h>
#include "query.h"
#include "th_logging.h"
#include "query_queue.h"

static queue_node_t* make_queue_node(query_t* query);

/**
 * Create a new empty queue
 * @returns queue pointer or NULL on failure
 */
queue_t* make_queue(const char* name) {
	queue_t* queue;
	sem_t* sem;
	sem = sem_open(name, O_CREAT, S_IRWXU, 0);
	if (sem == SEM_FAILED) {
		thlog(LOG_ERROR, "Failed to create queue semaphore %s: %s\n", name, strerror(errno));
		return NULL;
	}
	queue = (queue_t*)malloc(sizeof(queue_t));
	if (queue == NULL) {
		thlog(LOG_ERROR, "Failed to allocate space for queue %s\n", name);
		return NULL;
	}
	if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
		thlog(LOG_ERROR, "Failed to create mutex for queue %s\n", name);
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
		thlog(LOG_ERROR, "Failed to close semaphore: %s\n", strerror(errno));
	}
	if (pthread_mutex_destroy(&queue->mutex) != 0) {
		thlog(LOG_ERROR, "Failed to destroy queue mutex\n");
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
	node->prev = NULL;
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
	new_node->prev = queue->tail;
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
	if (queue->head != NULL) {
		queue->head->prev = NULL;
	}
	free(node);
	pthread_mutex_unlock(&queue->mutex);
	return query;
}

