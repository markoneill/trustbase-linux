#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include "query.h"
#include "query_queue.h"

static queue_node_t* make_queue_node(query_t* query);

/**
 * Create a new empty queue
 * @returns queue pointer or NULL on failure
 */
queue_t* make_queue(void) {
	queue_t* queue;
	queue = (queue_t*)malloc(sizeof(queue_t));
	if (queue == NULL) {
		return NULL;
	}
	queue->head = NULL;
	queue->tail = NULL;
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
		free(current);
		current = next;
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
	new_node = make_queue_node(query);
	if (new_node == NULL) {
		return 0;
	}
	// If queue is empty
	if (queue->head == NULL) {
		assert(queue->tail == NULL);
		queue->head = new_node;
		queue->tail = new_node;
		return 1;
	}

	// If queue already has something in it
	assert(queue->tail->next == NULL);
	new_node->prev = queue->tail;
	queue->tail->next = new_node;
	queue->tail = new_node;
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
	if (queue->head == NULL) {
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
	return query;
}

