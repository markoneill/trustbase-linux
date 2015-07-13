#ifndef _QUERY_QUEUE_H
#define _QUERY_QUEUE_H

#include <semaphore.h>
#include <pthread.h>
#include "query.h"

typedef struct queue_node_t {
	struct queue_node_t* next;
	struct queue_node_t* prev;
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

#endif
