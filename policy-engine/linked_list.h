#ifndef _LINKED_LIST_H
#define _LINKED_LIST_H

#include <pthread.h>
#include "query.h"

typedef struct list_node_t {
	query_t* query;
	struct list_node_t* prev;
	struct list_node_t* next;
} list_node_t;

typedef struct list_t {
	pthread_mutex_t mutex;
	struct list_node_t* head;
	struct list_node_t* tail;
} list_t;

int list_add(list_t* list, query_t* query);
query_t* list_get(list_t* list, int id);
query_t* list_remove(list_t* list, int id);
list_t* list_create(void);
void list_free(list_t* list);

#endif
