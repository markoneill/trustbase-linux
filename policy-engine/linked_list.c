#include <assert.h>

#include "query.h"
#include "th_logging.h"
#include "linked_list.h"

static list_node_t* list_node_create(query_t* query);
static query_t* list_node_remove(list_t* list, list_node_t* node);
static void list_node_free(list_node_t* node);

list_node_t* list_node_create(query_t* query) {
	list_node_t* node;
	node = (list_node_t*)malloc(sizeof(list_node_t));
	if (node == NULL) {
		return NULL;
	}
	node->prev = NULL;
	node->next = NULL;
	node->query = query;
	return node;
}

void list_node_free(list_node_t* node) {
	if (node == NULL) {
		return;
	}
	free(node);
	return;
}

query_t* list_node_remove(list_t* list, list_node_t* node) {
	query_t* query;
	pthread_mutex_lock(&list->mutex);
	assert(list != NULL);
	assert(list->head != NULL);
	assert(list->tail != NULL);
	
	/* Node to remove is the head */
	if (list->head == node) {
		list->head = node->next;
	}
	/* Node to remove is the tail */
	if (list->tail == node) {
		list->tail = node->prev;
	}

	if (node->next != NULL) {
		node->next->prev = node->prev;
	}
	if (node->prev != NULL) {
		node->prev->next = node->next;
	}

	query = node->query;
	list_node_free(node);
	pthread_mutex_unlock(&list->mutex);
	return query;
}

/* Returns 0 on success */
int list_add(list_t* list, query_t* query) {
	list_node_t* new_node;
	list_node_t* tmp;
	new_node = list_node_create(query);
	if (new_node == NULL) {
		return 1;
	}
	pthread_mutex_lock(&list->mutex);
	/* Empty list */
	if (list->head == NULL) {
		assert(list->tail == NULL);
		list->head = new_node;
		list->tail = new_node;
		pthread_mutex_unlock(&list->mutex);
		return 0;
	}

	/* Non empty list */
	tmp = list->tail;
	tmp->next = new_node;
	new_node->prev = tmp;
	list->tail = new_node;
	pthread_mutex_unlock(&list->mutex);
	return 0;
}

query_t* list_remove(list_t* list, int id) {
	list_node_t* current;
	list_node_t* tmp;
	pthread_mutex_lock(&list->mutex);
	if (list == NULL) {
		pthread_mutex_unlock(&list->mutex);
		return NULL;
	}
	if (list->head == NULL) {
		assert(list->tail == NULL);
		pthread_mutex_unlock(&list->mutex);
		return NULL;
	}
	
	/* List is not empty */
	current = list->head;
	while (current != NULL) {
		tmp = current;
		current = current->next;
		if (tmp->query->data->id == id) {
			pthread_mutex_unlock(&list->mutex);
			return list_node_remove(list, tmp);
		}
	}
	pthread_mutex_unlock(&list->mutex);
	return NULL;
}

query_t* list_get(list_t* list, int id) {
	list_node_t* current;
	list_node_t* tmp;
	pthread_mutex_lock(&list->mutex);
	if (list == NULL) {
		pthread_mutex_unlock(&list->mutex);
		return NULL;
	}
	if (list->head == NULL) {
		assert(list->tail == NULL);
		pthread_mutex_unlock(&list->mutex);
		return NULL;
	}
	
	/* List is not empty */
	current = list->head;
	while (current != NULL) {
		tmp = current;
		current = current->next;
		if (tmp->query->data->id == id) {
			pthread_mutex_unlock(&list->mutex);
			return tmp->query;
		}
	}
	pthread_mutex_unlock(&list->mutex);
	return NULL;
}

list_t* list_create(void) {
	list_t* list;
	list = (list_t*)malloc(sizeof(list_t));
	if (list == NULL) {
		return NULL;
	}
	if (pthread_mutex_init(&list->mutex, NULL) != 0) {
		thlog(LOG_ERROR, "Failed to create mutex for list");
		free(list); /* free allocated memory since this happened after malloc */
		return NULL;
	}
	list->head = NULL;
	list->tail = NULL;
	return list;
}

void list_free(list_t* list) {
	list_node_t* current;
	list_node_t* tmp;
	if (list == NULL) {
		return;
	}
	if (list->head == NULL) {
		assert(list->tail == NULL);
		free(list);
		return;
	}
	
	/* List is not empty */
	current = list->head;
	while (current != NULL) {
		tmp = current;
		current = current->next;
		list_node_free(tmp);
	}
	if (pthread_mutex_destroy(&list->mutex) != 0) {
		thlog(LOG_ERROR, "Failed to destroy list mutex");
	}
	free(list);
	return;
}

