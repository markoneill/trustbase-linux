#include <semaphore.h>
#include <stdlib.h>
#include "query.h"

query_t* create_query(int num_plugins) {
	query_t* query;
	query = (query_t*)malloc(sizeof(query_t));
	query->num_plugins = num_plugins;
	query->sync_sems = (sem_t*)malloc(sizeof(sem_t) * num_plugins);
	query->responses = (int*)malloc(sizeof(int) * num_plugins);
	return query;
}

void free_query(query_t* query) {
	if (query == NULL) {
		return;
	}
	if (query->sync_sems != NULL) {
		free(query->sync_sems);
	}
	if (query->responses != NULL) {
		free(query->responses);
	}
	free(query);
	return;
}
