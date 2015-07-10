#ifndef _TH_QUERY_H
#define _TH_QUERY_H

#include <stdint.h>
#include <semaphore.h>

typedef struct query_t {
	unsigned int id;
	uint64_t state_pointer;
	int num_plugins;
	sem_t* sync_sems;
	int* responses;
} query_t;

query_t* create_query(int num_plugins);
void free_query(query_t* query);
#endif
