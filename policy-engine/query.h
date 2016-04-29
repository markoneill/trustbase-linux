#ifndef _TH_QUERY_H
#define _TH_QUERY_H

#include <stdint.h>
#include <pthread.h>
#include "trusthub_plugin.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

typedef struct query_t {
	pthread_mutex_t mutex;
	pthread_cond_t threshold_met;
	uint32_t spid;
	uint64_t state_pointer;
	int num_plugins;
	int num_responses;
	int* responses;
	query_data_t* data;
} query_t;


query_t* create_query(int num_plugins, int id, uint32_t spid, uint64_t stptr, char* hostname, uint16_t port, unsigned char* cert_data, size_t len);
void free_query(query_t* query);
#endif
