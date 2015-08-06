#ifndef _TH_QUERY_H
#define _TH_QUERY_H

#include <stdint.h>
#include <pthread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

typedef struct query_t {
	int id;
	pthread_mutex_t mutex;
	pthread_cond_t threshold_met;
	uint64_t state_pointer;
	int num_plugins;
	STACK_OF(X509)* chain;
	char* hostname;
	unsigned char* raw_chain;
	size_t raw_chain_len;
	int num_responses;
	int* responses;
} query_t;

query_t* create_query(int num_plugins, int id, uint64_t stptr, char* hostname, unsigned char* cert_data, size_t len);
void free_query(query_t* query);
#endif
