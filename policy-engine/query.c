#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "plugin_response.h"
#include "query.h"

#define MAX_LENGTH	1024
#define CERT_LENGTH_FIELD_SIZE	3

static STACK_OF(X509)* parse_chain(unsigned char* data, size_t len);
static int ntoh24(const unsigned char* data);
//static void hton24(int x, unsigned char* buf);
void print_certificate(X509* cert);

query_t* create_query(int num_plugins, int id, uint64_t stptr, char* hostname, unsigned char* cert_data, size_t len) {
	int hostname_len;
	int i;
	query_t* query;
	//printf("Creating query for host %s\n", hostname);
	query = (query_t*)malloc(sizeof(query_t));
	if (query == NULL) {
		fprintf(stderr, "Could not create query\n");
		return NULL;
	}
	query->num_plugins = num_plugins;

	query->responses = (int*)malloc(sizeof(int) * num_plugins);
	if (query->responses == NULL) {
		fprintf(stderr, "Could not create response array for query\n");
		free(query);
		return NULL;
	}
	for (i = 0; i < num_plugins; i++) {
		/* Default to error */
		query->responses[i] = PLUGIN_RESPONSE_ERROR;
	}
	query->num_responses = 0;
	
	if (pthread_mutex_init(&query->mutex, NULL) != 0) {
		fprintf(stderr, "Failed to create mutex for query\n");
		free(query->responses);
		free(query);
		return NULL;
	}
	if (pthread_cond_init(&query->threshold_met, NULL) != 0) {
		fprintf(stderr, "Failed to create condvar for query\n");
		pthread_mutex_destroy(&query->mutex);
		free(query->responses);
		free(query);
		return NULL;
	}
	
	/* Parse chain to X509 structures */
	query->chain = parse_chain(cert_data, len);

	hostname_len = strlen(hostname)+1;
	query->hostname = (char*)malloc(sizeof(char) * hostname_len);
	if (query->hostname == NULL) {
		fprintf(stderr, "Failed to allocate hostname for query\n");
		pthread_mutex_destroy(&query->mutex);
		pthread_cond_destroy(&query->threshold_met);
		free(query->responses);
		free(query);
		return NULL;
	}
	query->raw_chain = (unsigned char*)malloc(sizeof(unsigned char) * len);
	if (query->hostname == NULL) {
		fprintf(stderr, "Failed to allocate cert chain for query\n");
		pthread_mutex_destroy(&query->mutex);
		pthread_cond_destroy(&query->threshold_met);
		free(query->responses);
		free(query->hostname);
		free(query);
		return NULL;
	}
	query->raw_chain_len = len;
	memcpy(query->hostname, hostname, hostname_len);
	memcpy(query->raw_chain, cert_data, len);
	query->state_pointer = stptr;
	query->id = id;
	return query;
}

void free_query(query_t* query) {
	if (query == NULL) {
		return;
	}
	if (query->responses != NULL) {
		free(query->responses);
	}
	if (pthread_mutex_destroy(&query->mutex) != 0) {
		fprintf(stderr, "Failed to destroy query mutex\n");
	}
	if (pthread_cond_destroy(&query->threshold_met) != 0) {
		fprintf(stderr, "Failed to destroy query condvar\n");
	}
	sk_X509_pop_free(query->chain, X509_free);
	free(query->raw_chain);
	free(query->hostname);
	free(query);
	return;
}


STACK_OF(X509)* parse_chain(unsigned char* data, size_t len) {
	unsigned char* start_pos;
	unsigned char* current_pos;
	const unsigned char* cert_ptr;
	X509* cert;
	int cert_len;
	start_pos = data;
	current_pos = data;
	STACK_OF(X509)* chain;

	chain = sk_X509_new_null();
	while ((current_pos - start_pos) < len) {
		cert_len = ntoh24(current_pos);
		current_pos += CERT_LENGTH_FIELD_SIZE;
		//printf("The next cert to parse is %d bytes\n", cert_len);
		cert_ptr = current_pos;
		cert = d2i_X509(NULL, &cert_ptr, cert_len);
		if (!cert) {
			fprintf(stderr,"unable to parse certificate\n");
		}
		//print_certificate(cert);
		
		sk_X509_push(chain, cert);
		current_pos += cert_len;
	}
	if (sk_X509_num(chain) <= 0) {
		// XXX Is this even possible?
	}
	return chain;
}

int ntoh24(const unsigned char* data) {
	int ret = (data[0] << 16) | (data[1] << 8) | data[2];
	return ret;
}

/*void hton24(int x, unsigned char* buf) {
	buf[0] = x >> 16 & 0xff;
	buf[1] = x >> 8 & 0xff;
	buf[2] = x & 0xff;
	return;
}*/


void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("subject: %s\n", subj);
	printf("issuer: %s\n", issuer);
}

