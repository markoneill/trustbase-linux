#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "trusthub_plugin.h"
#include "reverse_dns.h"
#include "query.h"
#include "th_logging.h"

#define MAX_LENGTH	1024
#define CERT_LENGTH_FIELD_SIZE	3

static STACK_OF(X509)* parse_chain(unsigned char* data, size_t len);
static unsigned int ntoh24(const unsigned char* data);
//static void hton24(int x, unsigned char* buf);

query_t* create_query(int num_plugins, int id, uint32_t spid, uint64_t stptr, char* hostname, uint16_t port, unsigned char* cert_data, size_t len) {
	char* hostname_resolved[1];
	int hostname_len;
	int i;
	query_t* query;
	//printf("Creating query for host %s\n", hostname);
	query = (query_t*)malloc(sizeof(query_t));
	if (query == NULL) {
		thlog(LOG_WARNING, "Could not create query");
		return NULL;
	}
	query->num_plugins = num_plugins;
	query->spid = spid;

	query->responses = (int*)malloc(sizeof(int) * num_plugins);
	if (query->responses == NULL) {
		thlog(LOG_WARNING, "Could not create response array for query");
		free(query);
		return NULL;
	}
	for (i = 0; i < num_plugins; i++) {
		/* Default to error */
		query->responses[i] = PLUGIN_RESPONSE_ERROR;
	}
	query->num_responses = 0;
	
	if (pthread_mutex_init(&query->mutex, NULL) != 0) {
		thlog(LOG_WARNING, "Failed to create mutex for query");
		free(query->responses);
		free(query);
		return NULL;
	}
	if (pthread_cond_init(&query->threshold_met, NULL) != 0) {
		thlog(LOG_WARNING, "Failed to create condvar for query");
		pthread_mutex_destroy(&query->mutex);
		free(query->responses);
		free(query);
		return NULL;
	}
	
	query->data = (query_data_t*)malloc(sizeof(query_data_t));
	if (query->data == NULL) {
		thlog(LOG_WARNING, "Could not allocate query_data_t");
		pthread_mutex_destroy(&query->mutex);
		pthread_cond_destroy(&query->threshold_met);
		free(query->responses);
		free(query);
		return NULL;
	}
	
	/* Parse chain to X509 structures */
	query->data->chain = parse_chain(cert_data, len);
	
	/* resolve the hostname */
	// This code below will do a Reverse DNS lookup
	// It could be insecure though, because a MitM attack can spoof the DNS lookup
	/*
	printf("Name before revDNS = %s\n", hostname);
	if (reverse_lookup(hostname, port, sk_X509_value(query->chain, 0), hostname_resolved) != LOOKUP_VALID) {
		fprintf(stderr, "Failed to do a reverse DNS lookup\n");
		pthread_mutex_destroy(&query->mutex);
		pthread_cond_destroy(&query->threshold_met);
		free(query->responses);
		free(query);
		free(hostname_resolved[0]);
		return NULL;
	}	
	printf("Name after revDNS = %s\n", hostname_resolved[0]);
	*/
	hostname_resolved[0] = hostname;

	hostname_len = strlen(hostname_resolved[0])+1;
	query->data->hostname = (char*)malloc(sizeof(char) * hostname_len);
	if (query->data->hostname == NULL) {
		fprintf(stderr, "Failed to allocate hostname for query");
		pthread_mutex_destroy(&query->mutex);
		pthread_cond_destroy(&query->threshold_met);
		free(query->responses);
		free(query->data);
		free(query);
		//free(hostname_resolved[0]);
		return NULL;
	}
	query->data->port = port;

	query->data->raw_chain = (unsigned char*)malloc(sizeof(unsigned char) * len);
	if (query->data->raw_chain == NULL) {
		fprintf(stderr, "Failed to allocate cert chain for query");
		pthread_mutex_destroy(&query->mutex);
		pthread_cond_destroy(&query->threshold_met);
		free(query->responses);
		free(query->data->hostname);
		free(query->data);
		free(query);
		//free(hostname_resolved[0]);
		return NULL;
	}
	query->data->raw_chain_len = len;
	memcpy(query->data->hostname, hostname_resolved[0], hostname_len);
	memcpy(query->data->raw_chain, cert_data, len);
	query->state_pointer = stptr;
	query->data->id = id;
	
	//free(hostname_resolved[0]);
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
	sk_X509_pop_free(query->data->chain, X509_free);
	free(query->data->raw_chain);
	free(query->data->hostname);
	free(query->data);
	free(query);
	return;
}


STACK_OF(X509)* parse_chain(unsigned char* data, size_t len) {
	unsigned char* start_pos;
	unsigned char* current_pos;
	const unsigned char* cert_ptr;
	X509* cert;
	unsigned int cert_len;
	start_pos = data;
	current_pos = data;
	STACK_OF(X509)* chain;


	//printf("1st char of chain is %02x\n", data[0] & 0xff);
	//printf("2nd char of chain is %02x\n", data[1] & 0xff);
	//printf("3rd char of chain is %02x\n", data[2] & 0xff);

	chain = sk_X509_new_null();
	while ((current_pos - start_pos) < len) {
		//printf("%02x%02x%02x", current_pos[0], current_pos[1], current_pos[2]);
		cert_len = ntoh24(current_pos);
		current_pos += CERT_LENGTH_FIELD_SIZE;
		//printf("The next cert to parse is %d bytes\n", cert_len);
		cert_ptr = current_pos;
		cert = d2i_X509(NULL, &cert_ptr, cert_len);
		if (!cert) {
			thlog(LOG_ERROR,"unable to parse certificate\n");
		}
		//thlog_cert(cert);
		
		sk_X509_push(chain, cert);
		current_pos += cert_len;
	}
	if (sk_X509_num(chain) <= 0) {
		// XXX Is this even possible?
	}
	return chain;
}

unsigned int ntoh24(const unsigned char* data) {
	unsigned int ret = (data[0] << 16) | (data[1] << 8) | data[2];
	return ret;
}

/*void hton24(int x, unsigned char* buf) {
	buf[0] = x >> 16 & 0xff;
	buf[1] = x >> 8 & 0xff;
	buf[2] = x & 0xff;
	return;
}*/



