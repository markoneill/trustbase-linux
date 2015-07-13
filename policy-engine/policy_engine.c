#include <stdio.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <pthread.h>

#include "netlink.h"
#include "configuration.h"
#include "query.h"
#include "query_queue.h"
#include "plugins.h"

#define MAX_LENGTH	1024
#define CERT_LENGTH_FIELD_SIZE	3

int chains_received;
policy_context_t context;

void* plugin_thread_init(void* arg);
static STACK_OF(X509)* parse_chain(unsigned char* data, size_t len);
static int ntoh24(const unsigned char* data);
static void hton24(int x, unsigned char* buf);
static void print_certificate(X509* cert);

typedef struct { unsigned char b[3]; } be24, le24;

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
		print_certificate(cert);
		
		sk_X509_push(chain, cert);
		current_pos += cert_len;
	}
	return chain;
}

int poll_schemes(char* hostname, unsigned char* data, size_t len, unsigned char** rcerts, int* rcerts_len) {
	int result;
	unsigned char* p;
	X509* bad_cert;
	STACK_OF(X509)* chain;
	int i;
	int ret_chain_len;
	int* cert_lens;
	unsigned char* ret_chain;
	ret_chain_len = 0;
	ret_chain = NULL;

	// Parse chain to X509 structures
	chain = parse_chain(data, len);
	if (sk_X509_num(chain) <= 0) {
		// XXX yeah...
	}
	
	// Validation
	//if (query_raw_plugin(&context.plugins[0], hostname, data, len) == 0) {
	if (query_plugin(&context.plugins[2], 2, hostname, chain, data, len) == 0) {
		result = 0;

		bad_cert = sk_X509_value(chain, 0); // Get first cert
		// Calculate bytes needed to represent chain in TLS message
		cert_lens = (int*)malloc(sizeof(int) * sk_X509_num(chain));
		for (i = 0; i < sk_X509_num(chain); i++) {
			bad_cert = sk_X509_value(chain, i);
			cert_lens[i] = i2d_X509(bad_cert, NULL);
			ret_chain_len += cert_lens[i] + 3; // +3 for length field length
		}

		// Create substitute TLS certificate message
		ret_chain = OPENSSL_malloc(ret_chain_len);
		p = ret_chain;
		for (i = 0; i < sk_X509_num(chain); i++) {
			bad_cert = sk_X509_value(chain, i);
			hton24(cert_lens[i], p); // Assign length
			p += 3; // Skip past length field (24 bits)
			i2d_X509(bad_cert, &p); // Write certificate
		}
		*rcerts_len = ret_chain_len;
		*rcerts = ret_chain;
		free(cert_lens);
		printf("sending fail response\n");
	}
	else {
		result = 1;
		*rcerts = NULL;
		*rcerts_len = 0;
		printf("sending valid response\n");
	}
	sk_X509_pop_free(chain, X509_free);
	return result;
}


int main() {
	int i;
	struct nl_sock* sock;
	pthread_t* plugin_threads;
	thread_param_t* plugin_thread_params;

	load_config(&context);
	init_addons(context.addons, context.addon_count, context.plugin_count);
	init_plugins(context.addons, context.addon_count, context.plugins, context.plugin_count);
	print_addons(context.addons, context.addon_count);
	print_plugins(context.plugins, context.plugin_count);


	// Plugin Threading
	plugin_thread_params = (thread_param_t*)malloc(sizeof(thread_param_t) * context.plugin_count);
	plugin_threads = (pthread_t*)malloc(sizeof(pthread_t) * context.plugin_count);
	for (i = 0; i < context.plugin_count; i++) {
		plugin_thread_params[i].queue = make_queue(context.plugins[i].name);
		plugin_thread_params[i].plugin_id = i;
		pthread_create(&plugin_threads[i], NULL, plugin_thread_init, &plugin_thread_params[i]);
	}

	sock = nl_socket_alloc();
	listen_for_queries(sock);

	// Cleanup
	for (i = 0; i < context.plugin_count; i++) {
		pthread_join(plugin_threads[i], NULL);
	}
	close_plugins(context.plugins, context.plugin_count);
	close_addons(context.addons, context.addon_count);
	free(plugin_thread_params);
	nl_socket_free(sock);
	return 0;
}

void* plugin_thread_init(void* arg) {
	queue_t* queue;
	int plugin_id;
	thread_param_t* params;
	params = (thread_param_t*)arg;
	queue = params->queue;
	plugin_id = params->plugin_id;
	
	//context.plugins[plugin_id].init();
	//context.plugins
	return NULL;
}

void hton24(int x, unsigned char* buf) {
	buf[0] = x >> 16 & 0xff;
	buf[1] = x >> 8 & 0xff;
	buf[2] = x & 0xff;
	return;
}

int ntoh24(const unsigned char* data) {
	int ret = (data[0] << 16) | (data[1] << 8) | data[2];
	return ret;
}

void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("subject: %s\n", subj);
	printf("issuer: %s\n", issuer);
}

