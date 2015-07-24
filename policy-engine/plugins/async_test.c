#include <stdio.h>
#include <openssl/x509.h>
#include <pthread.h>

#define MAX_LENGTH	1024

int initialize(int id, int(*callback)(int, int, int));
int finalize(void);
int query(int query_id, const char* hostname, STACK_OF(X509)* certs);
void print_certificate(X509* cert);

int (*result_callback)(int plugin_id, int query_id, int result);
int plugin_id;
pthread_t worker;

int initialize(int id, int(*callback)(int, int, int)) {
	result_callback = callback;
	plugin_id = id;
	printf("Initialized asynchronous test plugin\n");
	return 0;
}

int finalize(void) {
	return 0;
}

void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("subject: %s\n", subj);
	printf("issuer: %s\n", issuer);
}

int query(int query_id, const char* hostname, STACK_OF(X509)* certs) {
	//int i;
	//X509* cert;
	printf("Asynchronous Test Plugin checking cert for host: %s (query ID: %d)\n", hostname, query_id);
	result_callback(plugin_id, query_id, 1);
	/*printf("Certificate Data:\n");
	for (i = 0; i < sk_X509_num(certs); i++) {
		cert = sk_X509_value(certs, i);
		print_certificate(cert);
	}*/
	return 1;
}
