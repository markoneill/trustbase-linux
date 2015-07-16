#include <stdio.h>
#include <openssl/x509.h>

#define MAX_LENGTH	1024

int init(int(*callback)(int, int, int), int id);
int finalize(void);
int query(int query_id, const char* hostname, STACK_OF(X509)* certs);
static void print_certificate(X509* cert);

int (*result_callback)(int plugin_id, int query_id, int result);
int plugin_id;

int init(int(*callback)(int, int, int), id) {
	result_callback = callback;
	plugin_id = id;
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
	int i;
	X509* cert;
	printf("OpenSSL Test Plugin checking cert for host: %s\n", hostname);
	printf("Certificate Data:\n");
	for (i = 0; i < sk_X509_num(certs); i++) {
		cert = sk_X509_value(certs, i);
		print_certificate(cert);
	}
	return 1;
}
