#include <stdio.h>
#include <openssl/x509.h>
#include "../plugin_response.h"

#define MAX_LENGTH	1024

int query(const char* hostname, STACK_OF(X509)* certs);
void print_certificate(X509* cert);

void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("subject: %s\n", subj);
	printf("issuer: %s\n", issuer);
}

int query(const char* hostname, STACK_OF(X509)* certs) {
	//int i;
	//X509* cert;
	//printf("OpenSSL Test Plugin checking cert for host: %s\n", hostname);
	/*printf("Certificate Data:\n");
	for (i = 0; i < sk_X509_num(certs); i++) {
		cert = sk_X509_value(certs, i);
		print_certificate(cert);
	}*/
	return PLUGIN_RESPONSE_VALID;
}
