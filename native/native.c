#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

// For certificate parsing
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

// Local includes
#include "netlink.h"

int main(int argc, char* argv[]) {
	uint64_t query_id;
	FILE* fp;
	STACK_OF(X509)* chain;
	X509* cert;
	int response;


	// Retrieve test certificate from file
	char cert_path[] = "userspace_tests/www.google.com.crt";
	fp = fopen(cert_path, "r");
	if (!fp) {
		fprintf(stderr, "unable to open: %s\n", cert_path);
		return EXIT_FAILURE;
	}
	
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!cert) {
		fprintf(stderr, "unable to parse certificate in: %s\n", cert_path);
		fclose(fp);
		return EXIT_FAILURE;
	}
	
	chain = sk_X509_new_null();
	sk_X509_push(chain, cert);
	

	// Test a single query using given certificate
	query_id = 1;
	if (trustbase_connect()) {
		fprintf(stderr, "unable to connect to trustbase\n");
		return EXIT_FAILURE;
	}
	send_query_openssl(query_id, "google.com", 443, chain);
	response = recv_response();
	trustbase_disconnect();

	// Response checking
	if (response < 0) {
		printf("An error occured in receiving a message\n");
	}
	else if (response == 0) {
		printf("Certificate was invalid!\n");
	}
	else {
		printf("Certificate was valid!\n");
	}

	// Cleanup
	sk_X509_pop_free(chain, X509_free);
	fclose(fp);
	return 0;
}

