#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <arpa/inet.h>

#include "th_logging.h"
#include "check_root_store.h"
#include "reverse_dns.h"

typedef struct sockaddrunion_t{
	struct sockaddr_in6* sa6;
	struct sockaddr_in* sa4;
}sockaddrunion_t;

static int forward_lookup(char* hostname, uint16_t port, struct sockaddr* sa);
static int comp_sockaddr(struct sockaddr* sa_1, struct sockaddr* sa_2);
static int lookup_cert_names(struct sockaddr* sa, X509* cert, char** found_hostname, uint16_t port);
static int ip_to_hostname(struct sockaddr* sa, char** found_hostname);

int comp_sockaddr(struct sockaddr* sa_1, struct sockaddr* sa_2) {
	sockaddrunion_t sau_1;
	sockaddrunion_t sau_2;
	int i;

	if (sa_1->sa_family == AF_INET6) {
		if (sa_2->sa_family != AF_INET6) {
			return LOOKUP_FAIL;
		}
		sau_1.sa6 = (struct sockaddr_in6*)sa_1;
		sau_2.sa6 = (struct sockaddr_in6*)sa_2;
		for (i=0; i<16; i++) {
			if (sau_1.sa6->sin6_addr.s6_addr[i] != sau_2.sa6->sin6_addr.s6_addr[i]) {
				return LOOKUP_FAIL;
			}
		}
	} else if (sa_1->sa_family == AF_INET) {
		if (sa_2->sa_family != AF_INET) {
			return LOOKUP_FAIL;
		}
		sau_1.sa4 = (struct sockaddr_in*)sa_1;
		sau_2.sa4 = (struct sockaddr_in*)sa_2;
		if (sau_1.sa4->sin_addr.s_addr != sau_2.sa4->sin_addr.s_addr) {
			return LOOKUP_FAIL;
		}
	} else {
		return LOOKUP_ERR;
	}
	return LOOKUP_VALID;
}

int ip_to_hostname(struct sockaddr* sa, char** found_hostname) {
	socklen_t len;
	int error = LOOKUP_VALID;

	len = (sa->sa_family == AF_INET6)? sizeof(struct sockaddr_in6): sizeof(struct sockaddr_in);

	found_hostname[0] = (char*)malloc(NI_MAXHOST);

	if ((error = getnameinfo(sa, len, found_hostname[0], NI_MAXHOST, NULL, 0, NI_NAMEREQD))) {
		thlog(LOG_DEBUG,"\tError getting hostname: %i\n", error);
		thlog(LOG_DEBUG,"\tEAI_AGAIN: %i\n", EAI_AGAIN);
		thlog(LOG_DEBUG,"\tEAI_BADFLAGS: %i\n", EAI_BADFLAGS);
		thlog(LOG_DEBUG,"\tEAI_FAIL: %i\n", EAI_FAIL);
		thlog(LOG_DEBUG,"\tEAI_FAMILY: %i\n", EAI_FAMILY);
		thlog(LOG_DEBUG,"\tEAI_MEMORY: %i\n", EAI_MEMORY);
		thlog(LOG_DEBUG,"\tEAI_NONAME: %i\n", EAI_NONAME);
		thlog(LOG_DEBUG,"\tEAI_OVERFLOW: %i\n", EAI_OVERFLOW);
		thlog(LOG_DEBUG,"\tEAI_SYSTEM: %i\n", EAI_SYSTEM);
		free(found_hostname[0]);
		return error;
	}
	return LOOKUP_VALID;
}

// see if it is a 1pv4 or ipv6
// returns 1 on success and 0 on fail
int is_ip(const char* hostname) {
	sockaddrunion_t sa;
	int result;

	sa.sa4 = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	sa.sa6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));

	result = inet_pton(AF_INET, hostname, &(sa.sa4->sin_addr));
	if (result != 1) {
		result = inet_pton(AF_INET6, hostname, &(sa.sa6->sin6_addr));
		if (result == 1) {
			sa.sa6->sin6_family = AF_INET6;
			//print_ip((struct sockaddr*)sa.sa6);
		}
	} else {
		sa.sa4->sin_family = AF_INET;
		//print_ip((struct sockaddr*)sa.sa4);
	}
	free(sa.sa4);
	free(sa.sa6);
	// this is backwards from the rest of our functions, 0 is fail and 1 is success
	return result;
}

// This function is called if is_ip is true
// It will first check if there is a hostname of the ip address in the cert
// It will then do a forward DNS look up on the cert names
// if that fails to, it will try a ip_to_hostname
// The caller must make sure to free hostname_found[0] after they are done with it.
int reverse_lookup(const char* hostname, uint16_t port, X509* cert, char** hostname_found) {
	sockaddrunion_t sa;
	struct sockaddr* sap;
	int result;

	sa.sa4 = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	sa.sa6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
	// Check the hostname, and alternate hostnames, to see if the cert is made out to an ip
	if (verify_hostname(hostname, cert) == 1 || verify_alternate_hostname(hostname, cert) == 1) {
		// This hostname is good for this cert, no lookup needed
		// We will just copy the hostname given over
		hostname_found[0] = (char*)malloc(strlen(hostname)+1);
		strncpy(hostname_found[0], hostname, strlen(hostname)+1);
		result = LOOKUP_VALID;
		goto EXIT;
	}
	
	// do a forward DNS look up on the cert names
	// turn our hostname into a ip thing
	result = inet_pton(AF_INET, hostname, &(sa.sa4->sin_addr));
	if (result != 1) {
		result = inet_pton(AF_INET6, hostname, &(sa.sa6->sin6_addr));
		if (result != 1) {
			// this is not an ip address
			// We will just copy the hostname given over
			hostname_found[0] = (char*)malloc(strlen(hostname)+1);
			strncpy(hostname_found[0], hostname, strlen(hostname)+1);
			result = LOOKUP_VALID;
			goto EXIT;
		}
		sa.sa6->sin6_family = AF_INET6;
		sap = (struct sockaddr*)sa.sa6;
	} else {
		sa.sa4->sin_family = AF_INET;
		sap = (struct sockaddr*)sa.sa4;
	}
	// sap is our sockaddr now
	// loop through names in cert
	result = lookup_cert_names(sap, cert, hostname_found, port);
	if (result == LOOKUP_VALID) {
		goto EXIT;
	}	
	// lastly try a reverse look up
	result = ip_to_hostname(sap, hostname_found);
EXIT:
	free(sa.sa4);
	free(sa.sa6);
	return result;
}

int lookup_cert_names(struct sockaddr* sa, X509* cert, char** found_hostname, uint16_t port) {
	X509_NAME *subj;
	int i;
	X509_NAME_ENTRY* entry;
	ASN1_STRING* data;
	char* cn;
	int result;
	STACK_OF(GENERAL_NAME)* alt_names;
	const GENERAL_NAME* current_alt_name;
	
	found_hostname[0] = NULL;
	// Get the Common Name from the certificate
	subj = X509_get_subject_name(cert);
	result = LOOKUP_FAIL;
	
	i = -1;
	for (;;) {
		i = X509_NAME_get_index_by_NID(subj, NID_commonName, i);
		if (i == -1) {
			break;
		}
		entry = X509_NAME_get_entry(subj, i);
		data = X509_NAME_ENTRY_get_data(entry);
		cn = (char*)ASN1_STRING_data(data);
		
		// check for null characters
		if (ASN1_STRING_length(data) != strlen(cn)) {
			// Malformed Cert
			continue;
		}
		
		// check if it starts with a *, we can't do a lookup on that
		if (cn[0] == '*') {
			continue;
		}
		
		if (forward_lookup(cn, port, sa) == LOOKUP_VALID) {
			found_hostname[0] = (char*)malloc(strlen(cn)+1);
			strncpy(found_hostname[0],cn,strlen(cn)+1);
			return LOOKUP_VALID;
		}
	}
	
	// If the common names didn't work, we try the alternate names :(	

	alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (alt_names == NULL) {
		// No alternate names
		return LOOKUP_FAIL;
	}
	
	for (i=0; i<sk_GENERAL_NAME_num(alt_names); i++) {
		current_alt_name = sk_GENERAL_NAME_value(alt_names, i);
		
		if (current_alt_name->type == GEN_DNS) {
			cn = (char *) ASN1_STRING_data(current_alt_name->d.dNSName);

			// check for null characters
			if (ASN1_STRING_length(current_alt_name->d.dNSName) != strlen(cn)) {
				// Malformed Cert
				continue;
			}

			// check if it starts with a *, we can't do a lookup on that :(
			if (cn[0] == '*') {
				continue;
			}
			
			if (forward_lookup(cn, port, sa) == LOOKUP_VALID) {
				found_hostname[0] = (char*)malloc(strlen(cn)+1);
				strncpy(found_hostname[0],cn,strlen(cn)+1);
				result = LOOKUP_VALID;
				break;
			}
		}
	}
	sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
	return result;
}

int forward_lookup(char* hostname, uint16_t port, struct sockaddr* sa) {
	struct addrinfo hints, *servinfo, *p;
	int result;
	char port_string[6];
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; //TCP stuff

	sprintf(port_string, "%hu", port);
	
	if ((result = getaddrinfo(hostname, port_string, &hints, &servinfo)) != 0) {
		// we had a problem, and getaddrinfo didn't go well
		return LOOKUP_ERR; // error
	}
	
	result = LOOKUP_FAIL;
	// check if our address is in the results
	for(p = servinfo; p != NULL; p = p->ai_next) {
		//print_ip(p->ai_addr);
		if (comp_sockaddr(sa, p->ai_addr) == LOOKUP_VALID) {
			result = LOOKUP_VALID;
			break;
		}
	}

	freeaddrinfo(servinfo); // clean up
	return result;
}
