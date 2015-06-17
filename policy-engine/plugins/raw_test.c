#include <stdio.h>
#include <string.h>

int query(const char* hostname, unsigned char* certs, size_t certs_length);

int query(const char* hostname, unsigned char* certs, size_t certs_length) {
	if (strcmp(hostname, "www.google.com") == 0) {
		printf("Raw Test Plugin reporting bad cert!\n");
		return 0;
	}
	return 1;
}
