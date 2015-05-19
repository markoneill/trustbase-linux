#include <stdio.h>

int query(const char* hostname, unsigned char* certs, size_t certs_length);

int query(const char* hostname, unsigned char* certs, size_t certs_length) {
	printf("Raw Test Plugin reporting for duty!\n");
	return 1;
}
