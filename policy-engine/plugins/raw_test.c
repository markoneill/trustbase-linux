#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../plugin_response.h"

int query(const char* hostname, uint16_t port, unsigned char* certs, size_t certs_length);

int query(const char* hostname, uint16_t port, unsigned char* certs, size_t certs_length) {
	/*FILE *f = fopen("/tmp/raw_ran.txt", "a");
	if (f == NULL) {
		printf("Error opening file!\n");
		return PLUGIN_RESPONSE_ERROR;
	}

	fprintf(f, "It_ran for %s\n", hostname);

	fclose(f);*/
	return PLUGIN_RESPONSE_VALID;
}
