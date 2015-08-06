#include <stdio.h>
#include <string.h>
#include "../plugin_response.h"

int query(const char* hostname, unsigned char* certs, size_t certs_length);

int query(const char* hostname, unsigned char* certs, size_t certs_length) {
	return PLUGIN_RESPONSE_VALID;
}
