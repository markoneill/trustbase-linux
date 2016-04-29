#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../trusthub_plugin.h"

int query(query_data_t* data);

int query(query_data_t* data) {
	/*FILE *f = fopen("/tmp/raw_ran.txt", "a");
	if (f == NULL) {
		printf("Error opening file!\n");
		return PLUGIN_RESPONSE_ERROR;
	}

	fprintf(f, "It_ran for %s\n", hostname);

	fclose(f);*/
	return PLUGIN_RESPONSE_VALID;
}
