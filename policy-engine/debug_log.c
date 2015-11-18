#include "debug_log.h"
#include <stdio.h>

void write_debug(const char* out) {	
	FILE *f = fopen("/tmp/policy_engine_log.txt", "a");
	if (f == NULL) {
		printf("Error opening file!\n");
		return;
	}

	fprintf(f, "%s\n", out);

	fclose(f);
}
