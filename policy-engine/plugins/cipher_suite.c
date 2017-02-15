#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../trusthub_plugin.h"
#include "../th_logging.h"

int initialize(init_data_t* idata);
int query(query_data_t* data);
int finalize(void);

int (*plog)(thlog_level_t level, const char* format, ...);

int initialize(init_data_t* idata) {
	plog = idata->thlog;
	return 0;
}

int query(query_data_t* data) {
	int rval;
	rval = PLUGIN_RESPONSE_VALID;
	
	plog(LOG_DEBUG, "Cipher Suite Plugin:");
	
	plog(LOG_DEBUG, "Server Hello length %d", data->server_hello_len);
	if (data->server_hello == NULL) {
		plog(LOG_DEBUG, "Bad data");
		return PLUGIN_RESPONSE_ERROR;
	}
	//thlog_bytes(data->server_hello, data->server_hello_len);
	
	plog(LOG_DEBUG, "Client Hello length %d", data->client_hello_len);
	if (data->client_hello == NULL) {
		plog(LOG_DEBUG, "Bad data");
		return PLUGIN_RESPONSE_ERROR;
	}
	//thlog_bytes(data->client_hello, data->client_hello_len);
	
	return rval;
}

int finalize() {
	return 0;
}
