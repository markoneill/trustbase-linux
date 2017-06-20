#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include <libgen.h>
#include "../trustbase_plugin.h"
#include "../tb_logging.h"

#define CONFIG_FILE "/../plugin-config/cipher_suite.cfg"
#define PLUGIN_INIT_ERROR -1

#define CLIENT_HELLO_CIPHER_LEN_OFF	0x27
#define CLIENT_HELLO_CIPHER_LEN_SIZE	2
#define CLIENT_HELLO_COMPRESS_LEN_SIZE	1
#define CLIENT_HELLO_EXT_LEN_SIZE	2

#define SERVER_HELLO_CIPHER_OFF		0x47
#define SERVER_HELLO_CIPHER_SIZE	2

#define EXT_OFF				0x4c
#define EXT_SIZE			2
#define EXT_LEN_SIZE			2

int initialize(init_data_t* idata);
int query(query_data_t* data);
int finalize(void);

int (*plog)(tblog_level_t level, const char* format, ...);

static void hexdump(char* data, size_t len);
static void loadconfig(const char* config_path);
static unsigned int get_int_from_net(char* buf, int len);
static int verify_server_hello(char* server_hello, size_t server_hello_len);
static int verify_client_hello(char* client_hello, size_t client_hello_len);
static int processExtList(char* inbuf, int offset, int buf_len, int* req_exts, size_t req_exts_len, int* rej_exts, size_t rej_exts_len);

// global settings structure
typedef struct cipher_settings_t {
	int isApproved;
	int* cipherList;
	size_t cipherListSize;
	int* requiredServerExtList;
	size_t requiredServerExtListSize;
	int* rejectedServerExtList;
	size_t rejectedServerExtListSize;
	int* requiredClientExtList;
	size_t requiredClientExtListSize;
	int* rejectedClientExtList;
	size_t rejectedClientExtListSize;
} cipher_settings_t;

cipher_settings_t cipher_settings;

int initialize(init_data_t* idata) {
	char* plugin_path;
	char* config_path;
	int i;
	plog = idata->tblog;

	// make the path for our plugin
	plugin_path = idata->plugin_path;
	config_path = (char*)malloc(strlen(plugin_path) + strlen(CONFIG_FILE)+1);
	strcpy(config_path, plugin_path);
	config_path[strlen(plugin_path)] = '\0';
	
	// put a \0 in the thing
	for (i=strlen(config_path)-1; i>0; i--) {
		if (config_path[i] == '/' || config_path[i] == '\\') {
			config_path[i] = '\0';
			break;
		}
	}
	
	strcat(config_path, CONFIG_FILE);
	
	// load the settings
	loadconfig(config_path);
	
	free(config_path);
	return 0;
}

int query(query_data_t* data) {
	int rval;

	if (cipher_settings.isApproved == PLUGIN_INIT_ERROR) {
		return PLUGIN_RESPONSE_ERROR;
	}
	rval = PLUGIN_RESPONSE_VALID;
	
	if (data->client_hello == NULL) {
		plog(LOG_DEBUG, "Bad data");
		return PLUGIN_RESPONSE_ERROR;
	}
	hexdump(data->client_hello, data->client_hello_len);
	if (data->server_hello == NULL) {
		plog(LOG_DEBUG, "Bad data");
		return PLUGIN_RESPONSE_ERROR;
	}
	//hexdump(data->server_hello, data->server_hello_len);
	
	rval = verify_client_hello(data->client_hello, data->client_hello_len);
	if (rval != PLUGIN_RESPONSE_VALID) {
		return rval;
	}

	rval = verify_server_hello(data->server_hello, data->server_hello_len);
	
	return rval;
}

int finalize() {
	// free settings
	free(cipher_settings.cipherList);
	free(cipher_settings.requiredServerExtList);
	free(cipher_settings.rejectedServerExtList);
	free(cipher_settings.requiredClientExtList);
	free(cipher_settings.rejectedClientExtList);
	return 0;
}

int verify_client_hello(char* client_hello, size_t client_hello_len) {
	unsigned int offset;
	unsigned int size;
	
	offset = CLIENT_HELLO_CIPHER_LEN_OFF;
	if (offset+CLIENT_HELLO_CIPHER_LEN_SIZE > client_hello_len) {
		plog(LOG_ERROR, "Cipher Suite Plugin: Got a truncated Client Hello.");
		return PLUGIN_RESPONSE_ERROR;
	}
	size = get_int_from_net(&(client_hello[offset]), CLIENT_HELLO_CIPHER_LEN_SIZE);
	offset += CLIENT_HELLO_CIPHER_LEN_SIZE;
	offset += size;
	
	if (offset+CLIENT_HELLO_COMPRESS_LEN_SIZE > client_hello_len) {
		plog(LOG_ERROR, "Cipher Suite Plugin: Recieved a truncated Client Hello");
		return PLUGIN_RESPONSE_ERROR;
	}
	size = get_int_from_net(&(client_hello[offset]), CLIENT_HELLO_COMPRESS_LEN_SIZE);
	offset += CLIENT_HELLO_COMPRESS_LEN_SIZE;
	offset += size;	
	
	offset += CLIENT_HELLO_EXT_LEN_SIZE;
	
	return processExtList(client_hello, offset, client_hello_len, cipher_settings.requiredClientExtList, cipher_settings.requiredClientExtListSize, cipher_settings.rejectedClientExtList, cipher_settings.rejectedClientExtListSize);
}

int verify_server_hello(char* server_hello, size_t server_hello_len) {
	unsigned int offset;
	unsigned int cipher;
	int i;
	char found;
	
	// extract the choosen cipher
	offset = SERVER_HELLO_CIPHER_OFF;
	if (offset+SERVER_HELLO_CIPHER_SIZE > server_hello_len) {
		plog(LOG_ERROR, "Cipher Suite Plugin: Got truncated Server Hello");
		return PLUGIN_RESPONSE_ERROR;
	}
	
	cipher = get_int_from_net(&(server_hello[offset]), SERVER_HELLO_CIPHER_SIZE);
	//plog(LOG_DEBUG, "We see a cipher of %x", cipher);
	// check the cipher
	found = 0;
	for (i=0; i<cipher_settings.cipherListSize; i++) {
		if (cipher == cipher_settings.cipherList[i]) {
			if (cipher_settings.isApproved) {
				// we found an approved cipher
				found = 1;
				break;
			} else {
				// we found a bad cipher
				plog(LOG_INFO, "Cipher Suite Plugin: Found a rejected cipher suite");
				return PLUGIN_RESPONSE_INVALID;
			}
		}
	}
	if (cipher_settings.isApproved && !found) {
		plog(LOG_INFO, "Cipher Suite Plugin: Didn't find an accepted cipher suite");	
		return PLUGIN_RESPONSE_INVALID;
	}
	
	offset = EXT_OFF;
	return processExtList(server_hello, offset, server_hello_len, cipher_settings.requiredServerExtList, cipher_settings.requiredServerExtListSize, cipher_settings.rejectedServerExtList, cipher_settings.rejectedServerExtListSize);
}

int processExtList(char* inbuf, int offset, int buf_len, int* req_exts, size_t req_exts_len, int* rej_exts, size_t rej_exts_len) {
	int num_req_found;
	int i;
	unsigned int ext;
	unsigned int ext_len;

	num_req_found = 0;

	while (offset+EXT_SIZE+EXT_LEN_SIZE <= buf_len) {
		// get the ext id
		ext = get_int_from_net(&(inbuf[offset]), EXT_SIZE);
		//plog(LOG_DEBUG, "We see an ext of %04x", ext);
		for (i=0; i<req_exts_len; i++) {
			if (ext == req_exts[i]) {
				num_req_found++;
				// TODO doesn't account for duplicate extentions
				break;
			}
		}
		for (i=0; i<rej_exts_len; i++) {
			if (ext == rej_exts[i]) {
				plog(LOG_INFO, "Cipher Suite Plugin: Found a rejected extention");
				//return PLUGIN_RESPONSE_INVALID;
			}
		}
		
		// check the ext
		// get the size
		offset += EXT_SIZE;
		ext_len = get_int_from_net(&(inbuf[offset]), EXT_LEN_SIZE);

		// offset to the next one
		offset += EXT_LEN_SIZE;
		offset += ext_len;
	}
	if (num_req_found < req_exts_len) {
		plog(LOG_INFO, "Cipher Suite Plugin: Did not find a required extention");
		return PLUGIN_RESPONSE_INVALID;
	}
	return PLUGIN_RESPONSE_VALID;
}

unsigned int get_int_from_net(char* inbuf, int len) {
	int i;
	unsigned int response = 0;
	unsigned char* buf;
	buf = (unsigned char*) inbuf;
	for (i=0; i<len; i++) {
		response += ((unsigned)buf[i]) << (8 * (len-(i+1)));
	}
	return response;
}

void loadconfig(const char* config_path) {
	config_t cfg;
	config_setting_t* setting;
	FILE* config_file;
	int count, i;
	int status;

	config_file = fopen(config_path, "r");
	if (config_file == NULL) {
		plog(LOG_ERROR, "Cipher Suite Plugin could not open config file at %s", config_path);
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		return;
	}

	config_init(&cfg);
	status = config_read(&cfg, config_file);
	if (status == CONFIG_FALSE) {
		plog(LOG_ERROR, "Cipher Suite Plugin could not read the config file!");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	
	status = config_lookup_bool(&cfg, "approved_ciphers", &cipher_settings.isApproved);
	if (status == CONFIG_FALSE) {
		plog(LOG_ERROR, "Broken config file for cipher suite plugin.");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	
	setting = config_lookup(&cfg, "ciphers_list");
	if (setting == NULL) {
		plog(LOG_ERROR, "Broken config file for cipher suite plugin, no 'ciphers_list'");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}

	count = config_setting_length(setting);
	cipher_settings.cipherListSize = count;
	cipher_settings.cipherList = (int*)malloc(sizeof(int) * count);
	if (cipher_settings.cipherList == NULL && count > 0) {
		plog(LOG_ERROR, "Could not allocate space for settings");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	for (i=0; i<count; i++) {
		cipher_settings.cipherList[i] = config_setting_get_int_elem(setting, i);
	}

	setting = config_lookup(&cfg, "required_server_extentions");
	if (setting == NULL) {
		plog(LOG_ERROR, "Broken config file for cipher suite plugin, no 'required_server_extentions'");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	count = config_setting_length(setting);
	cipher_settings.requiredServerExtListSize = count;
	cipher_settings.requiredServerExtList = (int*)malloc(sizeof(int) * count);
	if (cipher_settings.requiredServerExtList == NULL && count > 0) {
		plog(LOG_ERROR, "Could not allocate space for settings");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	for (i=0; i<count; i++) {
		cipher_settings.requiredServerExtList[i] = config_setting_get_int_elem(setting, i);
	}

	setting = config_lookup(&cfg, "rejected_server_extentions");
	if (setting == NULL) {
		plog(LOG_ERROR, "Broken config file for cipher suite plugin, no 'rejected_server_extentions'");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	count = config_setting_length(setting);
	cipher_settings.rejectedServerExtListSize = count;
	cipher_settings.rejectedServerExtList = (int*)malloc(sizeof(int) * count);
	if (cipher_settings.rejectedServerExtList == NULL && count > 0) {
		plog(LOG_ERROR, "Could not allocate space for settings");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	for (i=0; i<count; i++) {
		cipher_settings.rejectedServerExtList[i] = config_setting_get_int_elem(setting, i);
	}
	



	setting = config_lookup(&cfg, "required_client_extentions");
	if (setting == NULL) {
		plog(LOG_ERROR, "Broken config file for cipher suite plugin, no 'required_client_extentions'");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	count = config_setting_length(setting);
	cipher_settings.requiredClientExtListSize = count;
	cipher_settings.requiredClientExtList = (int*)malloc(sizeof(int) * count);
	if (cipher_settings.requiredClientExtList == NULL && count > 0) {
		plog(LOG_ERROR, "Could not allocate space for settings");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	for (i=0; i<count; i++) {
		cipher_settings.requiredClientExtList[i] = config_setting_get_int_elem(setting, i);
	}

	setting = config_lookup(&cfg, "rejected_client_extentions");
	if (setting == NULL) {
		plog(LOG_ERROR, "Broken config file for cipher suite plugin, no 'rejected_client_extentions'");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	count = config_setting_length(setting);
	cipher_settings.rejectedClientExtListSize = count;
	cipher_settings.rejectedClientExtList = (int*)malloc(sizeof(int) * count);
	if (cipher_settings.rejectedClientExtList == NULL && count > 0) {
		plog(LOG_ERROR, "Could not allocate space for settings");
		cipher_settings.isApproved = PLUGIN_INIT_ERROR;
		config_destroy(&cfg);
		return;
	}
	for (i=0; i<count; i++) {
		cipher_settings.rejectedClientExtList[i] = config_setting_get_int_elem(setting, i);
	}
}

void hexdump(char* data, size_t len) {
	char* formatted;	
	char* formatter;
	int i;

	formatted = (char*)malloc((len * 3)* sizeof(char));

	for (i=0; i<len; i++) {
		if (!((i+1)%8)) {
			formatter = "\n";
		} else if (!((i+1)%4)) {
			formatter = "\t";
		} else {
			formatter = " ";
		}
		snprintf(formatted+(i*3), 27, "%02x%s", (unsigned char) data[i], formatter);
	}
	plog(LOG_DEBUG, "\n%s\n", formatted);
}
