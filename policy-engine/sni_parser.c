#include <string.h>
#include "sni_parser.h"
#include "tb_logging.h"

// Client Hello byte navigation
#define SIZE_CLIENT_HELLO_HEAD_LEN	4
#define SIZE_CLIENT_HELLO_LEN		3
#define SIZE_TLS_VERSION_INFO		2
#define SIZE_RANDOM_DATA		32
#define SIZE_SESSION_ID_LEN		1
#define	SIZE_CIPHER_SUITE_LEN		2
#define SIZE_COMPRESSION_METHODS_LEN	2
#define SIZE_EXTS_LEN			2
#define SIZE_EXT_TYPE			2
#define SIZE_EXT_LEN			2
#define	EXT_TYPE_SNI			0
#define SIZE_SNI_LIST_LEN		2
#define SIZE_SNI_TYPE			1
#define SIZE_SNI_NAME_LEN		2

char* sni_get_hostname(char* client_hello, int client_hello_len) {
	char* hostname;
	char* bufptr;
	unsigned int hello_length;
	unsigned char session_id_length;
	unsigned short cipher_suite_length;
	unsigned char compression_methods_length;
	unsigned short extensions_length;
	unsigned short extension_length;
	unsigned short extension_type;
	unsigned short name_length;

	hostname = NULL;

	bufptr = client_hello + 1;
	hello_length = be24_to_cpu(*(be24*)bufptr);
	bufptr += SIZE_CLIENT_HELLO_LEN; // advance past length info
	bufptr += SIZE_TLS_VERSION_INFO; // advance past version info
	bufptr += SIZE_RANDOM_DATA; // skip 32-byte random
	session_id_length = bufptr[0];
	bufptr += SIZE_SESSION_ID_LEN; // advance past session id length field
	bufptr += session_id_length; // advance past session ID
	cipher_suite_length = be16_to_cpu(*(be16*)bufptr);
	bufptr += SIZE_CIPHER_SUITE_LEN; // advance past cipher suite length field
	bufptr += cipher_suite_length; // advance past cipher suites;
	compression_methods_length = be16_to_cpu(*(be16*)bufptr);
	bufptr += SIZE_COMPRESSION_METHODS_LEN; // advance past compression methods length field
	bufptr += compression_methods_length; // advance past compression methods
	/* If there are bytes left, there are extensions, and possibly a SNI */
	if (hello_length - (unsigned int)(bufptr - (client_hello + SIZE_CLIENT_HELLO_HEAD_LEN)) > 0) {
		extensions_length = be16_to_cpu(*(be16*)bufptr);
		bufptr += SIZE_EXTS_LEN; // advance past extensions length
		while (extensions_length) {
			// Check how many bytes have been read vs how many are left
			extension_type = be16_to_cpu(*(be16*)bufptr);
			bufptr += SIZE_EXT_TYPE; // advance past type field
			extension_length = be16_to_cpu(*(be16*)bufptr);
			bufptr += SIZE_EXT_LEN; // advance past extension length field
			if (extension_type == EXT_TYPE_SNI) {
				bufptr += SIZE_SNI_LIST_LEN; // advance past the list length 
				bufptr += SIZE_SNI_TYPE; // advance past type field
				name_length = be16_to_cpu(*(be16*)bufptr);
				bufptr += SIZE_SNI_NAME_LEN; // advance past name length field
				hostname = (char*)malloc(name_length+1);
				memcpy(hostname, bufptr, name_length);
				hostname[name_length] = '\0'; // null terminate it
				tblog(LOG_DEBUG, "Found sni hostname %s", hostname);
				break;
			}
			bufptr += extension_length; // advanced to the next extension
			extensions_length -= extension_length + SIZE_EXT_TYPE + SIZE_EXT_LEN;
		}
	}
	
	return hostname;
}
