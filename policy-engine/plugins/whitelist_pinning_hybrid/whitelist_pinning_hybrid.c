#include <stdio.h>
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <string.h>
#include <fnmatch.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <libgen.h>
#include "../../trusthub_plugin.h"
#include "../../th_logging.h"


#define MAX_LENGTH	1024

int (*plog)(thlog_level_t level, const char* format, ...);
char* plugin_path;

int initialize(init_data_t* idata);
int query(query_data_t* data);
static unsigned int get_cert_fingerprint(X509* cert, EVP_MD* digest, unsigned char* fingerprint, unsigned int* fingerprint_len);
static int compare_fingerprint(unsigned char *fp1, int fp1len, unsigned char *fp2, int fp2len);
static STACK_OF(X509)* get_whitelist();

static int pem_append(char* filename, STACK_OF(X509)* chain);

static int verify_hostname(const char* hostname, X509* cert);

int initialize(init_data_t* idata) {
	plugin_path = idata->plugin_path;
	plog = idata->thlog;
	plog(LOG_DEBUG, "Whitelist initilized");
	return 0;
}

int query(query_data_t* data) {
	X509* cert;
	STACK_OF(X509)* whitelist;
	EVP_MD* digest;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	unsigned int fingerprint_len;
	int i;
	unsigned char white_fingerprint[EVP_MAX_MD_SIZE];
	unsigned int white_fingerprint_len;

	plog(LOG_DEBUG, "Whitelist querying");
	/* Only check the leaf certificate */
	cert = sk_X509_value(data->chain, 0);
	//print_certificate(cert);
	
	/* Get the fingerprint for the leaf cert */

	//OpenSSL_add_all_algorithms(); // Need this?
	
	digest = (EVP_MD*)EVP_sha1();
	fingerprint_len = sizeof(fingerprint);
	if (!get_cert_fingerprint(cert, digest, fingerprint, &fingerprint_len)) {
		return PLUGIN_RESPONSE_ERROR;
	}
	
	plog(LOG_DEBUG, "Got fingerprint");

	/* Compare fingerprint to the whitelist */
	whitelist = get_whitelist();
	if (!whitelist) {
		return PLUGIN_RESPONSE_ERROR;
	}
	
	// Right now this is going over every whitelisted cert, and taking a hash of them, then comparing
	// TODO: For quicker results, switch to storing only hashes of the whitelisted certificates
	plog(LOG_DEBUG, "running through whitelist");
	for (i = 0; i < sk_X509_num(whitelist); i++) {
		cert = sk_X509_value(whitelist, i);
		
		if (verify_hostname(data->hostname, cert) != 1) {
			continue;
		}
		
		white_fingerprint_len = sizeof(white_fingerprint);
		if (!get_cert_fingerprint(cert, digest, white_fingerprint, &white_fingerprint_len)) {
			// Couldn't get a fingerprint
			sk_X509_pop_free(whitelist, X509_free);
			return PLUGIN_RESPONSE_ERROR;
		}
		if (compare_fingerprint(fingerprint, fingerprint_len, white_fingerprint, white_fingerprint_len)) {
			// We found a good certificate
			sk_X509_pop_free(whitelist, X509_free);
			return PLUGIN_RESPONSE_VALID;
		}
	}
		
	sk_X509_pop_free(whitelist, X509_free);
	return PLUGIN_RESPONSE_INVALID;
}

static unsigned int get_cert_fingerprint(X509* cert, EVP_MD* digest, unsigned char* fingerprint, unsigned int* fingerprint_len) {
	if (*fingerprint_len < EVP_MD_size(digest)) {
		return 0;
	}
	if (!X509_digest(cert, digest, fingerprint, fingerprint_len)) {
		return 0;
	}
	return *fingerprint_len;
}
   
static int compare_fingerprint(unsigned char *fp1, int fp1len, unsigned char *fp2, int fp2len) {
	return ( (fp1len == fp2len) && !memcmp(fp1, fp2, fp1len));
}

static STACK_OF(X509)* get_whitelist() {
	STACK_OF(X509)* whitelist;
	DIR *dir;
	struct dirent *ent;
	char* whitelist_dir;
	char* temp_path;
	char* filename;

	whitelist_dir = (char*)malloc(strlen(plugin_path) + 11);
	if (whitelist_dir == NULL) {
		return NULL;
	}

	//make copy of plugin_path because dirname changes whats passed in
	temp_path = (char*)malloc(strlen(plugin_path)+1);
	if (temp_path == NULL) {
		return NULL;
	}
	
	strncpy(temp_path, plugin_path, strlen(plugin_path)+1);
	whitelist_dir = dirname(temp_path);
	strcat(whitelist_dir,"/whitelist");
	plog(LOG_DEBUG, "Getting whitelist at %s", whitelist_dir);

	whitelist = sk_X509_new_null();
	
	if ((dir = opendir (whitelist_dir)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (!fnmatch("*.pem", ent->d_name, 0)) {
				filename = (char*)malloc(sizeof(whitelist_dir) + sizeof(ent->d_name));
				sprintf(filename, "%s/%s", whitelist_dir, ent->d_name);
				if (!pem_append(filename, whitelist)) {
					// Could not add the file
				}
				free(filename);
			}
		}
		closedir(dir);
	}
	free(whitelist_dir);
	return whitelist;
}

static int pem_append(char* filename, STACK_OF(X509)* chain) {	
	FILE *fp = NULL;
	X509* cert = NULL;
	
	fp = fopen(filename,"rb");
	if (fp == NULL) {
		return 0;
	}	
	
	while (1==1) {
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (cert == NULL){
			break;
		}
		sk_X509_push(chain, cert);
	}
	fclose(fp);

	return 1;
}

/** This does the actual string manipulation and comparison for hostnames
 *
 */
static int cmp_names(const char* hostname, char* cn) {
	int i;
	int count;
	int len;
	char* tempstr;
	int result;

	result = 0;
	tempstr = NULL;
	
	/* Note, if the hostname starts with a dot, it should be valid for any subdomain */
	if (hostname[0] == '.') {
		count = 0;
		len = strlen(cn);
		for (i=0; cn[i]; i++) {
			if (cn[i] == '.') {
				count++;
			}
		}
		if (count > 1) {
			/* remove up to the first '.' */
			for (i=0; cn[i]; i++) {
				if (cn[i] == '.') {
					count = i;
					break;
				}
			}
			tempstr = (char *) malloc(len - (count));
			memcpy(tempstr, cn+count+1, len - (count));
			cn = tempstr;
		}
		/* add *. to the front of the cn */
		len = strlen(cn);
		tempstr = (char *) malloc(len+3);
		memcpy(tempstr, "*.", 2);
		memcpy(tempstr+2, cn, len+1);
		free(cn);
		cn = tempstr;
	}
	if (fnmatch(cn, hostname, 0) == 0) {
		result = 1;
	}
	if (tempstr != NULL) {
		free(tempstr);
	}
	return result;
}

/** This function tests a hostname against all CNs in the cert
 *
 */
static int verify_hostname(const char* hostname, X509* cert) {
	X509_NAME *subj;
	int lastpos;
	X509_NAME_ENTRY* entry;
	ASN1_STRING* data;
	char* cn;
	int result;
	
	/* Get the Common Name from the certificate */
		
	subj = X509_get_subject_name(cert);
	result = 0;
	
	lastpos = -1;
	for (;;) {
		lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
		if (lastpos == -1) {
			break;
		}
		entry = X509_NAME_get_entry(subj, lastpos);
		data = X509_NAME_ENTRY_get_data(entry);
		cn = (char*)ASN1_STRING_data(data);
		
		/* check for null characters */
		if (ASN1_STRING_length(data) != strlen(cn)) {
			thlog(LOG_DEBUG, "Parsing a malformed certificate");
			continue;
		}

		if (cmp_names(hostname, cn) > 0) {
			result = 1;
		}
	}
	
	
	return result;
}

