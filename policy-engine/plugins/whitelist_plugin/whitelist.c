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


#define MAX_LENGTH	1024
#define CRS_DEBUG	0

char* plugin_path; // This will be set by trusthub

int initialize(init_data_t* idata);
int query(query_data_t* data);
static unsigned int get_cert_fingerprint(X509* cert, EVP_MD* digest, unsigned char* fingerprint, unsigned int* fingerprint_len);
static int compare_fingerprint(unsigned char *fp1, int fp1len, unsigned char *fp2, int fp2len);
static STACK_OF(X509)* get_whitelist();

static int pem_append(char* filename, STACK_OF(X509)* chain);
//static void print_certificate(X509* cert);

int initialize(init_data_t* idata) {
	plugin_path = idata->plugin_path;
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

	/* Only check the leaf certificate */
	cert = sk_X509_value(data->chain, 0);
	//print_certificate(cert);
	
	/* Get the fingerprint for the leaf cert */

	//OpenSSL_add_all_algorithms(); // Need this?
	
	digest = (EVP_MD*)EVP_sha1();
	fingerprint_len = sizeof(fingerprint);
	if (!get_cert_fingerprint(cert, digest, fingerprint, &fingerprint_len)) {
		if (CRS_DEBUG >= 1) {	
			printf("Could not get the fingerprint of the leaf certificate\n");
		}
		return PLUGIN_RESPONSE_ERROR;
	}
	
	/* Compare fingerprint to the whitelist */
	whitelist = get_whitelist();
	if (!whitelist) {
		if (CRS_DEBUG >= 1) {
			printf("Could not get the whitelist\n");	
		}
		return PLUGIN_RESPONSE_ERROR;
	}
	
	// Right now this is going over every whitelisted cert, and taking a hash of them, then comparing
	// TODO: For quicker results, switch to storing only hashes of the whitelisted certificates
	for (i = 0; i < sk_X509_num(whitelist); i++) {
		cert = sk_X509_value(whitelist, i);
		white_fingerprint_len = sizeof(white_fingerprint);
		if (!get_cert_fingerprint(cert, digest, white_fingerprint, &white_fingerprint_len)) {
			if (CRS_DEBUG >= 1) {	
				printf("Could not get the fingerprint of the whitelist certificate #%d\n", i);
			}
			sk_X509_pop_free(whitelist, X509_free);
			return PLUGIN_RESPONSE_ERROR;
		}
		if (compare_fingerprint(fingerprint, fingerprint_len, white_fingerprint, white_fingerprint_len)) {
			if (CRS_DEBUG >= 1) {	
				printf("Found a whitelisted certificate #%d\n", i);
			}
			sk_X509_pop_free(whitelist, X509_free);
			return PLUGIN_RESPONSE_VALID;
		} else {
		}
	}
		
	if (CRS_DEBUG >= 1) {	
		printf("Could not find a whitelisted certificate\n");
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
	char* filename;

	whitelist_dir = (char*)malloc(strlen(plugin_path + 11);
	whitelist_dir = dirname(plugin_path);
	strcat(whitelist_dir,"/whitelist");

	whitelist = sk_X509_new_null();
	
	if ((dir = opendir (whitelist_dir)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (!fnmatch("*.pem", ent->d_name, 0)) {
				filename = (char*)malloc(sizeof(whitelist_dir) + sizeof(ent->d_name));
				sprintf(filename, "%s/%s", whitelist_dir, ent->d_name);
				if (!pem_append(filename, whitelist)) {
					if (CRS_DEBUG >= 1) {
						printf("Error adding %s\n", filename);
					}
				}
				free(filename);
			}
		}
		closedir(dir);
	}
	if (CRS_DEBUG >= 1) {
		printf("Whitelist size = %d certificates\n", sk_X509_num(whitelist));
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

/*static void print_certificate(X509* cert) {
        char subj[MAX_LENGTH+1];
        char issuer[MAX_LENGTH+1];
        X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
        printf("subject: %s\n", subj);
        printf("issuer : %s\n", issuer);
}*/
