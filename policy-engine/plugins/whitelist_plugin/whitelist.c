#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <string.h>
#include <fnmatch.h>
#include <openssl/evp.h>
#include <dirent.h>
#include "../../plugin_response.h"


#define MAX_LENGTH	1024
#define WHITELIST_DIR	"./policy-engine/plugins/whitelist_plugin/whitelist/"

#define CRS_DEBUG	1

int query(const char* hostname, STACK_OF(X509)* certs);
static unsigned int get_cert_fingerprint(X509* cert, EVP_MD* digest, unsigned char* fingerprint, unsigned int* fingerprint_len);
static int compare_fingerprint(unsigned char *fp1, int fp1len, unsigned char *fp2, int fp2len);
static STACK_OF(X509)* get_whitelist();

static int verify_alternate_hostname(const char* hostname, X509* cert);
static int verify_hostname(const char* hostname, X509* cert);
static int cmp_names(const char* hostname, char* cn);

static int pem_append(char* filename, STACK_OF(X509)* chain);
static void print_certificate(X509* cert);

int query(const char* hostname, STACK_OF(X509)* certs) {
	X509* cert;
	STACK_OF(X509)* whitelist;
	EVP_MD* digest;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	unsigned int fingerprint_len;
	int i;
	unsigned char white_fingerprint[EVP_MAX_MD_SIZE];
	unsigned int white_fingerprint_len;

	/* Only check the leaf certificate */
	cert = sk_X509_value(certs, 0);
	//print_certificate(cert);
	
	/* Check the hostname ? */	
	if (verify_hostname(hostname, cert) < 1) {
		if (verify_alternate_hostname(hostname, cert) < 1) {
			if (CRS_DEBUG >= 1) {	
				printf("The hostname was found invalid\n");
			}
			return PLUGIN_RESPONSE_INVALID;
		}
	}
	
	/* Get the fingerprint for the leaf cert */

	//OpenSSL_add_all_algorithms(); // Need this?
	
	digest = EVP_sha1();
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

/** This function checks the alternative hostnames in the certificate
 *
 */
static int verify_alternate_hostname(const char* hostname, X509* cert) {
	int result;
	int i;
	STACK_OF(GENERAL_NAME)* alt_names;
	const GENERAL_NAME* current_alt_name;
	char* cn;
	
	result = 0;

	alt_names = X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);
	if (alt_names == NULL) {
		return 0;
		if (CRS_DEBUG >= 1) {	
			printf("No alternative hostnames found.\n");
		}
	}
	
	for (i=0; i<sk_GENERAL_NAME_num(alt_names); i++) {
		current_alt_name = sk_GENERAL_NAME_value(alt_names, i);
		
		if (current_alt_name->type == GEN_DNS) {
			cn = (char *) ASN1_STRING_data(current_alt_name->d.dNSName);
			
			/* check for null characters */
			if (ASN1_STRING_length(current_alt_name->d.dNSName) != strlen(cn)) {
				if (CRS_DEBUG >= 1) {
					printf("Malformed Certificate\n");
				}
				continue;
			}
			
			if (cmp_names(hostname, cn) > 0) {
				result = 1;
			}
		}
	}
	sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
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
			if (CRS_DEBUG >= 1) {
				printf("Malformed Certificate\n");
			}
			continue;
		}

		if (cmp_names(hostname, cn) > 0) {
			result = 1;
		}
	}
	
	
	return result;
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

static STACK_OF(X509)* get_whitelist() {
	STACK_OF(X509)* whitelist;
	DIR *dir;
	struct dirent *ent;
	char* filename;

	whitelist = sk_X509_new_null();
	
	if ((dir = opendir (WHITELIST_DIR)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (!fnmatch("*.pem", ent->d_name, 0)) {
				filename = (char*)malloc(sizeof(WHITELIST_DIR) + sizeof(ent->d_name));
				sprintf(filename, "%s%s", WHITELIST_DIR, ent->d_name);
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

static void print_certificate(X509* cert) {
        char subj[MAX_LENGTH+1];
        char issuer[MAX_LENGTH+1];
        X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
        printf("subject: %s\n", subj);
        printf("issuer : %s\n", issuer);
}
