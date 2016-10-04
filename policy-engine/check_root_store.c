#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <string.h>
#include <fnmatch.h>
#include <openssl/evp.h>
#include <sys/utsname.h>
#include "trusthub_plugin.h"
#include "th_logging.h"
#include "check_root_store.h"

#define MAX_LENGTH 1024

static char* ca_filename_redhat = "ca-bundle.crt";
static char* ca_filename_debian = "ca-certificates.crt";

static int cmp_names(const char* hostname, char* cn);
static void print_certificate(X509* cert);
static void print_chain(STACK_OF(X509)*);
static const char* get_validation_errstr(long e);

/** This function returns a new X509_STORE* that contains the default CA system store.
 * You must free this STORE after use with X509_STORE_free.
 *
 * @return a X509_STORE pointer containing the root CA system store.
 */
X509_STORE* make_new_root_store() {
	struct utsname info;
	size_t ca_path_len;
	const char* store_path;
	char* full_path;
	char* ca_filename;
	size_t ca_filename_len;
	X509_STORE* store;
	
	/* create a new store */
	store = X509_STORE_new();
	if (store == NULL) {
		thlog(LOG_ERROR, "Unable to create new X509 store");
		return NULL;
	}
	
	/* get proper ca_filename */
	if (uname(&info) < 0) {
		thlog(LOG_ERROR, "Could not get the uname information, defaulting to redhat");
		ca_filename = ca_filename_redhat;
	} else {
		if (strstr(info.release, ".fc") != NULL) {
			ca_filename = ca_filename_redhat;
		} else {
			ca_filename = ca_filename_debian;
		}
	}
	
	/* build the root store path */
	store_path = X509_get_default_cert_dir();
	ca_path_len = strlen(store_path);
	ca_filename_len = strlen(ca_filename);
	full_path = (char *)malloc(ca_path_len + ca_filename_len + 2);
	sprintf(full_path, "%s/%s", store_path, ca_filename);
	
	/* load the store */
	if (X509_STORE_load_locations(store, full_path, NULL) < 1) {
		thlog(LOG_ERROR, "Unable to read the certificate store at %s", full_path);
		X509_STORE_free(store);
		return NULL;
	}
	free(full_path);
	return store;
}

/** This function verifies a certificate chain against the default root_store
 *
 * @param hostname The hostname of the leaf certificate. If it starts with a dot, then it will pass for all subdomains of the certificate.
 * @param certs A stack of pointers to X509 certificates, using the STACK_OF type.
 * @param root_store A pointer to the X509_STORE that contains the root_store. This can be obtained using make_new_root_store().
 * @return Returns a PLUGIN_RESPONSE where -1 is an error, 0 is for a invalid chain, 1 is for a valid chain, and 2 is abstained.
 */
int query_store(const char* hostname, STACK_OF(X509)* certs, X509_STORE* root_store) {
	X509* cert;
	X509_STORE_CTX* ctx;
	X509_STORE* store;
	int i;
	int valid;

	if (sk_X509_num(certs) <= 0) {
		thlog(LOG_WARNING, "Got a stack of certs that was empty");
		return PLUGIN_RESPONSE_ERROR;	
	}

	/* Check the hostname against the leaf certificate */
	
	if (verify_hostname(hostname, sk_X509_value(certs, 0)) < 1) {
		if (verify_alternate_hostname(hostname, sk_X509_value(certs, 0)) < 1) {
			thlog(LOG_INFO, "The hostname %s was found invalid", hostname);
			return PLUGIN_RESPONSE_INVALID;
		}
	}
	
	/* Verify the certificate chain */
	OpenSSL_add_all_algorithms();
	store = root_store;
	
	for (i=sk_X509_num(certs)-1; i>=0; i--) {
		cert = sk_X509_value(certs, i);
	
		ctx = X509_STORE_CTX_new();
		if (!ctx) {
			thlog(LOG_ERROR, "Unable to create new X509_STORE_CTX");
			return PLUGIN_RESPONSE_ERROR;
		}

		if (X509_STORE_CTX_init(ctx, store, cert, certs) < 1) {
			thlog(LOG_WARNING, "The certificate chain is invalid");
			print_chain(certs);
			X509_STORE_CTX_free(ctx);
			return PLUGIN_RESPONSE_INVALID;
		}
	
		/* Verify the build certificate context */
		valid = X509_verify_cert(ctx);
		if (valid < 1) {
			thlog(LOG_DEBUG, "A certificate gave an error %s. Certificate:", get_validation_errstr(X509_STORE_CTX_get_error(ctx)));	
			print_certificate(cert);
			X509_STORE_CTX_free(ctx);
			return PLUGIN_RESPONSE_INVALID;
		} else {
			/* Certificate passed */
		}

		/* Check if this cert can be a CA */
		if (i > 0) {
			/* This should be a CA */
			if (X509_check_ca(cert) < 1) {
				thlog(LOG_WARNING, "Found a certificate in the chain that is not a CA, but is signing");
				print_certificate(cert);
				X509_STORE_CTX_free(ctx);
				return PLUGIN_RESPONSE_INVALID;
			}
		}
			
		X509_STORE_CTX_free(ctx);
	}
	return PLUGIN_RESPONSE_VALID;
}

/** This function checks the alternative hostnames in the certificate
 *
 */
int verify_alternate_hostname(const char* hostname, X509* cert) {
	int result;
	int i;
	STACK_OF(GENERAL_NAME)* alt_names;
	const GENERAL_NAME* current_alt_name;
	char* cn;
	
	result = 0;

	alt_names = X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);
	if (alt_names == NULL) {
		return 0;
	}
	
	for (i=0; i<sk_GENERAL_NAME_num(alt_names); i++) {
		current_alt_name = sk_GENERAL_NAME_value(alt_names, i);
		
		if (current_alt_name->type == GEN_DNS) {
			cn = (char *) ASN1_STRING_data(current_alt_name->d.dNSName);
			
			/* check for null characters */
			if (ASN1_STRING_length(current_alt_name->d.dNSName) != strlen(cn)) {
				thlog(LOG_DEBUG, "Parsing a malformed certificate");
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
int verify_hostname(const char* hostname, X509* cert) {
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

/** This does the actual string manipulation and comparison for hostnames
 *
 */
int cmp_names(const char* hostname, char* cn) {
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

/** returns a STACK_OF(X509)* from a pem file containing certificates
 *
 */
STACK_OF(X509)* pem_to_stack(char* filename) {
	FILE *fp = NULL;
	STACK_OF(X509)* chain;
	X509* cert = NULL;
	
	fp = fopen(filename,"rb");
	if (fp == NULL) {
		return NULL;
	}
	
	chain = sk_X509_new_null();
	
	while (1==1) {
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (cert == NULL){
			break;
		}
		sk_X509_push(chain, cert);
	}

	return chain;
}

void print_certificate(X509* cert) {
        char subj[MAX_LENGTH+1];
        char issuer[MAX_LENGTH+1];
        X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
        thlog(LOG_DEBUG, "Certificate :SUBJECT: %s :ISSUER: %s", subj, issuer);
}

void print_chain(STACK_OF(X509)* in) {
	int i;
	for (i=0; i<sk_X509_num(in); i++) {
		print_certificate(sk_X509_value(in, i));
	}
}

const char* get_validation_errstr(long e) {
		switch ((int) e) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		return "ERR_UNABLE_TO_GET_ISSUER_CERT";
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		return "ERR_UNABLE_TO_GET_CRL";
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		return "ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		return "ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		return "ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		return "ERR_CERT_SIGNATURE_FAILURE";
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		return "ERR_CRL_SIGNATURE_FAILURE";
	case X509_V_ERR_CERT_NOT_YET_VALID:
		return "ERR_CERT_NOT_YET_VALID";
	case X509_V_ERR_CERT_HAS_EXPIRED:
		return "ERR_CERT_HAS_EXPIRED";
	case X509_V_ERR_CRL_NOT_YET_VALID:
		return "ERR_CRL_NOT_YET_VALID";
	case X509_V_ERR_CRL_HAS_EXPIRED:
		return "ERR_CRL_HAS_EXPIRED";
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		return "ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		return "ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		return "ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		return "ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
	case X509_V_ERR_OUT_OF_MEM:
		return "ERR_OUT_OF_MEM";
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		return "ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		return "ERR_SELF_SIGNED_CERT_IN_CHAIN";
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		return "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		return "ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		return "ERR_CERT_CHAIN_TOO_LONG";
	case X509_V_ERR_CERT_REVOKED:
		return "ERR_CERT_REVOKED";
	case X509_V_ERR_INVALID_CA:
		return "ERR_INVALID_CA";
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		return "ERR_PATH_LENGTH_EXCEEDED";
	case X509_V_ERR_INVALID_PURPOSE:
		return "ERR_INVALID_PURPOSE";
	case X509_V_ERR_CERT_UNTRUSTED:
		return "ERR_CERT_UNTRUSTED";
	case X509_V_ERR_CERT_REJECTED:
		return "ERR_CERT_REJECTED";
	case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		return "ERR_SUBJECT_ISSUER_MISMATCH";
	case X509_V_ERR_AKID_SKID_MISMATCH:
		return "ERR_AKID_SKID_MISMATCH";
	case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		return "ERR_AKID_ISSUER_SERIAL_MISMATCH";
	case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		return "ERR_KEYUSAGE_NO_CERTSIGN";
	case X509_V_ERR_INVALID_EXTENSION:
		return "ERR_INVALID_EXTENSION";
	case X509_V_ERR_INVALID_POLICY_EXTENSION:
		return "ERR_INVALID_POLICY_EXTENSION";
	case X509_V_ERR_NO_EXPLICIT_POLICY:
		return "ERR_NO_EXPLICIT_POLICY";
	case X509_V_ERR_APPLICATION_VERIFICATION:
		return "ERR_APPLICATION_VERIFICATION";
	default:
		return "ERR_UNKNOWN";
	}
}

