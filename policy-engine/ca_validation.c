/*
 * The functionality contained in this file validates a certificate using the root store.
 *
 * Pieces of this code have been taken from Zakir Durumeric's "Parsing X.509 Ceritficates with OpenSSL and C"
 * available at: https://zakird.com/2013/10/13/certificate-parsing-with-openssl and uses hostname validation
 * from iSEC partners (see notices in openssl_hostname_validation.c)
 *
 * Please report vulnerabilities or other bugs to Mark O'Neill <mto@byu.edu>.
 * 
 */

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <string.h>
#include <fnmatch.h>
#include <openssl/evp.h>
#include <sys/utsname.h>
#include "trustbase_plugin.h"
#include "tb_logging.h"
#include "ca_validation.h"
#include "openssl_hostname_validation.h"

#define MAX_LENGTH 1024

static char root_store_filename_redhat[] = "ca-bundle.crt";
static char root_store_filename_debian[] = "ca-certificates.crt";

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
	size_t root_store_dir_len;
	const char* root_store_dir;
	char* root_store_full_path;
	char* root_store_filename;
	size_t root_store_filename_len;
	X509_STORE* store;
	
	/* create a new store */
	store = X509_STORE_new();
	if (store == NULL) {
		tblog(LOG_ERROR, "Unable to create new X509 store");
		return NULL;
	}
	
	/* Attempt to discover root store location based on distro 
	 * Only support redhat and debian for now. */
	if (uname(&info) < 0) {
		tblog(LOG_ERROR, "Could not get uname information, defaulting to redhat");
		root_store_filename = root_store_filename_redhat;
	}
	else {
		if (strstr(info.release, ".fc") != NULL) {
			root_store_filename = root_store_filename_redhat;
		}
		else {
			root_store_filename = root_store_filename_debian;
		}
	}
	
	/* build the root store path */
	root_store_dir = X509_get_default_cert_dir();
	root_store_dir_len = strlen(root_store_dir);
	root_store_filename_len = strlen(root_store_filename);
	root_store_full_path = (char *)malloc(root_store_dir_len + root_store_filename_len + 2); /* +1 for NULL, +1 for / */
	sprintf(root_store_full_path, "%s/%s", root_store_dir, root_store_filename);
	tblog(LOG_INFO, "Policy Engine is using root store found at %s\n", root_store_full_path);
	
	/* load the store */
	if (X509_STORE_load_locations(store, root_store_full_path, NULL) < 1) {
		tblog(LOG_ERROR, "Unable to read the certificate store at %s", root_store_full_path);
		X509_STORE_free(store);
		return NULL;
	}

	OpenSSL_add_all_algorithms();
	free(root_store_full_path);
	return store;
}

/** This function verifies a certificate chain against the default root_store
 *
 * @param hostname The hostname of the leaf certificate. If it starts with a dot, then it will pass for all subdomains of the certificate.
 * @param chain An X509 certificate chain to be validated.
 * @param root_store A pointer to the X509_STORE that contains the root_store. This can be obtained using make_new_root_store().
 * @return Returns a PLUGIN_RESPONSE where -1 is an error, 0 is for a invalid chain, 1 is for a valid chain, and 2 is abstained.
 */
int query_store(const char* hostname, STACK_OF(X509)* chain, X509_STORE* root_store) {
	X509* cert;
	X509_STORE_CTX* ctx;
	X509_STORE* store;
	int i;
	int valid;

	if (sk_X509_num(chain) <= 0) {
		tblog(LOG_WARNING, "Received an empty cert chain");
		return PLUGIN_RESPONSE_ERROR;	
	}

	/* Check the hostname against the leaf certificate */
	if (validate_hostname(hostname, sk_X509_value(chain, 0)) != MatchFound) {
		tblog(LOG_INFO, "The leaf certificate is not issued to %s", hostname);
		return PLUGIN_RESPONSE_INVALID;
	}
	
	/* Verify the certificate chain */
	store = root_store;
	
	//for (i=sk_X509_num(chain)-1; i>=0; i--) {
	cert = sk_X509_value(chain, i);
	ctx = X509_STORE_CTX_new();
	if (!ctx) {
		tblog(LOG_ERROR, "Unable to create new X509_STORE_CTX");
		return PLUGIN_RESPONSE_ERROR;
	}

	if (X509_STORE_CTX_init(ctx, store, cert, chain) < 1) {
		tblog(LOG_WARNING, "The certificate chain is invalid");
		print_chain(chain);
		X509_STORE_CTX_free(ctx);
		return PLUGIN_RESPONSE_INVALID;
	}
	
	/* Verify the build certificate context */
	valid = X509_verify_cert(ctx);
	if (valid < 1) {
		tblog(LOG_DEBUG, "A certificate gave an error %s. Certificate:", get_validation_errstr(X509_STORE_CTX_get_error(ctx)));	
		print_certificate(cert);
		X509_STORE_CTX_free(ctx);
		return PLUGIN_RESPONSE_INVALID;
	}
	else {
		/* Certificate passed */
	}
	/* Check if this cert can be a CA 
	 * Mark: I'm fairly certain X509_verify_cert does this already. See openssl's x509_vfy.c 
	if (i > 0) {
		if (X509_check_ca(cert) < 1) {
			tblog(LOG_WARNING, "Found a certificate in the chain that is not a CA, but is signing");
			print_certificate(cert);
			X509_STORE_CTX_free(ctx);
			return PLUGIN_RESPONSE_INVALID;
		}
	}*/
		
	X509_STORE_CTX_free(ctx);
	//}
	return PLUGIN_RESPONSE_VALID;
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
        tblog(LOG_DEBUG, "Certificate :SUBJECT: %s :ISSUER: %s", subj, issuer);
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

