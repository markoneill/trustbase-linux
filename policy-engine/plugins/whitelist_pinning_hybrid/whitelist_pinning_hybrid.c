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

#include <stdlib.h>
#include <sqlite3.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>

#include "../../trustbase_plugin.h"
#include "../../tb_logging.h"


#define MAX_LENGTH	1024
#define PINNING_DATABASE "pinned_certs.db"

int (*plog)(tblog_level_t level, const char* format, ...);
char* plugin_path;
char* database_path;

int initialize(init_data_t* idata);
int query(query_data_t* data);
int finalize(void);

static unsigned int get_cert_fingerprint(X509* cert, EVP_MD* digest, unsigned char* fingerprint, unsigned int* fingerprint_len);
static int compare_fingerprint(unsigned char *fp1, int fp1len, unsigned char *fp2, int fp2len);
static STACK_OF(X509)* get_whitelist();

static int pem_append(char* filename, STACK_OF(X509)* chain);
static int verify_hostname(const char* hostname, X509* cert);

static time_t ASN1_GetTimeT(ASN1_TIME* time);

int initialize(init_data_t* idata) {
	char* plugin_path_cpy;
	
	plog = idata->tblog;
	
	// Whitelist Init
	plugin_path = idata->plugin_path;
	plog(LOG_DEBUG, "WHITELIST: Initilized");
	//////////////////////////////////////////////////
	
	// Pinning Init
	plugin_path_cpy = (char*)malloc(strlen(idata->plugin_path) + 1);
	strncpy(plugin_path_cpy, idata->plugin_path, strlen(idata->plugin_path));
	
	database_path = NULL;
	database_path = (char*)malloc(strlen(plugin_path_cpy) + 2 + strlen(PINNING_DATABASE));
	if (database_path == NULL) {
		free(plugin_path_cpy);
		return -1;
	}
	strncpy(database_path, dirname(plugin_path_cpy), strlen(plugin_path_cpy));
	strcat(database_path, "/");
	strcat(database_path, PINNING_DATABASE);
	free(plugin_path_cpy);
	plog(LOG_DEBUG, "CERT PINNING: Initialized, using database at %s", database_path);
	//////////////////////////////////////////////////
	
	return 0;
}

int query(query_data_t* data) {
	X509* cert;
	X509* matchingCert;
	STACK_OF(X509)* whitelist;
	EVP_MD* digest;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	unsigned int fingerprint_len;
	int i;
	unsigned char white_fingerprint[EVP_MAX_MD_SIZE];
	unsigned int white_fingerprint_len;

	int rval;
	unsigned char* hash;
	unsigned char* stored_hash;
	EVP_PKEY* pub_key;
	unsigned char* pkey_buf;
	sqlite3* database;
	sqlite3_stmt* statement;
	time_t ptime;
	time_t exptime;
	
	
	/* Only check the leaf certificate */
	cert = sk_X509_value(data->chain, 0);
	//print_certificate(cert);
	
	
	////////////////////////////////////////////////////////////////////////////////////////
	/* First, check for a match in the Whitelist */
	////////////////////////////////////////////////////////////////////////////////////////
	
	plog(LOG_DEBUG, "Whitelist querying");
		
	/* Get the fingerprint for the leaf cert */	
	digest = (EVP_MD*)EVP_sha1();
	fingerprint_len = sizeof(fingerprint);
	if (!get_cert_fingerprint(cert, digest, fingerprint, &fingerprint_len)) {
		return PLUGIN_RESPONSE_ERROR;
	}
	
	plog(LOG_DEBUG, "Got fingerprint of incoming cert");

	/* Get whitelist */
	whitelist = get_whitelist();
	if (!whitelist) {
		return PLUGIN_RESPONSE_ERROR;
	}
	
	// Right now this is going over every whitelisted cert, and taking a hash of them, then comparing
	// TODO: For quicker results, switch to storing only hashes of the whitelisted certificates
	plog(LOG_DEBUG, "Running through whitelist, size=%d", sk_X509_num(whitelist));
	for (i = 0; i < sk_X509_num(whitelist); i++) {
		matchingCert = sk_X509_value(whitelist, i);
		
		plog(LOG_DEBUG, "Verifying hostname...");
		if (verify_hostname(data->hostname, matchingCert) != 1) {
			plog(LOG_DEBUG, "Not a match");
			continue;
		}
		plog(LOG_DEBUG, "Hostname match found");
		
		white_fingerprint_len = sizeof(white_fingerprint);
		if (!get_cert_fingerprint(matchingCert, digest, white_fingerprint, &white_fingerprint_len)) {
			// Couldn't get a fingerprint
			plog(LOG_DEBUG, "Unable to get fingerprint for whitelist cert");
			sk_X509_pop_free(whitelist, X509_free);
			return PLUGIN_RESPONSE_ERROR;
		}
		if (compare_fingerprint(fingerprint, fingerprint_len, white_fingerprint, white_fingerprint_len)) {
			// We found a good certificate
			plog(LOG_DEBUG, "Cert fingerprint match found in whitelist");
			sk_X509_pop_free(whitelist, X509_free);
			return PLUGIN_RESPONSE_VALID;
		}
	}
		
	sk_X509_pop_free(whitelist, X509_free);
	//return PLUGIN_RESPONSE_INVALID;
	
	
	////////////////////////////////////////////////////////////////////////////////////////
	/* No match in whitelist, so go to Pinning */
	////////////////////////////////////////////////////////////////////////////////////////
	
	plog(LOG_DEBUG, "Not found in whitelist, defaulting to pinning");
	
	rval = PLUGIN_RESPONSE_VALID;
	
	// Get Certificate Public Key
	//cert = sk_X509_value(data->chain, 0);
	pub_key = X509_get_pubkey(cert);
	pkey_buf = NULL;
	i2d_PUBKEY(pub_key, &pkey_buf);

	// Hash it
	hash = (unsigned char*) malloc(SHA256_DIGEST_LENGTH + 1);
	hash[SHA256_DIGEST_LENGTH] = '\0';
	SHA256(pkey_buf, strlen((char*)pkey_buf), hash);
	OPENSSL_free(pkey_buf);

	// Check the Database
	database = NULL;
	statement = NULL;
	
	if (database_path == NULL) {
		return PLUGIN_RESPONSE_ERROR;
	}

	if (sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
		return PLUGIN_RESPONSE_ERROR;
	}
	
	// Build the table if it is not there
	if (sqlite3_prepare_v2(database, "CREATE TABLE IF NOT EXISTS pinned (hostname TEXT PRIMARY KEY, hash TEXT, exptime INTEGER)", -1, &statement, NULL) != SQLITE_OK) {
		plog(LOG_ERROR, "CERT PINNING: Could not create certificate table"); 
	}
	sqlite3_step(statement);
	sqlite3_finalize(statement);

	// Get the current time
	time(&ptime);
	// See if it is expired
	if (X509_cmp_time(X509_get_notAfter(cert), &ptime) < 0) {
		// This cert is expired, so just say no
		return PLUGIN_RESPONSE_INVALID;
	}
	// Get cert expire time as a time_t
	exptime = ASN1_GetTimeT(X509_get_notAfter(cert));
	
	/* There should be a table named 'pinned'
	 * CREATE TABLE pinned (hostname TEXT PRIMARY KEY, hash TEXT, exptime INTEGER);
	 */
	if (sqlite3_prepare_v2(database, "SELECT hash FROM pinned WHERE hostname=?1 AND exptime > ?2;", -1, &statement, NULL) != SQLITE_OK) {
		rval = PLUGIN_RESPONSE_ERROR;
	} else if (sqlite3_bind_text(statement, 1, (char*)data->hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
		rval = PLUGIN_RESPONSE_ERROR;
	} else if (sqlite3_bind_int64(statement, 2, (sqlite_uint64)ptime) != SQLITE_OK) {
		rval = PLUGIN_RESPONSE_ERROR;
	} else if (sqlite3_step(statement) == SQLITE_ROW) {
		plog(LOG_DEBUG, "Found a hit in pinning table");
		
		// There was a result, compare the stored hash with the new one
		stored_hash = (unsigned char*)sqlite3_column_blob(statement, 0);
		if (strcmp((char*)hash, (char*)stored_hash) != 0) {
			plog(LOG_DEBUG, "Pinned cert does not match");
			rval = PLUGIN_RESPONSE_INVALID;
		}
		plog(LOG_DEBUG, "Pinned cert matches");
	} else {
		plog(LOG_DEBUG, "Not found in pinning table. Now pinning new cert.");
		
		// There were no results, do an insert.
		sqlite3_finalize(statement);
		if (sqlite3_prepare_v2(database, "INSERT OR REPLACE INTO pinned VALUES(?1,?2,?3);", -1, &statement, NULL) != SQLITE_OK) {
			rval = PLUGIN_RESPONSE_ERROR;
		} else if (sqlite3_bind_text(statement, 1, (char*)data->hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
			rval = PLUGIN_RESPONSE_ERROR;
		} else if (sqlite3_bind_text(statement, 2, (char*)hash, -1, SQLITE_STATIC) != SQLITE_OK) {
			rval = PLUGIN_RESPONSE_ERROR;
		} else if (sqlite3_bind_int64(statement, 3, (sqlite_uint64)exptime) != SQLITE_OK) {
			rval = PLUGIN_RESPONSE_ERROR;
		} else if (sqlite3_step(statement) != SQLITE_DONE) {
			rval = PLUGIN_RESPONSE_ERROR;
		}
		
		if (rval == PLUGIN_RESPONSE_VALID) {
			plog(LOG_DEBUG, "Pinned cert successfully");
		}
	}

	sqlite3_finalize(statement);
	sqlite3_close(database);
	free(hash);
	return rval;
}

int finalize() {
	if (database_path != NULL) {
		free(database_path);
	}
	return 0;
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
			tblog(LOG_DEBUG, "Parsing a malformed certificate");
			continue;
		}

		if (cmp_names(hostname, cn) > 0) {
			result = 1;
		}
	}
	
	
	return result;
}

static time_t ASN1_GetTimeT(ASN1_TIME* time){
	struct tm t;
	const char* str = (const char*) time->data;
	size_t i = 0;

	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME) {/* two digit year */
		t.tm_year = (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		if (t.tm_year < 70) {
			t.tm_year += 100;
		}
	} else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year+= (str[i++] - '0') * 100;
		t.tm_year+= (str[i++] - '0') * 10;
		t.tm_year+= (str[i++] - '0');
		t.tm_year -= 1900;
	}
	t.tm_mon  = (str[i++] - '0') * 10;
	t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday+= (str[i++] - '0');
	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour+= (str[i++] - '0');
	t.tm_min  = (str[i++] - '0') * 10;
	t.tm_min += (str[i++] - '0');
	t.tm_sec  = (str[i++] - '0') * 10;
	t.tm_sec += (str[i++] - '0');

	/* Note: we did not adjust the time based on time zone information */
	return mktime(&t);
}
