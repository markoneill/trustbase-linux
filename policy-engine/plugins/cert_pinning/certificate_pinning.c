#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <sqlite3.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include "../../trusthub_plugin.h"
#include "../../th_logging.h"

#define PINNING_DATABASE "pinned_certs.db"

int initialize(init_data_t* idata);
int query(query_data_t* data);
int finalize(void);

char* database_path;

int (*plog)(thlog_level_t level, const char* format, ...);

static time_t ASN1_GetTimeT(ASN1_TIME* time);

int initialize(init_data_t* idata) {
	plog = idata->thlog;
	database_path = NULL;
	database_path = (char*)malloc(strlen(idata->plugin_path) + 2 + strlen(PINNING_DATABASE));
	if (database_path == NULL) {
		return -1;
	}

	strncpy(database_path, dirname(idata->plugin_path), strlen(idata->plugin_path));
	strcat(database_path, "/");
	strcat(database_path, PINNING_DATABASE);
	
	plog(LOG_DEBUG, "Trying to use database at %s", database_path);
	return 0;
}

int query(query_data_t* data) {
	int rval;
	unsigned char* hash;
	unsigned char* stored_hash;
	X509* cert;
	EVP_PKEY* pub_key;
	unsigned char* pkey_buf;
	sqlite3* database;
	sqlite3_stmt* statement;
	time_t ptime;
	time_t exptime;

	rval = PLUGIN_RESPONSE_VALID;
	
	// Get Certificate Public Key
	cert = sk_X509_value(data->chain, 0);
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
	} else if (sqlite3_bind_int64(statement, 2, (sqlite_uint64)exptime) != SQLITE_OK) {
		rval = PLUGIN_RESPONSE_ERROR;
	} else if (sqlite3_step(statement) == SQLITE_ROW) {
		// There was a result, compare the stored hash with the new one
		stored_hash = (unsigned char*)sqlite3_column_blob(statement, 0);
		if (strcmp((char*)hash, (char*)stored_hash) != 0) {
			rval = PLUGIN_RESPONSE_INVALID;
		}
	} else {
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
