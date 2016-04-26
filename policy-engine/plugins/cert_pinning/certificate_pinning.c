#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <stdint.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include "../../plugin_response.h"

#define PINNING_DATABASE "policy-engine/plugins/cert_pinning/pinned_certs.db"

int query(const char* hostname, uint16_t port, STACK_OF(X509)* certs);

int query(const char* hostname, uint16_t port, STACK_OF(X509)* certs) {
	int rval;
	unsigned char* hash;
	unsigned char* stored_hash;
	X509* cert;
	EVP_PKEY* pub_key;
	unsigned char* pkey_buf;
	sqlite3* database;
	sqlite3_stmt* statement;

	rval = PLUGIN_RESPONSE_VALID;
	
	// Get Certificate Public Key
	cert = sk_X509_value(certs, 0);
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
	sqlite3_open(PINNING_DATABASE, &database);
	
	/* There should be a table named 'pinned'
	 * CREATE TABLE pinned (hostname TEXT PRIMARY KEY, hash TEXT);
	 */
	if (sqlite3_prepare_v2(database, "SELECT hash FROM pinned WHERE hostname=?1;", -1, &statement, NULL) != SQLITE_OK) {
		rval = PLUGIN_RESPONSE_ERROR;
	} else if (sqlite3_bind_text(statement, 1, (char*)hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
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
		if (sqlite3_prepare_v2(database, "INSERT INTO pinned VALUES(?1,?2);", -1, &statement, NULL) != SQLITE_OK) {
			rval = PLUGIN_RESPONSE_ERROR;
		} else if (sqlite3_bind_text(statement, 1, (char*)hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
			rval = PLUGIN_RESPONSE_ERROR;
		} else if (sqlite3_bind_text(statement, 2, (char*)hash, -1, SQLITE_STATIC) != SQLITE_OK) {
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
