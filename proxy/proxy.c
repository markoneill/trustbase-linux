/**
 * TLS proxy for use with TrustHub.
 *
 * Derived from https://github.com/libevent/libevent/blob/master/sample/le-proxy.c.
 *
 * Scott Ruoti <ruoti@isrl.byu.edu>
 * Mark O'Neill <mto@byu.edu>
 */

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "proxy.h"

static void free_socket_settings(struct socket_settings* settings);

static int load_signing_info();
static int create_private_key();
static X509 *create_certificate(const unsigned char *cert, size_t cert_len);
static SSL_CTX *create_server_ssl_ctx(const char *cert, size_t cert_len);

static void read_cb(struct bufferevent *bev, void *ctx);
static void drained_writecb(struct bufferevent *bev, void *ctx);

static void event_cb(struct bufferevent *event, short what, void *context);
static void close_on_finished_write_cb(struct bufferevent *bev, void * context);
static void close_event(struct bufferevent *event);

static void setup_buffer_pair(struct bufferevent *event_in, struct socket_settings *settings);
static void read_settings_cb(struct bufferevent *event, void *context);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t client_socket, struct sockaddr *address,
    int address_length, void *context);
/*
 * ********************************************************
 * Global variables
 * ********************************************************
 */

// The base event.
static struct event_base *base;

// The context that all outgoing connections use.
SSL_CTX *client_ssl_ctx = NULL;

// The private key for the local connections.
EVP_PKEY *private_key;

// The TrustHub signing key.
EVP_PKEY *trust_hub_signing_key;

// The TrustHub certificate associated with the signing key.
X509 *trust_hub_cert;

/*
 * ********************************************************
 * Functions to handle structs
 * ********************************************************
 */

/**
 * Free the socket settings object.
 */
void free_socket_settings(struct socket_settings* settings) {
	if (settings->address) {
		free((char *)settings->address);
	}
	if (settings->hostname) {
		free((char *)settings->hostname);
	}
	if (settings->cert) {
		free((char *)settings->cert);
	}
	free(settings);
	return;
}

/*
 * ********************************************************
 * Functions to setup SSL contexts.
 * ********************************************************
 */

/**
 * Load the signing certificate and key.
 */
int load_signing_info() {
	RSA* rsa;
	// Load the signing key.
	FILE *fp = fopen(TRUST_HUB_PKEY_FILE, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Failed to read file %s\n", TRUST_HUB_PKEY_FILE);
		return -1;
	}

	rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (rsa == NULL) {
		fprintf(stderr, "Bad private key file %s\n", TRUST_HUB_PKEY_FILE);
		return -1;
	}

	trust_hub_signing_key = EVP_PKEY_new();
	if (!EVP_PKEY_assign_RSA(trust_hub_signing_key, rsa)) {
		if (private_key != NULL) {
			EVP_PKEY_free(trust_hub_signing_key);
		}
		if (rsa != NULL) {
			RSA_free(rsa);
		}
		return -1;
	}

	// Load the signing cert.
	fp = fopen(TRUST_HUB_CERT_FILE, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Failed to read file %s\n", TRUST_HUB_PKEY_FILE);
		return -1;
	}

	trust_hub_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (trust_hub_cert == NULL) {
		fprintf(stderr, "Bad private key %s\n", TRUST_HUB_PKEY_FILE);
		if (private_key != NULL) {
			EVP_PKEY_free(trust_hub_signing_key);
		}
		return -1;
	}
	return 0;
}

/**
 * Create a new RSA private key.
 */
int create_private_key() {
	RSA* rsa;
	private_key = EVP_PKEY_new();
	rsa = RSA_generate_key(RSA_BITS, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(private_key, rsa)) {
		if (private_key != NULL) {
			EVP_PKEY_free(private_key);
		}
		if (rsa != NULL) {
			RSA_free(rsa);
		}
		return -1;
	}
	return 0;
}

/**
 * Create a certificate that is a clone of the first one, but signed by TrustHub.
 */
X509 *create_certificate(const unsigned char *cert, size_t cert_len) {
	X509 *certificate = d2i_X509(NULL, &cert, cert_len);
	if (certificate == NULL) {
		return NULL;
	}

	// Change the public key to use the generated key.
	X509_set_pubkey(certificate, private_key);

	// Sign the certificate using the TrustHub signing key.
	X509_set_issuer_name(certificate, X509_NAME_dup(X509_get_subject_name(trust_hub_cert)));
	if (!X509_sign(certificate, trust_hub_signing_key, EVP_sha256())) {
		X509_free(certificate);
		return NULL;
	}
	return certificate;
}

/**
 * Create a server SSL context.
 */
SSL_CTX *create_server_ssl_ctx(const char *cert, size_t cert_len) {
	X509 *certificate;
	SSL_CTX* ssl_ctx;

	certificate = create_certificate(cert, cert_len);
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ssl_ctx) {
		X509_free(certificate);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey(ssl_ctx, private_key) != 1) {
		X509_free(certificate);
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}

	if (SSL_CTX_use_certificate(ssl_ctx, certificate) != 1) {
		X509_free(certificate);
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}
	return ssl_ctx;
}

/*
 * ********************************************************
 * Functions to transfer data from one socket to the other
 * ********************************************************
 */

/**
 * Copy information from one buffer to the partner buffer.
 */
void read_cb(struct bufferevent *event, void *context) {
	struct bufferevent *partner;
	struct evbuffer *src, *dst;
	size_t len;

	partner = (struct bufferevent*)context;
	src = bufferevent_get_input(event);
	len = evbuffer_get_length(src);

	// If the partner has been closed then just dump the input.
	if (!partner) {
		evbuffer_drain(src, len);
		return;
	}

	// Pipe to the partner buffer.
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	// If we are writing too much data into the partner, then we wait until it can be
	// drained a little bit.
	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
		bufferevent_setcb(partner, read_cb, drained_writecb, event_cb, event);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
		bufferevent_disable(event, EV_READ);
	}
	return;
}

/**
 * Called when the write buffer has been drained enough to allow us to continue reading from
 * the partner.
 */
void drained_writecb(struct bufferevent *event, void *context) {
	struct bufferevent *partner;
	partner = (struct bufferevent*)context;

	bufferevent_setcb(event, read_cb, NULL, event_cb, partner);
	bufferevent_setwatermark(event, EV_WRITE, 0, 0);

	// If the partner has not been closed, re-enable reading from it.
	if (partner) {
		bufferevent_enable(partner, EV_READ);
	}
	return;
}

/*
 * ********************************************************
 * Functions to handle socket errors and closing
 * ********************************************************
 */

void event_cb(struct bufferevent *event, short what, void *context) {
	struct bufferevent *partner;
	const char* msg;
	const char* lib;
	const char* func;
	unsigned long err;
	partner = (struct bufferevent*) context;

	// Close the socket if it reaches the end of the stream or has an unrecoverable error.
	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		// Report on the error that is causing us to close..
		if (what & BEV_EVENT_ERROR) {
			while ((err = (bufferevent_get_openssl_error(event)))) {
        			msg = (const char*) ERR_reason_error_string(err);
				lib = (const char*) ERR_lib_error_string(err);
				func = (const char*) ERR_func_error_string(err);
				fprintf(stderr, "%s in %s %s\n", msg, lib, func);
			}
			if (errno) {
				perror("connection error");
			}
		}

		// If there is a partner, this event needs to finish writing to it before closing.
		if (partner) {
			// Transfer remaining data.
			read_cb(event, context);

			// If the partner still has content to write, schedule it to close when finished.
			if (evbuffer_get_length(bufferevent_get_output(partner))) {
				bufferevent_setcb(partner, NULL, close_on_finished_write_cb, event_cb, NULL);
				bufferevent_disable(partner, EV_READ);
			}
			else {
				close_event(partner);
			}
		}
		close_event(event);
	}
	return;
}

/**
 * Fired once the event is finished writing and can be closed.
 */
void close_on_finished_write_cb(struct bufferevent *event, void * context) {
	if (evbuffer_get_length(bufferevent_get_output(event)) == 0) {
		close_event(event);
	}
	return;
}

/**
 * Closes and frees the given event.
 */
void close_event(struct bufferevent *event) {
	SSL *ssl;
	SSL_CTX* ssl_ctx;

	ssl = bufferevent_openssl_get_ssl(event);
	ssl_ctx = SSL_get_SSL_CTX(ssl);

	// Shutdown the SSL session. This is apparently neccessary due to a limitation in libevent and openssl.
	SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
	SSL_shutdown(ssl);

	// The server client contexts need to be freed along with the connection that created them.
	if (ssl_ctx != client_ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
	}

	// Free the event.
	bufferevent_free(event);
	return;
}

/*
 * ********************************************************
 * Functions to setup new connections
 * ********************************************************
 */

void setup_buffer_pair(struct bufferevent *event_in, struct socket_settings *settings) {
	// Parse the settings.
	SSL_CTX* server_ssl_ctx;
	SSL* ssl_in;
	SSL* ssl_out;
	struct bufferevent* event_in_ssl;
	struct bufferevent* event_out;
	struct sockaddr_storage remote_address;
	int remote_address_len = sizeof(remote_address);
	memset(&remote_address, 0, sizeof(remote_address));
	if (evutil_parse_sockaddr_port(settings->address, (struct sockaddr*) &remote_address, &remote_address_len) < 0) {
		bufferevent_free(event_in);
		return;
	}

	// Wrap the local event in a SSL filter.
	server_ssl_ctx = create_server_ssl_ctx(settings->cert, settings->cert_len);
	ssl_in = SSL_new(server_ssl_ctx);
	event_in_ssl = bufferevent_openssl_filter_new(base, event_in, ssl_in, BUFFEREVENT_SSL_ACCEPTING, 		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!event_in_ssl) {
		perror("Bufferevent_openssl_new");
		bufferevent_free(event_in);
	}
	event_in = event_in_ssl;

	// Create the remote connection and associated event.
	ssl_out = SSL_new(client_ssl_ctx);
	#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		SSL_set_tlsext_host_name(ssl_out, settings->hostname);
	#endif

	event_out = bufferevent_openssl_socket_new(base, -1, ssl_out, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	if (bufferevent_socket_connect(event_out, (struct sockaddr*)&remote_address,
			remote_address_len) < 0) {
		perror("bufferevent_socket_connect");
		bufferevent_free(event_in);
		bufferevent_free(event_out);
		return;
	}

	// Update the event callbacks.
	bufferevent_setcb(event_in, read_cb, NULL, event_cb, event_out);
	bufferevent_setcb(event_out, read_cb, NULL, event_cb, event_in);

	bufferevent_enable(event_in, EV_READ | EV_WRITE);
	bufferevent_enable(event_out, EV_READ | EV_WRITE);
	return;
}

/**
 * Read the settings from the connection and then begin proxying it.
 */
void read_settings_cb(struct bufferevent *event_in, void *context) {
	struct socket_settings *settings;
	struct evbuffer* input;
	char *data;
	size_t len;

	settings = (struct socket_settings*)context;
	input = bufferevent_get_input(event_in);

	// Get the address to proxy.
	if (!settings->address) {
		data = evbuffer_readln(input, &len, EVBUFFER_EOL_ANY);
		if (!data) {
			return;
		}
		settings->address = data;
	}

	// Get the hostname to proxy.
	if (!settings->hostname) {
		data = evbuffer_readln(input, &len, EVBUFFER_EOL_ANY);
		if (!data) {
			return;
		}
		settings->hostname = data;
	}

	// Get the length of the cert to proxy.
	if (!settings->cert_len) {
		data = evbuffer_readln(input, &len, EVBUFFER_EOL_ANY);
		if (!data) {
			return;
		}
		settings->cert_len = atoi(data);
		free(data);
	}

	// At this point the certificate should not have been retrieved. This is just to make sure we aren't
	// in this method when we shouldn't be.
	if (settings->cert) {
		return;
	}

	// Ensure that the whole certificate has arrived.
	len = evbuffer_get_length(input);
	if (len < settings->cert_len) {
		return;
	}

	// Read the certificate.
	settings->cert = malloc(sizeof(char) * (settings->cert_len + 1));
	memset(settings->cert, '\0', sizeof(char) * (settings->cert_len + 1));
	evbuffer_copyout(input, settings->cert, settings->cert_len);
	evbuffer_drain(input, len);

	// Setup the buffer pair and then clean up.
	setup_buffer_pair(event_in, settings);
	free_socket_settings(settings);
	return;
}

/**
 * Setup the inbound connection handler and prepare to receive its initial settings.
 */
void accept_cb(struct evconnlistener *listener, evutil_socket_t client_socket, struct sockaddr *address, int address_length, void *context) {
	struct bufferevent *event_in;
	struct socket_settings* settings;

	event_in = bufferevent_socket_new(base, client_socket,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	settings = malloc(sizeof(struct socket_settings));
	memset(settings, 0, sizeof(struct socket_settings));

	bufferevent_setcb(event_in, read_settings_cb, NULL, event_cb, settings);
	bufferevent_enable(event_in, EV_READ | EV_WRITE);
	return;
}

/*
 * ********************************************************
 * Main method
 * ********************************************************
 */

/**
 * Starts the proxy on the given port.
 *
 * The proxy expects that it will get a single line of data on inbound connections. The format of this line is:
 * IP:PORT
 * HOSTNAME
 * CERT_LEN
 * CERT
 *
 * After that line has been set, this connection will act as a normal SSL connection.
 */
int main(int argc, char **argv) {
	// Initialize SSL.
	int r;
	struct sockaddr_in loopback;
	struct evconnlistener* listener;
	SSL_library_init(); 
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	r = RAND_poll();
	if (r == 0) {
		fprintf(stderr, "RAND_poll() failed.\n");
		return 1;
	}

	// Initializes the keys and certs.
	if (create_private_key() < 0) {
		fprintf(stderr, "create_private_key() failed.\n");
		return 1;
	}
	if (load_signing_info() < 0) {
		EVP_PKEY_free(private_key);
		fprintf(stderr, "load_signing_info() failed.\n");
		return 1;
	}

	// Initializes the client SSL context.
	client_ssl_ctx = SSL_CTX_new(SSLv23_client_method());

	// Create the event base.
	base = event_base_new();
	if (!base) {
		perror("event_base_new");
		SSL_CTX_free(client_ssl_ctx);
		return -1;
	}

	// Setup the listener to work on the loopback address.
	memset(&loopback, 0, sizeof(struct sockaddr_in));
	loopback.sin_family = AF_INET;
	loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	loopback.sin_port = htons(PORT);

	listener = evconnlistener_new_bind(base, accept_cb, NULL, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE,
		 -1, (struct sockaddr*) &loopback, sizeof(struct sockaddr_in));

	if (!listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		EVP_PKEY_free(private_key);
		SSL_CTX_free(client_ssl_ctx);
		return 1;
	}

	// Listen.
	event_base_dispatch(base);

	// Clean up the listener.
	evconnlistener_free(listener);
	event_base_free(base);

	EVP_PKEY_free(private_key);
	EVP_PKEY_free(trust_hub_signing_key);
	X509_free(trust_hub_cert);
	SSL_CTX_free(client_ssl_ctx);

	return 0;
}

