/*
 * TLS proxy for use with TrustHub.
 *
 * Derived from https://github.com/libevent/libevent/blob/master/sample/le-proxy.c.
 *
 * Scott Ruoti <ruoti@isrl.byu.edu>
 */

#ifndef _PROXY_H
#define _PROXY_H

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// The port to run the server on.
#define PORT ((uint16_t)8888)

// Max amount of data we allow in an outgoing buffer.
#define MAX_OUTPUT (512*1024)

// Private key settings.
#define RSA_BITS (1024)
#define TRUST_HUB_PKEY_FILE ("/home/Phoenix_1/trusthub-linux/proxy/trusthub.key")
#define TRUST_HUB_CERT_FILE ("/home/Phoenix_1/trusthub-linux/proxy/trusthub.pem")

/**
 * Structure for the local connection's settings.
 */
struct socket_settings {
	const char* address;
	const char* hostname;
	unsigned char *cert;
	size_t cert_len;
};


#endif /* _PROXY_H */
