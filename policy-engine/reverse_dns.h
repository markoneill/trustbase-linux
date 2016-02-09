#ifndef REVERSE_DNS_H
#define REVERSE_DNS_H

#include <openssl/x509.h>
#include <stdint.h>

#define LOOKUP_ERR	(-1)
#define LOOKUP_FAIL	1
#define LOOKUP_VALID	0

int is_ip(const char* hostname);
int reverse_lookup(const char* hostname, uint16_t port, X509* cert, char** found_hostname);

#endif //REVERSE_DNS_H
