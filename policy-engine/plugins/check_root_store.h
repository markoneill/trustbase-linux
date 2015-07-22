#ifndef CHECK_ROOT_STORE_H
#define CHECK_ROOT_STORE_H

#include <openssl/x509.h>

X509_STORE* make_new_root_store(void);

int query_store(const char* hostname, STACK_OF(X509)* certs, X509_STORE* root_store);

STACK_OF(X509)* pem_to_stack(char*);

#endif //CHECK_ROOT_STORE_H
