#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <assert.h>

void printCert(unsigned char* cert, size_t length);
int compareCerts(unsigned char* cert_a, size_t a_len, unsigned char* cert_b, size_t b_len);
static void callback(int p, int n, void *arg);

int main() {
	FILE* fp;
	FILE* fp2;
	X509 *cert;
	unsigned char* orig_cert;
	unsigned char* mod_cert;
	unsigned char* p;
	int ret;
	size_t mod_cert_length;
	size_t orig_cert_length;
	EVP_PKEY* new_pub_key;
	EVP_PKEY* orig_pub_key;
	RSA* new_rsa;
	int key_size;

	char cert_path[] = "userspace_tests/www.google.com.crt";
	char cert_path2[] = "userspace_tests/www.google.com.modded.crt";
	fp = fopen(cert_path, "r");
	if (!fp) {
		fprintf(stderr, "unable to open: %s\n", cert_path);
		return EXIT_FAILURE;
	}
	
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!cert) {
		fprintf(stderr, "unable to parse certificate in: %s\n", cert_path);
		fclose(fp);
		return EXIT_FAILURE;
	}
	
	orig_pub_key = X509_get_pubkey(cert);
	orig_cert_length = i2d_X509(cert, NULL);
	orig_cert = OPENSSL_malloc(orig_cert_length);
	p = orig_cert;
	i2d_X509(cert, &p);
	printCert(orig_cert, orig_cert_length);

	// Change the cert
	//key_size = orig_pub_key->key
	new_pub_key = EVP_PKEY_new();
	new_rsa = RSA_generate_key(2048, RSA_F4, callback, NULL);
	EVP_PKEY_assign_RSA(new_pub_key, new_rsa);
	ret = X509_set_pubkey(cert, new_pub_key);
	//X509_sign(cert, new_pub_key, EVP_md5());
	//cert->cert_info->key->public_key->length;
	//cert->cert_info->key->public_key->data[0] = 0xFF;
	cert->cert_info->enc.modified = 1;
	//printf("set_pubkey returned %d\n", ret);
	EVP_PKEY_free(new_pub_key);

	mod_cert_length = i2d_X509(cert, NULL);
	mod_cert = OPENSSL_malloc(mod_cert_length);
	p = mod_cert;
	i2d_X509(cert, &p);
	printCert(mod_cert, mod_cert_length);

	compareCerts(orig_cert, orig_cert_length, mod_cert, mod_cert_length);
	assert(mod_cert_length == orig_cert_length);

	// Save the modified one in PEM format
	fp2 = fopen(cert_path2, "w");
	if (!fp2) {
		fprintf(stderr, "unable to open: %s\n", cert_path2);
		return EXIT_FAILURE;
	}
	PEM_write_X509(fp2, cert);
	// Cleanup
	X509_free(cert);
	fclose(fp);
	fclose(fp2);
	OPENSSL_free(orig_cert);
	OPENSSL_free(mod_cert);
	return 0;
}


void callback(int p, int n, void *arg) {
	return;
}

void printCert(unsigned char* cert, size_t length) {
	int i;
	printf("---Start Certificate---\n");
	for (i = 0; i < length; i++) {
		printf("%02X", cert[i]);
	}
	printf("\n---End Certificate---\n");
	return;
}

int compareCerts(unsigned char* cert_a, size_t a_len, unsigned char* cert_b, size_t b_len) {
	int i;
	int max_length;
	if (a_len != b_len) {
		printf("Certificate sizes are different\n");
	}
	max_length = a_len > b_len ? b_len : a_len;
	for (i = 0; i < max_length; i++) {
		if (cert_a[i] != cert_b[i]) {
			printf("Certificates are different\n");
			return 1;
		}
	}
	printf("Certificates are the same\n");
	return 0;
}
