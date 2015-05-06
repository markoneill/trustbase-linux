#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "../handshake-handler/communications.h"

#define MAX_LENGTH	1024
#define CERT_LENGTH_FIELD_SIZE	3

int chains_received;
int family;

static struct nla_policy th_policy[TRUSTHUB_A_MAX + 1] = {
        [TRUSTHUB_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTHUB_A_HOSTNAME] = { .type = NLA_STRING },
        [TRUSTHUB_A_RESULT] = { .type = NLA_U32 },
        [TRUSTHUB_A_STATE_PTR] = { .type = NLA_U64 },
};

static STACK_OF(X509)* parse_chain(unsigned char* data, size_t len);
static int poll_schemes(char* hostname, unsigned char* data, size_t len, unsigned char** rcerts, int* rcerts_len);
static int send_response(struct nl_sock* sock, uint64_t stptr, int result, char* rcerts, int rcerts_len);

typedef struct { unsigned char b[3]; } be24, le24;


static void hton24(int x, unsigned char* buf) {
	buf[0] = x >> 16 & 0xff;
	buf[1] = x >> 8 & 0xff;
	buf[2] = x & 0xff;
	return;
}

static int ntoh24(const unsigned char* data) {
	int ret = (data[0] << 16) | (data[1] << 8) | data[2];
	return ret;
}

static void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("subject: %s\n", subj);
	printf("issuer: %s\n", issuer);
}

int send_response(struct nl_sock* sock, uint64_t stptr, int result, char* ret_certs, int ret_length) {
	int rc;
	struct nl_msg* msg;
	void* msg_head;
	msg = nlmsg_alloc();
	if (msg == NULL) {
		printf("failed to allocate message buffer\n");
		return -1;
	}
	msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, TRUSTHUB_C_RESPONSE, 1);
	if (msg_head == NULL) {
		printf("failed in genlmsg_put\n");
		return -1;
	}
	rc = nla_put_u64(msg, TRUSTHUB_A_STATE_PTR, stptr);
	if (rc != 0) {
		printf("failed to insert state pointer\n");
		return -1;
	}
	rc = nla_put_u32(msg, TRUSTHUB_A_RESULT, result);
	if (rc != 0) {
		printf("failed to insert result\n");
		return -1;
	}
	if (result == 0) { // Only send back new chain if we're going to claim invalidity
		rc = nla_put(msg, TRUSTHUB_A_CERTCHAIN, ret_length, ret_certs);
		if (rc != 0) {
			printf("failed to insert return chain\n");
			return -1;
		}
	}
	rc = nl_send_auto(sock, msg);
	if (rc < 0) {
		printf("failed in nl send with error code %d\n", rc);
		return -1;
	}
	return 0;	
}

STACK_OF(X509)* parse_chain(unsigned char* data, size_t len) {
	unsigned char* start_pos;
	unsigned char* current_pos;
	const unsigned char* cert_ptr;
	X509* cert;
	int cert_len;
	start_pos = data;
	current_pos = data;
	STACK_OF(X509)* chain;

	chain = sk_X509_new_null();
	while ((current_pos - start_pos) < len) {
		cert_len = ntoh24(current_pos);
		current_pos += CERT_LENGTH_FIELD_SIZE;
		//printf("The next cert to parse is %d bytes\n", cert_len);
		cert_ptr = current_pos;
		cert = d2i_X509(NULL, &cert_ptr, cert_len);
		if (!cert) {
			fprintf(stderr,"unable to parse certificate\n");
		}
		print_certificate(cert);
		
		sk_X509_push(chain, cert);
		current_pos += cert_len;
	}
	return chain;
}

static void callback(int p, int n, void *arg) {
	return;
}

int poll_schemes(char* hostname, unsigned char* data, size_t len, unsigned char** rcerts, int* rcerts_len) {
	int pubkey_algonid;
	int result;
	int ret;
	unsigned char* p;
	X509* bad_cert;
	RSA* new_rsa;
	STACK_OF(X509)* chain;
	EVP_PKEY* pub_key;
	EVP_PKEY* new_pub_key;
	X509_NAME* name;

	int i;
	int ret_chain_len;
	int* cert_lens;
	unsigned char* ret_chain;
	ret_chain_len = 0;
	ret_chain = NULL;

	pub_key = NULL;
	new_pub_key = NULL;

	// Parse chain to X509 structures
	chain = parse_chain(data, len);
	if (sk_X509_num(chain) <= 0) {
		// XXX yeah...
	}
	
	// Validation
	//if (strcmp(hostname,"www.google.com") == 0) {
	if (strcmp(hostname, "login.live.com") == 0) {
		result = 0;

		bad_cert = sk_X509_value(chain, 0); // Get first cert
		/*pub_key = X509_get_pubkey(bad_cert);
		pubkey_algonid = OBJ_obj2nid(bad_cert->cert_info->key->algor->algorithm);
		if (pubkey_algonid == NID_rsaEncryption) {
			printf("rsa key detected\n");
		pub_key->pkey.rsa->n = BN_bin2bn("lolz!", 6, NULL);
		}
		else if (pubkey_algonid == NID_dsa) {
			printf("dsa key detected\n");
		pub_key->pkey.dsa->p = BN_bin2bn("lalala", 6, NULL);
		}
		else if (pubkey_algonid == NID_X9_62_id_ecPublicKey) {
			printf("ec key detected\n");
			//pub_key->pkey.ec->p = BN_bin2bn("lalala", 6, NULL);
		}
		else {
			printf("Oh noes! Unknown key type!\n");
		}
		name = X509_get_subject_name(bad_cert);
		//X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"US",        -1, -1, 0);
		//X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"TrustHub",     -1, -1, 0);
		//X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"TrustHub", -1, -1, 0);
		//X509_set_issuer_name(bad_cert, name);
		
		new_pub_key = EVP_PKEY_new();
		new_rsa = RSA_generate_key(2048, RSA_F4, callback, NULL);
		EVP_PKEY_assign_RSA(new_pub_key, new_rsa);
		ret = X509_set_pubkey(bad_cert, new_pub_key);
		//printf("ret is %d\n", ret);
		//ret = X509_set_pubkey(bad_cert, pub_key);
		bad_cert->cert_info->enc.modified = 1;
		X509_sign(bad_cert, new_pub_key, EVP_md5());
		EVP_PKEY_free(new_pub_key);
		*/

		// Calculate bytes needed to represent chain in TLS message
		cert_lens = (int*)malloc(sizeof(int) * sk_X509_num(chain));
		for (i = 0; i < sk_X509_num(chain); i++) {
			bad_cert = sk_X509_value(chain, i);
			cert_lens[i] = i2d_X509(bad_cert, NULL);
			ret_chain_len += cert_lens[i] + 3; // +3 for length field length
		}

		// Create substitute TLS certificate message
		ret_chain = OPENSSL_malloc(ret_chain_len);
		p = ret_chain;
		for (i = 0; i < sk_X509_num(chain); i++) {
			bad_cert = sk_X509_value(chain, i);
			hton24(cert_lens[i], p); // Assign length
			p += 3; // Skip past length field (24 bits)
			i2d_X509(bad_cert, &p); // Write certificate
		}
		*rcerts_len = ret_chain_len;
		*rcerts = ret_chain;
		free(cert_lens);
		printf("sending fail response\n");
	}
	else {
		result = 1;
		*rcerts = NULL;
		*rcerts_len = 0;
		printf("sending valid response\n");
	}
	sk_X509_pop_free(chain, X509_free);
	return result;
}

int recv_query(struct nl_msg *msg, void *arg) {
	// Netlink Variables
	struct nlmsghdr* nlh;
	struct genlmsghdr* gnlh;
	struct nlattr* attrs[TRUSTHUB_A_MAX + 1];
	char* hostname;
	char* cert_chain;
	int chain_length;
	uint64_t stptr;

	// Decision variables
	int result;
	int rcert_len;
	unsigned char* rcert;
	

	// Get Message
	nlh = nlmsg_hdr(msg);
	gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
	genlmsg_parse(nlh, 0, attrs, TRUSTHUB_A_MAX, th_policy);
	switch (gnlh->cmd) {
		case TRUSTHUB_C_QUERY:
			// Get message fields
			chain_length = nla_len(attrs[TRUSTHUB_A_CERTCHAIN]);
			cert_chain = nla_data(attrs[TRUSTHUB_A_CERTCHAIN]);
			stptr = nla_get_u64(attrs[TRUSTHUB_A_STATE_PTR]);
			hostname = nla_get_string(attrs[TRUSTHUB_A_HOSTNAME]);

			// Query registered schemes
			result = poll_schemes(hostname, cert_chain, chain_length, &rcert, &rcert_len);
			if (result == 0) { // Invalid
				send_response(arg, stptr, result, rcert, rcert_len);
				OPENSSL_free(rcert);
			}
			else { // Valid
				send_response(arg, stptr, result, NULL, 0);
			}
			//chains_received++;
			//printf("chains receieved: %d\n", chains_received);
			//printf("Got a certificate chain for %s of %d bytes\n", hostname, chain_length);
			//printf("Got state pointer value of %p\n",(void*)stptr);
			break;
		default:
			printf("Got something unusual...\n");
			break;
	}
	return 0;
}

int main() {
	int group;
	struct nl_sock* sock = nl_socket_alloc();

	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, recv_query, (void*)sock);
	if (sock == NULL) {
		fprintf(stderr, "Failed to allocate socket\n");
		return -1;
	}
	/* Internally this calls socket() and bind() using Netlink
 	 (specifically Generic Netlink)
 	 */
	if (genl_connect(sock) != 0) {
		fprintf(stderr, "Failed to connect to Generic Netlink control\n");
		return -1;
	}
	
	if ((family = genl_ctrl_resolve(sock, "TRUSTHUB")) < 0) {
		fprintf(stderr, "Failed to resolve TRUSTHUB family identifier\n");
		return -1;
	}

	if ((group = genl_ctrl_resolve_grp(sock, "TRUSTHUB", "query")) < 0) {
		fprintf(stderr, "Failed to resolve group identifier\n");
		return -1;
	}

	if (nl_socket_add_membership(sock, group) < 0) {
		fprintf(stderr, "Failed to add membership to group\n");
		return -1;
	}
	
	while (1) {
		if (nl_recvmsgs_default(sock) < 0) {
			printf("Failing out of main loop\n");
			break;
		}
	}

	nl_socket_free(sock);
	return 0;
}


