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

static int handle_certchain(const unsigned char* data, size_t len);
static int send_response(struct nl_sock* sock, uint64_t stptr, int result);

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

int send_response(struct nl_sock* sock, uint64_t stptr, int result) {
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
		printf("failed in nla_put_u64\n");
		return -1;
	}
	rc = nla_put_u32(msg, TRUSTHUB_A_RESULT, result);
	if (rc != 0) {
		printf("failed in nla_put_u32\n");
		return -1;
	}
	rc = nl_send_auto(sock, msg);
	if (rc < 0) {
		printf("failed in nl send with error code %d\n", rc);
		return -1;
	}
	return 0;	
}

int handle_certchain(const unsigned char* data, size_t len) {
	const unsigned char* start_pos;
	const unsigned char* current_pos;
	const unsigned char* cert_ptr;
	int length;
	start_pos = data;
	current_pos = data;
	X509* cert;
	STACK_OF(X509)* chain = sk_X509_new_null();
	while ((current_pos - start_pos) < len) {
		length = ntoh24(current_pos);
		current_pos += CERT_LENGTH_FIELD_SIZE;
		printf("The next cert to parse is %d bytes\n", length);
		cert_ptr = current_pos;
		cert = d2i_X509(NULL, &cert_ptr, length);
		if (!cert) {
			fprintf(stderr,"unable to parse certificate\n");
		}
		print_certificate(cert);
		sk_X509_push(chain, cert);
		current_pos += length;
	}
	sk_X509_pop_free(chain, X509_free);
	chains_received++;
	printf("chains receieved: %d\n", chains_received);
	return 0;
}

int recv_query(struct nl_msg *msg, void *arg) {
	struct nlmsghdr* nlh = nlmsg_hdr(msg);
	struct genlmsghdr* gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
	struct nlattr* attrs[TRUSTHUB_A_MAX + 1];
	char* hostname;
	int chain_length;
	uint64_t stptr;
	int result;
	genlmsg_parse(nlh, 0, attrs, TRUSTHUB_A_MAX, th_policy);
	switch (gnlh->cmd) {
		case TRUSTHUB_C_QUERY:
			chain_length = nla_len(attrs[TRUSTHUB_A_CERTCHAIN]);
			handle_certchain(nla_data(attrs[TRUSTHUB_A_CERTCHAIN]), chain_length);
			stptr = nla_get_u64(attrs[TRUSTHUB_A_STATE_PTR]);
			hostname = nla_get_string(attrs[TRUSTHUB_A_HOSTNAME]);
			//printf("Got state pointer value of %p\n",(void*)stptr);
			printf("Got a certificate chain for %s of %d bytes\n", hostname, chain_length);
			printf("sending response\n");
			if (strcmp(hostname,"www.youtube.com") == 0) {
				result = 0;
			}
			else {
				result = 1;
			}
			send_response(arg, stptr, result);
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


