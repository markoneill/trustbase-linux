#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "netlink.h"
#include "policy_engine.h"

static struct nla_policy th_policy[TRUSTHUB_A_MAX + 1] = {
        [TRUSTHUB_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTHUB_A_HOSTNAME] = { .type = NLA_STRING },
        [TRUSTHUB_A_RESULT] = { .type = NLA_U32 },
        [TRUSTHUB_A_STATE_PTR] = { .type = NLA_U64 },
};

int family;

int send_response(struct nl_sock* sock, uint64_t stptr, int result, unsigned char* ret_certs, int ret_length) {
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
	/*if (result == 0) { // Only send back new chain if we're going to claim invalidity
		rc = nla_put(msg, TRUSTHUB_A_CERTCHAIN, ret_length, ret_certs);
		if (rc != 0) {
			printf("failed to insert return chain\n");
			return -1;
		}
	}*/
	rc = nl_send_auto(sock, msg);
	if (rc < 0) {
		printf("failed in nl send with error code %d\n", rc);
		return -1;
	}
	return 0;	
}

int recv_query(struct nl_msg *msg, void *arg) {
	// Netlink Variables
	struct nlmsghdr* nlh;
	struct genlmsghdr* gnlh;
	struct nlattr* attrs[TRUSTHUB_A_MAX + 1];
	char* hostname;
	unsigned char* cert_chain;
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
				//OPENSSL_free(rcert);
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

int listen_for_queries(struct nl_sock* sock) {
	int group;
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
	return 0;
}

