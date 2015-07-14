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

static int family;
struct nl_sock* netlink_sock;
pthread_mutex_t nl_sock_mutex;

int send_response(uint64_t stptr, int result) {
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
	pthread_mutex_lock(&nl_sock_mutex);
	rc = nl_send_auto(netlink_sock, msg);
	pthread_mutex_unlock(&nl_sock_mutex);
	if (rc < 0) {
		printf("failed in nl send with error code %d\n", rc);
		return -1;
	}
	return 0;	
}

int recv_query(struct nl_msg *msg, void *arg) {
	struct nlmsghdr* nlh;
	struct genlmsghdr* gnlh;
	struct nlattr* attrs[TRUSTHUB_A_MAX + 1];
	char* hostname;
	unsigned char* cert_chain;
	int chain_length;
	uint64_t stptr;

	// Get Message
	nlh = nlmsg_hdr(msg);
	gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
	genlmsg_parse(nlh, 0, attrs, TRUSTHUB_A_MAX, th_policy);
	switch (gnlh->cmd) {
		case TRUSTHUB_C_QUERY:
			/* Get message fields */
			chain_length = nla_len(attrs[TRUSTHUB_A_CERTCHAIN]);
			cert_chain = nla_data(attrs[TRUSTHUB_A_CERTCHAIN]);
			stptr = nla_get_u64(attrs[TRUSTHUB_A_STATE_PTR]);
			hostname = nla_get_string(attrs[TRUSTHUB_A_HOSTNAME]);

			/* Query registered schemes */
			poll_schemes(stptr, hostname, cert_chain, chain_length);
			// XXX I *think* the message is freed by whatever function calls this one
			// within libnl.  Verify this.
			break;
		default:
			printf("Got something unusual...\n");
			break;
	}
	return 0;
}

int listen_for_queries(void) {
	int group;
	netlink_sock = nl_socket_alloc();
	if (pthread_mutex_init(&nl_sock_mutex, NULL) != 0) {
		fprintf(stderr, "Failed to create mutex for netlink\n");
		return -1;
	}
	nl_socket_disable_seq_check(netlink_sock);
	nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, recv_query, (void*)netlink_sock);
	if (netlink_sock == NULL) {
		fprintf(stderr, "Failed to allocate socket\n");
		return -1;
	}
	/* Internally this calls socket() and bind() using Netlink
 	 (specifically Generic Netlink)
 	 */
	if (genl_connect(netlink_sock) != 0) {
		fprintf(stderr, "Failed to connect to Generic Netlink control\n");
		return -1;
	}
	
	if ((family = genl_ctrl_resolve(netlink_sock, "TRUSTHUB")) < 0) {
		fprintf(stderr, "Failed to resolve TRUSTHUB family identifier\n");
		return -1;
	}

	if ((group = genl_ctrl_resolve_grp(netlink_sock, "TRUSTHUB", "query")) < 0) {
		fprintf(stderr, "Failed to resolve group identifier\n");
		return -1;
	}

	if (nl_socket_add_membership(netlink_sock, group) < 0) {
		fprintf(stderr, "Failed to add membership to group\n");
		return -1;
	}
	
	while (1) {
		if (nl_recvmsgs_default(netlink_sock) < 0) {
			printf("Failing out of main loop\n");
			break;
		}
	}
	nl_socket_free(netlink_sock);
	return 0;
}

