#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "communications.h"

static struct nla_policy th_policy[TRUSTHUB_A_MAX + 1] = {
        [TRUSTHUB_A_MSG] = { .type = NLA_UNSPEC },
        [TRUSTHUB_A_RESULT] = { .type = NLA_U32 },
};

static int recv_query(struct nl_msg *msg, void *arg);

int recv_query(struct nl_msg *msg, void *arg) {
	struct nlmsghdr* nlh = nlmsg_hdr(msg);
	struct genlmsghdr* gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
	struct nlattr* attrs[TRUSTHUB_A_MAX + 1];
	int certLength;
	genlmsg_parse(nlh, 0, attrs, TRUSTHUB_A_MAX, th_policy);
	switch (gnlh->cmd) {
		case TRUSTHUB_C_QUERY:
			certLength = nla_len(attrs[TRUSTHUB_A_MSG]);
			printf("Got a certificate of %d bytes\n", certLength);
			break;
		default:
			printf("Got something unusual...\n");
			break;
	}
}

int main() {
	int family;
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


