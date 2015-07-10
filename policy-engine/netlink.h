#ifndef POLICY_ENGINE_NETLINK_H
#define POLICY_ENGINE_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "../handshake-handler/communications.h"


int send_response(struct nl_sock* sock, uint64_t stptr, int result, unsigned char* rcerts, int rcerts_len);
int recv_query(struct nl_msg *msg, void *arg);
int listen_for_queries(struct nl_sock* sock);
#endif
