#ifndef POLICY_ENGINE_NETLINK_H
#define POLICY_ENGINE_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "../handshake-handler/communications.h"

int send_response(uint32_t spid, uint64_t stptr, int result);
int recv_query(struct nl_msg *msg, void *arg);
int listen_for_queries(void);
#endif
