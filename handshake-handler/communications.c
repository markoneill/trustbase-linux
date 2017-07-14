#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/semaphore.h>
#include <linux/version.h>

#include "handshake_handler.h"
#include "../util/ktb_logging.h" // For logging
#include "communications.h"


#define IPV4_STR_LEN			15
#define IPV6_STR_LEN			39
int tb_response(struct sk_buff* skb, struct genl_info* info);
int tb_query(struct sk_buff* skb, struct genl_info* info);

static const struct nla_policy tb_policy[TRUSTBASE_A_MAX + 1] = {
	[TRUSTBASE_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTBASE_A_CLIENT_HELLO] = { .type = NLA_UNSPEC },
	[TRUSTBASE_A_SERVER_HELLO] = { .type = NLA_UNSPEC },
	[TRUSTBASE_A_IP] = { .type = NLA_NUL_STRING },
	[TRUSTBASE_A_PORTNUMBER] = { .type = NLA_U16 },
	[TRUSTBASE_A_RESULT] = { .type = NLA_U32 },
	[TRUSTBASE_A_STATE_PTR] = { .type = NLA_U64 },
};

static struct genl_ops tb_ops[] = {
	{
		.cmd = TRUSTBASE_C_QUERY,
		.flags = GENL_ADMIN_PERM,
		.policy= tb_policy,
		.doit = tb_query,
		.dumpit = NULL,
	},
	{
		.cmd = TRUSTBASE_C_RESPONSE,
		.flags = 0,
		.policy = tb_policy,
		.doit = tb_response,
		.dumpit = NULL,
	},
	{
		.cmd = TRUSTBASE_C_QUERY_NATIVE,
		.flags = 0,
		.policy = tb_policy,
		.doit = tb_query,
		.dumpit = NULL,
	},
};

static const struct genl_multicast_group tb_grps[] = {
	[TRUSTBASE_QUERY] = { .name = "query", },
};

static struct genl_family tb_family = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	.module = THIS_MODULE,
	.ops = tb_ops,
	.n_ops = ARRAY_SIZE(tb_ops),
	.mcgrps = tb_grps,
	.n_mcgrps = ARRAY_SIZE(tb_grps),
#else
	.id = GENL_ID_GENERATE,
#endif
	.hdrsize = 0,
	.name = "TRUSTBASE",
	.version = 1,
	.maxattr = TRUSTBASE_A_MAX,
};

int tb_query(struct sk_buff* skb, struct genl_info* info) {
	ktblog(LOG_WARNING, "Kernel receieved a Trustbase query. This should never happen!");
	return -1;
}

int tb_response(struct sk_buff* skb, struct genl_info* info) {
	struct nlattr* na;
	uint64_t statedata;
	handler_state_t* state;
	int result;
	if (info == NULL) {
		ktblog(LOG_ERROR, "Message info is null");
		return -1;
	}
	if ((na = info->attrs[TRUSTBASE_A_STATE_PTR]) == NULL) {
		ktblog(LOG_ERROR, "Can't find state pointer in response");
		return -1;
	}
	statedata = nla_get_u64(na);
	if ((na = info->attrs[TRUSTBASE_A_RESULT]) == NULL) {
		ktblog(LOG_ERROR, "Can't find result in response");
		return -1;
	}
	result = nla_get_u32(na);
	state = (struct handler_state_t*)statedata;
	state->policy_response = result;
	up(&state->sem);
	return 0;
}

int tb_register_netlink() {
	int rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	rc = genl_register_family(&tb_family);
#else
	rc = genl_register_family_with_ops_groups(&tb_family, tb_ops, tb_grps);
#endif
	if (rc != 0) {
		return -1;
	}
	
	return 0;
}

void tb_unregister_netlink() {
	genl_unregister_family(&tb_family);
}

int tb_send_certificate_query(handler_state_t* state, unsigned char* certificate, size_t length) {
	struct sk_buff* skb;
	int rc;
	void* msg_head;
	uint16_t port;
	skb = genlmsg_new(length+strlen(state->ip)+state->client_hello_len+state->server_hello_len+250, GFP_ATOMIC); // size is port + client_hello + ip + chain + state pointer
	//ktblog(LOG_DEBUG, "Trying to send a cert query");
	if (skb == NULL) {
		ktblog(LOG_ERROR, "failed in genlmsg for sending the query");
		nlmsg_free(skb);
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &tb_family, 0, TRUSTBASE_C_QUERY);
	if (msg_head == NULL) {
		ktblog(LOG_ERROR, "failed in genlmsg_put");
		nlmsg_free(skb);
		return -1;
	}
	ktblog(LOG_DEBUG, "Trying to send client hello of length %d", state->client_hello_len);
	rc = nla_put(skb, TRUSTBASE_A_CLIENT_HELLO, state->client_hello_len, state->client_hello);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put for Client Hello");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put(skb, TRUSTBASE_A_SERVER_HELLO, state->server_hello_len, state->server_hello);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put for Server Hello");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put_string(skb, TRUSTBASE_A_IP, state->ip);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put_string");
		nlmsg_free(skb);
		return -1;
	}
	if (state->is_ipv6) {
		port = ntohs((uint16_t)state->addr_v4.sin_port);
	} else {
		port = ntohs((uint16_t)state->addr_v6.sin6_port);
	}
	rc = nla_put(skb, TRUSTBASE_A_CERTCHAIN, length, certificate);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put (chain)");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put_u16(skb, TRUSTBASE_A_PORTNUMBER, port);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put (port number)");
		nlmsg_free(skb);
		return -1;
	}

	sema_init(&state->sem, 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	rc = nla_put_u64_64bit(skb, TRUSTBASE_A_STATE_PTR, (uint64_t)state, TRUSTBASE_A_PAD);
#else
	rc = nla_put_u64(skb, TRUSTBASE_A_STATE_PTR, (uint64_t)state);
#endif
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put (sem)");
		nlmsg_free(skb);
		return -1;
	}

	genlmsg_end(skb, msg_head);
	// skbs are freed by genlmsg_multicast
	rc = genlmsg_multicast(&tb_family, skb, 0, TRUSTBASE_QUERY, GFP_ATOMIC);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in genlmsg_multicast %d", rc);
		return -1;
	}

	// Pause execution and wait for a response
	down(&state->sem);
	return 0;
}

int tb_send_shutdown() {
	struct sk_buff* skb;
	int rc;
	void* msg_head;
	
	skb = genlmsg_new(0, GFP_ATOMIC);
	if (skb == NULL) {
		ktblog(LOG_ERROR, "failed in genlmsg for sending shutdown");
		nlmsg_free(skb);
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &tb_family, 0, TRUSTBASE_C_SHUTDOWN);
	if (msg_head == NULL) {
		ktblog(LOG_ERROR, "failed in genlmsg_put");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	// skbs are freed by genlmsg_multicast
	rc = genlmsg_multicast(&tb_family, skb, 0, TRUSTBASE_QUERY, GFP_ATOMIC);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in genlmsg_multicast %d", rc);
		return -1;
	}
	return 0;
}

int tb_send_is_starttls_query(struct handler_state_t* state) {
	struct sk_buff* skb;
	int rc;
	void* msg_head;
	uint16_t port;

	skb = genlmsg_new(strlen(state->ip) + 250, GFP_ATOMIC);
	ktblog(LOG_DEBUG, "Trying to send a shouldtls query for %s", state->ip);
	if (skb == NULL) {
		ktblog(LOG_ERROR, "failed in genlmsg for starttls");
		nlmsg_free(skb);
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &tb_family, 0, TRUSTBASE_C_SHOULDTLS);
	if (msg_head == NULL) {
		ktblog(LOG_ERROR, "failed in genlmsg_put");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put_string(skb, TRUSTBASE_A_IP, state->ip);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put_string (ip)");
		nlmsg_free(skb);
		return -1;
	}
	if (state->is_ipv6) {
		port = ntohs((uint16_t)state->addr_v4.sin_port);
	}
	else {
		port = ntohs((uint16_t)state->addr_v6.sin6_port);
	}
	rc = nla_put_u16(skb, TRUSTBASE_A_PORTNUMBER, port);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put (port number)");
		nlmsg_free(skb);
		return -1;
	}
	sema_init(&state->sem, 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	rc = nla_put_u64_64bit(skb, TRUSTBASE_A_STATE_PTR, (uint64_t)state, TRUSTBASE_A_PAD);
#else
	rc = nla_put_u64(skb, TRUSTBASE_A_STATE_PTR, (uint64_t)state);
#endif
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in nla_put (sem)");
		nlmsg_free(skb);
		return -1;
	}

	genlmsg_end(skb, msg_head);
	// skbs are freed by genlmsg_multicast
	rc = genlmsg_multicast(&tb_family, skb, 0, TRUSTBASE_QUERY, GFP_ATOMIC);
	if (rc != 0) {
		ktblog(LOG_ERROR, "failed in genlmsg_multicast %d", rc);
		return -1;
	}

	// Pause execution and wait for a response
	down(&state->sem);
	return 0;
}
