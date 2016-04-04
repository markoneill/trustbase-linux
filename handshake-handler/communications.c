#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/semaphore.h>
#include "handshake_handler.h"
#include "communications.h"

int th_response(struct sk_buff* skb, struct genl_info* info);
int th_query(struct sk_buff* skb, struct genl_info* info);

static const struct nla_policy th_policy[TRUSTHUB_A_MAX + 1] = {
	[TRUSTHUB_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTHUB_A_HOSTNAME] = { .type = NLA_NUL_STRING },
	[TRUSTHUB_A_PORTNUMBER] = { .type = NLA_U16 },
	[TRUSTHUB_A_RESULT] = { .type = NLA_U32 },
	[TRUSTHUB_A_STATE_PTR] = { .type = NLA_U64 },
};

static struct genl_family th_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "TRUSTHUB",
	.version = 1,
	.maxattr = TRUSTHUB_A_MAX,
};

static struct genl_ops th_ops[] = {
	{
		.cmd = TRUSTHUB_C_QUERY,
		.flags = GENL_ADMIN_PERM,
		.policy= th_policy,
		.doit = th_query,
		.dumpit = NULL,
	},
	{
		.cmd = TRUSTHUB_C_RESPONSE,
		.flags = GENL_ADMIN_PERM,
		.policy = th_policy,
		.doit = th_response,
		.dumpit = NULL,
	},
};

static const struct genl_multicast_group th_grps[] = {
	[TRUSTHUB_QUERY] = { .name = "query", },
};

int th_query(struct sk_buff* skb, struct genl_info* info) {
	printk(KERN_ALERT "Kernel receieved a TrustHub query. This should never happen!");
	return -1;
}

int th_response(struct sk_buff* skb, struct genl_info* info) {
	struct nlattr* na;
	uint64_t statedata;
	handler_state_t* state;
	int result;
	if (info == NULL) {
		printk(KERN_ALERT "Message info is null");
		return -1;
	}
	if ((na = info->attrs[TRUSTHUB_A_STATE_PTR]) == NULL) {
		printk(KERN_ALERT "Can't find state pointer in response");
		return -1;
	}
	statedata = nla_get_u64(na);
	if ((na = info->attrs[TRUSTHUB_A_RESULT]) == NULL) {
		printk(KERN_ALERT "Can't find result in response");
		return -1;
	}
	result = nla_get_u32(na);
	state = (struct handler_state_t*)statedata;
	state->policy_response = result;
	//printk(KERN_ALERT "I received a state ptr value of %p", state);
	//printk(KERN_ALERT "sending a wakeup up");
	up(&state->sem);
	return 0;
}

int th_register_netlink() {
	int rc;
	rc = genl_register_family_with_ops_groups(&th_family, th_ops, th_grps);
	if (rc != 0) {
		return -1;
	}
	
	return 0;
}

void th_unregister_netlink() {
	genl_unregister_family(&th_family);
}

int th_send_certificate_query(handler_state_t* state, char* hostname, unsigned char* certificate, size_t length) {
	struct sk_buff* skb;
	int rc;
	void* msg_head;
	uint16_t port;
	skb = genlmsg_new(length, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_ALERT "failed in genlmsg");
		nlmsg_free(skb);
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &th_family, 0, TRUSTHUB_C_QUERY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "failed in genlmsg_put");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put_string(skb, TRUSTHUB_A_HOSTNAME, hostname);
	if (rc != 0) {
		printk(KERN_ALERT "failed in nla_put_string");
		nlmsg_free(skb);
		return -1;
	}
	if (state->is_ipv6) {
		port = ntohs((uint16_t)state->addr_v4.sin_port);
	}
	else {
		port = ntohs((uint16_t)state->addr_v6.sin6_port);
	}
	rc = nla_put(skb, TRUSTHUB_A_CERTCHAIN, length, certificate);
	/*printk(KERN_ALERT "-3rd char of chain is %02x", certificate[-3] & 0xff);
	printk(KERN_ALERT "-2nd char of chain is %02x", certificate[-2] & 0xff);
	printk(KERN_ALERT "-1st char of chain is %02x", certificate[-1] & 0xff);
	printk(KERN_ALERT "1st char of chain is %02x", certificate[0] & 0xff);
	printk(KERN_ALERT "2nd char of chain is %02x", certificate[1] & 0xff);
	printk(KERN_ALERT "3rd char of chain is %02x", certificate[2] & 0xff);*/
	if (rc != 0) {
		printk(KERN_ALERT "failed in nla_put (chain)");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put_u16(skb, TRUSTHUB_A_PORTNUMBER, port);
	if (rc != 0) {
		printk(KERN_ALERT "failed in nla_put (port number)");
		nlmsg_free(skb);
		return -1;
	}

	sema_init(&state->sem, 0);
	rc = nla_put_u64(skb, TRUSTHUB_A_STATE_PTR, (uint64_t)state);
	//printk(KERN_ALERT "Putting in pointer value %p", state);
	if (rc != 0) {
		printk(KERN_ALERT "failed in nla_put (sem)");
		nlmsg_free(skb);
		return -1;
	}

	genlmsg_end(skb, msg_head);
	// skbs are freed by genlmsg_multicast
	rc = genlmsg_multicast(&th_family, skb, 0, TRUSTHUB_QUERY, GFP_ATOMIC);
	if (rc != 0) {
		printk(KERN_ALERT "failed in genlmsg_multicast %d", rc);
		return -1;
	}

	// Pause execution and wait for a response
	//printk(KERN_ALERT "sleeping after send");
	down(&state->sem);
	//printk(KERN_ALERT "woken up!");
	return 0;
}

int th_send_shutdown() {
	struct sk_buff* skb;
	int rc;
	void* msg_head;
	
	skb = genlmsg_new(0, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_ALERT "failed in genlmsg");
		nlmsg_free(skb);
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &th_family, 0, TRUSTHUB_C_SHUTDOWN);
	if (msg_head == NULL) {
		printk(KERN_ALERT "failed in genlmsg_put");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	// skbs are freed by genlmsg_multicast
	rc = genlmsg_multicast(&th_family, skb, 0, TRUSTHUB_QUERY, GFP_ATOMIC);
	if (rc != 0) {
		printk(KERN_ALERT "failed in genlmsg_multicast %d", rc);
		return -1;
	}
	return 0;
}
