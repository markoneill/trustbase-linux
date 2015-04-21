#include <net/netlink.h>
#include <net/genetlink.h>
#include "communications.h"

int th_query(struct sk_buff* skb, struct genl_info* info);

struct netlink_kernel_cfg cfg = {
	.input = th_query,
};

static const struct nla_policy th_policy[TRUSTHUB_A_MAX + 1] = {
	[TRUSTHUB_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTHUB_A_HOSTNAME] = { .type = NLA_NUL_STRING },
	[TRUSTHUB_A_RESULT] = { .type = NLA_U32 },
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
		.doit = th_query,
		.dumpit = NULL,
	},
};

static const struct genl_multicast_group th_grps[] = {
	[TRUSTHUB_QUERY] = { .name = "query", },
};

int th_query(struct sk_buff* skb, struct genl_info* info) {
	printk(KERN_ALERT "is anything happening here?");
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

int th_send_certificate_query(char* certificate, size_t length) {
	struct nl_sock* nl_sk;
	//nl_sk = netlink_kernel_create(&init_net, NETLINK_GENERIC, &cfg);
	struct sk_buff* skb;
	int rc;
	void* msg_head;
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
	rc = nla_put_string(skb, TRUSTHUB_A_HOSTNAME, "hosthere");
	if (rc != 0) {
		printk(KERN_ALERT "failed in nla_put_string");
		nlmsg_free(skb);
		return -1;
	}
	rc = nla_put(skb, TRUSTHUB_A_CERTCHAIN, length, certificate);
	if (rc != 0) {
		printk(KERN_ALERT "failed in nla_put");
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

