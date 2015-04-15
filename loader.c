#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>

#include "loader.h"
#include "interceptor.h" // For decls and defs of refs and wrappers
#include "connection_state.h" // For inits and frees on load/unload (and currently op registration)
#include "communications.h" // For registering/unregistering netlink family
#include "utils.h" // For debug

extern struct proto tcp_prot;
extern conn_state_ops_t trusthub_ops;
extern conn_state_ops_t* h_ops;
struct proto * tcpv6_prot_ptr;

static int __init loader_start(void);
static void __exit loader_end(void);

module_init(loader_start);
module_exit(loader_end);
MODULE_LICENSE("GPL");

int __init loader_start(void) {
	// Set up IPC module-policyengine interaction
	if (th_register_netlink() != 0) {
		printk(KERN_ALERT "unable to register netlink family and ops");
		return -1;
	}

	// Set trusthub ops as default XXX can we make this more API-like?
	h_ops = &trusthub_ops;

	// Initialize buckets in hash table
	th_conn_state_init_all();

	// Save all references to original TCP functionality and override them with wrappers
	printk(KERN_INFO "address of tcp_prot is %p", &tcp_prot);
	ref_tcp_v4_connect = (void *)tcp_prot.connect;
	ref_tcp_disconnect = (void *)tcp_prot.disconnect;
	ref_tcp_close = (void *)tcp_prot.close;
	ref_tcp_sendmsg = (void *)tcp_prot.sendmsg;
	ref_tcp_recvmsg = (void *)tcp_prot.recvmsg;
	tcp_prot.connect = new_tcp_v4_connect;
	tcp_prot.disconnect = new_tcp_disconnect;
	tcp_prot.close = new_tcp_close;
	tcp_prot.sendmsg = new_tcp_sendmsg;
	tcp_prot.recvmsg = new_tcp_recvmsg;
	if ((tcpv6_prot_ptr = (void *)kallsyms_lookup_name("tcpv6_prot")) == 0) {
		printk(KERN_ALERT "tcpv6_prot lookup failed, not intercepting IPv6 traffic");
	}
	else {
		printk(KERN_INFO "tcpv6_prot lookup succeeded, address is %p", tcpv6_prot_ptr);
		ref_tcp_v6_connect = (void *)tcpv6_prot_ptr->connect;
		tcpv6_prot_ptr->connect = new_tcp_v6_connect;
		tcpv6_prot_ptr->disconnect = new_tcp_disconnect;
		tcpv6_prot_ptr->close = new_tcp_close;
		tcpv6_prot_ptr->sendmsg = new_tcp_sendmsg;
		tcpv6_prot_ptr->recvmsg = new_tcp_recvmsg;
	}
	return 0;
}

void __exit loader_end(void) {

	// Restore original TCP functions
	tcp_prot.connect = ref_tcp_v4_connect;
	tcp_prot.disconnect = ref_tcp_disconnect;
	tcp_prot.close = ref_tcp_close;
	tcp_prot.sendmsg = ref_tcp_sendmsg;
	tcp_prot.recvmsg = ref_tcp_recvmsg;
	if (tcpv6_prot_ptr != 0) {
		tcpv6_prot_ptr->connect = ref_tcp_v6_connect;
		tcpv6_prot_ptr->disconnect = ref_tcp_disconnect;
		tcpv6_prot_ptr->close = ref_tcp_close;
		tcpv6_prot_ptr->sendmsg = ref_tcp_sendmsg;
		tcpv6_prot_ptr->recvmsg = ref_tcp_recvmsg;
	}

	// Free up conn state memory
	th_conn_state_free_all();
	// Unregister the IPC 
	th_unregister_netlink();
	return;
}

