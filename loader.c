#include <linux/module.h>
#include <linux/kernel.h>

#include "interceptor/interceptor.h" // For registering/unregistering proxy functions
#include "handshake-handler/communications.h" // For registering/unregistering netlink family
#include "handshake-handler/handshake_handler.h" // For referencing proxy functions

// TrustHub interception operations
proxy_handler_ops_t trusthub_ops;

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

	trusthub_ops = (proxy_handler_ops_t) {
		.state_init = th_state_init,
		.state_free = th_state_free,
		.get_state = th_get_state,
		.give_to_handler_send = th_give_to_handler_send,
		.give_to_handler_recv = th_give_to_handler_recv,
		.update_send_state = th_update_state_send,
		.update_recv_state = th_update_state_recv,
		.fill_send_buffer = th_fill_send_buffer, // XXX rename this
		.copy_to_user = th_copy_to_user_buffer, // XXX rename this
		.num_send_bytes_to_forward = th_num_bytes_to_forward_send,
		.num_recv_bytes_to_forward = th_num_bytes_to_forward_recv,
		.inc_send_bytes_forwarded = th_update_bytes_forwarded_send,
		.inc_recv_bytes_forwarded = th_update_bytes_forwarded_recv,
		.bytes_to_read_send = th_get_bytes_to_read_send,
		.bytes_to_read_recv = th_get_bytes_to_read_recv,
	};

	proxy_register(&trusthub_ops);

	return 0;
}

void __exit loader_end(void) {
	proxy_unregister();
	// Unregister the IPC 
	th_unregister_netlink();
	return;
}

