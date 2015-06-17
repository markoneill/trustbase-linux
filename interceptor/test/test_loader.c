#include <linux/module.h>
#include <linux/kernel.h>

#include "../interceptor.h" // For registering/unregistering proxy functions
#include "test_handler.h"

// TrustHub interception operations
proxy_handler_ops_t test_ops;

static int __init loader_start(void);
static void __exit loader_end(void);

module_init(loader_start);
module_exit(loader_end);
MODULE_LICENSE("GPL");

int __init loader_start(void) {
	test_ops = (proxy_handler_ops_t) {
		.state_init = state_init,
		.state_free = state_free,
		.get_state = get_state,
		.give_to_handler_send = give_to_handler_send,
		.give_to_handler_recv = give_to_handler_recv,
		.update_send_state = update_state_send,
		.update_recv_state = update_state_recv,
		.fill_send_buffer = fill_send_buffer, // XXX rename this
		.copy_to_user = copy_to_user_buffer, // XXX rename this
		.num_send_bytes_to_forward = num_bytes_to_forward_send,
		.num_recv_bytes_to_forward = num_bytes_to_forward_recv,
		.inc_send_bytes_forwarded = update_bytes_forwarded_send,
		.inc_recv_bytes_forwarded = update_bytes_forwarded_recv,
		.bytes_to_read_send = get_bytes_to_read_send,
		.bytes_to_read_recv = get_bytes_to_read_recv,
	};

	proxy_register(&test_ops);

	return 0;
}

void __exit loader_end(void) {
	proxy_unregister();
	return;
}

