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
		.send_state_init = state_init,
		.recv_state_init = state_init,
		.send_state_free = state_free,
		.recv_state_free = state_free,
		.send_to_proxy = copy_to_handler,
		.update_send_state = update_state,
		.update_recv_state = update_state,
		.fill_send_buffer = copy_to_send_buffer,
		.copy_to_user = copy_to_user_buffer,
		.num_send_bytes_to_forward = num_bytes_to_forward,
		.num_recv_bytes_to_forward = num_bytes_to_forward,
		.inc_send_bytes_forwarded = update_bytes_forwarded,
		.inc_recv_bytes_forwarded = update_bytes_forwarded,
		.get_send_state = get_state,
		.get_recv_state = get_state,
		.bytes_to_read = get_bytes_to_read,
	};

	proxy_register(&test_ops);

	return 0;
}

void __exit loader_end(void) {
	proxy_unregister();
	return;
}

