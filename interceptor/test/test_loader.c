#include <linux/module.h>
#include <linux/kernel.h>

#include "../interceptor.h" // For registering/unregistering proxy functions

// TrustHub interception operations
proxy_handler_ops_t trusthub_ops;

static int __init loader_start(void);
static void __exit loader_end(void);

module_init(loader_start);
module_exit(loader_end);
MODULE_LICENSE("GPL");

int __init loader_start(void) {
	/*trusthub_ops = (proxy_handler_ops_t) {
		.send_state_init = th_buf_state_init,
		.recv_state_init = th_buf_state_init,
		.send_state_free = th_buf_state_free,
		.recv_state_free = th_buf_state_free,
		.send_to_proxy = th_send_to_proxy,
		.update_send_state = th_update_state,
		.update_recv_state = th_update_state,
		.fill_send_buffer = th_fill_send_buffer,
		.num_send_bytes_to_forward = th_num_bytes_to_forward,
		.num_recv_bytes_to_forward = th_num_bytes_to_forward,
		.inc_send_bytes_forwarded = th_update_bytes_forwarded,
		.inc_recv_bytes_forwarded = th_update_bytes_forwarded,
		.get_send_state = th_get_state,
		.get_recv_state = th_get_state,
		.copy_to_user = th_copy_to_user_buffer,
		.bytes_to_read = th_get_bytes_to_read,
	};*/

	proxy_register(&trusthub_ops);

	return 0;
}

void __exit loader_end(void) {
	proxy_unregister();
	return;
}

