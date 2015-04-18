#ifndef _INTERCEPTOR_H
#define _INTERCEPTOR_H

typedef struct proxy_handler_ops_t {
	void* (*state_init)(pid_t pid);
	void (*state_free)(void* state);
	int (*get_state)(void* state);
	int (*give_to_handler_send)(void* state, void* src_buf, size_t length);
	int (*give_to_handler_recv)(void* state, void* src_buf, size_t length);
	int (*update_send_state)(void* state);
	int (*update_recv_state)(void* state);
	int (*fill_send_buffer)(void* state, void** bufptr, size_t* length);
	int (*copy_to_user)(void* state, void __user *dst_buf, size_t length);
	int (*num_send_bytes_to_forward)(void* state);
	int (*num_recv_bytes_to_forward)(void* state);
	int (*inc_send_bytes_forwarded)(void* state, size_t forwarded);
	int (*inc_recv_bytes_forwarded)(void* state, size_t forwarded);
	int (*bytes_to_read_send)(void* state);
	int (*bytes_to_read_recv)(void* state);
} proxy_handler_ops_t;

int proxy_register(proxy_handler_ops_t* ops);
int proxy_unregister(void);

#endif
