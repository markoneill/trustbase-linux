#ifndef _INTERCEPTOR_H
#define _INTERCEPTOR_H

#include "connection_state.h"

typedef struct proxy_handler_ops_t {
	void* (*send_state_init)(pid_t pid);
	void* (*recv_state_init)(pid_t pid);
	void (*send_state_free)(void* send_state);
	void (*recv_state_free)(void* recv_state);
	int (*send_to_proxy)(void* send_state, void* src_buf, size_t length);
	int (*update_send_state)(void* send_state);
	int (*update_recv_state)(void* recv_state);
	int (*fill_send_buffer)(void* send_state, void** bufptr, size_t* length);
	int (*num_send_bytes_to_forward)(void* send_state);
	int (*num_recv_bytes_to_forward)(void* recv_state);
	int (*inc_send_bytes_forwarded)(void* send_state, size_t forwarded);
	int (*inc_recv_bytes_forwarded)(void* recv_state, size_t forwarded);
	int (*bytes_to_read)(void* recv_state);
	int (*get_send_state)(void* send_state);
	int (*get_recv_state)(void* recv_state);
	int (*copy_to_user)(void* buf_state, void __user *dst_buf, size_t length);
} proxy_handler_ops_t;

int proxy_register(proxy_handler_ops_t* ops);
int proxy_unregister(void);

#endif
