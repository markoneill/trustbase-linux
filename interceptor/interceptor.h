#ifndef _INTERCEPTOR_H
#define _INTERCEPTOR_H

#include <linux/socket.h>
#include <net/sock.h>

typedef struct proxy_handler_ops_t {
	void* (*state_init)(pid_t pid, struct socket* sock, struct sockaddr *uaddr, int is_ipv6, int addr_len);
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
	// the following two functions may be placed elsewhere later
	int (*is_asynchronous)(void* state);
	struct socket* (*get_async_sk)(void* state);
} proxy_handler_ops_t;

int proxy_register(proxy_handler_ops_t* ops);
int proxy_unregister(void);

// These are exposed so we can make a passthrough if a handler wants to make its own
// (hidden) connection
extern int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern void (*ref_tcp_close)(struct sock *sk, long timeout);
extern int (*ref_tcp_disconnect)(struct sock *sk, int flags);
#endif

