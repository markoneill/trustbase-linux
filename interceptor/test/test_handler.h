#ifndef _TEST_HANDLER_H
#define _TEST_HANDLER_H

#include <linux/socket.h>
#include <net/sock.h>

void* state_init(pid_t pid, pid_t parent_pid, struct socket* sock, struct sockaddr *uaddr, int is_ipv6, int addr_len);
void state_free(void* buf_state);
int get_state(void* state);
int give_to_handler_send(void* state, void* src_buf, size_t length);
int give_to_handler_recv(void* state, void* src_buf, size_t length);
int update_state_send(void* state);
int update_state_recv(void* state);
int fill_send_buffer(void* state, void** bufptr, size_t* length);
int copy_to_user_buffer(void* state, void __user *dst_buf, size_t length);
int num_bytes_to_forward_send(void* state);
int num_bytes_to_forward_recv(void* state);
int update_bytes_forwarded_send(void* state, size_t forwarded);
int update_bytes_forwarded_recv(void* state, size_t forwarded);
int get_bytes_to_read_send(void* state);
int get_bytes_to_read_recv(void* state);

#endif
