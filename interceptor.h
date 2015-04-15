#ifndef _INTERCEPTOR_H
#define _INTERCEPTOR_H

#include <linux/socket.h>
#include "connection_state.h"

// TCP IPv4-specific reference functions
int new_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

// TCP IPv6-specific wrapper functions
int new_tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

// TCP General wrapper functions
int new_tcp_disconnect(struct sock *sk, int flags);
void new_tcp_close(struct sock *sk, long timeout);
int new_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size);
int new_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);

#endif
