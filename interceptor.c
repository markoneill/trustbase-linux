#include <linux/kernel.h>
#include <linux/syscalls.h> // For kallsyms lookups
#include <linux/sched.h> // For current (pointer to task)
#include <linux/pid.h> // For pid_t
#include <linux/socket.h> // For socket structures
#include <linux/slab.h> // For memory allocation
#include <linux/tcp.h> // For TCP structures

#include "interceptor.h"
#include "connection_state.h" // For accessing handler functions

// TCP IPv6-specific reference functions
int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// TCP IPv4-specific wrapper functions
int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// TCP General reference functions
int (*ref_tcp_disconnect)(struct sock *sk, int flags);
void (*ref_tcp_close)(struct sock *sk, long timeout);
int (*ref_tcp_sendmsg)(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size);
int (*ref_tcp_recvmsg)(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);

// TCP IPv4-specific reference functions
int new_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// TCP IPv6-specific wrapper functions
int new_tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// TCP General wrapper functions
int new_tcp_disconnect(struct sock *sk, int flags);
void new_tcp_close(struct sock *sk, long timeout);
int new_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size);
int new_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);

// Helpers
static conn_state_t* start_conn_state(pid_t pid, struct socket* sock);
static int stop_conn_state(conn_state_t* conn_state);

// Global ops registration
static proxy_handler_ops_t* ops;

// OS Structures to hook into for interception
extern struct proto tcp_prot;
struct proto * tcpv6_prot_ptr;

int proxy_register(proxy_handler_ops_t* reg_ops) {
	// Initialize buckets in hash table
	conn_state_init_all();

	ops = reg_ops;

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

int proxy_unregister(void) {
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
	conn_state_delete_all();
	return 0;
}


conn_state_t* start_conn_state(pid_t pid, struct socket* sock) {
	conn_state_t* ret;
	ret = conn_state_create(pid, sock);
	if (ret != NULL) {
		ret->send_state = ops->send_state_init(ret->pid);
		ret->recv_state = ops->recv_state_init(ret->pid);
	}
	return ret;
}

int stop_conn_state(conn_state_t* conn_state) {
	ops->send_state_free(conn_state->send_state);
	ops->recv_state_free(conn_state->recv_state);
	return conn_state_delete(conn_state->pid, conn_state->sock);
}

// Wrapper definitions
int new_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	int ret;
	struct socket* sock;
	sock = sk->sk_socket;
	ret = ref_tcp_v4_connect(sk, uaddr, addr_len);
	//printk(KERN_INFO "TCP over IPv4 connection detected");
	//print_call_info(sock, "TCP IPv4 connect");
	start_conn_state(current->pid, sock);
	return ret;
}

int new_tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	int ret;
	struct socket* sock;
	sock = sk->sk_socket;
	ret = ref_tcp_v6_connect(sk, uaddr, addr_len);
	//printk(KERN_INFO "TCP over IPv6 connection detected");
	//print_call_info(sock, "TCP IPv6 connect");
	start_conn_state(current->pid, sock);
	return ret;
}

int new_tcp_disconnect(struct sock *sk, int flags) {
	int ret;
	ret = ref_tcp_disconnect(sk, flags);
	//printk(KERN_INFO "TCP disconnect detected");
	return ret;
}

void new_tcp_close(struct sock *sk, long timeout) {
	struct socket* sock;
	conn_state_t* conn_state;
	sock = sk->sk_socket;
	if ((conn_state = conn_state_get(current->pid, sock)) != NULL) {
		stop_conn_state(conn_state);
		//print_call_info(sock, "TCP close");
	}
	ref_tcp_close(sk, timeout);
	return;
}

int new_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size) {
	conn_state_t* conn_state;
	struct socket* sock;
	int real_ret;
	struct iovec iov;
	struct msghdr kmsg;
	void* new_data;
	mm_segment_t oldfs;
	sock = sk->sk_socket;

	// Adopt default kernel behavior if we're not monitoring this connection
	if ((conn_state = conn_state_get(current->pid, sock)) == NULL) {
		return ref_tcp_sendmsg(iocb, sk, msg, size);
	}

	// Copy attributes of existing message into our custom one
	kmsg = *msg;
	iov.iov_len = 0; // will be set later
	iov.iov_base = NULL; // will be set later
	kmsg.msg_iov = &iov;

	// Pointer to data being sent by user.
	new_data = msg->msg_iov->iov_base;

	// 0) If last send attempt was an error, don't copy or update state
	if (conn_state->queued_send_ret > 0) {
		// 1) Copy data from user to our connection state buffer
		if (ops->send_to_proxy(conn_state->send_state, new_data, size) != 0) {
			printk(KERN_ALERT "failed to copy data to handler");
			// XXX delete this connection, we can't handle it
			// Do we try to send existing buffer data?
			// Abort by calling original functionality
			return ref_tcp_sendmsg(iocb, sk, msg, size);
		}
		// 2) Update handler's state now that it has new data
		if (ops->update_send_state(conn_state->send_state) != 0) {
			printk(KERN_ALERT "failed to update state");
			// XXX delete this connection, we can't handle it
			// Do we try to send existing buffer data?
			// Abort by calling original functionality
			return ref_tcp_sendmsg(iocb, sk, msg, size);
		}
	}
	else {
		// This branch indicates that the last send operation resulted in an
		// error.
		//
		// By skipping the copy and update phases in this branch we
		// effectively assume that the data being sent after an error
		// is the same as the previous time.
		//
		// XXX We could set up something here to verify that the 
		// data sent by the client this time around is the same as last time
		// but I'm not sure we have to.  Only a dumb programmer would alter
		// the contents of his buffer in between send attempts. While I
		// acknowledge the existence of dumb programmers, it seems like they
		// would get what they deserve in this case.
	}

	// 3) Have handler tell us what we should forward
	//    This will be the same as last time if an error occurred
	ops->fill_send_buffer(conn_state->send_state, &iov.iov_base, &iov.iov_len);

	// 4) Forward what handler told us to forward, if anything
	if (iov.iov_len <= 0) { //should never really be negative
		if (ops->num_send_bytes_to_forward(conn_state->send_state) == 0 && ops->get_send_state(conn_state->send_state) == 0) {
			//print_call_info(sock, "No longer interested in socket, ceasing monitoring");
			stop_conn_state(conn_state); 
	        }
		// Tell the user we sent everything he wanted
		return size;
	}
	// Use real tcp_sendmsg call to transmit
	// but do it via the persona of the kernel
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	real_ret = ref_tcp_sendmsg(iocb, sk, &kmsg, iov.iov_len);
	set_fs(oldfs);
	// Record result
	conn_state->queued_send_ret = real_ret;
	if (real_ret > 0) {
		ops->inc_send_bytes_forwarded(conn_state->send_state, real_ret);
	}
	if (real_ret != iov.iov_len) {
		printk(KERN_ALERT "Kernel couldn't send everything we wanted to");
		if (msg->msg_flags & MSG_DONTWAIT) { // nonblocking IO
			// This forces a resend (dont need to delete here because we're
			// still interested in socket, clearly)
			conn_state->queued_send_ret = -EAGAIN;
			return -EAGAIN;
		}
		else { // blocking IO
			// loop here to retry because this might be the last time we're ever called
			while (ops->num_send_bytes_to_forward(conn_state->send_state) > 0) {
				// Ask handler to update our pointer and length again
				ops->fill_send_buffer(conn_state->send_state, &iov.iov_base, &iov.iov_len);
				// Attempt send again
				real_ret = ref_tcp_sendmsg(iocb, sk, &kmsg, iov.iov_len);
				// Record bytes sent
				ops->inc_send_bytes_forwarded(conn_state->send_state, real_ret);
			}
		}
	}
	// If handler doesn't care about connection anymore then delete it
	if (ops->num_send_bytes_to_forward(conn_state->send_state) == 0 && ops->get_send_state(conn_state->send_state) == 0) {
		//print_call_info(sock, "No longer interested in socket, ceasing monitoring");
		stop_conn_state(conn_state); 
        }
	// Just tell the user we sent everything he wanted
	// or an error code, if an error occurred
	return real_ret > 0 ? size : real_ret;
}

int new_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len) {
	int ret;
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr kmsg;
	void* buffer;
	struct socket* sock;
	conn_state_t* conn_state;
	int bytes_to_copy;
	int bytes_sent;
	int b_to_forward;
	int b_to_read;
	sock = sk->sk_socket;

 	// New way
	// Early breakout if we aren't monitoring this connection
	if ((conn_state = conn_state_get(current->pid, sock)) == NULL) {
		ret = ref_tcp_recvmsg(iocb, sk, msg, len, nonblock, flags, addr_len);
		return ret;
	}

	bytes_sent = 0;
	// 1) Place into user's buffer any data already marked for fowarding
	//    up to maxiumum user is requesting (len)
	b_to_forward = ops->num_recv_bytes_to_forward(conn_state->recv_state);
	if (b_to_forward > 0) {
		bytes_to_copy = b_to_forward > len ? len : b_to_forward;
		if (ops->copy_to_user(conn_state->recv_state, (void __user *)msg->msg_iov->iov_base, bytes_to_copy) != 0) {
			printk(KERN_ALERT "failed to copy what we wanted to");
			// XXX how do we fail here?
		}
		bytes_sent += bytes_to_copy;
		ops->inc_recv_bytes_forwarded(conn_state->recv_state, bytes_sent);
	}

	if (bytes_sent)
		printk(KERN_ALERT "I sent the user %d cached bytes", bytes_sent);
	// 2) If we've already given the user everything he wants, end
	if (bytes_sent == len) {
		return len;
	}

	// If we've not sent anything yet and the socket was closed last time
	// we actually read, then delete state and return
	if (bytes_sent == 0 && conn_state->queued_recv_ret == 0) {
		stop_conn_state(conn_state);
		return 0;
	}
	if (bytes_sent == 0 && conn_state->queued_recv_ret < 0) {
		ret = conn_state->queued_recv_ret;
		conn_state->queued_recv_ret = 1; // pretend no error for next time
		return ret;
	}


	// If we don't care to read any more bytes for this socket, stop now
	if (ops->bytes_to_read(conn_state->recv_state) == 0) {
		if (bytes_sent > 0) {
			return bytes_sent;
		}
		else {
			stop_conn_state(conn_state);
			return ref_tcp_recvmsg(iocb, sk, msg, len, nonblock, flags, addr_len);
		}
	}

	// At this point bytes_to_forward should be zero,
	// queued_recv_ret should be positive, and bytes_to_read
	// should be positive
	
	
	// 3) Attempt to get more data from external sources
	while (ops->num_recv_bytes_to_forward(conn_state->recv_state) == 0) {
		kmsg = *msg;
		kmsg.msg_iov = &iov;
		b_to_read = ops->bytes_to_read(conn_state->recv_state);
	        buffer = kmalloc(b_to_read, GFP_KERNEL);
		iov.iov_len = b_to_read;
		iov.iov_base = buffer;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = ref_tcp_recvmsg(iocb, sk, &kmsg, iov.iov_len, nonblock, flags, addr_len);
		//printk(KERN_ALERT "real ret is %d", ret);
		if (ret == -EIOCBQUEUED) {
			ret = wait_on_sync_kiocb(iocb);
		}
		set_fs(oldfs);
		
		// 4) if operation failed then just return what we've sent so far
		//    or the error code
		conn_state->queued_recv_ret = ret;
		if (ret <= 0) {
			if (bytes_sent > 0) {
				// error code is cached for next time
				return bytes_sent; 
			}
			else {
				// Pretend no error for next time since we're
				// sending it now
				conn_state->queued_recv_ret = 1;
				return ret;
			}
		}

		// 5) If operation succeeded then copy to state and update state
		if (ops->send_to_proxy(conn_state->recv_state, buffer, ret) != 0) {
			printk(KERN_ALERT "failed to copy to recv state");
			// XXX how do we fail here?
		}
		kfree(buffer);
		if (ops->update_recv_state(conn_state->recv_state) != 0) {
			printk(KERN_ALERT "failed to update recv state");
			// XXX how do we fail here?
		}

		// 6) If this was a nonblocking call and we still don't have any
		//    additional bytes to forward, break out early
		if (nonblock && ops->num_recv_bytes_to_forward(conn_state->recv_state) == 0) {
			//printk(KERN_ALERT "returning at nonb with %d", bytes_sent);
			return bytes_sent > 0 ? bytes_sent : -EAGAIN;
		}

		// 7) Otherwise if this was a blocking call keep trying until we have
		//    at least something to send back
	}

	// 8) copy to user what we received. return total number bytes sent
	b_to_forward = ops->num_recv_bytes_to_forward(conn_state->recv_state);
	bytes_to_copy = b_to_forward > len - bytes_sent ? len - bytes_sent : b_to_forward;
	if (ops->copy_to_user(conn_state->recv_state, (void __user *)msg->msg_iov->iov_base + bytes_sent, bytes_to_copy) != 0) {
		printk(KERN_ALERT "failed to copy what we wanted to");
		// XXX how do we fail here?
	}
	ops->inc_recv_bytes_forwarded(conn_state->recv_state, bytes_to_copy);
	bytes_sent += bytes_to_copy;
	//printk(KERN_ALERT "returning at end with %d", bytes_sent);
	return bytes_sent;

}

