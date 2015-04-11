#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/pid.h>
#include <linux/socket.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/tcp.h>

#include "connection_state.h"
#include "secure_handshake_parser.h"
#include "communications.h"
#include "utils.h"

// New approach
extern struct proto tcp_prot;
//extern struct proto tcpv6_prot;
struct proto * tcpv6_prot_ptr;

// TCP IPv4-specific reference functions
int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// TCP IPv4-specific wrapper functions
int new_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

// TCP IPv6-specific reference functions
int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// TCP IPv6-specific wrapper functions
int new_tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

// TCP General reference functions
int (*ref_tcp_disconnect)(struct sock *sk, int flags);
void (*ref_tcp_close)(struct sock *sk, long timeout);
int (*ref_tcp_sendmsg)(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size);
int (*ref_tcp_recvmsg)(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);
// TCP General wrapper functions
int new_tcp_disconnect(struct sock *sk, int flags);
void new_tcp_close(struct sock *sk, long timeout);
int new_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size);
int new_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);

// Wrapper definitions
int new_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	int ret;
	struct socket* sock;
	sock = sk->sk_socket;
	ret = ref_tcp_v4_connect(sk, uaddr, addr_len);
	//printk(KERN_INFO "TCP over IPv4 connection detected");
	th_conn_state_create(current->pid, sock);
	print_call_info(sock, "TCP IPv4 connect");
	return ret;
}

int new_tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	int ret;
	struct socket* sock;
	sock = sk->sk_socket;
	ret = ref_tcp_v6_connect(sk, uaddr, addr_len);
	//printk(KERN_INFO "TCP over IPv6 connection detected");
	th_conn_state_create(current->pid, sock);
	print_call_info(sock, "TCP IPv6 connect");
	return ret;
}

int new_tcp_disconnect(struct sock *sk, int flags) {
	int ret;
	ret = ref_tcp_disconnect(sk, flags);
	printk(KERN_INFO "TCP disconnect detected");
	return ret;
}

void new_tcp_close(struct sock *sk, long timeout) {
	struct socket* sock;
	sock = sk->sk_socket;
	if (th_conn_state_delete(current->pid, sock)) {
		print_call_info(sock, "TCP close");
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
	if ((conn_state = th_conn_state_get(current->pid, sock)) == NULL) {
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
	if (conn_state->send_state.last_ret > 0) {
		// 1) Copy data from user to our connection state buffer
		if (th_copy_to_state(&conn_state->send_state, new_data, size) != 0) {
			printk(KERN_ALERT "failed to copy data to connstate buffer");
			// XXX delete this connection, we can't handle it
			// Do we try to send existing buffer data?
			// Abort by calling original functionality
			return ref_tcp_sendmsg(iocb, sk, msg, size);
		}
		// 2) Update handler's state now that it has new data
		if (th_update_conn_state(conn_state, &conn_state->send_state) != 0) {
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
		// the contents of his buffer in between send attempts.
	}

	// 3) Have handler tell us what we should forward
	//    This will be the same as last time if an error occurred
	th_fill_send_buffer(&conn_state->send_state, &iov.iov_base, &iov.iov_len);

	// 4) Forward what handler told us to forward, if anything
	if (iov.iov_len <= 0) { //should never really be negative
		if (conn_state->send_state.bytes_to_forward == 0 && conn_state->send_state.state == IRRELEVANT) {
			print_call_info(sock, "No longer interested in socket, ceasing monitoring");
			th_conn_state_delete(current->pid, sock); // XXX this isn't thread safe 
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
	conn_state->send_state.last_ret = real_ret;
	if (real_ret > 0) {
		th_update_bytes_forwarded(&conn_state->send_state, real_ret);
	}
	if (real_ret != iov.iov_len) {
		printk(KERN_ALERT "Kernel couldn't send everything we wanted to");
		// XXX loop here to retry because this might be the last time we're ever called
		// return -EAGAIN if this is nonblocking, call send again otherwise
	}
	// If handler doesn't care about connection anymore then delete it
	if (conn_state->send_state.bytes_to_forward == 0 && conn_state->send_state.state == IRRELEVANT) {
		print_call_info(sock, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(current->pid, sock); // XXX this isn't thread safe 
        }
	// Just tell the user we sent everything he wanted
	// or an error code, if an error occurred
	return real_ret > 0 ? size : real_ret;

/*
	// Passthrough version	
	real_ret = ref_tcp_sendmsg(iocb, sk, msg, size);
	if (real_ret < 0) {
		return real_ret;
	}
	if ((conn_state = th_conn_state_get(current->pid, sock)) == NULL) {
		return real_ret;
	}
	th_parse_comm(current->pid, sock, (char*)msg->msg_iov->iov_base, real_ret, TH_SEND);
	if (conn_state->send_state.state == IRRELEVANT) {
		print_call_info(sock, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(current->pid, sock); // XXX this isn't thread safe 
	}
	return real_ret;
*/
}

int new_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len) {
	int ret;
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr kmsg;
	void* buffer;
	struct socket* sock;
	conn_state_t* conn_state;

	sock = sk->sk_socket;

	// Early breakout if we aren't monitoring this connection
	if ((conn_state = th_conn_state_get(current->pid, sock)) == NULL) {
		ret = ref_tcp_recvmsg(iocb, sk, msg, len, nonblock, flags, addr_len);
		return ret;
	}

	buffer = kmalloc(len, GFP_KERNEL);
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/*printk(KERN_INFO "Before:");
	printk(KERN_INFO "msg->msg_control: %p", msg->msg_control);
	printk(KERN_INFO "msg->controllen: %d", msg->msg_controllen);
	printk(KERN_INFO "msg->msg_iovlen: %d", msg->msg_iovlen);
	printk(KERN_INFO "msg->msg_iov: %p", msg->msg_iov);
	
	printk(KERN_INFO "msg->msg_iov->iov_len: %d", msg->msg_iov->iov_len);
	printk(KERN_INFO "msg->msg_iov->iov_base: %p", msg->msg_iov->iov_base);

	printk(KERN_INFO "msg->msg_name: %p", msg->msg_name);
	printk(KERN_INFO "msg->msg_namelen: %d", msg->msg_namelen);
	*/

	kmsg.msg_control = NULL;
	kmsg.msg_controllen = 0;
	kmsg.msg_iovlen = 1;
	kmsg.msg_iov = &iov;
	iov.iov_len = len;
	iov.iov_base = buffer;
	kmsg.msg_name = 0;
	kmsg.msg_namelen = 0;

	ret = ref_tcp_recvmsg(iocb, sk, &kmsg, len, nonblock, flags, addr_len);

	if (ret == -EIOCBQUEUED) {
		ret = wait_on_sync_kiocb(iocb);
	}

	set_fs(oldfs);
	if (ret < 0) {
		kfree(buffer);
		return ret;
	}

	// F UP ANYTHING YOU WANT.  IT'S YOURS.
	th_parse_comm(current->pid, sock, (char*)buffer, ret, TH_RECV);
	if (conn_state->recv_state.bytes_to_forward == 0 && conn_state->recv_state.state == IRRELEVANT) {
		print_call_info(sock, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(current->pid, sock); // XXX this isn't thread safe 
	}

	if (copy_to_user((void __user *)msg->msg_iov->iov_base, buffer, len) != 0) {
		printk(KERN_ALERT "yikes! couldn't copy all the data!");
	}
	//printk(KERN_INFO "After:");
	//printk(KERN_INFO "recv returned: %s", (char*)(buffer));
	kfree(buffer);

	/*printk(KERN_INFO "msg->msg_control: %p", kmsg.msg_control);
	printk(KERN_INFO "msg->controllen: %d", kmsg.msg_controllen);
	printk(KERN_INFO "msg->msg_iovlen: %d", kmsg.msg_iovlen);
	printk(KERN_INFO "msg->msg_iov: %p", kmsg.msg_iov);

	printk(KERN_INFO "msg->msg_iov->iov_len: %d", kmsg.msg_iov->iov_len);
	printk(KERN_INFO "msg->msg_iov->iov_base: %p", kmsg.msg_iov->iov_base);

	printk(KERN_INFO "msg->msg_name: %p", kmsg.msg_name);
	printk(KERN_INFO "msg->msg_namelen: %d", kmsg.msg_namelen);
	*/
	return ret;
}

static int __init interceptor_start(void);
static void __exit interceptor_end(void);

module_init(interceptor_start);
module_exit(interceptor_end);
MODULE_LICENSE("GPL");

int __init interceptor_start(void) {
	// Set up IPC module-policyengine interaction
	if (th_register_netlink() != 0) {
		printk(KERN_ALERT "unable to register netlink family and ops");
		return -1;
	}


	// Initialize buckets in hash table
	th_conn_state_init_all();

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

void __exit interceptor_end(void) {

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
	th_conn_state_free_all();
	// Unregister the IPC 
	th_unregister_netlink();
	return;
}

