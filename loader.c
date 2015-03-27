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
	//printk(KERN_INFO "TCP close detected");
	if (th_conn_state_delete(current->pid, sock)) {
		print_call_info(sock, "TCP close");
	}
	ref_tcp_close(sk, timeout);
	return;
}

int new_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size) {
	struct socket* sock;
	int ret;
	//printk("sendmsg fs is: %p", oldfs);
	ret = ref_tcp_sendmsg(iocb, sk, msg, size);

        if (ret < 0) {
                return ret;
        }

	sock = sk->sk_socket;
	//printk(KERN_INFO "send returned: %s", (char*)msg->msg_iov->iov_base);
	th_parse_comm(current->pid, sock, (char*)msg->msg_iov->iov_base, ret, TH_SEND);
	//printk(KERN_INFO "TCP send detected");
	return ret;
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
		return ret;
	}

	// F UP ANYTHING YOU WANT.  IT'S YOURS.
	th_parse_comm(current->pid, sock, (char*)buffer, ret, TH_RECV);

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
	return;
}

