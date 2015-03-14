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

#include "connection_state.h"
#include "secure_handshake_parser.h"
#include "utils.h"

// Forward delcarations
//struct user_msghdr;

// Needed for system call override
static unsigned long **sys_call_table;
static unsigned long original_cr0;

// Storage for original system calls
asmlinkage long (*ref_sys_socketcall)(int call, unsigned long *args);
asmlinkage long (*ref_sys_write)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*ref_sys_close)(unsigned int fd);
asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*ref_sys_recv)(int sockfd, void __user * buf, size_t len, unsigned flags);
asmlinkage long (*ref_sys_recvfrom)(int sockfd, void __user * buf, size_t len, unsigned flags, struct sockaddr __user * src_addr, int __user * addrlen);
asmlinkage long (*ref_sys_recvmsg)(int sockfd, struct msghdr __user *msg, unsigned flags);
asmlinkage long (*ref_sys_recvmmsg)(int sockfd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout);
asmlinkage long (*ref_sys_send)(int sockfd, void __user * buf, size_t len, unsigned flags);
asmlinkage long (*ref_sys_sendto)(int sockfd, void __user * buf, size_t len, unsigned flags, struct sockaddr __user * dest_addr, int addrlen);
asmlinkage long (*ref_sys_sendmsg)(int sockfd, struct msghdr __user *msg, unsigned flags);
asmlinkage long (*ref_sys_sendmmsg)(int sockfd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
asmlinkage long (*ref_sys_socket)(int family, int type, int protocol);

// Replacement system calls
asmlinkage long new_sys_socketcall(int call, unsigned long *args);
asmlinkage long new_sys_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long new_sys_close(unsigned int fd);
asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long new_sys_recv(int sockfd, void __user * buf, size_t len, unsigned flags);
asmlinkage long new_sys_recvfrom(int sockfd, void __user * buf, size_t len, unsigned flags, struct sockaddr __user * src_addr, int __user * addrlen);
asmlinkage long new_sys_recvmsg(int sockfd, struct msghdr __user *msg, unsigned flags);
asmlinkage long new_sys_recvmmsg(int sockfd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout);
asmlinkage long new_sys_send(int sockfd, void __user * buf, size_t len, unsigned flags);
asmlinkage long new_sys_sendto(int sockfd, void __user * buf, size_t len, unsigned flags, struct sockaddr __user * dest_addr, int addrlen);
asmlinkage long new_sys_sendmsg(int sockfd, struct msghdr __user *msg, unsigned flags);
asmlinkage long new_sys_sendmmsg(int sockfd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
asmlinkage long new_sys_socket(int family, int type, int protocol);

// Helpers
static unsigned long **aquire_sys_call_table(void);
static int __init interceptor_start(void);
static void __exit interceptor_end(void);

module_init(interceptor_start);
module_exit(interceptor_end);
MODULE_LICENSE("GPL");

long new_sys_socketcall(int call, unsigned long *args) {
	long ret;
	ret = ref_sys_socketcall(call, args);
	print_call_info(call, "socketcall: ");
	return ret;
}

long new_sys_write(unsigned int fd, const char __user *buf, size_t count) {
	long ret = ref_sys_write(fd, buf, count);
	if (ret < 0) {
		return ret;
	}
	//print_call_info(fd, "writing to socket");
	th_read_request(current->pid, fd, (char*)buf, ret);
	return ret;
}

long new_sys_close(unsigned int fd) {
	long ret;
	ret = ref_sys_close(fd);
	if (th_conn_state_delete(current->pid, fd)) {
		//print_call_info(fd, "closing socket");
	}
	return ret;
}

long new_sys_read(unsigned int fd, char __user *buf, size_t count) {
	long ret = ref_sys_read(fd, buf, count);
	if (ret < 0) {
		return ret;
	}
	th_read_response(current->pid, fd, buf, ret);
	return ret;
}

long new_sys_recv(int sockfd, void __user * buf, size_t len, unsigned flags) {
	return ref_sys_recv(sockfd, buf, len, flags);
}

long new_sys_recvfrom(int sockfd, void __user * buf, size_t len, unsigned flags, struct sockaddr __user * src_addr, int __user * addrlen) {
	long ret = ref_sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	if (ret < 0) {
		return ret;
	}
	th_read_response(current->pid, sockfd, buf, ret);
	return ret;
}

long new_sys_recvmsg(int sockfd, struct msghdr __user *msg, unsigned flags) {
	struct iovec iov;
	long ret = ref_sys_recvmsg(sockfd, msg, flags);
	if (ret < 0) {
		return ret;
	}
	iov = *msg->msg_iov;
	th_read_response(current->pid, sockfd, (char*)iov.iov_base, ret);
	return ret;
}

long new_sys_recvmmsg(int sockfd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout) {
	return ref_sys_recvmmsg(sockfd, msg, vlen, flags, timeout);
}

long new_sys_send(int sockfd, void __user * buf, size_t len, unsigned flags) {
	return ref_sys_send(sockfd, buf, len, flags);
}

long new_sys_sendto(int sockfd, void __user * buf, size_t len, unsigned flags, struct sockaddr __user * dest_addr, int addrlen) {
	long ret = ref_sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	if (ret < 0) {
		return ret;
	}
	th_read_request(current->pid, sockfd, (char*)buf, ret);
	//print_call_info(sockfd, "in sendto()");
	return ret;
}

long new_sys_sendmsg(int sockfd, struct msghdr __user *msg, unsigned flags) {
	struct iovec iov;
        long ret = ref_sys_sendmsg(sockfd, msg, flags);
	iov = *msg->msg_iov;
	th_read_request(current->pid, sockfd, (char*)iov.iov_base, ret);
	//print_call_info(sockfd, "you all end up here anyway");
	return ret;
}

long new_sys_sendmmsg(int sockfd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags) {
	return ref_sys_sendmmsg(sockfd, msg, vlen, flags);
}

long new_sys_socket(int family, int type, int protocol) {
	long ret;
	ret = ref_sys_socket(family, type, protocol);

	// Only continue if the socket creation suceeded
	if (ret == -1) {
		printk(KERN_ALERT "Socket creation failed");
		return ret;
	}
	//print_call_info(ret, "creating socket");
	th_conn_state_create(current->pid, ret);
	//th_conn_state_print_all();
	return ret;
}

unsigned long **aquire_sys_call_table(void) {
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;
	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;
		if (sct[__NR_close] == (unsigned long *) sys_close) 
			return sct;
		offset += sizeof(void *);
	}
	return NULL;
}

int __init interceptor_start(void) {
	// Try to get the system call table
	if(!(sys_call_table = aquire_sys_call_table()))
		return -1;
	
	// Initialize buckets in hash table
	th_conn_state_init_all();

	// Override system calls
	original_cr0 = read_cr0();
	write_cr0(original_cr0 & ~0x00010000);
	ref_sys_socket = (void *)sys_call_table[__NR_socket];
	ref_sys_recvfrom = (void *)sys_call_table[__NR_recvfrom];
	ref_sys_recvfrom = (void *)sys_call_table[__NR_recvmsg];
	ref_sys_read = (void *)sys_call_table[__NR_read];
	ref_sys_sendto = (void *)sys_call_table[__NR_sendto];
	ref_sys_sendmsg = (void *)sys_call_table[__NR_sendmsg];
	ref_sys_write = (void *)sys_call_table[__NR_write];
	ref_sys_close = (void *)sys_call_table[__NR_close];
	//ref_sys_socketcall = (void *)sys_call_table[__NR_socketcall];
	sys_call_table[__NR_socket] = (unsigned long *)new_sys_socket;
	sys_call_table[__NR_recvfrom] = (unsigned long *)new_sys_recvfrom;
	sys_call_table[__NR_recvmsg] = (unsigned long *)new_sys_recvmsg;
	sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
	sys_call_table[__NR_sendto] = (unsigned long *)new_sys_sendto;
	sys_call_table[__NR_sendmsg] = (unsigned long *)new_sys_sendmsg;
	sys_call_table[__NR_write] = (unsigned long *)new_sys_write;
	sys_call_table[__NR_close] = (unsigned long *)new_sys_close;
	//sys_call_table[__NR_socketcall] = (unsigned long *)new_sys_socketcall;
	write_cr0(original_cr0);

	return 0;
}

void __exit interceptor_end(void) {
	if(!sys_call_table) {
		return;
	}
	
	write_cr0(original_cr0 & ~0x00010000);
	sys_call_table[__NR_socket] = (unsigned long *)ref_sys_socket;
	sys_call_table[__NR_recvfrom] = (unsigned long *)ref_sys_recvfrom;
	sys_call_table[__NR_recvmsg] = (unsigned long *)ref_sys_recvmsg;
	sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
	sys_call_table[__NR_sendto] = (unsigned long *)ref_sys_sendto;
	sys_call_table[__NR_sendmsg] = (unsigned long *)ref_sys_sendmsg;
	sys_call_table[__NR_write] = (unsigned long *)ref_sys_write;
	sys_call_table[__NR_close] = (unsigned long *)ref_sys_close;
	//sys_call_table[__NR_socketcall] = (unsigned long *)ref_sys_socketcall;
	write_cr0(original_cr0);

	// Free up conn state memory
	th_conn_state_free_all();

	msleep(2000);
}

