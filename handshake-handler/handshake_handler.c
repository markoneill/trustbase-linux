#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <linux/net.h>

#include "handshake_handler.h"
#include "communications.h"
#include "../util/utils.h"
#include "../interceptor/interceptor.h"
#include "../loader.h"
#define CERTIFICATE_LENGTH_FIELD_SIZE	3

// Handshake type identifiers
#define TYPE_HELLO_REQUEST		0
#define TYPE_CLIENT_HELLO		1
#define TYPE_SERVER_HELLO		2
#define TYPE_CERTIFICATE		11
#define TYPE_SERVER_KEY_EXCHANGE	12
#define TYPE_CERTIFICATE_REQUEST	13
#define TYPE_SERVER_HELLO_DONE		14
#define TYPE_CERTIFICATE_VERIFY		15
#define TYPE_CLIENT_KEY_EXCHANGE	16
#define TYPE_FINISHED			20

inline size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state);
inline int th_buf_state_can_transition(buf_state_t* buf_state);
static void* buf_state_init(buf_state_t* buf_state);

// Interception helpers
static inline int copy_to_buf_state(buf_state_t* buf_state, void* src_buf, size_t length);

// State machine handling
static void update_buf_state_recv(handler_state_t* state, buf_state_t* buf_state);
static void update_buf_state_send(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_unknown(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_record_layer(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_client_hello_sent(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_server_hello_done_sent(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_handshake_layer(handler_state_t* state, buf_state_t* buf_state);
static unsigned int handle_certificates(handler_state_t* state, unsigned char* buf);
static void set_state_hostname(handler_state_t* state, char* buf);

// SSL Proxy Setup
static void setup_ssl_proxy(handler_state_t* state);
int kernel_tcp_send_buffer(struct socket *sock, const char *buffer,const size_t length);


// Main proxy functionality
void* th_state_init(pid_t pid, struct socket* sock, struct sockaddr *uaddr, int is_ipv6, int addr_len) {
	handler_state_t* state;

	// Let policy engine and proxy daemon operate without handler
	if (pid == mitm_proxy_task->pid) {
		printk(KERN_INFO "Detected a connection from the tls proxy");
		return NULL;
	}

	state = kmalloc(sizeof(handler_state_t), GFP_KERNEL);
	if (state != NULL) {
		state->pid = pid;
		state->interest = INTERESTED;
		state->is_attack = 0;
		state->new_cert = NULL;
		state->new_cert_length = 0;
		state->hostname = NULL; // This is initialized only if we get a client hello
		if (is_ipv6) {
			state->addr_v6 = *((struct sockaddr_in6 *)uaddr);
		}
		else {
			state->addr_v4 = *((struct sockaddr_in*)uaddr);
		}
		state->is_ipv6 = is_ipv6;
		state->addr_len = addr_len;
		state->mitm_sock = NULL;
		state->orig_sock = sock;
		state->is_asynchronous = 0; // Default to synchronous
		buf_state_init(&state->send_state);
		buf_state_init(&state->recv_state);
	}
	//setup_ssl_proxy(state); // XXX test
	return state;
}

void* buf_state_init(buf_state_t* buf_state) {
	buf_state->buf_length = 0;
	buf_state->bytes_read = 0;
	buf_state->user_cur = 0;
	buf_state->user_cur_max = 0;
	buf_state->bytes_to_read = TH_TLS_HANDSHAKE_IDENTIFIER_SIZE;
	buf_state->buf = NULL;
	buf_state->state = UNKNOWN;
	return buf_state;
}

void th_state_free(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	if (s->send_state.buf != NULL) {
		kfree(s->send_state.buf);
	}
	if (s->recv_state.buf != NULL) {
		kfree(s->recv_state.buf);
	}
	if (s->hostname != NULL) {
		kfree(s->hostname);
	}
	if (s->new_cert != NULL) {
		kfree(s->new_cert);
	}
	kfree(s);
	return;
}

int th_get_state(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	return s->interest == INTERESTED ? 1 : 0;
}

int th_give_to_handler_send(void* state, void* src_buf, size_t length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	return copy_to_buf_state(bs, src_buf, length);
}

int th_give_to_handler_recv(void* state, void* src_buf, size_t length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	return copy_to_buf_state(bs, src_buf, length);
}

int th_update_state_send(void* state) {
	handler_state_t* s;
	buf_state_t* bs;
	s = (handler_state_t*)state;
	bs = &s->send_state;
        while (th_buf_state_can_transition(bs)) {
                update_buf_state_send(state, bs);
        }
	if (s->interest == UNINTERESTED) {
		bs->user_cur_max = bs->buf_length;
	}
	return 0;
}

int th_update_state_recv(void* state) {
	handler_state_t* s;
	buf_state_t* bs;
	s = (handler_state_t*)state;
	bs = &s->recv_state;
        while (th_buf_state_can_transition(bs)) {
                update_buf_state_recv(state, bs);
        }
	if (s->interest == UNINTERESTED) {
		bs->user_cur_max = bs->buf_length;
	}
	return 0;
}

// XXX change this to set_buffer_send
int th_fill_send_buffer(void* state, void** bufptr, size_t* length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	*length = bs->user_cur_max - bs->user_cur;
	*bufptr = bs->buf + bs->user_cur;
	return 0;
}

// XXX change this (and semantics) to set_buffer_recv
int th_copy_to_user_buffer(void* state, void __user *dst_buf, size_t length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	if (copy_to_user(dst_buf, bs->buf + bs->user_cur, length) != 0) {
		return -1;
	}
	return 0;
}

int th_num_bytes_to_forward_send(void* state) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	return bs->user_cur_max - bs->user_cur;
}

int th_num_bytes_to_forward_recv(void* state) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	return bs->user_cur_max - bs->user_cur;
}

int th_update_bytes_forwarded_send(void* state, size_t forwarded) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	bs->user_cur += forwarded;
	return 0;
}

int th_update_bytes_forwarded_recv(void* state, size_t forwarded) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	bs->user_cur += forwarded;
	return 0;
}

int th_get_bytes_to_read_send(void* state) {
	return ((handler_state_t*)state)->send_state.bytes_to_read;
}

int th_get_bytes_to_read_recv(void* state) {
	return ((handler_state_t*)state)->recv_state.bytes_to_read;
}

// State Machine functionality
void update_buf_state_send(handler_state_t* state, buf_state_t* buf_state) {
	switch (buf_state->state) {
		case UNKNOWN:
			handle_state_unknown(state, buf_state);
			break;
		case RECORD_LAYER:
			handle_state_record_layer(state, buf_state);
			break;
		case HANDSHAKE_LAYER:
			handle_state_handshake_layer(state, buf_state);
			break;
		case CLIENT_HELLO_SENT:
			handle_state_client_hello_sent(state, buf_state);
			break;
		case IRRELEVANT:
			// Should never get here
		default:
			printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	return;
}
void update_buf_state_recv(handler_state_t* state, buf_state_t* buf_state) {
	switch (buf_state->state) {
		case UNKNOWN:
			handle_state_unknown(state, buf_state);
			break;
		case RECORD_LAYER:
			handle_state_record_layer(state, buf_state);
			break;
		case HANDSHAKE_LAYER:
			handle_state_handshake_layer(state, buf_state);
			break;
		case SERVER_HELLO_DONE_SENT:
			handle_state_server_hello_done_sent(state, buf_state);
			break;
		case IRRELEVANT:
			// Should never get here
		default:
			printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	return;
}

void handle_state_unknown(handler_state_t* state, buf_state_t* buf_state) {
	// Below is is intentionally commented out.  We shouldn't increment
	// our read state in this one case so we can enter the record layer
	// state and act like we've never read any part of it.  This is 
	// essentially a "peek" to support early ignoring of non-TLS 
	// connections.
	//buf_state->bytes_read += buf_state->bytes_to_read;
	if (buf_state->buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
		//print_call_info("May be initiating an SSL/TLS connection");
		buf_state->state = RECORD_LAYER;
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
	}
	else {
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
		state->interest = UNINTERESTED;
		buf_state->user_cur_max = buf_state->buf_length;
	}
	return;
}

void handle_state_record_layer(handler_state_t* state, buf_state_t* buf_state) {
	char* cs_buf;
	unsigned char tls_major_version;
	unsigned char tls_minor_version;
	unsigned short tls_record_length;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	tls_major_version = cs_buf[1];
	tls_minor_version = cs_buf[2];
	tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
	//print_call_info("SSL version %u.%u Record size: %u", tls_major_version, tls_minor_version, tls_record_length);
	// XXX To continue verifying that this is indeed a real SSL/TLS connection we should fail out here if its not a valid SSL/TLS version number. (it's possible that they're just happening to send the write bytes to appear like a TLS connection)
	buf_state->state = HANDSHAKE_LAYER;
	buf_state->bytes_read += buf_state->bytes_to_read;
	buf_state->bytes_to_read = tls_record_length;
	return;
}

void handle_state_client_hello_sent(handler_state_t* state, buf_state_t* buf_state) {
	buf_state->user_cur_max = buf_state->buf_length;
	return;
}

void handle_state_server_hello_done_sent(handler_state_t* state, buf_state_t* buf_state) {
	if (!state->is_attack) {
		buf_state->user_cur_max = buf_state->buf_length;
	}
	return;
}

void handle_state_handshake_layer(handler_state_t* state, buf_state_t* buf_state) {
	unsigned int new_bytes;
	unsigned int tls_record_bytes;
	unsigned int handshake_message_length;
	bool need_to_proxy;
	char* cs_buf;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	tls_record_bytes = buf_state->bytes_to_read;
	// We're going to read everything to just let it be known now
	buf_state->bytes_read += buf_state->bytes_to_read;
	//printk(KERN_ALERT "Record length is %u", tls_record_bytes);
	while (tls_record_bytes > 0) {
		handshake_message_length = be24_to_cpu(*(__be24*)(cs_buf+1)) + 4;
		//printk(KERN_ALERT "Message length is %u", handshake_message_length);
		tls_record_bytes -= handshake_message_length;
		if (cs_buf[0] == TYPE_CLIENT_HELLO) {
			//print_call_info("Sent a Client Hello");
			buf_state->bytes_to_read = 0;
			buf_state->state = CLIENT_HELLO_SENT;
			set_state_hostname(state, cs_buf+1); // Plus one to ignore protocol type
			buf_state->user_cur_max = buf_state->bytes_read;
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_CERTIFICATE_VERIFY ||
			 cs_buf[0] == TYPE_CLIENT_KEY_EXCHANGE) {
			// Should never get here (should already be uninterested
			// or in client hello sent state
			printk(KERN_ALERT "AFDSDFFDFAF");
			BUG_ON(1);
		}
		else if (cs_buf[0] == TYPE_SERVER_HELLO) {
			//print_call_info(conn_state->sock, "Received a Server Hello");
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_CERTIFICATE) { 
			// XXX check to see if additional certificates are contained within this record
			new_bytes = handle_certificates(state, &cs_buf[1]); // Certificates start here
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
			if (new_bytes == 0) {
				buf_state->user_cur_max = buf_state->buf_length;
			}
			else { // this should probably be deprecated now
				buf_state->user_cur_max += new_bytes + 1; // + 1 for 0x0b
			}
			need_to_proxy = true; // static for now, for testing purposes
			if (need_to_proxy) {
				setup_ssl_proxy(state);
				buf_state->user_cur_max = 0; // don't forward jack squat if we need to mitm
				buf_state->bytes_to_read = 0;
				return; // break out early, we no longer care about anything here
			}
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_SERVER_KEY_EXCHANGE) {
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
			buf_state->user_cur_max = buf_state->buf_length;
			printk(KERN_ALERT "Server Key Exchange Received");
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_SERVER_HELLO_DONE) {	
			buf_state->bytes_to_read = 0;
			buf_state->state = SERVER_HELLO_DONE_SENT;
			buf_state->user_cur_max = buf_state->buf_length;
			state->interest = UNINTERESTED;
			printk(KERN_ALERT "Server Hello Done Received");
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_HELLO_REQUEST || 
			 cs_buf[0] == TYPE_CERTIFICATE_REQUEST) {
			cs_buf += handshake_message_length;
			buf_state->user_cur_max = buf_state->buf_length;
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
		}
		else if (cs_buf[0] == TYPE_FINISHED) {
			// Should never get here (should already be uninterested)
			printk(KERN_ALERT "AFDSDFFDFAF");
			BUG_ON(1);
		}
		else {
			buf_state->bytes_to_read = 0;
			buf_state->state = IRRELEVANT;
			state->interest = UNINTERESTED;
			buf_state->user_cur_max = buf_state->buf_length;
			printk(KERN_ALERT "Someone sent a weird thing: %x", (unsigned int)cs_buf[0]);
			cs_buf += handshake_message_length;
			tls_record_bytes = 0; // Out
		}
	} // End while tls_record_bytes > 0
	return;
}

unsigned int handle_certificates(handler_state_t* state, unsigned char* buf) {
	unsigned char* bufptr;
	__be24 be_handshake_message_length;
	__be24 be_certificates_length;
	unsigned int handshake_message_length;
	unsigned int certificates_length;
	//unsigned int cert_length;
	bufptr = buf;
	//int i = 0;
	handshake_message_length = be24_to_cpu(*(__be24*)bufptr);

	//th_send_certificate_query(
	bufptr += 3; // handshake identifier + 24bit length of protocol message
	//certificates_length = be32_to_cpu(*(unsigned int*)(bufptr) & 0xFFFFFF00);
	certificates_length = be24_to_cpu(*(__be24*)bufptr);
	bufptr += 3; // 24-bit length of certificates
	//printk(KERN_ALERT "length of msg is %u", handshake_message_length);
	//printk(KERN_ALERT "length of certs is %u", certificates_length);
	//printk(KERN_ALERT "Sending certificates to policy engine");
	th_send_certificate_query(state, state->hostname, bufptr, certificates_length);
	if (state->is_attack) {

		// Override certificate data
		memcpy(bufptr, state->new_cert, state->new_cert_length);
		//be_certificate_length = cpu_to_be24(state->new_cert_length);
		//printk(KERN_ALERT "CL BE:%02x%02x%02x LE:%06x", 
		//	((unsigned char*)&be_certificate_length)[0],
		//	((unsigned char*)&be_certificate_length)[1],
		//	((unsigned char*)&be_certificate_length)[2],
		//	state->new_cert_length
		//);
	
		// Update length of all certificates
		bufptr -= 3;
		be_certificates_length = cpu_to_be24(state->new_cert_length);
		//memcpy(bufptr, &be_certificates_length, 3);
		bufptr[0] = ((unsigned char*)&be_certificates_length)[0];
		bufptr[1] = ((unsigned char*)&be_certificates_length)[1];
		bufptr[2] = ((unsigned char*)&be_certificates_length)[2];

		// Update handshake message length
		bufptr -= 3;
		be_handshake_message_length = cpu_to_be24(state->new_cert_length + 3);
		bufptr[0] = ((unsigned char*)&be_handshake_message_length)[0];
		bufptr[1] = ((unsigned char*)&be_handshake_message_length)[1];
		bufptr[2] = ((unsigned char*)&be_handshake_message_length)[2];
		//memcpy(bufptr, &be_handshake_message_length, 3);
		
		printk(KERN_ALERT "attack! and certlength is %d", state->new_cert_length);
		return state->new_cert_length + 6;
	}
	return 0;
}

void set_state_hostname(handler_state_t* state, char* buf) {
	// XXX clean this function up.  It was made in haste just to get the hostname
	char* bufptr;
	unsigned int hello_length;
	unsigned char major_version;
	unsigned char minor_version;
	unsigned char session_id_length;
	unsigned short cipher_suite_length;
	unsigned char compression_methods_length;
	unsigned short extensions_length;
	unsigned short extension_length;
	unsigned short extension_type;
	unsigned short list_length;
	unsigned char type;
	unsigned short name_length;
	char uname[] = "Unknown";
	bufptr = buf;
	hello_length = be24_to_cpu(*(__be24*)bufptr);
	//printk(KERN_ALERT "client hello length is %u", hello_length);
	bufptr += 3; // advance past length info
	major_version = bufptr[0];
	minor_version = bufptr[1];
	//printk(KERN_ALERT "tls version %u.%u", major_version, minor_version);
	bufptr += 2; // advance past version info
	bufptr += 32; // skip 32-byte random
	session_id_length = bufptr[0];
	//printk(KERN_ALERT "session id length %u", session_id_length);
	bufptr += 1; // advance past session id length field
	bufptr += session_id_length; // advance past session ID
	cipher_suite_length = be16_to_cpu(*(__be16*)bufptr);
	bufptr += 2; // advance past cipher suite length field
	//printk(KERN_ALERT "cipher suite length %u", cipher_suite_length);
	bufptr += cipher_suite_length; // advance past cipher suites;
	compression_methods_length = be16_to_cpu(*(__be16*)bufptr);
	bufptr += 2; // advance past compression methods length field
	bufptr += compression_methods_length; // advance past compression methods
	extensions_length = be16_to_cpu(*(__be16*)bufptr);
	bufptr += 2; // advance past extensions length
	//printk(KERN_ALERT "extensions length is %u", extensions_length);
	while (extensions_length) {
		extension_type = be16_to_cpu(*(__be16*)bufptr);
		bufptr += 2; // advance past type field
		extension_length = be16_to_cpu(*(__be16*)bufptr);
		bufptr += 2; // advance past extension length field
		if (extension_type == 0) {
			//printk(KERN_ALERT "We found an SNI extension!");
			list_length = be16_to_cpu(*(__be16*)bufptr);
			bufptr += 2; // advance past 
			type = bufptr[0];
			bufptr++; // advance past type field
			name_length = be16_to_cpu(*(__be16*)bufptr);
			bufptr += 2; // advance past name length field
			state->hostname = kmalloc(name_length+1, GFP_KERNEL);
			memcpy(state->hostname, bufptr, name_length);
			state->hostname[name_length] = '\0'; // null terminate it
			break;
		}
		extensions_length -= extension_length;
	}

	// XXX change this so that hostname gets set by kernel on connect if we
	// didn't find an SNI extension in the hello
	if (state->hostname == NULL) {
		state->hostname = kmalloc(sizeof(uname), GFP_KERNEL);
		memcpy(state->hostname, uname, sizeof(uname));
	}
	//printk(KERN_ALERT "Hostname is %s", state->hostname);
	return;
}

size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state) {
	return buf_state->buf_length - buf_state->bytes_read;
}

int th_buf_state_can_transition(buf_state_t* buf_state) {
	size_t unread = th_buf_state_get_num_bytes_unread(buf_state);
	//printk(KERN_ALERT "Unread: %u", unread);
	return buf_state->bytes_to_read && unread && unread >= buf_state->bytes_to_read;
}

// Support routines
void printbuf(char* buf, int length) {
	int i;
	for (i = 0; i < length; i++) {
		printk(KERN_INFO "%02X", buf[i]);
	}
}

int copy_to_buf_state(buf_state_t* bs, void* src_buf, size_t length) {
	if ((bs->buf = krealloc(bs->buf, bs->buf_length + length, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "krealloc failed in copy_to_buf_state");
		return -1;
	}
	memcpy(bs->buf + bs->buf_length, src_buf, length);
	bs->buf_length += length;
	bs->last_payload_length = length;
	return 0;
}


// The following functions will probably be moved later
int th_is_asynchronous(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	return s->is_asynchronous;
}

struct socket* th_get_async_sk(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	if (s->mitm_sock != NULL) {
		return s->mitm_sock;
	}
	return NULL;
}

void send_proxy_meta_data(struct socket* sock, struct sockaddr* addr, int ipv6, char* hostname) {
	char buffer[1024];
	int bytes_written;
	char ipv6_init[] = "%pI6:%d\n%s\n5\n12345";
	char ipv4_init[] = "%pI4:%d\n%s\n5\n12345";
	if (ipv6 == 1) {
		bytes_written = snprintf(buffer, 1024, ipv6_init, 
			&((struct sockaddr_in6*)addr)->sin6_addr, 
			ntohs(((struct sockaddr_in6*)addr)->sin6_port),
			hostname);
	}
	else {
		bytes_written = snprintf(buffer, 1024, ipv4_init, 
			&((struct sockaddr_in*)addr)->sin_addr,
			ntohs(((struct sockaddr_in*)addr)->sin_port),
			hostname);
	}
	if (bytes_written < 0 || bytes_written > 1024) {
		printk(KERN_ALERT "Failed to snprintf");
		return;
	}
	printk(KERN_INFO "%s", buffer);
	kernel_tcp_send_buffer(sock, buffer, bytes_written);
	return;
}

void setup_ssl_proxy(handler_state_t* state) {
	int error;
	struct sockaddr_in proxy_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(8888),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK), // 127.0.0.1
	};
	state->is_asynchronous = 1;
	
	ref_tcp_disconnect(state->orig_sock->sk, 0);
	ref_tcp_v4_connect(state->orig_sock->sk, (struct sockaddr*)&proxy_addr, sizeof(struct sockaddr));

	//printk(KERN_INFO "Sending proxy meta information");
	//error = kernel_tcp_send_buffer(state->orig_sock, );
	if (state->is_ipv6 == 1) {
		//send_proxy_meta_data(&state->addr_v6, state->hostname);
		send_proxy_meta_data(state->orig_sock,
			(struct sockaddr*)&state->addr_v6, state->is_ipv6, state->hostname);
	}
	else {
		send_proxy_meta_data(state->orig_sock,
			(struct sockaddr*)&state->addr_v4, state->is_ipv6, state->hostname);
	}
	printk(KERN_INFO "Sending cloned Client Hello (and anything else sent by client)");
	error = kernel_tcp_send_buffer(state->orig_sock, state->send_state.buf, state->send_state.buf_length);

	//printk(KERN_ALERT "%d", error);
	return;
}

int kernel_tcp_send_buffer(struct socket *sock, const char *buffer,const size_t length) {
	struct msghdr	msg;
	mm_segment_t	oldfs;
	struct iovec	iov;
	int 		len;
	
	msg.msg_name     = 0;
	msg.msg_namelen  = 0;
	msg.msg_iov	 = &iov;
	msg.msg_iovlen   = 1;
	msg.msg_control  = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags    = MSG_NOSIGNAL;
	msg.msg_iov->iov_len = (__kernel_size_t)length;
	msg.msg_iov->iov_base = (char*) buffer;
	
	oldfs = get_fs(); set_fs(KERNEL_DS);
	len = sock_sendmsg(sock, &msg, length);
	set_fs(oldfs);
	return len;
}

