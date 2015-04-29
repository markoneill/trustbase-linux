#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <linux/net.h>

#include "handshake_handler.h"
#include "communications.h"
#include "../util/utils.h"

inline size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state);
inline int th_buf_state_can_transition(buf_state_t* buf_state);
static void* buf_state_init(buf_state_t* buf_state);

// Interception helpers
static inline int copy_to_buf_state(buf_state_t* buf_state, void* src_buf, size_t length);

// State machine handling
static void update_buf_state_recv(handler_state_t* state, buf_state_t* buf_state);
static void update_buf_state_send(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_unknown(buf_state_t* buf_state);
static void handle_state_record_layer(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_client_hello_sent(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_certificates_sent(handler_state_t* state, buf_state_t* buf_state);
static void handle_state_handshake_layer(handler_state_t* state, buf_state_t* buf_state);
static void handle_certificates(handler_state_t* state, char* buf);
static void set_state_hostname(handler_state_t* state, char* buf);

// Main proxy functionality
void* th_state_init(pid_t pid) {
	handler_state_t* state;
	state = kmalloc(sizeof(handler_state_t), GFP_KERNEL);
	if (state != NULL) {
		state->pid = pid;
		state->interest = INTERESTED;
		state->is_attack = 0;
		state->new_cert = NULL;
		state->new_cert_length = 0;
		state->hostname = NULL; // This is initialized only if we get a client hello
		buf_state_init(&state->send_state);
		buf_state_init(&state->recv_state);
	}
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
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
        while (th_buf_state_can_transition(bs)) {
                update_buf_state_send(state, bs);
        }
	return 0;
}

int th_update_state_recv(void* state) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
        while (th_buf_state_can_transition(bs)) {
                update_buf_state_recv(state, bs);
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
			handle_state_unknown(buf_state);
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
			handle_state_unknown(buf_state);
			break;
		case RECORD_LAYER:
			handle_state_record_layer(state, buf_state);
			break;
		case HANDSHAKE_LAYER:
			handle_state_handshake_layer(state, buf_state);
			break;
		case SERVER_CERTIFICATES_SENT:
			handle_state_certificates_sent(state, buf_state);
			break;
		case IRRELEVANT:
			// Should never get here
		default:
			printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	return;
}

void handle_state_unknown(buf_state_t* buf_state) {
	//buf_state->bytes_read += buf_state->bytes_to_read; // XXX this is intentionally commented out.  We shouldn't increment our read state in this one case so we can enter the record layer state and act like we've never read any part of it.  This is essentially a "peek" to support early ignoring of non-TLS connections
	if (buf_state->buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
		//print_call_info(conn_state->sock, "may be doing SSL");
		buf_state->state = RECORD_LAYER;
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
	}
	else {
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
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
	//printk(KERN_INFO "SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
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

void handle_state_certificates_sent(handler_state_t* state, buf_state_t* buf_state) {
	buf_state->user_cur_max = buf_state->buf_length;
	return;
}

void handle_state_handshake_layer(handler_state_t* state, buf_state_t* buf_state) {
	char* cs_buf;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	buf_state->bytes_read += buf_state->bytes_to_read;
	if (cs_buf[0] == 0x01) {
		//print_call_info(conn_state->sock, "Sent a Client Hello");
		buf_state->bytes_to_read = 0;
		buf_state->state = CLIENT_HELLO_SENT;
		set_state_hostname(state, cs_buf+1); // Plus one to ignore protocol type
		buf_state->user_cur_max = buf_state->bytes_read;
	}
	else if (cs_buf[0] == 0x02) { // XXX add something here to check to see if the certificate message (or part of it) is contained within this same record
		//print_call_info(conn_state->sock, "Received a Server Hello");
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
		buf_state->state = RECORD_LAYER;
	}
	else if (cs_buf[0] == 0x0b) { // XXX add something here to check to see if additional certificates are contained within this record?
		//XXX this is temporary until we get send handler to parse out domain name
		handle_certificates(state, &cs_buf[1]); // Certificates start here
		//printk(KERN_ALERT "length is %u", handshake_message_length);
		//printk(KERN_ALERT "bytes_to_read was %u", buf_state->bytes_to_read);
		//handle_certificate
		//buf_state->bytes_to_read
		//print_call_info(conn_state->sock, "Received a Certificate(s)");
		buf_state->bytes_to_read = 0;
		buf_state->state = SERVER_CERTIFICATES_SENT;
		buf_state->user_cur_max = buf_state->buf_length; // Set this to zero to block certs
	}
	else {
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
		buf_state->user_cur_max = buf_state->buf_length;
		printk(KERN_ALERT "Someone sent a weird thing");
	}
	return;
}

void handle_certificates(handler_state_t* state, char* buf) {
	char* bufptr;
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
		//bufptr[7] = 0; // poison certificate test
		bufptr += 3;
		//printk(KERN_ALERT "first byte of sent certs was %x",bufptr[0]);
		memcpy(bufptr, state->new_cert, state->new_cert_length);
		printk(KERN_ALERT "attack! and certlength is %d", state->new_cert_length);
	}
	return;
}

void set_state_hostname(handler_state_t* state, char* buf) {
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
			printk(KERN_ALERT "Hostname is %s", state->hostname);
			break;
		}
		extensions_length -= extension_length;
	}

	// XXX change this so that hostname gets set by kernel on connect if we
	// didn't find an SNI extension in the hello
	if (state->hostname == NULL) {
	}
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
