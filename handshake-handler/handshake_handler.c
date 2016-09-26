#include <linux/sched.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <linux/net.h>
// only for Bug 001 squashing
#include <linux/tcp.h>
//#include "../tcp/th_tcp.h"
// End only for Bug 001 squashing
#include <net/inet_connection_sock.h>

#include "handshake_handler.h"
#include "communications.h"
#include "../util/kth_logging.h" // For logging
#include "../util/utils.h"
#include "../interceptor/interceptor.h"
#include "../loader.h"
#include "../policy-engine/policy_response.h"

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
// TLS Handshake Extensions
#define TYPE_CERTIFICATE_URL		21
#define TYPE_CERTIFICATE_STATUS		22

// Client Hello byte navigation
#define SIZE_CLIENT_HELLO_LEN		3
#define SIZE_TLS_VERSION_INFO		2
#define SIZE_RANDOM_DATA		32
#define SIZE_SESSION_ID_LEN		1
#define	SIZE_CIPHER_SUITE_LEN		2
#define SIZE_COMPRESSION_METHODS_LEN	2
#define SIZE_EXTS_LEN			2
#define SIZE_EXT_TYPE			2
#define SIZE_EXT_LEN			2
#define	EXT_TYPE_SNI			0
#define SIZE_SNI_LIST_LEN		2
#define SIZE_SNI_TYPE			1
#define SIZE_SNI_NAME_LEN		2
#define IPV4_STR_LEN			15
#define IPV6_STR_LEN			39


// STARTTLS entries
char smtp_string[] = "EHLO ";
char smtp_server_string[] = "220 ";
char smtp_starttls_command[] = "STARTTLS\r\n";

inline size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state);
inline int th_buf_state_can_transition(buf_state_t* buf_state, int interest);
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
static void set_state_client_hello(handler_state_t* state, char* buf, unsigned int message_length);

// SMTP state machine handling
void handle_state_smtp_potential(handler_state_t* state, buf_state_t* buf_state);
void handle_state_smtp_fqdn(handler_state_t* state, buf_state_t* buf_state);
void handle_state_smtp_starttls(handler_state_t* state, buf_state_t* buf_state);
void handle_state_smtp_server_potential(handler_state_t* state, buf_state_t* buf_state);
void handle_state_smtp_server_greeting(handler_state_t* state, buf_state_t* buf_state);
void handle_state_smtp_server_options(handler_state_t* state, buf_state_t* buf_state);

// SSL Proxy Setup
void set_orig_leaf_cert(handler_state_t* state, unsigned char* bufptr, unsigned int certificates_length);
static void setup_ssl_proxy(handler_state_t* state);
int kernel_tcp_send_buffer(struct socket *sock, const char *buffer,const size_t length);


// Main proxy functionality
void* th_state_init(pid_t pid, pid_t tgid, struct socket* sock, struct sockaddr *uaddr, int is_ipv6, int addr_len) {
	handler_state_t* state;

	// Let policy engine and proxy daemon operate without handler
	if (tgid == mitm_proxy_task->pid) {
		kthlog(LOG_INFO, "Detected a connection from the local proxy");
		return NULL;
	}
	
	if (policy_engine_task != NULL && tgid == policy_engine_task->pid) {
		kthlog(LOG_INFO, "Detected a connection from a plugin");
		return NULL;
	}

	state = kmalloc(sizeof(handler_state_t), GFP_KERNEL);
	if (state != NULL) {
		state->pid = pid;
		state->tgid = tgid;
		state->interest = INTERESTED;
		/* For security, default to invalid */
		state->policy_response = POLICY_RESPONSE_INVALID;
		state->new_cert = NULL;
		state->new_cert_length = 0;
		state->client_hello = NULL; // This is initialized only if we get a client hello
		if (is_ipv6) {
			state->addr_v6 = *((struct sockaddr_in6 *)uaddr);
			state->ip = kmalloc(IPV6_STR_LEN+1, GFP_KERNEL);
			snprintf(state->ip, IPV6_STR_LEN+1, "%pI6", &(state->addr_v6.sin6_addr));
		}
		else {
			state->addr_v4 = *((struct sockaddr_in*)uaddr);
			state->ip = kmalloc(IPV4_STR_LEN+1, GFP_KERNEL);
			snprintf(state->ip, IPV4_STR_LEN+1, "%pI4", &(state->addr_v4.sin_addr));
		}
		state->is_ipv6 = is_ipv6;
		state->addr_len = addr_len;
		state->orig_sock = sock;
		state->mitm_sock = NULL;
		buf_state_init(&state->send_state);
		buf_state_init(&state->recv_state);
	}
	return state;;
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
	if (s->new_cert != NULL) {
		kfree(s->new_cert);
	}
	kfree(s);
	return;
}

int th_get_state(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	if (s->interest == INTERESTED) {
		return 1;
	}
	else if (s->interest == PROXIED) {
		return 2;
	}
	return 0;
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
        while (th_buf_state_can_transition(bs, s->interest)) {
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
        while (th_buf_state_can_transition(bs, s->interest)) {
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
			kthlog(LOG_DEBUG, "case UNKNOWN");
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
		case SMTP_POTENTIAL:
			handle_state_smtp_potential(state, buf_state);
			break;
		case SMTP_FQDN:
			handle_state_smtp_fqdn(state, buf_state);
			break;
		case SMTP_STARTTLS:
			handle_state_smtp_starttls(state, buf_state);
			break;
		case IRRELEVANT:
			// Should never get here
		default:
			kthlog(LOG_ERROR, "Unknown connection state!");
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
		case SMTP_SERVER_POTENTIAL:
			handle_state_smtp_server_potential(state, buf_state);
			break;
		case SMTP_SERVER_GREETING:
			handle_state_smtp_server_greeting(state, buf_state);
			break;
		case SMTP_SERVER_OPTIONS:
		case SMTP_SERVER_OPTIONS_END:
		case SMTP_SERVER_OPTIONS_DONE:
			handle_state_smtp_server_options(state, buf_state);
			break;
		case IRRELEVANT:
			// Should never get here
		default:
			kthlog(LOG_ERROR, "Unknown connection state!");
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
		buf_state->state = RECORD_LAYER;
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
		//kthlog(LOG_DEBUG, "set bytes to read from TH_TLS_RECORD_HEADER_SIZE of %i", TH_TLS_RECORD_HEADER_SIZE); 
	}
	else if (buf_state->buf[0] == smtp_string[0]) {
		buf_state->state = SMTP_POTENTIAL;
		buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
		//kthlog(LOG_DEBUG, "set bytes to read to %i for SMTP", TH_SMTP_READ_SIZE);
	}
	else if (buf_state->buf[0] == smtp_server_string[0]) {
		buf_state->state = SMTP_SERVER_POTENTIAL;
		buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
		//kthlog(LOG_DEBUG, "set bytes to read to %i for SMTP", TH_SMTP_READ_SIZE);
	}
	else {
		kthlog(LOG_DEBUG, "Read an unknown 0x%x at buf[0]", buf_state->buf[0]);
		kthlog_buffer(buf_state->buf, buf_state->buf_length);
		buf_state->bytes_to_read = 0;
		//kthlog(LOG_DEBUG, "set bytes to read to 0"); 
		buf_state->state = IRRELEVANT;
		state->interest = UNINTERESTED;
		buf_state->user_cur_max = buf_state->buf_length;
	}
	return;
}

void handle_state_smtp_server_potential(handler_state_t* state, buf_state_t* buf_state) {
	if (buf_state->buf[buf_state->bytes_read] != smtp_server_string[buf_state->bytes_read]) {
		buf_state-> state = IRRELEVANT;
		state->interest = UNINTERESTED;
		buf_state->bytes_to_read = 0;
		kthlog(LOG_DEBUG, "server not SMTP, ignoring now"); 
	}
	else {
		buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
	}

	// Regardless of what we see, let data pass on and update our counters
	buf_state->bytes_read++;
	buf_state->user_cur_max = buf_state->bytes_read;

	if (buf_state->bytes_read == strlen(smtp_server_string)) {
		buf_state->state = SMTP_SERVER_GREETING;
		kthlog(LOG_DEBUG, "full server 220 found, most likely SMTP");
	}
	return;
}

void handle_state_smtp_server_greeting(handler_state_t* state, buf_state_t* buf_state) {
	if (buf_state->buf[buf_state->bytes_read] == '\n') {
		kthlog(LOG_DEBUG, "Server greeting found: %s", &buf_state->buf[strlen(smtp_server_string)]);
		buf_state->state = SMTP_SERVER_OPTIONS;
	}
	// Regardless of what we see, let data pass on and update our counters
	buf_state->bytes_read++;
	buf_state->user_cur_max = buf_state->bytes_read;
	buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
	return;
}

void handle_state_smtp_server_options(handler_state_t* state, buf_state_t* buf_state) {
	buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
	if (buf_state->state == SMTP_SERVER_OPTIONS &&
		buf_state->buf[buf_state->bytes_read] == ' ' &&
		buf_state->buf[buf_state->bytes_read-1] == '0' && 
		buf_state->buf[buf_state->bytes_read-2] == '5' && 
		buf_state->buf[buf_state->bytes_read-3] == '2') { // XXX should be checking for status code here, but PoC first
		kthlog(LOG_DEBUG, "Last line of server options found");
		buf_state->state = SMTP_SERVER_OPTIONS_END;
	}
	else if (buf_state->state == SMTP_SERVER_OPTIONS_END &&
		buf_state->buf[buf_state->bytes_read] == '\n') {
		kthlog(LOG_DEBUG, "Server options ended: %s", buf_state->buf);
		buf_state->state = SMTP_SERVER_OPTIONS_DONE;
		th_send_is_starttls_query(state);
		if (state->policy_response == POLICY_RESPONSE_VALID) {
			
			//reset this, we'll use it again when we check the cert
			// XXX should probably make a cleanr version of this
			state->policy_response = POLICY_RESPONSE_INVALID;

			if (strnstr(buf_state->buf, "\r\n250-STARTTLS\r\n", buf_state->buf_length) == 0 &&
		            strnstr(buf_state->buf, "\r\n250 STARTTLS\r\n", buf_state->buf_length) == 0) {
				buf_state->bytes_to_read = 0;
				buf_state->user_cur_max = buf_state->buf_length;
				buf_state->state = IRRELEVANT;
				state->interest = UNINTERESTED;
				kthlog(LOG_DEBUG, "STRIPTLS attack detected!  Abort!");
				ref_tcp_disconnect(state->orig_sock->sk, 0); // terminate the connection
				return;
			}
		}
	}
	else if (buf_state->state == SMTP_SERVER_OPTIONS_DONE &&
		buf_state->buf[buf_state->bytes_read] == '\n') {
		buf_state->state = RECORD_LAYER;
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
		kthlog(LOG_DEBUG, "Server responded again with %s", buf_state->buf);
		//kthlog(LOG_DEBUG, "Full output: %s", buf_state->buf);

	}

	// Regardless of what we see, let data pass on and update our counters
	buf_state->bytes_read++;
	buf_state->user_cur_max = buf_state->bytes_read;
	return;
}

void handle_state_smtp_potential(handler_state_t* state, buf_state_t* buf_state) {
	if (buf_state == &state->recv_state) kthlog(LOG_DEBUG, "uh oh");
	if (buf_state->buf[buf_state->bytes_read] != smtp_string[buf_state->bytes_read]) {
		buf_state-> state = IRRELEVANT;
		state->interest = UNINTERESTED;
		buf_state->bytes_to_read = 0;
		kthlog(LOG_DEBUG, "not SMTP, ignoring now"); 
	}
	else {
		buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
	}

	// Regardless of what we see, let data pass on and update our counters
	buf_state->bytes_read++;
	buf_state->user_cur_max = buf_state->bytes_read;

	// If we're done reading a full "EHLO ", go to next state
	if (buf_state->bytes_read == strlen(smtp_string)) {
		kthlog(LOG_DEBUG, "full EHLO found, most likely SMTP");
		buf_state->state = SMTP_FQDN;
	}
	return;
}

void handle_state_smtp_fqdn(handler_state_t* state, buf_state_t* buf_state) {
	if (buf_state->buf[buf_state->bytes_read] == '\n') {
		kthlog(LOG_DEBUG, "SMTP IP/FQDN found: %s", &buf_state->buf[strlen(smtp_string)]);
		buf_state->state = SMTP_STARTTLS;
	}
	// Regardless of what we see, let data pass on and update our counters
	buf_state->bytes_read++;
	buf_state->user_cur_max = buf_state->bytes_read;
	buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
	return;
}

void handle_state_smtp_starttls(handler_state_t* state, buf_state_t* buf_state) {
	buf_state->bytes_to_read = TH_SMTP_READ_SIZE;
	if (buf_state->buf[buf_state->bytes_read] == '\n') {
		if (strncmp(&buf_state->buf[buf_state->bytes_read - (strlen(smtp_starttls_command) -1)],
			smtp_starttls_command, strlen(smtp_starttls_command)-1) == 0) {
			kthlog(LOG_DEBUG, "Found a STARTTLS command");
			//kthlog(LOG_DEBUG, "Send Buffer contents: %s", buf_state->buf);
			//kthlog(LOG_DEBUG, "Recv Buffer contents: %s", state->recv_state.buf);
			buf_state->state = RECORD_LAYER;
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
		}
		else {
			kthlog(LOG_DEBUG, "no STARTTLS! stopped tracking SMTP %s", &buf_state->buf[buf_state->bytes_read-9]);
			buf_state->state = IRRELEVANT;
			state->interest = UNINTERESTED;
			buf_state->bytes_to_read = 0;
		}
	}
	buf_state->bytes_read++;
	buf_state->user_cur_max = buf_state->bytes_read;
	return;
}

void handle_state_record_layer(handler_state_t* state, buf_state_t* buf_state) {
	char* cs_buf;
	unsigned char tls_major_version;
	unsigned char tls_minor_version;
	unsigned short tls_record_length;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	if (cs_buf[0] != TH_TLS_HANDSHAKE_IDENTIFIER) {
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
		state->interest = UNINTERESTED;
		buf_state->user_cur_max = buf_state->buf_length;
		return;
	}
	tls_major_version = cs_buf[1];
	tls_minor_version = cs_buf[2];
	tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
	//print_call_info("SSL version %u.%u Record size: %u", tls_major_version, tls_minor_version, tls_record_length);
	// XXX To continue verifying that this is indeed a real SSL/TLS connection we should fail out here if its not a valid SSL/TLS version number. (it's possible that they're just happening to send the right bytes to appear like a TLS connection)
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
	if (!state->policy_response != POLICY_RESPONSE_INVALID) {
		buf_state->user_cur_max = buf_state->buf_length;
	}
	return;
}

void handle_state_handshake_layer(handler_state_t* state, buf_state_t* buf_state) {
	unsigned int new_bytes;
	unsigned int tls_record_bytes;
	unsigned int handshake_message_length;
	char* cs_buf;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	tls_record_bytes = buf_state->bytes_to_read;
	// We're going to read everything to just let it be known now
	buf_state->bytes_read += buf_state->bytes_to_read;
	kthlog(LOG_DEBUG, "Watching handshake layer");
	while (tls_record_bytes > 0) {
		handshake_message_length = be24_to_cpu(*(__be24*)(cs_buf+1)) + 4;
		tls_record_bytes -= handshake_message_length;
		if (cs_buf[0] == TYPE_CLIENT_HELLO) {
			kthlog(LOG_DEBUG, "Sent a Client Hello");
			buf_state->bytes_to_read = 0;
			buf_state->state = CLIENT_HELLO_SENT;
			set_state_client_hello(state, cs_buf, handshake_message_length);
			buf_state->user_cur_max = buf_state->bytes_read;
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_CERTIFICATE_VERIFY ||
			 cs_buf[0] == TYPE_CLIENT_KEY_EXCHANGE) {
			// Should never get here (should already be uninterested
			// or in client hello sent state
			//kthlog(LOG_DEBUG, "Received a certificate verify or client key exchange");
			//BUG_ON(1);
		}
		else if (cs_buf[0] == TYPE_SERVER_HELLO) {
			kthlog(LOG_DEBUG, "Received a Server Hello");
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_CERTIFICATE) { 
			// XXX check to see if additional certificates are contained within this record
			kthlog(LOG_DEBUG, "Received a Certificate");
			new_bytes = handle_certificates(state, &cs_buf[1]); // Certificates start here
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
			if (state->policy_response == POLICY_RESPONSE_VALID_PROXY) {
				state->interest = PROXIED;
				setup_ssl_proxy(state);
				buf_state->user_cur_max = 0; // don't forward jack squat if we need to mitm
				buf_state->bytes_to_read = 0;
				return; // break out early, we no longer care about anything here
			}
			else if (state->policy_response == POLICY_RESPONSE_VALID) {
				buf_state->user_cur_max = buf_state->buf_length;
				buf_state->bytes_to_read = 0;
				buf_state->state = IRRELEVANT;
				state->interest = UNINTERESTED;
			}
			else { /* Invalid case */
				// XXX scramble, disconnect
				// For now just mess up cert
				cs_buf[1] = 'd';
				cs_buf[2] = '2';
				buf_state->bytes_to_read = 0;
				buf_state->user_cur_max = buf_state->buf_length;
				buf_state->state = IRRELEVANT;
				state->interest = UNINTERESTED;
				return;
			}
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_SERVER_KEY_EXCHANGE) {
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
			buf_state->user_cur_max = buf_state->buf_length;
			//kthlog(LOG_DEBUG, "Received a Server Key Exchange");
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_SERVER_HELLO_DONE) {	
			buf_state->bytes_to_read = 0;
			buf_state->state = SERVER_HELLO_DONE_SENT;
			buf_state->user_cur_max = buf_state->buf_length;
			state->interest = UNINTERESTED;
			//kthlog(LOG_DEBUG, "Received a Server Hello Done Exchange");
			cs_buf += handshake_message_length;
		}
		else if (cs_buf[0] == TYPE_HELLO_REQUEST || 
			 cs_buf[0] == TYPE_CERTIFICATE_REQUEST) {
			
			if (cs_buf[0] == TYPE_HELLO_REQUEST) {
				//kthlog(LOG_DEBUG, "Read a Hello Request (0) at %p", cs_buf);
			} else {
				//kthlog(LOG_DEBUG, "Read a Certificate request");
			};
			cs_buf += handshake_message_length;
			buf_state->user_cur_max = buf_state->buf_length;
			buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			buf_state->state = RECORD_LAYER;
		}
		else if (cs_buf[0] == TYPE_FINISHED) {
			// Should never get here (should already be uninterested)
			//kthlog(LOG_DEBUG, "Finished message received");
			BUG_ON(1);
		}
		else if (cs_buf[0] == TYPE_CERTIFICATE_URL ||
			 cs_buf[0] == TYPE_CERTIFICATE_STATUS) {
			//kthlog(LOG_DEBUG, "TLS Handshake extension message sent/received");
			// We may have to handle these situations in the future
			// See: https://www.ietf.org/rfc/rfc3546.txt
			cs_buf += handshake_message_length;
		}
		else {
			buf_state->bytes_to_read = 0;
			buf_state->state = IRRELEVANT;
			state->interest = UNINTERESTED;
			buf_state->user_cur_max = buf_state->buf_length;
			kthlog(LOG_DEBUG, "Someone sent a weird thing: %x", (unsigned int)cs_buf[0] & 0xFF);
			kthlog(LOG_DEBUG, "It was from the %s buffer", buf_state == &state->recv_state ? "receive" : "send");
			cs_buf += handshake_message_length;
			tls_record_bytes = 0; // Out
		}
	} // End while tls_record_bytes > 0
	return;
}

unsigned int handle_certificates(handler_state_t* state, unsigned char* buf) {
	unsigned char* bufptr;
	//__be24 be_handshake_message_length;
	//__be24 be_certificates_length;
	unsigned int handshake_message_length;
	unsigned int certificates_length;
	//unsigned int cert_length;
	bufptr = buf;
	//int i = 0;
	handshake_message_length = be24_to_cpu(*(__be24*)bufptr);

	//th_send_certificate_query
	bufptr += 3; // handshake identifier + 24bit length of protocol message
	//certificates_length = be32_to_cpu(*(unsigned int*)(bufptr) & 0xFFFFFF00);
	certificates_length = be24_to_cpu(*(__be24*)bufptr);
	bufptr += 3; // 24-bit length of certificates
	set_orig_leaf_cert(state, bufptr, certificates_length);
	th_send_certificate_query(state, bufptr, certificates_length);
	return 0;
}

void set_state_client_hello(handler_state_t* state, char* buf, unsigned int message_len) {
	state->client_hello = (char*)kmalloc(message_len, GFP_KERNEL); 
	memcpy(state->client_hello, buf, message_len);
	state->client_hello_len = message_len;
	return;
}

size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state) {
	return buf_state->buf_length - buf_state->bytes_read;
}

int th_buf_state_can_transition(buf_state_t* buf_state, int interest) {
	size_t unread = th_buf_state_get_num_bytes_unread(buf_state);
	if (interest == PROXIED) return 0;
	return buf_state->bytes_to_read && unread && unread >= buf_state->bytes_to_read;
}

// Support routines
void printbuf(char* buf, int length) {
	int i;
	for (i = 0; i < length; i++) {
		kthlog(LOG_INFO, "%02X", buf[i] & 0xFF);
	}
}

int copy_to_buf_state(buf_state_t* bs, void* src_buf, size_t length) {
	if ((bs->buf = krealloc(bs->buf, bs->buf_length + length, GFP_KERNEL)) == NULL) {
		kthlog(LOG_ERROR, "krealloc failed in copy_to_buf_state");
		return -1;
	}
	memcpy(bs->buf + bs->buf_length, src_buf, length);
	bs->buf_length += length;
	bs->last_payload_length = length;
	return 0;
}


void set_orig_leaf_cert(handler_state_t* state, unsigned char* bufptr, unsigned int certificates_length) {
	unsigned int cert_len;
	unsigned char* cert_start;
	cert_len = be24_to_cpu(*(__be24*)bufptr);
	cert_start = bufptr + 3;
	state->orig_leaf_cert = cert_start;
	state->orig_leaf_cert_len = cert_len;
	return;
}

void send_proxy_meta_data(struct socket* sock, struct sockaddr* addr, int ipv6, char* hostname, char* cert, int cert_len) {
	char buffer[1024];
	int bytes_written;
	char ipv6_init[] = "%pI6:%d\n%s\n%d\n";
	char ipv4_init[] = "%pI4:%d\n%s\n%d\n";
	if (ipv6 == 1) {
		bytes_written = snprintf(buffer, 1024, ipv6_init, 
			&((struct sockaddr_in6*)addr)->sin6_addr, 
			ntohs(((struct sockaddr_in6*)addr)->sin6_port),
			hostname, cert_len);
	}
	else {
		bytes_written = snprintf(buffer, 1024, ipv4_init, 
			&((struct sockaddr_in*)addr)->sin_addr,
			ntohs(((struct sockaddr_in*)addr)->sin_port),
			hostname, cert_len);
	}
	if (bytes_written < 0 || bytes_written > 1024) {
		kthlog(LOG_ERROR, "Failed to snprintf");
		return;
	}
	kernel_tcp_send_buffer(sock, buffer, bytes_written);
	kernel_tcp_send_buffer(sock, cert, cert_len);
	return;
}

void setup_ssl_proxy(handler_state_t* state) {
	struct tcp_sock* tp;
	int error;
	__be16 src_port;
	struct sockaddr_in proxy_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(8888),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK), // 127.0.0.1
	};
	struct sockaddr_in source_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_ANY), // 127.0.0.1
	};
	
	ref_tcp_disconnect(state->orig_sock->sk, 0);

	src_port = inet_sk(state->orig_sock->sk)->inet_sport;
	source_addr.sin_port = src_port;
	kernel_bind(state->orig_sock, (struct sockaddr*)&source_addr, sizeof(source_addr));
	if (add_to_proxy_accept_list(src_port, (struct sockaddr*)&state->addr_v4, state->is_ipv6)) {
		kthlog(LOG_ERROR, "Cannot send data to local proxy, error occured");
		return;
	}
	tp = tcp_sk(state->orig_sock->sk);
	lock_sock(state->orig_sock->sk);
	error = ref_tcp_v4_connect(state->orig_sock->sk, (struct sockaddr*)&proxy_addr, sizeof(struct sockaddr));
	release_sock(state->orig_sock->sk);
	src_port = inet_sk(state->orig_sock->sk)->inet_sport;

	kthlog(LOG_DEBUG, "Sending cloned Client Hello (and anything else sent by client)");
	error = kernel_tcp_send_buffer(state->orig_sock, state->send_state.buf, state->send_state.buf_length);
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
int __our_sock_sendmsg_nosec(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size) {
	int ret;
	struct sock_iocb *si = kiocb_to_siocb(iocb);
	si->sock = sock;
	si->scm = NULL;
	si->msg = msg;
	si->size = size;
	ret = sock->ops->sendmsg(iocb, sock, msg, size);
	return ret;
}

int our_sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;
	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __our_sock_sendmsg_nosec(&iocb, sock, msg, size);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}


int kernel_tcp_send_buffer(struct socket *sock, const char *buffer, const size_t length) {
	struct msghdr	msg;
	mm_segment_t	oldfs;
	struct iovec	iov;
	int 		len;
	
	iov.iov_base = (char*)buffer;
	iov.iov_len = length;
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	msg.msg_iter.iov = &iov;
	msg.msg_iter.nr_segs = 1;
	#else
	msg.msg_iov = &iov;
	msg.msg_iovlen   = 1;
	#endif

	msg.msg_name     = 0;
	msg.msg_namelen  = 0;
	msg.msg_control  = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags    = MSG_NOSIGNAL & MSG_FASTOPEN;
	
	oldfs = get_fs(); set_fs(KERNEL_DS);
	len = our_sock_sendmsg(sock, &msg, length);
	set_fs(oldfs);
	return len;
}

#else

int kernel_tcp_send_buffer(struct socket *sock, const char *buffer, const size_t length) {
	int ret;
	struct kvec vec;
	//struct msghdr msg = { .msg_flags = MSG_NOSIGNAL | MSG_FASTOPEN };
	struct msghdr msg = { .msg_flags =  0 };
	vec.iov_base = (void *)buffer;
	vec.iov_len = length;
	//ret = kernel_sendmsg(sock, &msg, &vec, 1, length);
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, &vec, 1, length);
	ret = sock->ops->sendmsg(sock, &msg, msg_data_left(&msg));
	kthlog(LOG_DEBUG, "Successfully sent proxy %d bytes", ret);
	return ret;
}

#endif

struct sock* th_get_mitm_sock(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	return (struct sock*)s->mitm_sock->sk;
}

