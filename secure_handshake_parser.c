#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>
#include <linux/net.h>

#include "secure_handshake_parser.h"
#include "connection_state.h"
#include "communications.h"
#include "utils.h"


static void update_state(conn_state_t* conn_state, buf_state_t* buf_state);
static void handle_state_unknown(conn_state_t* conn_state, buf_state_t* buf_state);
static void handle_state_record_layer(conn_state_t* conn_state, buf_state_t* buf_state);
static void handle_state_handshake_layer(conn_state_t* conn_state, buf_state_t* buf_state);
static void handle_certificates(char* buf);

void printbuf(char* buf, int length) {
	int i;
	for (i = 0; i < length; i++) {
		printk(KERN_INFO "%02X", buf[i]);
	}
}

void th_parse_comm(pid_t pid, struct socket* sock, char* new_buf, long ret, int sendrecv) {
        conn_state_t* conn_state;
	buf_state_t* buf_state;
	if ((conn_state = th_conn_state_get(pid, sock)) == NULL) {
		//printk(KERN_INFO "someone is sending from an unregistered socket");
		return;
	}
	if (sendrecv == TH_RECV) {
		buf_state = &conn_state->recv_state;
	}
	else {
		buf_state = &conn_state->send_state;
	}
	if ((buf_state->buf = krealloc(buf_state->buf, buf_state->buf_length + ret, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "Oh noes!  krealloc failed!");
		return;
	}
	memcpy(buf_state->buf + buf_state->buf_length, new_buf, ret);
	buf_state->buf_length += ret;
	while (th_buf_state_can_transition(buf_state)) {
		update_state(conn_state, buf_state);
	}
	if (buf_state->state == IRRELEVANT) {
		print_call_info(sock, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(pid, sock); // this isn't thread safe 
	}
	return;
}

void update_state(conn_state_t* conn_state, buf_state_t* buf_state) {
	switch (buf_state->state) {
		case UNKNOWN:
			handle_state_unknown(conn_state, buf_state);
			break;
		case RECORD_LAYER:
			handle_state_record_layer(conn_state, buf_state);
			break;
		case HANDSHAKE_LAYER:
			handle_state_handshake_layer(conn_state, buf_state);
			break;
		case IRRELEVANT:
			// Should never get here
		default:
			printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	return;
}

void handle_state_unknown(conn_state_t* conn_state, buf_state_t* buf_state) {
	//buf_state->bytes_read += buf_state->bytes_to_read; // XXX this is intentionally commented out.  We shouldn't increment our read state in this one case so we can enter the record layer state and act like we've never read any part of it.  This is essentially a "peek" to support early ignoring of non-TLS connections
	if (buf_state->buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
		print_call_info(conn_state->sock, "may be doing SSL");
		buf_state->state = RECORD_LAYER;
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
	}
	else {
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
	}
	return;
}

void handle_state_record_layer(conn_state_t* conn_state, buf_state_t* buf_state) {
	char* cs_buf;
	unsigned char tls_major_version;
	unsigned char tls_minor_version;
	unsigned short tls_record_length;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	tls_major_version = cs_buf[1];
	tls_minor_version = cs_buf[2];
	tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
	printk(KERN_INFO "SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
	// XXX To continue verifying that this is indeed a real SSL/TLS connection we should fail out here if its not a valid SSL/TLS version number. (it's possible that they're just happening to send the write bytes to appear like a TLS connection)
	buf_state->state = HANDSHAKE_LAYER;
	buf_state->bytes_read += buf_state->bytes_to_read;
	buf_state->bytes_to_read = tls_record_length;
	return;
}

void handle_state_handshake_layer(conn_state_t* conn_state, buf_state_t* buf_state) {
	char* cs_buf;
	cs_buf = &buf_state->buf[buf_state->bytes_read];
	buf_state->bytes_read += buf_state->bytes_to_read;
	if (cs_buf[0] == 0x01) {
		print_call_info(conn_state->sock, "Sent a Client Hello");
		buf_state->bytes_to_read = 0;
		buf_state->state = CLIENT_HELLO_SENT;
	}
	else if (cs_buf[0] == 0x02) { // XXX add something here to check to see if the certificate message (or part of it) is contained within this same record
		print_call_info(conn_state->sock, "Received a Server Hello");
		buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
		buf_state->state = RECORD_LAYER;
	}
	else if (cs_buf[0] == 0x0b) { // XXX add something here to check to see if additional certificates are contained within this record?
		handle_certificates(&cs_buf[1]); // Certificates start here
		//printk(KERN_ALERT "length is %u", handshake_message_length);
		//printk(KERN_ALERT "bytes_to_read was %u", buf_state->bytes_to_read);
		//handle_certificate
		//buf_state->bytes_to_read
		print_call_info(conn_state->sock, "Received a Certificate(s)");
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
	}
	else {
		buf_state->bytes_to_read = 0;
		buf_state->state = IRRELEVANT;
		print_call_info(conn_state->sock, "Someone sent a weird thing");
	}
	return;
}

void handle_certificates(char* buf) {
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
	printk(KERN_ALERT "length of msg is %u", handshake_message_length);
	printk(KERN_ALERT "length of certs is %u", certificates_length);
	th_send_certificate_query(bufptr, certificates_length);
	// XXX add some extra conditions to force this loop to terminate if we have a douchebag trying to hang the system
	/*while (certificates_length > 0) {
		cert_length = be32_to_cpu(*(unsigned int*)(bufptr-1) & 0xFFFFFF00);
		bufptr += 3; // 24-bit length of indidividual cert
		certificates_length -= 3;
		//handle_certificate(bufptr);
		printk(KERN_ALERT "length of one cert is %u", cert_length);
		if (th_send_certificate_query(bufptr, cert_length) < 0) {
			printk(KERN_ALERT "test failed");
		}
		bufptr += cert_length;
		certificates_length -= cert_length;
	}*/
	return;
}
