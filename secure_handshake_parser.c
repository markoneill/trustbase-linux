#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>

#include "secure_handshake_parser.h"
#include "connection_state.h"
#include "utils.h"


static void update_state(conn_state_t* conn_state);

void printbuf(char* buf, int length) {
	int i;
	for (i = 0; i < length; i++) {
		printk(KERN_INFO "%02X", buf[i]);
	}
}

void th_read(pid_t pid, int sockfd, char* buf, long ret) {
        conn_state_t* conn_state;
	if ((conn_state = th_conn_state_get(pid, sockfd)) == NULL) {
		//printk(KERN_INFO "someone is sending from an unregistered socket");
		return;
	}
	if ((conn_state->buf = krealloc(conn_state->buf, conn_state->data_length + ret, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "Oh noes!  krealloc failed!");
		return;
	}
	memcpy(conn_state->buf + conn_state->data_length, buf, ret);
	conn_state->data_length += ret;
	while (conn_state->state != IRRELEVANT && conn_state->state != TLS_SERVER_HELLO && conn_state->data_length >= conn_state->bytes_to_read) {
		update_state(conn_state);
	}
	if (conn_state->state == IRRELEVANT) {
		print_call_info(sockfd, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(pid, sockfd);
	}
	return;
}


void update_state(conn_state_t* conn_state) {
	char* cs_buf = NULL;
	int sockfd = conn_state->socketfd;
	unsigned char tls_major_version;
	unsigned char tls_minor_version;
	unsigned short tls_record_length;
	switch (conn_state->state) {
		case UNKNOWN:
			if (conn_state->buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
				print_call_info(sockfd, "may be doing SSL");
				conn_state->state = TLS_NEW;
				conn_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			}
			else {
				conn_state->state = IRRELEVANT;
			}
			break;
		case TLS_NEW:
			cs_buf = conn_state->buf;
			printbuf(cs_buf, TH_TLS_RECORD_HEADER_SIZE);
			tls_major_version = cs_buf[1];
			tls_minor_version = cs_buf[2];
			tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
			printk(KERN_INFO "SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
			conn_state->bytes_to_read = tls_record_length;
			conn_state->state = TLS_CLIENT_HELLO;
			break;
		case TLS_CLIENT_HELLO:
			print_call_info(sockfd, "read all of CLIENT_HELLO");
			conn_state->state = TLS_SERVER_HELLO;
			break;
		case IRRELEVANT:
			// Should never get here
			break;
		default:
			printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	return;
}

