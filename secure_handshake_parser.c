#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>

#include "secure_handshake_parser.h"
#include "connection_state.h"
#include "utils.h"


static void update_send_state(conn_state_t* conn_state);
static void update_recv_state(conn_state_t* conn_state);

void printbuf(char* buf, int length) {
	int i;
	for (i = 0; i < length; i++) {
		printk(KERN_INFO "%02X", buf[i]);
	}
}

void th_read_request(pid_t pid, int sockfd, char* buf, long ret) {
        conn_state_t* conn_state;
	if ((conn_state = th_conn_state_get(pid, sockfd)) == NULL) {
		//printk(KERN_INFO "someone is sending from an unregistered socket");
		return;
	}
	if ((conn_state->send_buf = krealloc(conn_state->send_buf, conn_state->send_buf_length + ret, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "Oh noes!  krealloc failed!");
		return;
	}
	memcpy(conn_state->send_buf + conn_state->send_buf_length, buf, ret);
	conn_state->send_buf_length += ret;
	while (conn_state->state != IRRELEVANT && conn_state->state != TLS_SERVER_UNKNOWN && conn_state->state != TLS_SERVER_NEW && conn_state->state != TLS_SERVER_HELLO && conn_state->send_buf_length >= conn_state->send_bytes_to_read) {
		update_send_state(conn_state);
	}
	if (conn_state->state == IRRELEVANT) {
		print_call_info(sockfd, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(pid, sockfd);
	}
	return;
}

void th_read_response(pid_t pid, int sockfd, char* buf, long ret) {
	conn_state_t* conn_state;
	if ((conn_state = th_conn_state_get(pid, sockfd)) == NULL) {
		return;
	}
	if (ret == 0) {
		print_call_info(sockfd, "remote host closed socket");
		th_conn_state_delete(pid, sockfd);
		return;
	}
        if ((conn_state->recv_buf = krealloc(conn_state->recv_buf, conn_state->recv_buf_length + ret, GFP_KERNEL)) == NULL) {
                printk(KERN_ALERT "Oh noes!  krealloc failed!");
                return;
        }
        memcpy(conn_state->recv_buf + conn_state->recv_buf_length, buf, ret);
        conn_state->recv_buf_length += ret;
	//printk(KERN_ALERT "recv_buf_length is %u", conn_state->recv_buf_length);

        while (conn_state->state != IRRELEVANT && conn_state->recv_buf_length >= conn_state->recv_bytes_to_read) {
                update_recv_state(conn_state);
        }
        if (conn_state->state == IRRELEVANT) {
                print_call_info(sockfd, "No longer interested in socket, ceasing monitoring");      
                th_conn_state_delete(pid, sockfd);
        }	
	return;
}

void update_send_state(conn_state_t* conn_state) {
	char* cs_buf = NULL;
	int sockfd = conn_state->socketfd;
	unsigned char tls_major_version;
	unsigned char tls_minor_version;
	unsigned short tls_record_length;
	switch (conn_state->state) {
		case TLS_CLIENT_UNKNOWN:
			if (conn_state->send_buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
				print_call_info(sockfd, "may be doing SSL");
				conn_state->state = TLS_CLIENT_NEW;
				conn_state->send_bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
			}
			else {
				conn_state->state = IRRELEVANT;
			}
			break;
		case TLS_CLIENT_NEW:
			cs_buf = conn_state->send_buf;
			printbuf(cs_buf, TH_TLS_RECORD_HEADER_SIZE);
			tls_major_version = cs_buf[1];
			tls_minor_version = cs_buf[2];
			tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
			printk(KERN_INFO "SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
			conn_state->send_bytes_to_read = tls_record_length;
			conn_state->state = TLS_CLIENT_HELLO;
			break;
		case TLS_CLIENT_HELLO:
			print_call_info(sockfd, "read all of CLIENT_HELLO");
			conn_state->state = TLS_SERVER_UNKNOWN;
			conn_state->recv_bytes_to_read = TH_TLS_HANDSHAKE_IDENTIFIER_SIZE;
			break;
		case IRRELEVANT:
			// Should never get here
			break;
		default:
			//printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	return;
}

void update_recv_state(conn_state_t* conn_state) {
        char* cs_buf = NULL;
        int sockfd = conn_state->socketfd;
        unsigned char tls_major_version;
        unsigned char tls_minor_version;
        unsigned short tls_record_length;
	switch(conn_state->state) {
		case TLS_SERVER_UNKNOWN:
                        if (conn_state->recv_buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
                                print_call_info(sockfd, "remote may be doing SSL");
                                conn_state->state = TLS_SERVER_NEW;
                                conn_state->recv_bytes_to_read = TH_TLS_RECORD_HEADER_SIZE;
				//printk(KERN_ALERT "recv buf length is %u and toread is: %d", conn_state->recv_buf_length, conn_state->recv_bytes_to_read);
                        }
                        else {
                                conn_state->state = IRRELEVANT;
                        }
			break;
		case TLS_SERVER_NEW:
                        cs_buf = conn_state->recv_buf;
                        printbuf(cs_buf, TH_TLS_RECORD_HEADER_SIZE);
                        tls_major_version = cs_buf[1];
                        tls_minor_version = cs_buf[2];
                        tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
                        printk(KERN_INFO "Remote: SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
                        conn_state->recv_bytes_to_read = tls_record_length;
			conn_state->state = TLS_SERVER_HELLO;
			break;
		case TLS_SERVER_HELLO:
			conn_state->state = IRRELEVANT;
			print_call_info(sockfd, "read all of SERVER_HELLO");
			break;
		case TLS_CLIENT_UNKNOWN: // temporarily just ignore connections made asyncronously
		case TLS_CLIENT_NEW:
		case TLS_CLIENT_HELLO:
			conn_state->state = IRRELEVANT;
			break;
		case TLS_SERVER_CERTIFICATE:
		case TLS_ESTABLISHED:
		default:
			printk(KERN_ALERT "Unknown connection state!");
			conn_state->state = IRRELEVANT;
			break;
	}
	return;
}

