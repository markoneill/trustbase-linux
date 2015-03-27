#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
#include <asm/byteorder.h>
#include <linux/net.h>

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

void th_read_request(pid_t pid, struct socket* sock, char* new_buf, long ret) {
        conn_state_t* conn_state;
	buf_state_t* buf_state;
	if ((conn_state = th_conn_state_get(pid, sock)) == NULL) {
		//printk(KERN_INFO "someone is sending from an unregistered socket");
		return;
	}
	buf_state = &conn_state->send_state;
	if ((buf_state->buf = krealloc(buf_state->buf, buf_state->buf_length + ret, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "Oh noes!  krealloc failed!");
		return;
	}
	memcpy(buf_state->buf + buf_state->buf_length, new_buf, ret);
	buf_state->buf_length += ret;
	while (th_buf_state_can_transition(buf_state)) {
		update_send_state(conn_state);
	}
	if (buf_state->state == IRRELEVANT) {
		print_call_info(sock, "No longer interested in socket, ceasing monitoring");
		th_conn_state_delete(pid, sock); // this isn't thread safe 
	}
	return;
}

/*void th_read_response(pid_t pid, struct socket* sock, char* buf, long ret) {
	conn_state_t* conn_state;
	if (ret <= 0) {
		return;
	}
        if ((conn_state->recv_buf = krealloc(conn_state->recv_buf, conn_state->recv_buf_length + ret, GFP_KERNEL)) == NULL) {
                printk(KERN_ALERT "Oh noes!  krealloc failed!");
                return;
        }
        memcpy(conn_state->recv_buf + conn_state->recv_buf_length, buf, ret);
        conn_state->recv_buf_length += ret;
        
	while (th_conn_state_can_transition_recv(conn_state)) {
		update_recv_state(conn_state);
        }

        if (conn_state->state == IRRELEVANT) {
        	print_call_info(sock, "No longer interested in socket, cease monitoring");
                th_conn_state_delete(pid, sock);
        }
        return;
}*/

/*void th_read_response(pid_t pid, struct socket* sock, char* buf, long ret) {
	conn_state_t* conn_state;
	if ((conn_state = th_conn_state_get(pid, sock)) == NULL) {
		return;
	}
	if (ret == 0) {
		print_call_info(sock, "remote host closed socket");
		th_conn_state_delete(pid, sock);
		return;
	}
        if ((conn_state->recv_buf = krealloc(conn_state->recv_buf, conn_state->recv_buf_length + ret, GFP_KERNEL)) == NULL) {
                printk(KERN_ALERT "Oh noes!  krealloc failed!");
                return;
        }
        memcpy(conn_state->recv_buf + conn_state->recv_buf_length, buf, ret);
        conn_state->recv_buf_length += ret;
	//printk(KERN_ALERT "recv_buf_length is %u", conn_state->recv_buf_length);

	//printbuf(conn_state->recv_buf, conn_state->recv_buf_length);
        while (conn_state->state != IRRELEVANT && conn_state->recv_buf_length >= conn_state->recv_bytes_to_read) {
		//printk(KERN_INFO "heyu");
                update_recv_state(conn_state);
        }
        if (conn_state->state == IRRELEVANT) {
		print_call_info(sock, "No longer interested in socket, ceasing monitoring");      
                th_conn_state_delete(pid, sock);
        }
	return;
}*/

void update_send_state(conn_state_t* conn_state) {
	char* cs_buf = NULL;
	struct socket* sock;
	unsigned char tls_major_version;
	unsigned char tls_minor_version;
	unsigned short tls_record_length;
	buf_state_t* buf_state;
	buf_state = &conn_state->send_state;
	sock = conn_state->sock;
	switch (buf_state->state) {
		case UNKNOWN:
			buf_state->bytes_read += buf_state->bytes_to_read;
			if (buf_state->buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
				print_call_info(sock, "may be doing SSL");
				buf_state->state = RECORD_LAYER;
				buf_state->bytes_to_read = TH_TLS_RECORD_HEADER_SIZE-1; // minus one because we've just read the first byte (to support early failure)
			}
			else {
				buf_state->bytes_to_read = 0;
				buf_state->state = IRRELEVANT;
			}
			break;
		case RECORD_LAYER:
			cs_buf = buf_state->buf;
			tls_major_version = cs_buf[1];
			tls_minor_version = cs_buf[2];
			tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
			printk(KERN_INFO "SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
			buf_state->state = HANDSHAKE_LAYER;
			buf_state->bytes_read += buf_state->bytes_to_read;
			buf_state->bytes_to_read = tls_record_length;
			break;
		case HANDSHAKE_LAYER:
			cs_buf = buf_state->buf;
			if (cs_buf[buf_state->bytes_read] == 0x01) {
				print_call_info(sock, "Sent a Client Hello");
			}
			else {
				print_call_info(sock, "Someone sent a weird thing");
			}
			buf_state->bytes_read += buf_state->bytes_to_read;
			buf_state->bytes_to_read = 0;
			buf_state->state = IRRELEVANT;
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

/*void update_recv_state(conn_state_t* conn_state) {
	switch(conn_state->recv_state) {
		case 
	}
	return;
}*/

/*void update_recv_state(conn_state_t* conn_state) {
        char* cs_buf = NULL;
        struct socket* sock = conn_state->sock;
        unsigned char tls_major_version;
        unsigned char tls_minor_version;
        unsigned short tls_record_length;
	switch(conn_state->state) {
		case TLS_SERVER_UNKNOWN:
			//printk(KERN_INFO "recveived: %02X hai", conn_state->recv_buf[0]);
                        if (conn_state->recv_buf[0] == TH_TLS_HANDSHAKE_IDENTIFIER) {
				//print_call_info(sock, "remote may be doing SSL");
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
                        //printbuf(cs_buf, TH_TLS_RECORD_HEADER_SIZE);
                        tls_major_version = cs_buf[1];
                        tls_minor_version = cs_buf[2];
                        tls_record_length = be16_to_cpu(*(unsigned short*)(cs_buf+3));
                        printk(KERN_INFO "Remote: SSL version %d.%d record size: %d", tls_major_version, tls_minor_version, tls_record_length);
                        conn_state->recv_bytes_to_read = tls_record_length;
			conn_state->state = TLS_SERVER_HELLO;
			break;
		case TLS_SERVER_HELLO:
			conn_state->state = TLS_SERVER_CERTIFICATE;
			print_call_info(sock, "Sent a Server Hello");
			break;
		case TLS_SERVER_CERTIFICATE:
			print_call_info(sock, "Received Server Certificate");
		case TLS_CLIENT_UNKNOWN: // temporarily just ignore connections made asyncronously
		case TLS_CLIENT_NEW:
		case TLS_CLIENT_HELLO:
			conn_state->state = IRRELEVANT;
			break;
		case TLS_ESTABLISHED:
		default:
			printk(KERN_ALERT "Unknown connection state!");
			conn_state->state = IRRELEVANT;
			break;
	}
	return;
}*/

