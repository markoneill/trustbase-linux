#include <linux/sched.h>
#include <linux/slab.h>

#include "secure_handshake_parser.h"
#include "connection_state.h"
#include "utils.h"


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
	switch (conn_state->state) {
		case UNKNOWN:
			if (conn_state->data_length >= 1) {
				if (conn_state->buf[0] == TLS_HANDSHAKE_IDENTIFIER) {
					print_call_info(sockfd, "may be doing SSL");
				}
				else {
					printk(KERN_INFO "not doing ssl. would delete here");
					//th_delete();
				}
			}
			if (conn_state->data_length >= TLS_RECORD_HEADER_SIZE) {
				printk(KERN_INFO "tls record header: %02x", *((int*)(conn_state->buf+1)));
			}
			break;
		case IRRELEVANT:
			break;
		default:
			printk(KERN_ALERT "Unknown connection state!");
			break;
	}
	//if (conn_state->state == UNKNOWN && conn_statedata_length > 1) {
	//}
}


