/**
 * @file interceptor/connection_state.c
 * @brief The connection state functions.
 */

#ifndef _CONNECTION_STATE_H
#define _CONNECTION_STATE_H

typedef struct conn_state_t {
        unsigned long key;
        pid_t pid;
	/*struct socket* mitmsock;
	union {
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	int addr_len;*/
	struct socket* sock;
        struct hlist_node hash;
	void* state;
	int queued_send_ret;
	int queued_recv_ret;
} conn_state_t;


conn_state_t* conn_state_create(pid_t pid, struct socket* sock);
void conn_state_init_all(void);
int conn_state_delete(pid_t pid, struct socket* sock);
void conn_state_delete_all(void);
conn_state_t* conn_state_get(pid_t pid, struct socket* sock);
void th_conn_state_print_all(void);

#endif
