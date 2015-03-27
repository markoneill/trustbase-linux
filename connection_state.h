#ifndef _TH_CONNECTION_STATE_H
#define _TH_CONNECTION_STATE_H

typedef enum state_t {
	UNKNOWN,
	HANDSHAKE_LAYER,
	RECORD_LAYER,
	CLIENT_HELLO_SENT,
	IRRELEVANT
} state_t;

typedef struct buf_state_t {
	state_t	state;
	size_t buf_length;
	size_t bytes_read;
	size_t bytes_to_read;
	char* buf;
} buf_state_t;

typedef struct conn_state_t {
        unsigned long key;
        pid_t pid;
	struct socket* sock;
        struct hlist_node hash;
	buf_state_t send_state;
	buf_state_t recv_state;
} conn_state_t;

void th_conn_state_free(conn_state_t* conn_state);
void th_conn_state_create(pid_t pid, struct socket* sock);
conn_state_t* th_conn_state_get(pid_t pid, struct socket* sock);
void th_conn_state_free_all(void);
void th_conn_state_init_all(void);
void th_conn_state_print_all(void);
int th_conn_state_delete(pid_t pid, struct socket* sock);
inline size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state);
inline int th_buf_state_can_transition(buf_state_t* buf_state);

#endif
