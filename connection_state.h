#ifndef _TH_CONNECTION_STATE_H
#define _TH_CONNECTION_STATE_H

typedef enum state_t {
	IRRELEVANT,
	TLS_CLIENT_UNKNOWN,
	TLS_CLIENT_NEW,
	TLS_CLIENT_HELLO,
	TLS_SERVER_UNKNOWN,
	TLS_SERVER_NEW,
	TLS_SERVER_HELLO,
	TLS_SERVER_CERTIFICATE,
	TLS_ESTABLISHED
} state_t;

typedef struct conn_state_t {
        unsigned int key;
        pid_t pid;
        unsigned int socketfd;
        struct hlist_node hash;
	state_t state;
	size_t send_buf_length;
	size_t recv_buf_length;
	size_t send_bytes_to_read;
	size_t recv_bytes_to_read;
	char* send_buf;
	char* recv_buf;
} conn_state_t;

void th_conn_state_free(conn_state_t* conn_state);
void th_conn_state_create(pid_t pid, unsigned int socketfd);
conn_state_t* th_conn_state_get(pid_t pid, int fd);
void th_conn_state_free_all(void);
void th_conn_state_init_all(void);
void th_conn_state_print_all(void);
int th_conn_state_delete(pid_t pid, unsigned int fd);

#endif
