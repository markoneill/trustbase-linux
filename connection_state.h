#ifndef _TH_CONNECTION_STATE_H
#define _TH_CONNECTION_STATE_H

typedef struct conn_state_ops_t {
	void* (*send_state_init)(void);
	void* (*recv_state_init)(void);
	void (*send_state_free)(void* send_state);
	void (*recv_state_free)(void* recv_state);
	int (*send_to_proxy)(void* send_state, void* src_buf, size_t length);
	int (*update_send_state)(void* send_state);
	int (*update_recv_state)(void* recv_state);
	int (*fill_send_buffer)(void* send_state, void** bufptr, size_t* length);
	int (*num_send_bytes_to_forward)(void* send_state);
	int (*num_recv_bytes_to_forward)(void* recv_state);
	int (*inc_send_bytes_forwarded)(void* send_state, size_t forwarded);
	int (*inc_recv_bytes_forwarded)(void* recv_state, size_t forwarded);
	int (*bytes_to_read)(void* recv_state);
	int (*get_send_state)(void* send_state);
	int (*get_recv_state)(void* recv_state);
	int (*copy_to_user)(void* buf_state, void __user *dst_buf, size_t length);
} conn_state_ops_t;

typedef struct conn_state_t {
        unsigned long key;
        pid_t pid;
	struct socket* sock;
        struct hlist_node hash;
	void* send_state;
	void* recv_state;
	int queued_send_ret;
	int queued_recv_ret;
	conn_state_ops_t* ops;
} conn_state_t;


void th_conn_state_free(conn_state_t* conn_state);
void conn_state_create(pid_t pid, struct socket* sock, conn_state_ops_t* ops);
conn_state_t* th_conn_state_get(pid_t pid, struct socket* sock);
void th_conn_state_free_all(void);
void th_conn_state_init_all(void);
void th_conn_state_print_all(void);
int th_conn_state_delete(pid_t pid, struct socket* sock);


#endif
