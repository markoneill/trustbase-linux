#ifndef _TH_CONNECTION_STATE_H
#define _TH_CONNECTION_STATE_H

typedef struct conn_state_t {
        unsigned int key;
        pid_t pid;
        unsigned int socketfd;
        struct hlist_node hash;
} conn_state_t;

void th_delete_conn_state(conn_state_t* conn_state);
void th_create_conn_state(pid_t pid, unsigned int socketfd);
void th_conn_state_free_all(void);
void th_conn_state_init_all(void);
void th_conn_state_print_all(void);
int th_conn_state_delete(pid_t pid, unsigned int fd);

#endif
