#ifndef _SECURE_HANDSHAKE_PARSER_H
#define _SECURE_HANDSHKAE_PARSER_H

#include "connection_state.h"

#define TH_TLS_HANDSHAKE_IDENTIFIER	0x16
#define TH_TLS_RECORD_HEADER_SIZE		5
#define TH_TLS_HANDSHAKE_IDENTIFIER_SIZE	1

#define TH_SEND	1
#define TH_RECV	0

int th_parse_comm(pid_t pid, struct socket* sock, char* buf, long ret, int sendrecv);
int th_optimistic_parse_send(pid_t pid, struct socket* sock, char* buf, long size);
int th_is_tracking(pid_t pid, struct socket* sock);
void* th_get_forwarding_base(pid_t pid, struct socket* sock);
int th_restore_state(pid_t pid, struct socket* sock);

/* New Stuff */
int th_copy_to_state(buf_state_t* buf_state, void* src_buf, size_t length);
int th_update_conn_state(conn_state_t* conn_state, buf_state_t* buf_state);
int th_fill_send_buffer(buf_state_t* buf_state, void** bufptr, size_t* length);
int th_update_bytes_forwarded(buf_state_t* buf_state, size_t forwarded);
#endif
