#ifndef _SECURE_HANDSHAKE_PARSER_H
#define _SECURE_HANDSHKAE_PARSER_H

#include "connection_state.h"

#define TH_TLS_HANDSHAKE_IDENTIFIER	0x16
#define TH_TLS_RECORD_HEADER_SIZE		5
#define TH_TLS_HANDSHAKE_IDENTIFIER_SIZE	1

typedef enum state_t {
	UNKNOWN,
	HANDSHAKE_LAYER,
	RECORD_LAYER,
	CLIENT_HELLO_SENT,
	SERVER_CERTIFICATES_SENT,
	IRRELEVANT
} state_t;

typedef struct buf_state_t {
	state_t	state;
	pid_t pid;
	size_t buf_length;
	size_t bytes_read;
	size_t bytes_to_read;
	size_t bytes_forwarded;
	size_t bytes_to_forward;
	char* buf;
} buf_state_t;


int th_send_to_proxy(void* buf_state, void* src_buf, size_t length);
int th_update_state(void* buf_state);
int th_fill_send_buffer(void* buf_state, void** bufptr, size_t* length);
int th_num_bytes_to_forward(void* buf_state);
int th_update_bytes_forwarded(void* buf_state, size_t forwarded);
int th_copy_to_user_buffer(void* buf_state, void __user *dst_buf, size_t length);
inline size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state);
inline int th_buf_state_can_transition(buf_state_t* buf_state);
void* th_buf_state_init(pid_t pid);
void th_buf_state_free(void* buf_state);
int th_get_state(void* buf_state);
int th_get_bytes_to_read(void* buf_state);

#endif
