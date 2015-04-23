#ifndef _HANDSHAKE_HANDLER_H
#define _HANDSHAKE_HANDLER_H

#include <linux/semaphore.h>

#define TH_TLS_HANDSHAKE_IDENTIFIER	0x16
#define TH_TLS_RECORD_HEADER_SIZE		5
#define TH_TLS_HANDSHAKE_IDENTIFIER_SIZE	1

typedef enum tls_state_t {
	UNKNOWN,
	HANDSHAKE_LAYER,
	RECORD_LAYER,
	CLIENT_HELLO_SENT,
	SERVER_CERTIFICATES_SENT,
	IRRELEVANT,
} tls_state_t;

typedef struct buf_state_t {
	tls_state_t state;
	size_t buf_length;
	size_t bytes_read;
	size_t bytes_to_read;
	size_t user_cur;
	size_t user_cur_max;
	size_t last_payload_length;
	char* buf;
} buf_state_t;

typedef enum interest_state_t {
	INTERESTED,
	UNINTERTED,
} interest_state_t;

typedef struct handler_state_t {
	struct semaphore sem;
	interest_state_t interest;
	pid_t pid;
	buf_state_t recv_state;
	buf_state_t send_state;
} handler_state_t;

void* th_state_init(pid_t pid);
void th_state_free(void* buf_state);
int th_get_state(void* state);
int th_give_to_handler_send(void* state, void* src_buf, size_t length);
int th_give_to_handler_recv(void* state, void* src_buf, size_t length);
int th_update_state_send(void* state);
int th_update_state_recv(void* state);
int th_fill_send_buffer(void* state, void** bufptr, size_t* length);
int th_copy_to_user_buffer(void* state, void __user *dst_buf, size_t length);
int th_num_bytes_to_forward_send(void* state);
int th_num_bytes_to_forward_recv(void* state);
int th_update_bytes_forwarded_send(void* state, size_t forwarded);
int th_update_bytes_forwarded_recv(void* state, size_t forwarded);
int th_get_bytes_to_read_send(void* state);
int th_get_bytes_to_read_recv(void* state);

#endif
