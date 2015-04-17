#ifndef _TEST_HANDLER_H
#define _TEST_HANDLER_H

void* state_init(pid_t pid);
void state_free(void* buf_state);
int copy_to_handler(void* buf_state, void* src_buf, size_t length);
int update_state(void* buf_state);
int copy_to_send_buffer(void* buf_state, void** bufptr, size_t* length);
int copy_to_user_buffer(void* buf_state, void __user *dst_buf, size_t length);
int num_bytes_to_forward(void* buf_state);
int update_bytes_forwarded(void* buf_state, size_t forwarded);
int get_state(void* buf_state);
int get_bytes_to_read(void* buf_state);

#endif
