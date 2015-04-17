#include <linux/slab.h>
#include <asm/uaccess.h>

#include "test_handler.h"


typedef struct buf_state_t {
	int state;
	pid_t pid;
	size_t buf_length;
	size_t bytes_read;
	size_t bytes_to_read;
	size_t bytes_forwarded;
	size_t bytes_to_forward;
	char* buf;
} buf_state_t;

static void replace_bytes(buf_state_t*, char c, char r);
void* state_init(pid_t pid) {
	buf_state_t* buf_state = kmalloc(sizeof(buf_state_t), GFP_KERNEL);
	*buf_state = (buf_state_t) {
		.state = 1,
		.pid = pid,
		.buf_length = 0,
		.bytes_read = 0,
		.bytes_to_read = 0,
		.bytes_forwarded = 0,
		.bytes_to_forward = 0,
		.buf = NULL,
	};
	return buf_state;
}
void state_free(void* buf_state) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	if (bs->buf != NULL) {
		kfree(bs->buf);
	}
	return;
}
int copy_to_handler(void* buf_state, void* src_buf, size_t length) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	if ((bs->buf = krealloc(bs->buf, bs->buf_length + length, GFP_KERNEL)) == NULL) {
		return -1;
	}
	memcpy(bs->buf + bs->buf_length, src_buf, length);
	bs->buf_length += length;
	return 0;
}
int update_state(void* buf_state) {
	int max_compare;
	buf_state_t* bs = (buf_state_t*)buf_state;
	max_compare = bs->buf_length < 4 ? bs->buf_length : 4;
	bs->bytes_to_read = 4;
	if (strncmp(bs->buf, "test",max_compare) != 0) {
		bs->bytes_to_forward = bs->buf_length;
		bs->state = 0;
		printk(KERN_ALERT "Not interested in socket anymore");
		return 0;
	}
	replace_bytes(bs, 'e', 'b');
	bs->bytes_to_read = 0;
	bs->state = 0;
	bs->bytes_to_forward += bs->buf_length;
	return 0;
}
int copy_to_send_buffer(void* buf_state, void** bufptr, size_t* length) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	*length = bs->bytes_to_forward;
	*bufptr = bs->buf + bs->bytes_forwarded;
	return 0;
}
int copy_to_user_buffer(void* buf_state, void __user *dst_buf, size_t length) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	if (copy_to_user(dst_buf, bs->buf + bs->bytes_forwarded, length) != 0) {
		return -1;
	}
	return 0;
}
int num_bytes_to_forward(void* buf_state) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	return bs->bytes_to_forward;
}
int update_bytes_forwarded(void* buf_state, size_t forwarded) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	bs->bytes_forwarded += forwarded;
	return 0;
}
int get_state(void* buf_state) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	return bs->state;
}
int get_bytes_to_read(void* buf_state) {
	buf_state_t* bs = (buf_state_t*)buf_state;
	return bs->bytes_to_read;
}
void replace_bytes(buf_state_t* bs, char c, char r) {
	int length;
	int i;
	length = bs->buf_length;
	for (i = 0; i < length; i++) {
		if (bs->buf[i] == c) {
			bs->buf[i] = r;
		}
	}
	return;
}
