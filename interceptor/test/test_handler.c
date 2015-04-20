#include <linux/slab.h>
#include <asm/uaccess.h>

#include "test_handler.h"
#include "../../util/utils.h"


typedef struct buf_state_t {
	int state;
	size_t buf_length;
	size_t bytes_read;
	size_t bytes_to_read;
	size_t bytes_forwarded;
	size_t bytes_to_forward;
	size_t last_payload_size;
	char* buf;
} buf_state_t;

typedef struct handler_state_t {
	int interest;
	pid_t pid;
	buf_state_t recv_state;
	buf_state_t send_state;
} handler_state_t;

static void replace_bytes(buf_state_t*, char c, char r);
inline size_t buf_state_get_num_bytes_unread(buf_state_t* buf_state);
inline int buf_state_can_transition(buf_state_t* buf_state);
static void* buf_state_init(buf_state_t* buf_state);

// Interception helpers
static inline int copy_to_buf_state(buf_state_t* buf_state, void* src_buf, size_t length);

// Main proxy functionality
void* state_init(pid_t pid) {
	handler_state_t* state;
	state = kmalloc(sizeof(handler_state_t), GFP_KERNEL);
	print_call_info("state init");
	if (state != NULL) {
		state->pid = pid;
		state->interest = 1;
		buf_state_init(&state->send_state);
		buf_state_init(&state->recv_state);
	}
	return state;
}

void* buf_state_init(buf_state_t* buf_state) {
	buf_state->buf_length = 0;
	buf_state->bytes_read = 0;
	buf_state->bytes_forwarded = 0;
	buf_state->bytes_to_forward = 0;
	buf_state->bytes_to_read = 1;
	buf_state->buf = NULL;
	buf_state->state = 1;
	buf_state->last_payload_size = 0;
	return buf_state;
}

void state_free(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	print_call_info("state free");
	if (s->send_state.buf != NULL) {
		kfree(s->send_state.buf);
	}
	if (s->recv_state.buf != NULL) {
		kfree(s->recv_state.buf);
	}
	kfree(s);
	return;
}

int get_state(void* state) {
	handler_state_t* s = (handler_state_t*)state;
	print_call_info("get state");
	return s->interest;
}

int give_to_handler_send(void* state, void* src_buf, size_t length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	print_call_info("give_to_handler_send");
	return copy_to_buf_state(bs, src_buf, length);
}

int give_to_handler_recv(void* state, void* src_buf, size_t length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	return copy_to_buf_state(bs, src_buf, length);
}

int update_state_send(void* state) {
        int max_compare;
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
        max_compare = bs->buf_length < 4 ? bs->buf_length : 4;
	print_call_info("update_state_send");
        if (strncmp(bs->buf, "test", max_compare) != 0) {
		bs->bytes_to_forward += bs->last_payload_size;
                bs->state = 0;
                bs->bytes_to_read = 0;
		((handler_state_t*)state)->interest = 0;
                return 0;
        }
        printk(KERN_ALERT "Performing some tomfoolery on ur dataz");
        //replace_bytes(bs, 'e', 'b');
        bs->bytes_to_read = 0;
        bs->state = 0;
	bs->bytes_to_forward += bs->last_payload_size;
	((handler_state_t*)state)->interest = 0;
	return 0;
}

int update_state_recv(void* state) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	bs->bytes_to_forward += bs->last_payload_size;
	bs->bytes_to_read = 0;
	((handler_state_t*)state)->interest = 0;
	return 0;
}

int fill_send_buffer(void* state, void** bufptr, size_t* length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	print_call_info("fill_send_buffer");
	*length = bs->bytes_to_forward;
	*bufptr = bs->buf + bs->bytes_forwarded;
	return 0;
}

int copy_to_user_buffer(void* state, void __user *dst_buf, size_t length) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	if (copy_to_user(dst_buf, bs->buf + bs->bytes_forwarded, length) != 0) {
		return -1;
	}
	return 0;
}

int num_bytes_to_forward_send(void* state) {
	return ((handler_state_t*)state)->send_state.bytes_to_forward;
}

int num_bytes_to_forward_recv(void* state) {
	return ((handler_state_t*)state)->recv_state.bytes_to_forward;
}

int update_bytes_forwarded_send(void* state, size_t forwarded) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->send_state;
	bs->bytes_forwarded += forwarded;
	bs->bytes_to_forward -= forwarded;
	return 0;
}

int update_bytes_forwarded_recv(void* state, size_t forwarded) {
	buf_state_t* bs;
	bs = &((handler_state_t*)state)->recv_state;
	bs->bytes_forwarded += forwarded;
	bs->bytes_to_forward -= forwarded;
	return 0;
}

int get_bytes_to_read_send(void* state) {
	return ((handler_state_t*)state)->send_state.bytes_to_read;
}

int get_bytes_to_read_recv(void* state) {
	return ((handler_state_t*)state)->recv_state.bytes_to_read;
}

size_t buf_state_get_num_bytes_unread(buf_state_t* buf_state) {
	return buf_state->buf_length - buf_state->bytes_read;
}

int buf_state_can_transition(buf_state_t* buf_state) {
	size_t unread = buf_state_get_num_bytes_unread(buf_state);
	//printk(KERN_ALERT "Unread: %u", unread);
	return buf_state->bytes_to_read && unread && unread >= buf_state->bytes_to_read;
}

int copy_to_buf_state(buf_state_t* bs, void* src_buf, size_t length) {
	if ((bs->buf = krealloc(bs->buf, bs->buf_length + length, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "krealloc failed in copy_to_buf_state");
		return -1;
	}
	memcpy(bs->buf + bs->buf_length, src_buf, length);
	bs->buf_length += length;
	bs->last_payload_size = length;
	return 0;
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
