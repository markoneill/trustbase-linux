#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "connection_state.h"
#include "secure_handshake_parser.h"
#include "utils.h"

extern unsigned int allocsminusfrees;
#define HASH_TABLE_BITSIZE	8
static DEFINE_HASHTABLE(conn_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(conn_state_lock);

static void th_buf_state_init(buf_state_t* buf_state);

void th_conn_state_free(conn_state_t* conn_state) {
	if (conn_state->send_state.buf != NULL) {
		kfree(conn_state->send_state.buf);
	}
	if (conn_state->recv_state.buf != NULL) {
		kfree(conn_state->recv_state.buf);
	}
	kfree(conn_state);
	allocsminusfrees--;
	return;
}

conn_state_t* th_conn_state_get(pid_t pid, struct socket* sock) {
	conn_state_t* conn_state = NULL;
	conn_state_t* conn_state_it;
	hash_for_each_possible(conn_table, conn_state_it, hash, pid ^ (unsigned long)sock) {
                if (conn_state_it->pid == pid && conn_state_it->sock == sock) {
                        conn_state = conn_state_it;
                        break;
                }
        }
	return conn_state;
}


void th_conn_state_create(pid_t pid, struct socket* sock) {
	conn_state_t* new_conn_state = NULL;
	if ((new_conn_state = kmalloc(sizeof(conn_state_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed when creating connection state");
	}
	allocsminusfrees++;
	new_conn_state->pid = pid;
	new_conn_state->sock = sock;
	new_conn_state->key = pid ^ (unsigned long)sock;
	th_buf_state_init(&new_conn_state->send_state);
	th_buf_state_init(&new_conn_state->recv_state);
	// Add to hash table
	spin_lock(&conn_state_lock);
	hash_add(conn_table, &new_conn_state->hash, new_conn_state->key);
	spin_unlock(&conn_state_lock);
	return;
}

void th_conn_state_print_all(void) {
	int bkt;
	conn_state_t* conn_state_it;
	hash_for_each(conn_table, bkt, conn_state_it, hash) {
		printk(KERN_INFO "bucket [%d] has pid value %d and socket value %p", bkt, conn_state_it->pid, conn_state_it->sock);
	}
	return;
}

void th_conn_state_init_all(void) {
	allocsminusfrees = 0;
	hash_init(conn_table);
	return;
}

void th_conn_state_free_all(void) {
	int bkt;
	conn_state_t* conn_state_it;
	struct hlist_node tmp;
	struct hlist_node* tmpptr = &tmp;
	spin_lock(&conn_state_lock);
	hash_for_each_safe(conn_table, bkt, tmpptr, conn_state_it, hash) {
		printk(KERN_INFO "Deleting things in bucket [%d] with pid value %d and socket value %p", bkt, conn_state_it->pid, conn_state_it->sock);
		hash_del(&conn_state_it->hash);
		th_conn_state_free(conn_state_it);
	}
	spin_unlock(&conn_state_lock);
	printk(KERN_INFO "kallocs minus kfrees: %i", allocsminusfrees);
	return;
}

int th_conn_state_delete(pid_t pid, struct socket* sock) {
	int found = 0;
	conn_state_t* conn_state_it;
	spin_lock(&conn_state_lock);
        hash_for_each_possible(conn_table, conn_state_it, hash, pid ^ (unsigned long)sock) {
		if (conn_state_it->pid == pid && conn_state_it->sock == sock) {
			hash_del(&conn_state_it->hash);
			th_conn_state_free(conn_state_it);
			found = 1;
			break;
		}
	}
	spin_unlock(&conn_state_lock);
	return found;
}

size_t th_buf_state_get_num_bytes_unread(buf_state_t* buf_state) {
	return buf_state->buf_length - buf_state->bytes_read;
}

int th_buf_state_can_transition(buf_state_t* buf_state) {
	size_t unread = th_buf_state_get_num_bytes_unread(buf_state);
	//printk(KERN_ALERT "Unread: %u", unread);
	return buf_state->bytes_to_read && unread && unread >= buf_state->bytes_to_read;
}

void th_buf_state_init(buf_state_t* buf_state) {
	buf_state->buf_length = 0;
	buf_state->bytes_read = 0;
	buf_state->bytes_forwarded = 0;
	buf_state->bytes_to_forward = 0;
	buf_state->last_ret = 1; // Positive value required
	buf_state->bytes_to_read = TH_TLS_HANDSHAKE_IDENTIFIER_SIZE;
	buf_state->buf = NULL;
	buf_state->state = UNKNOWN;
	return;
}

