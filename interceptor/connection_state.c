/**
 * @file interceptor/connection_state.c
 * @brief The connection state functions.
 */

#include <linux/hashtable.h> // For global conn state hash table
#include <linux/slab.h> // For allocations
#include "connection_state.h"

unsigned int allocsminusfrees;
#define HASH_TABLE_BITSIZE	8
static DEFINE_HASHTABLE(conn_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(conn_state_lock);

static void conn_state_free(conn_state_t* conn_state);

void conn_state_free(conn_state_t* conn_state) {
	kfree(conn_state);
	allocsminusfrees--;
	return;
}

/**
 * Finds a connection state in the hash table.
 * @param pid The desired connection's Process ID.
 * @param sock A pointer to socket struct for the connection.
 * @return The connection state
 */
conn_state_t* conn_state_get(pid_t pid, struct socket* sock) {
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

/**
 * Creates a connection state with no filled state and adds it to the hash table.
 * @param pid The desired connection's Process ID.
 * @param sock A pointer to socket struct for the connection.
 * @return a pointer to the new connection state
 */
conn_state_t* conn_state_create(pid_t pid, struct socket* sock) {
	conn_state_t* new_conn_state = NULL;
	if ((new_conn_state = kmalloc(sizeof(conn_state_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed when creating connection state");
		return NULL;
	}
	allocsminusfrees++;
	new_conn_state->pid = pid;
	new_conn_state->sock = sock;
	new_conn_state->key = pid ^ (unsigned long)sock;
	new_conn_state->queued_send_ret = 1; // this value needs to be positive initially
	new_conn_state->queued_recv_ret = 1; // this value needs to be positive initially
	new_conn_state->state = NULL;
	// Add to hash table
	spin_lock(&conn_state_lock);
	hash_add(conn_table, &new_conn_state->hash, new_conn_state->key);
	spin_unlock(&conn_state_lock);
	return new_conn_state;
}

/**
 * A debug tool to print all the stored connection states in the hash.
 */
void conn_state_print_all(void) {
	int bkt;
	conn_state_t* conn_state_it;
	hash_for_each(conn_table, bkt, conn_state_it, hash) {
		printk(KERN_INFO "bucket [%d] has pid value %d and socket value %p", bkt, conn_state_it->pid, conn_state_it->sock);
	}
	return;
}

/**
 * Initiates the table of connection states.
 * @remark hash_init is a macro that checks its own pre-conditions.
 */
void conn_state_init_all(void) {
	allocsminusfrees = 0;
	hash_init(conn_table);
	return;
}

/**
 * Deletes all of the connections in the hash table.
 */
void conn_state_delete_all(void) {
	int bkt;
	conn_state_t* conn_state_it;
	struct hlist_node tmp;
	struct hlist_node* tmpptr = &tmp;
	spin_lock(&conn_state_lock);
	hash_for_each_safe(conn_table, bkt, tmpptr, conn_state_it, hash) {
		printk(KERN_INFO "Deleting things in bucket [%d] with pid value %d and socket value %p", bkt, conn_state_it->pid, conn_state_it->sock);
		hash_del(&conn_state_it->hash);
		conn_state_free(conn_state_it);
	}
	spin_unlock(&conn_state_lock);
	printk(KERN_INFO "kallocs minus kfrees: %i", allocsminusfrees);
	return;
}

/**
 * Deletes a single connection state.
 * @return 1 if a connection was found and deleted, 0 otherwise
 */
int conn_state_delete(pid_t pid, struct socket* sock) {
	int found = 0;
	conn_state_t* conn_state_it;
	spin_lock(&conn_state_lock);
        hash_for_each_possible(conn_table, conn_state_it, hash, pid ^ (unsigned long)sock) {
		if (conn_state_it->pid == pid && conn_state_it->sock == sock) {
			hash_del(&conn_state_it->hash);
			conn_state_free(conn_state_it);
			found = 1;
			break;
		}
	}
	spin_unlock(&conn_state_lock);
	return found;
}

