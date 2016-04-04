#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include "kth_logging.h"

/* FIFO linked list, to store log entries */
typedef struct log_msg_t {
	char* message;
	struct log_msg_t* next;
	char sent;
}log_msg_t;

static log_msg_t* log_head;
static log_msg_t* log_tail;

static void log_new(char* message);
static void log_remove(log_msg_t* entry);

/* Proc File with Sequence File for communication */
static struct proc_dir_entry* kthlog_file;

static void * kth_seq_start(struct seq_file *m, loff_t *pos);
static int kth_seq_show(struct seq_file *m, void *v);
static void * kth_seq_next(struct seq_file *m, void *v, loff_t *pos);
static void kth_seq_stop(struct seq_file *m, void *v);

static struct seq_operations kth_seq_ops = {
	.start = kth_seq_start;
	.show = kth_seq_show;
	.next = kth_seq_next;
	.stop = kth_seq_stop;
}; 

static int kthlog_open(struct inode *inode, struct file *file);

static const struct file_operations kth_file_ops = {
	.owner = THIS_MODULE,
	.open = kthlog_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

// Tells the proc file how to handle being opened
int kthlog_open(struct inode *inode, struct file *file) {
	return seq_open(file, &kth_seq_ops);
}

int kthlog_init() {
	struct proc_dir_entry *entry;

	log_head = NULL;
	log_tail = NULL;


	entry = create_proc_entry(KTHLOG_FILENAME, 0, NULL);
	if (entry) {
		entry->proc_fops = &kth_file_ops;
	}
	return 0;
}

void kthlog_exit() {
	remove_proc_entry(KTHLOG_FILENAME, NULL);
}

int log_new(const char* msg) {
	log_msg_t* entry;
	// Allocate new entry
	entry = (log_msg_t*)malloc(sizeof(*entry));
	if (entry == NULL) {
		// Ran out of memory
		return -1;
	}
	// Set tail's next as new entry
	if (log_tail == NULL) {
		log_head = entry;
	} else {
		log_tail->next = entry;
	}
	// Set new entry as new tail
	entry->next = NULL;
	entry->message = msg;
	entry->sent = 0;
	log_tail = entry;
	return 0;
}

void log_remove(log_msg_t* entry) {
	// This should only be called on the head
	// Set new head as next
	log_head = entry->next;
	if (log_head == NULL) {
		log_tail == NULL;
	}
	// Free the message string
	free(entry->message);
	// Free the entry
	free(entry);
}

void * kth_seq_start(struct seq_file *m, loff_t *pos) {
	return log_head;
}
int kth_seq_show(struct seq_file *m, void *v) {
	log_msg_t* entry;
	entry = (log_msg_t*)v;
	seq_printf(m, "%s\n", entry->message);
	entry->sent = 1;
	return 0;
}
void * kth_seq_next(struct seq_file *m, void *v, loff_t *pos) {
	log_msg_t* entry;
	entry = (log_msg_t*)v;
	return entry->next;
}
void kth_seq_stop(struct seq_file *m, void *v) {
	while(log_head != NULL && log_head->sent == 1) {
		log_remove(log_head);
	}
}
