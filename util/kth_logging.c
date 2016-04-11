#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "kth_logging.h"

// Magic Numbers
#define PROCESS_INFO_LENGTH	64
#define MAX_LOG_LENGTH		1024

/* FIFO linked list, to store log entries */
typedef struct log_msg_t {
	char* message;
	thlog_level_t level;
	struct log_msg_t* next;
	char sent;
}log_msg_t;

static log_msg_t* log_head;
static log_msg_t* log_tail;

static int log_new(thlog_level_t level, char* msg);
static void log_remove(log_msg_t* entry);

/* Proc File with Sequence File for communication */
static void * kth_seq_start(struct seq_file *m, loff_t *pos);
static int kth_seq_show(struct seq_file *m, void *v);
static void * kth_seq_next(struct seq_file *m, void *v, loff_t *pos);
static void kth_seq_stop(struct seq_file *m, void *v);

static void get_call_info(char* info);

static struct seq_operations kth_seq_ops = {
	.start = kth_seq_start,
	.show = kth_seq_show,
	.next = kth_seq_next,
	.stop = kth_seq_stop,
}; 

static int kthlog_open(struct inode *inode, struct file *file);

static const struct file_operations kth_file_ops = {
	.owner = THIS_MODULE,
	.open = kthlog_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

// Tells the proc file how to handle being opened
int kthlog_open(struct inode *inode, struct file *file) {
	return seq_open(file, &kth_seq_ops);
}

int kthlog_init() {
	struct proc_dir_entry *entry;

	log_head = NULL;
	log_tail = NULL;


	entry = proc_create(KTHLOG_FILENAME, 0440, NULL, &kth_file_ops);
	return 0;
}

void kthlog_exit() {
	remove_proc_entry(KTHLOG_FILENAME, NULL);
}

void kthlog(thlog_level_t level, const char* fmt, ...) {
	va_list args;
	char* log_message;

	if (level == LOG_PROCESS) {	
		log_message = (char*)kmalloc(MAX_LOG_LENGTH, GFP_KERNEL);
		get_call_info(log_message);
		va_start(args, fmt);
		vsnprintf(log_message + strlen(log_message), MAX_LOG_LENGTH - PROCESS_INFO_LENGTH, fmt, args);
		va_end(args);
	} else {
		log_message = (char*)kmalloc(MAX_LOG_LENGTH, GFP_KERNEL);
		
		va_start(args, fmt);
		vsnprintf(log_message, MAX_LOG_LENGTH, fmt, args);
		va_end(args);
	}
	
	log_new(level, log_message);
	
	return;
}

int log_new(thlog_level_t level, char* msg) {
	log_msg_t* entry;
	// Allocate new entry
	entry = (log_msg_t*)kmalloc(sizeof(*entry), GFP_KERNEL);
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
	entry->level = level;
	log_tail = entry;
	return 0;
}

void log_remove(log_msg_t* entry) {
	// This should only be called on the head
	// Set new head as next
	log_head = entry->next;
	if (log_head == NULL) {
		log_tail = NULL;
	}
	// Free the message string
	kfree(entry->message);
	// Free the entry
	kfree(entry);
}

void * kth_seq_start(struct seq_file *m, loff_t *pos) {
	return log_head;
}
int kth_seq_show(struct seq_file *m, void *v) {
	log_msg_t* entry;
	char* level;
	if (v == NULL) {
		return 0;
	}
	entry = (log_msg_t*)v;
	switch (entry->level) {
	case LOG_DEBUG:
	case LOG_PROCESS:
		level = "KDBG";
		break;
	case LOG_INFO:
		level = "KINF";
		break;
	case LOG_WARNING:
		level = "KWRN";
		break;
	case LOG_ERROR:
		level = "KERR";
		break;
	default:
		level = "KDBG";
	}
	seq_printf(m, "%s: %s\n", level, entry->message);
	entry->sent = 1;
	return 0;
}
void * kth_seq_next(struct seq_file *m, void *v, loff_t *pos) {
	log_msg_t* entry;
	// Inc the offset, just because
	(*pos)++;
	entry = (log_msg_t*)v;
	return entry->next;
}
void kth_seq_stop(struct seq_file *m, void *v) {
	while(log_head != NULL && log_head->sent == 1) {
		log_remove(log_head);
	}
}

void get_call_info(char* info) {
	struct task_struct* tgptr;
	tgptr = pid_task(find_vpid(current->tgid), PIDTYPE_PID);
	snprintf(info, PROCESS_INFO_LENGTH, "%s (PID: %i)(TGID: %i): ", tgptr->comm, current->pid, current->tgid);
}
