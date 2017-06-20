#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "ktb_logging.h"

// Magic Numbers
#define PROCESS_INFO_LENGTH	64
#define MAX_LOG_LENGTH		1024

/* FIFO linked list, to store log entries */
typedef struct log_msg_t {
	char* message;
	tblog_level_t level;
	struct log_msg_t* next;
	char sent;
}log_msg_t;

static log_msg_t* log_head;
static log_msg_t* log_tail;

static int log_new(tblog_level_t level, char* msg);
static void log_remove(log_msg_t* entry);

/* Proc File with Sequence File for communication */
static void * ktb_seq_start(struct seq_file *m, loff_t *pos);
static int ktb_seq_show(struct seq_file *m, void *v);
static void * ktb_seq_next(struct seq_file *m, void *v, loff_t *pos);
static void ktb_seq_stop(struct seq_file *m, void *v);

static void get_call_info(char* info);

static struct seq_operations ktb_seq_ops = {
	.start = ktb_seq_start,
	.show = ktb_seq_show,
	.next = ktb_seq_next,
	.stop = ktb_seq_stop,
}; 

static int ktblog_open(struct inode *inode, struct file *file);

static const struct file_operations ktb_file_ops = {
	.owner = THIS_MODULE,
	.open = ktblog_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

// Tells the proc file how to handle being opened
int ktblog_open(struct inode *inode, struct file *file) {
	return seq_open(file, &ktb_seq_ops);
}

int ktblog_init() {
	struct proc_dir_entry *entry;

	log_head = NULL;
	log_tail = NULL;


	entry = proc_create(KTBLOG_FILENAME, 00444, NULL, &ktb_file_ops);
	return 0;
}

void ktblog_exit() {
	remove_proc_entry(KTBLOG_FILENAME, NULL);
}

void ktblog(tblog_level_t level, const char* fmt, ...) {
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

void ktblog_buffer(void* buffer, int length) {
	unsigned char* msg;
	unsigned char* end;
	int i;
	int w;
	
	if (length > 1024) {
		length = 1024;
	}
	msg = (unsigned char*)kmalloc((length * 3) + 1, GFP_KERNEL | __GFP_NOFAIL);
	if (msg == NULL) {
		ktblog(LOG_DEBUG, "Could not allocate memory to print the buffer");
		return;
	}
	msg[0] = '\0';
	end = msg;
	for (i=0; i < length; i++) {
		// Sorry if this is messy, but it outputs the buffer as hex, grouping the output
		w = snprintf(end, 4, "%02x%s", ((unsigned char*)buffer)[i], ((i+1)%16)?((i+1)%2)?"":" ":"\n");
		end = end + w;
	}
	
	log_new(LOG_HEX, msg);
}

int log_new(tblog_level_t level, char* msg) {
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

void * ktb_seq_start(struct seq_file *m, loff_t *pos) {
	return log_head;
}
int ktb_seq_show(struct seq_file *m, void *v) {
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
	case LOG_HEX:
		seq_printf(m, "KDBG:HEX START:\n%s\nKDBG:HEX END:\n", entry->message);
		entry->sent = 1;
		return 0;;
	default:
		level = "KDBG";
	}
	seq_printf(m, "%s: %s\n", level, entry->message);
	entry->sent = 1;
	return 0;
}
void * ktb_seq_next(struct seq_file *m, void *v, loff_t *pos) {
	log_msg_t* entry;
	// Inc the offset, just because
	(*pos)++;
	entry = (log_msg_t*)v;
	return entry->next;
}
void ktb_seq_stop(struct seq_file *m, void *v) {
	while(log_head != NULL && log_head->sent == 1) {
		log_remove(log_head);
	}
}

void get_call_info(char* info) {
	struct task_struct* tgptr;
	tgptr = pid_task(find_vpid(current->tgid), PIDTYPE_PID);
	snprintf(info, PROCESS_INFO_LENGTH, "%s (PID: %i)(TGID: %i): ", tgptr->comm, current->pid, current->tgid);
}
