#include <linux/kernel.h>
#include <linux/sched.h>
#include "utils.h"

void print_call_info(const char* str) {
	struct task_struct* tgptr = pid_task(find_vpid(current->tgid), PIDTYPE_PID);
	printk(KERN_INFO "%s (PID: %i): %s", tgptr->comm, current->pid, str);
}

