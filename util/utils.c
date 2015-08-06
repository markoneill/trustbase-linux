#include <linux/kernel.h>
#include <linux/sched.h>
#include "utils.h"

void print_call_info(const char* fmt, ...) {
	va_list args;
	struct task_struct* tgptr;
	tgptr = pid_task(find_vpid(current->tgid), PIDTYPE_PID);
	printk(KERN_INFO "%s (PID: %i) (Parent PID: %i): ", tgptr->comm, current->pid, current->parent->pid);
	va_start(args, fmt);
	vprintk(fmt, args);
	printk("\n");
	va_end(args);
	return;
}

