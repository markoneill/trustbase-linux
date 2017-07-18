#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/pid.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>

#include "interceptor/interceptor.h" // For registering/unregistering proxy functions
#include "handshake-handler/communications.h" // For registering/unregistering netlink family
#include "handshake-handler/handshake_handler.h" // For referencing proxy functions
#include "util/ktb_logging.h" // For logging

// Kernel module parameters
static char* tb_path = "/usr/bin";
module_param(tb_path, charp, 0000);
MODULE_PARM_DESC(tb_path, "An absolute path to the Trustbase install location");

// Trustbase interception operations
proxy_handler_ops_t trustbase_ops;
// Userspace daemon pointers
struct task_struct* mitm_proxy_task;
struct task_struct* policy_engine_task;

static int __init loader_start(void);
static void __exit loader_end(void);

module_init(loader_start);
module_exit(loader_end);
MODULE_AUTHOR("Mark O'Neill");
MODULE_LICENSE("GPL");

int start_policy_engine(char* path);
int start_mitm_proxy(char* path);
int policy_engine_init(struct subprocess_info *info, struct cred *new);
int mitm_proxy_init(struct subprocess_info *info, struct cred *new);
int alt_call_usermodehelper(char *path, char **argv, char **envp, int wait, 
		int (*init)(struct subprocess_info *info, struct cred *new));
void stop_task(struct task_struct* task, int signal);

/**
 * the initial function that sets up the MITM proxy and handler
 * @see handshake-handler/handshake_handler.h
 * @post MITM proxy ready, and TCP function pointers point to Trustbase functions
 * @return an error code
 */
int __init loader_start(void) {
	// Register the proc file
	if (ktblog_init() != 0) {
		printk(KERN_ALERT "Unable to allocate memory for the proc file");
	}

	// Set up IPC module-policyengine interaction
	if (tb_register_netlink() != 0) {
		ktblog(LOG_ERROR, "Unable to register generic netlink family and ops for Trusthub");
		return -1;
	}

	trustbase_ops = (proxy_handler_ops_t) {
		.state_init = tb_state_init,
		.state_free = tb_state_free,
		.get_state = tb_get_state,
		.give_to_handler_send = tb_give_to_handler_send,
		.give_to_handler_recv = tb_give_to_handler_recv,
		.update_send_state = tb_update_state_send,
		.update_recv_state = tb_update_state_recv,
		.fill_send_buffer = tb_fill_send_buffer, // XXX rename this
		.copy_to_user = tb_copy_to_user_buffer, // XXX rename this
		.num_send_bytes_to_forward = tb_num_bytes_to_forward_send,
		.num_recv_bytes_to_forward = tb_num_bytes_to_forward_recv,
		.inc_send_bytes_forwarded = tb_update_bytes_forwarded_send,
		.inc_recv_bytes_forwarded = tb_update_bytes_forwarded_recv,
		.bytes_to_read_send = tb_get_bytes_to_read_send,
		.bytes_to_read_recv = tb_get_bytes_to_read_recv,
		.get_mitm_sock = tb_get_mitm_sock,
	};
	
	ktblog(LOG_DEBUG, "Looking for Trustbase binaries in %s", tb_path);
	start_mitm_proxy(tb_path);
	nat_ops_register();
	proxy_register(&trustbase_ops);
	ktblog(LOG_DEBUG, "SSL/TLS MITM Proxy started (PID: %d)", mitm_proxy_task->pid);
	start_policy_engine(tb_path);
	ktblog(LOG_DEBUG, "Policy Engine started (PID: %d)(GID: %d)", policy_engine_task->pid, policy_engine_task->tgid);

	return 0;
}

/**
 * The end function that calls the functions to unregister and stop Trustbase
 * @post Trustbase unregistered and stopped
 */
void __exit loader_end(void) {
	int i;
	// Kill policy engine before killing IPC because
	// the IPC is needed for shutdown message
	stop_task(policy_engine_task, SIGINT);
	// Send shutdown message to policy_engine
	tb_send_shutdown();
	
	// Wait until the policy_engine is done until we shut down the netlink socket
	
	i = 0;
	while (i < 300) {
		if (policy_engine_task->state > 0) {
			break;
		}
		msleep(10);
		i++;
	}
		
	proxy_unregister();
	nat_ops_unregister();


	// Unregister the IPC
	tb_unregister_netlink();

	stop_task(mitm_proxy_task, SIGTERM);

	// Remove the Proc File
	ktblog_exit();
	return;
}

/**
 * Sends SIGTERM to a task
 * @param task A pointer to a task_struct
 */
void stop_task(struct task_struct* task, int signal) {
	struct siginfo sinfo;
	memset(&sinfo, 0, sizeof(struct siginfo));
	sinfo.si_signo = signal;
	sinfo.si_code = SI_KERNEL;
	send_sig_info(signal, &sinfo, task);
	return;
}
/**
 * The following functions start up external daemons
 */
int start_policy_engine(char* path) {
        char prog_path[64];
        char* envp[] = { "HOME=/",
                "TERM=linux",
                "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
                NULL
        };
        char* argv[3];
        snprintf(prog_path, 64, "%s/policy_engine", path);
	ktblog(LOG_INFO, "Starting policy engine at %s", prog_path);
        argv[0] = prog_path;
        argv[1] = path;
	argv[2] = NULL;
        alt_call_usermodehelper(prog_path, argv, envp, UMH_WAIT_EXEC, policy_engine_init);
        return 0;
}

int start_mitm_proxy(char* path) {
        char prog_path[64];
        char cert_path[64];
        char key_path[64];
        char* envp[] = { "HOME=/",
                "TERM=linux",
                "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
                NULL
        };
        char* argv[11];
        snprintf(prog_path, 64, "%s/sslsplit/sslsplit", path);
	ktblog(LOG_INFO, "Starting SSLSplit at %s", prog_path);
        snprintf(cert_path, 64, "%s/certs/ca.crt", path);
        snprintf(key_path, 64, "%s/certs/ca.key", path);
        argv[0] = prog_path;
        argv[1] = "-k";
        argv[2] = key_path;
        argv[3] = "-c";
        argv[4] = cert_path;
        argv[5] = "ssl";
        argv[6] = "0.0.0.0";
        argv[7] = "8888";
        argv[8] = "trustbase";
        argv[9] = "-d";
        argv[10] = NULL;
        alt_call_usermodehelper(prog_path, argv, envp, UMH_WAIT_EXEC, mitm_proxy_init);
        return 0;
}

int mitm_proxy_init(struct subprocess_info *info, struct cred *new) {
	mitm_proxy_task = current;
	return 0;
}

int policy_engine_init(struct subprocess_info *info, struct cred *new) {
	policy_engine_task = current;
	return 0;
}

int alt_call_usermodehelper(char *path, char **argv, char **envp, int wait, 
	int (*init)(struct subprocess_info *info, struct cred *new)) {
	struct subprocess_info *info;
	gfp_t gfp_mask = (wait == UMH_NO_WAIT) ? GFP_ATOMIC : GFP_KERNEL;
        info = call_usermodehelper_setup(path, argv, envp, gfp_mask, init, NULL, NULL);
	if (info == NULL) {
		return -ENOMEM;
	}
	return call_usermodehelper_exec(info, wait);
}

