#include <linux/module.h>
#include <linux/kernel.h>

#include "interceptor/interceptor.h" // For registering/unregistering proxy functions
#include "handshake-handler/communications.h" // For registering/unregistering netlink family
#include "handshake-handler/handshake_handler.h" // For referencing proxy functions

// Kernel module parameters
static char* th_path = "/usr/bin";
module_param(th_path, charp, 0000);
MODULE_PARM_DESC(th_path, "An absolute path to the TrustHub install location");

// TrustHub interception operations
proxy_handler_ops_t trusthub_ops;
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
void stop_task(struct task_struct* task);

/**
 * the initial function that sets up the MITM proxy and handler
 * @see handshake-handler/handshake_handler.h
 * @post MITM proxy ready, and TCP function pointers point to TrustHub functions
 * @return an error code
 */
int __init loader_start(void) {
	// Set up IPC module-policyengine interaction
	if (th_register_netlink() != 0) {
		printk(KERN_ALERT "unable to register netlink family and ops");
		return -1;
	}

	trusthub_ops = (proxy_handler_ops_t) {
		.state_init = th_state_init,
		.state_free = th_state_free,
		.get_state = th_get_state,
		.give_to_handler_send = th_give_to_handler_send,
		.give_to_handler_recv = th_give_to_handler_recv,
		.update_send_state = th_update_state_send,
		.update_recv_state = th_update_state_recv,
		.fill_send_buffer = th_fill_send_buffer, // XXX rename this
		.copy_to_user = th_copy_to_user_buffer, // XXX rename this
		.num_send_bytes_to_forward = th_num_bytes_to_forward_send,
		.num_recv_bytes_to_forward = th_num_bytes_to_forward_recv,
		.inc_send_bytes_forwarded = th_update_bytes_forwarded_send,
		.inc_recv_bytes_forwarded = th_update_bytes_forwarded_recv,
		.bytes_to_read_send = th_get_bytes_to_read_send,
		.bytes_to_read_recv = th_get_bytes_to_read_recv,
		.get_mitm_sock = th_get_mitm_sock,
	};
	
	printk(KERN_INFO "Looking for TrustHub binaries in %s", th_path);
	start_mitm_proxy(th_path);
	nat_ops_register();
	proxy_register(&trusthub_ops);
	start_policy_engine(th_path);
	printk(KERN_INFO "SSL/TLS MITM Proxy started (PID: %d)", mitm_proxy_task->pid);

	return 0;
}

/**
 * The end function that calls the functions to unregister and stop TrustHub
 * @post TrustHub unregistered and stopped
 */
void __exit loader_end(void) {
	// Send shutdown message to policy-engine
	th_send_shutdown();
	proxy_unregister();
	nat_ops_unregister();

	// Kill policy engine before killing IPC because
	// the IPC is needed for shutdown message
	stop_task(policy_engine_task);

	// Unregister the IPC
	th_unregister_netlink();

	stop_task(mitm_proxy_task);
	return;
}

/**
 * Sends SIGTERM to a task
 * @param task A pointer to a task_struct
 */
void stop_task(struct task_struct* task) {
	struct siginfo sinfo;
	memset(&sinfo, 0, sizeof(struct siginfo));
	sinfo.si_signo = SIGTERM;
	sinfo.si_code = SI_KERNEL;
	send_sig_info(SIGTERM, &sinfo, task);
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
        char* argv[2];
        snprintf(prog_path, 64, "%s/policy_engine", path);
	printk(KERN_INFO "Starting policy engine at %s", prog_path);
        argv[0] = prog_path;
        argv[1] = NULL;
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
        char* argv[10];
        snprintf(prog_path, 64, "%s/sslsplit/sslsplit", path);
	printk(KERN_INFO "Starting SSLSplit at %s", prog_path);
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
        argv[8] = "trusthub";
        argv[9] = NULL;
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

