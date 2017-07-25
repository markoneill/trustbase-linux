#include <sys/types.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "tb_logging.h"
#include "tb_user.h"

static int set_uid_with_cap(uid_t u_uid);
static int create_user(const char* username);
static int get_uid(const char* username, uid_t* u_uid, gid_t* u_gid);

int change_to_user(const char* username) {
	uid_t user_uid;
	gid_t user_gid;
	
	if (get_uid(username, &user_uid, &user_gid) != 0) {
		tblog(LOG_INFO, "Didn't find user %s\nCreating system user %s\n", username, username);
		if (create_user(username) == 0) {
			if (get_uid(username, &user_uid, &user_gid) != 0) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	// setgid then set uid
	// setuid change to that user
	if (setgid(user_gid) != 0) {
		tblog(LOG_ERROR, "Could not take the gid of %s", username);
	}
	
	if (set_uid_with_cap(user_uid) != 0) {
		tblog(LOG_ERROR, "Could not take the uid of %s", username);
		return -1;
	}
	tblog(LOG_DEBUG, "Falling from admin to system user %s", username);
	return 0;
}

int set_uid_with_cap(uid_t u_uid) {
	cap_value_t root_caps[3] = { CAP_NET_ADMIN, CAP_SETUID, CAP_DAC_OVERRIDE }; // Capabilites to be set before the change
	cap_value_t user_caps[2] = { CAP_NET_ADMIN, CAP_DAC_OVERRIDE }; // Capabilites to keep after the change
	cap_t       capabilities;

	capabilities = cap_init();

	// Set permitted and effective capabilities in the structure, not inherited
	if (cap_set_flag(capabilities, CAP_PERMITTED, sizeof root_caps / sizeof root_caps[0], root_caps, CAP_SET) ||
			cap_set_flag(capabilities, CAP_EFFECTIVE, sizeof root_caps / sizeof root_caps[0], root_caps, CAP_SET)) {
		tblog(LOG_ERROR, "Could not set the capabilities flag when changeing user: %s.\n", strerror(errno));
		return -1;
	}

	// Set the capabilities
	if (cap_set_proc(capabilities)) {
		tblog(LOG_ERROR, "Can not set current process's capabilities: %s.\n", strerror(errno));
		return -1;
	}

	// Save these capabilites after the setuid
	if (prctl(PR_SET_KEEPCAPS, 1L)) {
		tblog(LOG_ERROR, "Cannot keep capabilities after dropping privileges: %s.\n", strerror(errno));
		return -1;
	}

	// Change user
	if (setuid(u_uid)) {
		tblog(LOG_ERROR, "Cannot drop to user: %s.\n", strerror(errno));
		return -1;
	}

	// Remove the extra capability of SETUID
	if (cap_clear(capabilities)) {
		tblog(LOG_ERROR, "Cannot clear capabilities: %s.\n", strerror(errno));
		return -1;
	}

	if (cap_set_flag(capabilities, CAP_PERMITTED, sizeof user_caps / sizeof user_caps[0], user_caps, CAP_SET) ||
			cap_set_flag(capabilities, CAP_EFFECTIVE, sizeof user_caps / sizeof user_caps[0], user_caps, CAP_SET)) {
		tblog(LOG_ERROR, "Cannot change capabilites: %s.\n", strerror(errno));
		return -1;
	}

	// Apply our capabilities
	if (cap_set_proc(capabilities)) {
		tblog(LOG_ERROR, "Cannot set our capabilites as user: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
}

int create_user(const char* username) {
	pid_t child_pid;
	int child_status;

	child_pid = fork();
	
	if (child_pid == -1) {
		// We were unable to fork
		return -1;
	} else if (child_pid == 0) {
		execl("/sbin/useradd", "/sbin/useradd", "-r", "-M", "-s", "/sbin/nologin", username, (char*)NULL);
		// If we reach here we failed on the execl
		return -1;
	} else {
		// Wait for the useradd
		waitpid(child_pid, &child_status, 0);
		if (child_status == 0) {
			return 0;
		} else {
			return -1;
		}
	}
}

int get_uid(const char* username, uid_t* u_uid, gid_t* u_gid) {
	struct passwd* pwd;	
	
	// Get the user uid
	pwd = getpwnam(username);
	if (pwd == NULL) {
		return -1;
	}
	*u_uid = pwd->pw_uid;
	*u_gid = pwd->pw_gid;
	return 0;
}
