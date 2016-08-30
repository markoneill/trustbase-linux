#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include "th_logging.h"
#include "th_user.h"

static int create_user(const char* username);
static int get_uid(const char* username, uid_t* u_uid, gid_t* u_gid);

int change_to_user(const char* username) {
	uid_t user_uid;
	gid_t user_gid;
	
	if (get_uid(username, &user_uid, &user_gid) != 0) {
		thlog(LOG_INFO, "Didn't find user %s\nCreating system user %s\n", username, username);
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
		thlog(LOG_ERROR, "Could not take the gid of %s", username);
	}
	
	if (setuid(user_uid) != 0) {
		thlog(LOG_ERROR, "Could not take the uid of %s", username);
		return -1;
	}
	thlog(LOG_DEBUG, "Falling from admin to system user %s", username);
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
