#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>
#include <fcntl.h>
#include "tb_logging.h"
#include "notifications.h"

#define TERM_COL 60
#define TERM_ROW 9
#define TERM_HEADER "~Trustbase Message~"
#define MAX_USERNAME 32
#define MAX_TERMS 16
#define TERM_DIR "/dev/"

static void terminal_notify(FILE* term, char* message);
static void terminal_restore(FILE* term);
static int notify_user_term(char* username, char* message);

/* This function will notify a user in the best way */
int notify_user(char* username, char* message) {
	// TODO
	switch (user_type(username)) {
	case USER_NO_GUI:
		notify_user_term(username, message);
		break;
	default:
		// Write to the log
		tblog(LOG_WARNING, "Failed to notify %s: %s", username, message);
	}
	return 0; // Success
}

user_session_t user_type(char* username) {
	struct utmp current_record;
	int utmpfd;
	int i;
	int num_sessions;
	int reclen = sizeof(current_record);
	
	utmpfd = open(UTMP_FILE, O_RDONLY);
	if (utmpfd == -1) {
		return USER_ERROR;
	}

	num_sessions = 0;
	while (read(utmpfd, &current_record, reclen) == reclen) {
		// Parse the record
		if (strncmp(current_record.ut_name, username, MAX_USERNAME) != 0) {
			continue;
		}
		num_sessions++;
		// find any screens, local or remote
		for (i=0; i<strlen(current_record.ut_line); i++) {
			if (current_record.ut_line[i] == ':') {
				// User has a display, and probably a GUI
				// We can use a popup or whatever
				return USER_GUI;
			}
		} 
	}
	
	if (num_sessions > 0) {
		return USER_NO_GUI;
	}
	return USER_UNKNOWN;
}

void terminal_notify(FILE* term, char* message) {
	int c;
	int r;
	int i;
	// Save the screen and make the cursor invisible
	fprintf(term, "\033[?47h\033[?25l");
	
	// Make the notification area
	for (r=0; r<TERM_ROW; r++) {
		fprintf(term, "\033[%i;0H",r+1);
		for (c=0; c<TERM_COL; c++) {
			// A white box with a black border
			fprintf(term,"\033[4%im ", (r==0||r==TERM_ROW-1||c==0||c==TERM_COL-1)?0:7);
		}
		fprintf(term,"\n");
	}
	// Change color
	fprintf(term,"\033[47m\033[30m");
	// Print the header centered
	fprintf(term,"\033[3;%iH%s", (TERM_COL/2) - ((int)strlen(TERM_HEADER)/2), TERM_HEADER);
	// Print a message
	
	c = 0;
	r = 0;
	for (i=0; i<(TERM_COL-4)*3 && i<strlen(message); i++) {
		fprintf(term,"\033[%i;%iH%c", 5+r, 3+c, message[i]);
		if (c > TERM_COL-6) {
			r++;
			c = 0;
		} else {
			c++;
		}
	}
	
	// Move the cursor to the edge
	fprintf(term,"\033[%i;%iH\033[49m\033[39m",TERM_ROW, TERM_COL);
	fflush(term);
}

void terminal_restore(FILE* term) {
	// Restore the screen and cursor
	fprintf(term, "\033[?25h\033[?47l");
	fflush(term);
}

/* The strings and array of strings must be freed after */
int notify_user_term(char* username, char* message) {
	struct utmp current_record;
	int utmpfd;
	char* term_path;
	FILE* terminal;
	FILE* terminals[MAX_TERMS];
	int term_num;
	int i;
	int reclen = sizeof(current_record);
	
	utmpfd = open(UTMP_FILE, O_RDONLY);
	if (utmpfd == -1) {
		return 1;
	}

	term_num = 0;
	while (read(utmpfd, &current_record, reclen) == reclen) {
		if (term_num >= MAX_TERMS) {
			break;
		}
		// Parse the record
		if (strncmp(current_record.ut_name, username, MAX_USERNAME) != 0) {
			continue;
		}
		// Ignore any screens, local or remote
		for (i=0; i<strlen(current_record.ut_line); i++) {
			if (current_record.ut_line[i] == ':') {
				i = -1;
				break;
			}
		} 
		if (i == -1) {
			continue;
		}
		term_path = (char*)malloc(strlen(TERM_DIR) + strlen(current_record.ut_line) + 1);
		strcpy(term_path, TERM_DIR);
		strcat(term_path, current_record.ut_line);
		// concat the strings;
		terminal = fopen(term_path, "a");
		if (terminal == NULL) {
			continue;
		}
		terminals[term_num] = terminal;
		term_num++;
		terminal_notify(terminal, message);
	}
	sleep(3); // Wait for a bit
	for (i=0; i<term_num; i++) {
		terminal_restore(terminals[i]);
		fclose(terminals[i]);
	}
	close(utmpfd);
	return 0; // return success
}
