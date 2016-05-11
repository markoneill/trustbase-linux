

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define TERM_COL 60
#define TERM_ROW 9
#define TERM_HEADER "~TrustHub Message~"

void terminal_notifiy(FILE* term, const char* message);

/* This will alert the user based on who made the call, and if they have a GUI or not */
void notify_user() {
	terminal_notify();
}

void terminal_notify(FILE* term, const char* message) {
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
	fprintf(term,"\033[3;%iH%s", (TERM_COL/2) - (strlen(TERM_HEADER)/2), TERM_HEADER);
	// Print a message
	c = 0;
	r = 0;
	for (i=0; i<(TERM_COL-6)*3 && i<strlen(message); i++) {
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
	// Flush and wait
	fflush(term);
	sleep(3);
	
	// Restore the screen and cursor
	fprintf(term, "\003[?25h\033[?47l");
}
