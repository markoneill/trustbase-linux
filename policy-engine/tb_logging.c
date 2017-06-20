#include <sys/klog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <openssl/x509.h>
#include "tb_logging.h"

/* Useful trick for windows */
#ifdef WIN32
    #define my_vsnprintf _vsnprintf
#else
    #define my_vsnprintf vsnprintf
#endif

FILE *log_file = NULL;
tblog_level_t minimum_level = LOG_WARNING;

int tblog_init(const char *log_file_name, tblog_level_t min_level) {
	// Write log
	log_file = fopen(log_file_name, "a");
	if (log_file == NULL) {
		return 1;
	}
	minimum_level = min_level;
	
	return 0;
}

int tblog(tblog_level_t level, const char* format, ... ) {
	char* extended_format;
	va_list args;
	time_t current_time;

	
	// If the log level is below the minimum, ditch it
	if (minimum_level > level) {
		return 0;
	}
	// Check the file
	if (log_file == NULL) {
		return 1;
	}
	// Parse the args
	va_start(args, format);
	
	// Extend the format
	// Add the time and log level
	current_time = time(NULL);
	extended_format = (char*)malloc(strlen(format) + 25 + 7 + 1 + 1);
	memcpy(extended_format, asctime(gmtime(&current_time)), 24);
	extended_format[24] = '\0';
	switch (level) {
	case LOG_DEBUG:
		strncat(extended_format, " :DBG: ", 7);
		break;
	case LOG_INFO:
		strncat(extended_format, " :INF: ", 7);
		break;
	case LOG_WARNING:
		strncat(extended_format, " :WRN: ", 7);
		break;
	case LOG_ERROR:
		strncat(extended_format, " :ERR: ", 7);
		break;
	case LOG_NONE:
		strncat(extended_format, " :", 2);
		break;
	}
	strncat(extended_format, format, strlen(format));
	strncat(extended_format, "\n", 1);
	
	// Write to the log
	vfprintf(log_file, extended_format, args);
	fflush(log_file);
	
	va_end(args);
	free(extended_format);
	return 0;
} 

int tblog_bytes(char* seq, int num) {
	int i;
	char* output_str;
	
	output_str = (char*) malloc(num * 3);
	output_str[0] = '\0';
	for (i=0; i<num; i++) {
		sprintf(output_str, "%s%02x%s", output_str, seq[i] & 0xff, ((i+1)%16==0 || i==num-1)?"\n":((i+1)%2==0)?" ":"");
	}
	tblog(LOG_NONE, output_str);
	free(output_str);
	return 0;
}

int tblog_cert(X509* cert) {
	static const int MAX_LENGTH = 1024;
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	tblog(LOG_DEBUG, "subject: %s", subj);
	tblog(LOG_DEBUG, "issuer: %s", issuer);
	return 0;
}

void tblog_close() {	
	if (log_file == NULL) {
		return;
	}

	fflush(log_file);
	fclose(log_file);
}

void* read_ktblog(void* arg) {
	while (1) {
		sleep(1);
		FILE * fp;
		char * line = NULL;
		size_t len = 0;
		ssize_t read;
		fp = fopen("/proc/trustbase_klog", "r");
		if (fp == NULL) {
			tblog(LOG_ERROR, "Failed to open kernel log");
			return NULL;
		}
	
		while ((read = getline(&line, &len, fp)) != -1) {
			// replace newline
			line[strlen(line)-1] = '\0';
			// Read to know what type it is
			// Hackish way
			switch (minimum_level) {
			case LOG_DEBUG:
				break;
			case LOG_INFO:
				if (line[2] == 'D') {
					continue;
				}
				break;
			case LOG_WARNING:
				if (line[2] == 'D' || line[2] == 'I') {
					continue;
				}
				break;
			case LOG_ERROR:
				if (line[2] == 'D' || line[2] == 'I' || line[2] == 'W') {
					continue;
				}
				break;
			case LOG_NONE:
				break;
			}
			tblog(LOG_NONE, line);
		}
		
		fclose(fp);
		
		if (line) {
			free(line);
		}
	}
	return NULL;
}
