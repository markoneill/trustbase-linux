#ifndef _KTH_LOGGING_H
#define _KTH_LOGGING_H

#define KTHLOG_FILENAME	"trusthub_klog"

typedef enum thlog_level_t {LOG_DEBUG=0, LOG_PROCESS=1, LOG_INFO=2, LOG_WARNING=3, LOG_ERROR=4, LOG_HEX=5} thlog_level_t;


/* Logs to the trusthub log location
 * like printf, but starting with a log level param
 */
void kthlog(thlog_level_t level, const char* fmt, ...);

/* Prints out length bytes in hex of the data pointed to by buffer
 */
void kthlog_buffer(void* buffer, int length);

int kthlog_init(void);
void kthlog_exit(void);

#endif
