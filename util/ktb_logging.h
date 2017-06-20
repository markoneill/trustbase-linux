#ifndef _KTB_LOGGING_H
#define _KTB_LOGGING_H

#define KTBLOG_FILENAME	"trustbase_klog"

typedef enum tblog_level_t {LOG_DEBUG=0, LOG_PROCESS=1, LOG_INFO=2, LOG_WARNING=3, LOG_ERROR=4, LOG_HEX=5} tblog_level_t;


/* Logs to the trustbase log location
 * like printf, but starting with a log level param
 */
void ktblog(tblog_level_t level, const char* fmt, ...);

/* Prints out length bytes in hex of the data pointed to by buffer
 */
void ktblog_buffer(void* buffer, int length);

int ktblog_init(void);
void ktblog_exit(void);

#endif
