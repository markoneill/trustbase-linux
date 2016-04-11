#ifndef _KTH_LOGGING_H
#define _KTH_LOGGING_H

#define KTHLOG_FILENAME	"trusthub_klog"

typedef enum thlog_level_t {LOG_DEBUG=0, LOG_PROCESS=1, LOG_INFO=2, LOG_WARNING=3, LOG_ERROR=4} thlog_level_t;


void kthlog(thlog_level_t level, const char* fmt, ...);

int kthlog_init(void);
void kthlog_exit(void);

#endif
