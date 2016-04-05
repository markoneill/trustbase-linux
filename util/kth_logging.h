#ifndef _KTH_LOGGING_H
#define _KTH_LOGGING_H

#define KTHLOG_FILENAME	"trusthub_klog"

typedef enum thlog_level_t {LOG_DEBUG=0, LOG_INFO=1, LOG_WARNING=2, LOG_ERROR=3} thlog_level_t;


void kthlog(thlog_level_t level, const char* fmt, ...);

int kthlog_init(void);
void kthlog_exit(void);

#endif
