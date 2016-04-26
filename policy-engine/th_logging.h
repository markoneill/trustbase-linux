#ifndef TH_LOGGING_H_
#define TH_LOGGING_H_

typedef enum thlog_level_t {LOG_DEBUG=0, LOG_INFO=1, LOG_WARNING=2, LOG_ERROR=3, LOG_NONE=4} thlog_level_t;

int thlog_init(const char *log_file_name, thlog_level_t min_level);
int thlog(thlog_level_t level, const char* format, ... );
int thlog_cert(X509* cert);
void thlog_close();
void* read_kthlog(void* arg);

#endif
