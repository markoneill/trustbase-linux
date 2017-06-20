#ifndef TB_LOGGING_H_
#define TB_LOGGING_H_

#include <openssl/x509.h>

typedef enum tblog_level_t {LOG_DEBUG=0, LOG_INFO=1, LOG_WARNING=2, LOG_ERROR=3, LOG_NONE=4} tblog_level_t;

int tblog_init(const char *log_file_name, tblog_level_t min_level);
int tblog(tblog_level_t level, const char* format, ... );
int tblog_bytes(char* seq, int num);
int tblog_cert(X509* cert);
void tblog_close();
void* read_ktblog(void* arg);

#endif
