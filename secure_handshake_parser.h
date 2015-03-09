#ifndef _SECURE_HANDSHAKE_PARSER_H
#define _SECURE_HANDSHKAE_PARSER_H

#define TLS_HANDSHAKE_IDENTIFIER	0x16
#define TLS_RECORD_HEADER_SIZE		5

void th_read(pid_t pid, int sockfd, char* buf, long ret);

#endif
