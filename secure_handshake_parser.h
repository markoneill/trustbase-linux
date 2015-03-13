#ifndef _SECURE_HANDSHAKE_PARSER_H
#define _SECURE_HANDSHKAE_PARSER_H

#define TH_TLS_HANDSHAKE_IDENTIFIER	0x16
#define TH_TLS_RECORD_HEADER_SIZE		5
#define TH_TLS_HANDSHAKE_IDENTIFIER_SIZE	1

void th_read_request(pid_t pid, int sockfd, char* buf, long ret);
void th_read_response(pid_t pid, int sockfd, char* buf, long ret);

#endif
