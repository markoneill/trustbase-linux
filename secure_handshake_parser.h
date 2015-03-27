#ifndef _SECURE_HANDSHAKE_PARSER_H
#define _SECURE_HANDSHKAE_PARSER_H

#define TH_TLS_HANDSHAKE_IDENTIFIER	0x16
#define TH_TLS_RECORD_HEADER_SIZE		5
#define TH_TLS_HANDSHAKE_IDENTIFIER_SIZE	1

#define TH_SEND	1
#define TH_RECV	0

void th_parse_comm(pid_t pid, struct socket* sock, char* buf, long ret, int sendrecv);

#endif
