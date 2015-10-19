#ifndef _TH_TCP_H
#define _TH_TCP_H

int tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size);

#endif /* _TH_TCP_H */
