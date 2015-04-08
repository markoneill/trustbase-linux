#ifndef _TH_COMMUNICATIONS_H
#define _TH_COMMUNICATIONS_H

int th_register_netlink(void);
void th_unregister_netlink(void);
int th_send_certificate_query(char* certificate, size_t length);

// Family
enum {
	TRUSTHUB_A_UNSPEC,
	TRUSTHUB_A_MSG,
	TRUSTHUB_A_RESULT,
	__TRUSTHUB_A_MAX,
};

#define TRUSTHUB_A_MAX	(__TRUSTHUB_A_MAX - 1)

// Operations
enum {
	TRUSTHUB_C_UNSPEC,
	TRUSTHUB_C_QUERY,
	TRUSTHUB_C_RESPONSE,
	__TRUSTHUB_C_MAX,
};

#define TRUSTHUB_C_MAX	(__TRUSTHUB_C_MAX - 1)

// Multicast group
enum trusthub_groups {
	TRUSTHUB_QUERY,
	TRUSTHUB_RESPONSE,
};


#endif
