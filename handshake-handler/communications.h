#ifndef _TH_COMMUNICATIONS_H
#define _TH_COMMUNICATIONS_H

struct handler_state_t;

int th_register_netlink(void);
void th_unregister_netlink(void);
int th_send_certificate_query(struct handler_state_t* state, unsigned char* certificate, size_t length);
int th_send_is_starttls_query(struct handler_state_t* state);
int th_send_shutdown(void);
//int th_get_certificate_response(void);

// Attributes
enum {
	TRUSTHUB_A_UNSPEC,
	TRUSTHUB_A_CERTCHAIN,
	TRUSTHUB_A_HOSTNAME,
	TRUSTHUB_A_CLIENT_HELLO,
	TRUSTHUB_A_SERVER_HELLO,
	TRUSTHUB_A_IP,
	TRUSTHUB_A_PORTNUMBER,
	TRUSTHUB_A_RESULT,
	TRUSTHUB_A_STATE_PTR,
	__TRUSTHUB_A_MAX,
};

#define TRUSTHUB_A_MAX	(__TRUSTHUB_A_MAX - 1)

// Operations
enum {
	TRUSTHUB_C_UNSPEC,
	TRUSTHUB_C_QUERY,
	TRUSTHUB_C_QUERY_NATIVE,
	TRUSTHUB_C_RESPONSE,
	TRUSTHUB_C_SHUTDOWN,
	TRUSTHUB_C_SHOULDTLS,
	__TRUSTHUB_C_MAX,
};

#define TRUSTHUB_C_MAX	(__TRUSTHUB_C_MAX - 1)

// Multicast group
enum trusthub_groups {
	TRUSTHUB_QUERY,
};


#endif
