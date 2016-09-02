#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <signal.h>
#include <sqlite3.h>
#include "sni_parser.h"
#include "policy_engine.h"
#include "th_logging.h"
#include "th_user.h"
#include "netlink.h"

static struct nla_policy th_policy[TRUSTHUB_A_MAX + 1] = {
        [TRUSTHUB_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTHUB_A_HOSTNAME] = { .type = NLA_STRING },
	[TRUSTHUB_A_CLIENT_HELLO] = { .type = NLA_UNSPEC },
	[TRUSTHUB_A_IP] = { .type = NLA_STRING },
        [TRUSTHUB_A_PORTNUMBER] = { .type = NLA_U16 },
	[TRUSTHUB_A_RESULT] = { .type = NLA_U32 },
        [TRUSTHUB_A_STATE_PTR] = { .type = NLA_U64 },
};

static int family;
struct nl_sock* netlink_sock;
pthread_mutex_t nl_sock_mutex;
static volatile int keep_running;
sqlite3* db;

void int_handler(int signal);

int send_response(uint32_t spid, uint64_t stptr, int result) {
	int rc;
	struct nl_msg* msg;
	void* msg_head;
	msg = nlmsg_alloc();
	if (msg == NULL) {
		thlog(LOG_WARNING, "failed to allocate message buffer");
		return -1;
	}
	msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, TRUSTHUB_C_RESPONSE, 1);
	if (msg_head == NULL) {
		thlog(LOG_WARNING, "failed in genlmsg_put");
		return -1;
	}
	rc = nla_put_u64(msg, TRUSTHUB_A_STATE_PTR, stptr);
	if (rc != 0) {
		thlog(LOG_WARNING, "failed to insert state pointer");
		return -1;
	}
	rc = nla_put_u32(msg, TRUSTHUB_A_RESULT, result);
	if (rc != 0) {
		thlog(LOG_WARNING, "failed to insert result");
		return -1;
	}
	pthread_mutex_lock(&nl_sock_mutex);
	nl_socket_set_peer_port(netlink_sock, spid);
	rc = nl_send_auto(netlink_sock, msg);
	pthread_mutex_unlock(&nl_sock_mutex);
	if (rc < 0) {
		thlog(LOG_WARNING, "failed in nl send with error code %d", rc);
		return -1;
	}
	return 0;	
}

int recv_query(struct nl_msg *msg, void *arg) {
	struct nlmsghdr* nlh;
	struct genlmsghdr* gnlh;
	struct nlattr* attrs[TRUSTHUB_A_MAX + 1];
	char query[256];
	sqlite3_stmt* res;
	char* hostname;
	char* ip_str;
	unsigned char* cert_chain;
	int chain_length;
	char* client_hello;
	int client_hello_len;
	uint64_t stptr;
	uint16_t port;

	hostname = NULL;
	ip_str = NULL;

	// Get Message
	thlog(LOG_DEBUG, "Received a message");
	nlh = nlmsg_hdr(msg);
	gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
	genlmsg_parse(nlh, 0, attrs, TRUSTHUB_A_MAX, th_policy);
	switch (gnlh->cmd) {
		case TRUSTHUB_C_QUERY_NATIVE:
			hostname = nla_get_string(attrs[TRUSTHUB_A_HOSTNAME]);
			chain_length = nla_len(attrs[TRUSTHUB_A_CERTCHAIN]);
			cert_chain = nla_data(attrs[TRUSTHUB_A_CERTCHAIN]);
			port = nla_get_u16(attrs[TRUSTHUB_A_PORTNUMBER]);
			stptr = nla_get_u64(attrs[TRUSTHUB_A_STATE_PTR]);
			poll_schemes(nlh->nlmsg_pid, stptr, hostname, port, cert_chain, chain_length);
			break;
		case TRUSTHUB_C_QUERY:
			thlog(LOG_DEBUG, "Received a query from PID %u", nlh->nlmsg_pid);
			thlog(LOG_DEBUG, "Policy engine PID is %u", nl_socket_get_local_port(netlink_sock));
			/* Get message fields */
			chain_length = nla_len(attrs[TRUSTHUB_A_CERTCHAIN]);
			cert_chain = nla_data(attrs[TRUSTHUB_A_CERTCHAIN]);
			port = nla_get_u16(attrs[TRUSTHUB_A_PORTNUMBER]);
			stptr = nla_get_u64(attrs[TRUSTHUB_A_STATE_PTR]);
			client_hello_len = nla_len(attrs[TRUSTHUB_A_CLIENT_HELLO]);
			client_hello = nla_data(attrs[TRUSTHUB_A_CLIENT_HELLO]);
			hostname = sni_get_hostname(client_hello, client_hello_len);
			ip_str = nla_get_string(attrs[TRUSTHUB_A_IP]);
			/* Query registered schemes */
			poll_schemes(nlh->nlmsg_pid, stptr, hostname, port, cert_chain, chain_length);
			sprintf(query, "INSERT OR IGNORE INTO Pins VALUES ('%s', %d)", ip_str, port);
			if (sqlite3_prepare_v2(db, query, 256, &res, 0) != SQLITE_OK) {
				thlog(LOG_ERROR, "TLS Pin insert failed %s", sqlite3_errmsg(db));
			} else {
				sqlite3_step(res);
				sqlite3_finalize(res);
			}
			// XXX I *think* the message is freed by whatever function calls this one
			// within libnl.  Verify this.
			break;
		case TRUSTHUB_C_SHOULDTLS:
			port = nla_get_u16(attrs[TRUSTHUB_A_PORTNUMBER]);
			stptr = nla_get_u64(attrs[TRUSTHUB_A_STATE_PTR]);
			ip_str = nla_get_string(attrs[TRUSTHUB_A_IP]);
			sprintf(query, "SELECT COUNT(*) FROM Pins WHERE Hostname = '%s' AND Port = %d", ip_str, port);
			if (sqlite3_prepare_v2(db, query, 256, &res, 0) != SQLITE_OK) {
				thlog(LOG_ERROR, "Failed to lookup pin, %s", sqlite3_errmsg(db));
			}
			if (sqlite3_step(res) == SQLITE_ROW) {
				if (sqlite3_column_int(res, 0) == 1) {
					send_response(nlh->nlmsg_pid, stptr, 1);
					thlog(LOG_DEBUG, "Pin found!");
				}
				else {
					send_response(nlh->nlmsg_pid, stptr, 0);
					thlog(LOG_DEBUG, "Pin not found");
				}
			}
			else {
				thlog(LOG_ERROR, "Failed to return a result");
			}
			sqlite3_finalize(res);
			break;
		case TRUSTHUB_C_SHUTDOWN:
			/* Receiving this will exit the listen_for_queries loop, as long as keep_running is set to 0 first */
			thlog(LOG_DEBUG, "Received a shutdown message");
			break;
		default:
			thlog(LOG_DEBUG, "Got something unusual...");
			break;
	}
	return 0;
}

int prep_communication(const char* username) {
	int group;
	char query[256];
	sqlite3_stmt* res;
	netlink_sock = nl_socket_alloc();
	if (sqlite3_open("/var/log/tls_pinning.db", &db) != SQLITE_OK) {
		thlog(LOG_ERROR, "Failed to open sqlite database for tls pinning");
		return -1;
	}
	sprintf(query, "CREATE TABLE IF NOT EXISTS Pins (Hostname TEXT, Port INT, PRIMARY KEY (Hostname, Port))");
	if (sqlite3_prepare_v2(db, query, 256, &res, 0) != SQLITE_OK) {
		thlog(LOG_ERROR, "Pin table creation failed %s", sqlite3_errmsg(db));
	}
	sqlite3_step(res);
	sqlite3_finalize(res);
	nl_socket_set_local_port(netlink_sock, 100);
	thlog(LOG_DEBUG, "policy engine has PID %u", nl_socket_get_local_port(netlink_sock));
	if (pthread_mutex_init(&nl_sock_mutex, NULL) != 0) {
		thlog(LOG_ERROR, "Failed to create mutex for netlink");
		return -1;
	}
	nl_socket_disable_seq_check(netlink_sock);
	nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, recv_query, (void*)netlink_sock);
	if (netlink_sock == NULL) {
		thlog(LOG_ERROR, "Failed to allocate socket");
		return -1;
	}
	/* Internally this calls socket() and bind() using Netlink
 	 (specifically Generic Netlink)
 	 */
	if (genl_connect(netlink_sock) != 0) {
		thlog(LOG_ERROR, "Failed to connect to Generic Netlink control");
		return -1;
	}
	
	if ((family = genl_ctrl_resolve(netlink_sock, "TRUSTHUB")) < 0) {
		thlog(LOG_ERROR, "Failed to resolve TRUSTHUB family identifier");
		return -1;
	}

	if ((group = genl_ctrl_resolve_grp(netlink_sock, "TRUSTHUB", "query")) < 0) {
		thlog(LOG_ERROR, "Failed to resolve group identifier");
		return -1;
	}

	if (nl_socket_add_membership(netlink_sock, group) < 0) {
		thlog(LOG_ERROR, "Failed to add membership to group");
		return -1;
	}
	
	sqlite3_close(db);
	// drop root permissions
	change_to_user(username);
	return 0;
}
	
int listen_for_queries() {
	struct sigaction new_action;
	struct sigaction old_action;

	int err;
	keep_running = 1;
	thlog(LOG_DEBUG, "listening for queries");

	new_action.sa_handler = int_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, NULL, &old_action);
	if (sigaction(SIGINT, &new_action, NULL) == -1) {
		thlog(LOG_ERROR, "Cannot set handler for SIGINT");
	}

	while (keep_running == 1) {
		err = nl_recvmsgs_default(netlink_sock);
		if (err < 0) {
			thlog(LOG_DEBUG, "nl_recv failed with code %i", err);
			break;
		}
	}
	nl_socket_free(netlink_sock);
	thlog(LOG_DEBUG, "no longer listening for queries");
	return 0;
}

void int_handler(int signal) {
	if (signal == SIGINT) {
		thlog(LOG_DEBUG, "Caught SIGINT");
		printf("Caught SIGINT");
		keep_running = 0;
		// Wait for our netlink_message to break the loop
	}
}
