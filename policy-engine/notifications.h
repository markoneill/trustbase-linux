#ifndef NOTIFICATIONS_H_
#define NOTIFICATIONS_H_

typedef enum user_session_t {USER_GUI, USER_NO_GUI, USER_UNKNOWN, USER_ERROR} user_session_t;

int notify_user(char* username, char* message);

user_session_t user_type(char* username);

#endif
