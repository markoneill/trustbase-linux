#ifndef _CONFIGURATION_H
#define _CONFIGURATION_H

#include "policy_engine.h"

#define MAX_USERNAME_LEN 32

int load_config(policy_context_t* policy_context, char* path, char* username);

#endif
