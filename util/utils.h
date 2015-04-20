#ifndef _TH_UTILS_H
#define _TH_UTILS_H

#include <linux/net.h>

#ifndef be24_to_cpu

typedef struct { __u8 b[3]; } __be24, __le24;

#define __be24_to_cpu(x) \
({ \
	__be24 _x = (x); \
	(__u32) ((_x.b[0] << 16) | (_x.b[1] << 8) | (_x.b[2])); \
})

#define be24_to_cpu	__be24_to_cpu
#endif

void print_call_info(const char* str);
#endif
