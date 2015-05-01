#ifndef _TH_UTILS_H
#define _TH_UTILS_H

#include <linux/net.h>

typedef struct { __u8 b[3]; } __be24, __le24;

#ifndef be24_to_cpu
#define __be24_to_cpu(x) \
({ \
	__be24 _x = (x); \
	(__u32) ((_x.b[0] << 16) | (_x.b[1] << 8) | (_x.b[2])); \
})

#define be24_to_cpu	__be24_to_cpu
#endif

#ifndef cpu_to_be24
#define __cpu_to_be24(x) \
({ \
	__u32 _x = (x); \
	(__be24) { .b = { (_x >> 16) & 0xff, (_x >> 8) & 0xff, _x & 0xff } }; \
})

#define cpu_to_be24	__cpu_to_be24
#endif

void print_call_info(const char* str);
#endif
