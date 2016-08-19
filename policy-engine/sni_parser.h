#ifndef SNI_PARSER_H
#define SNI_PARSER_H

#include <stdint.h>

typedef struct { uint8_t b[2]; } be16, le16;

#ifndef be16_to_cpu
#define be16_to_cpu(x) \
({ \
	be16 _x = (x); \
	(uint16_t) ((_x.b[0] << 8) | (_x.b[1])); \
})
#endif

#ifndef cpu_to_be16
#define cpu_to_be16(x) \
({ \
	uint16_t _x = (x); \
	(be24) { .b = { (_x >> 8) & 0xff, _x & 0xff } }; \
})
#endif


typedef struct { uint8_t b[3]; } be24, le24;

#ifndef be24_to_cpu
#define be24_to_cpu(x) \
({ \
	be24 _x = (x); \
	(uint32_t) ((_x.b[0] << 16) | (_x.b[1] << 8) | (_x.b[2])); \
})
#endif

#ifndef cpu_to_be24
#define cpu_to_be24(x) \
({ \
	uint32_t _x = (x); \
	(be24) { .b = { (_x >> 16) & 0xff, (_x >> 8) & 0xff, _x & 0xff } }; \
})
#endif

char* sni_get_hostname(char* client_hello, int client_hello_len);

#endif
