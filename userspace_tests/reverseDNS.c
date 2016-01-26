#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int ip_to_hostname(char *ip, char* dest) {
	struct sockaddr_in addr;
	socklen_t len;
	char hbuf[NI_MAXHOST];
	int error = 0;

	if(!inet_pton(AF_INET, ip, &(addr.sin_addr))) {
		printf("\tInvalid ip: %s\n", ip);
		return 0;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htonl(80);
	if(error = getnameinfo((struct sockaddr*)&addr, len, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD)) {
		printf("\tError getting hostname: %i\n", error);
		printf("\tEAI_AGAIN: %i\n", EAI_AGAIN);
		printf("\tEAI_BADFLAGS: %i\n", EAI_BADFLAGS);
		printf("\tEAI_FAIL: %i\n", EAI_FAIL);
		printf("\tEAI_FAMILY: %i\n", EAI_FAMILY);
		printf("\tEAI_MEMORY: %i\n", EAI_MEMORY);
		printf("\tEAI_NONAME: %i\n", EAI_NONAME);
		printf("\tEAI_OVERFLOW: %i\n", EAI_OVERFLOW);
		printf("\tEAI_SYSTEM: %i\n", EAI_SYSTEM);
		return error;
	}
	strcpy(dest, hbuf); // BUFFER OVERFLOW HERE
	return 1;
}

int main(int argc, char* argv[]) {
	char dest[NI_MAXHOST];
	int i;
	if(argc < 2) {
		printf("usage: %s <ip addr>\n", argv[0]);
		return 1;
	}
	for(i = 1; i < argc; i++) {
		if(ip_to_hostname(argv[i], dest) == 1) {
			printf("%s hostname: %s\n", argv[i], dest);
		}
		else {
			printf("%s ERROR\n", argv[i]);
		}
	}
}
