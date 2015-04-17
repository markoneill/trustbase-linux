#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

int connect_to_host(const char* host, int port);
int recv_comm(int socket, char* buffer, int length);
int send_comm(int socket, char* buffer, int length);

int main() {
	char sendbuf[] = "testingthisthing";
	int serverSocket = connect_to_host("localhost", 3333);
	send_comm(serverSocket, sendbuf, 4);
	close(serverSocket);
	return 0;
}
int connect_to_host(const char* host, int port) {
	int serverSocket;
	struct sockaddr_in server_addr;

	// use DNS to get IP address
	struct hostent *hostEntry;
	hostEntry = gethostbyname(host);
	if (!hostEntry) {
		printf("No such host name: %s\n", host);
		exit(EXIT_FAILURE);
	}
	// setup socket address structure
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	memcpy(&server_addr.sin_addr, hostEntry->h_addr_list[0], hostEntry->h_length);

	// create socket
	serverSocket = socket(PF_INET, SOCK_STREAM, 0);
	if (!serverSocket) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// connect to server
	if (connect(serverSocket,(const struct sockaddr *)&server_addr,sizeof(server_addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	return serverSocket;
}

int recv_comm(int socket, char* buffer, int length) {
	char* ptr;
	int bytesLeft;
	int bytesRead;
	ptr = buffer;
	bytesLeft = length;
	while (bytesLeft) {
		bytesRead = recv(socket, ptr, bytesLeft, 0);
		if (bytesRead < 0) {
			if (errno == EINTR) {
				continue; // continue upon interrupt
			}
			else { // something else happened, abort
				return -2;
			}
		}
		else if (bytesRead == 0) {
			return -1;
		}
		ptr += bytesRead;
		bytesLeft -= bytesRead;
	}
	return 0;
}

int send_comm(int socket, char* buffer, int length) {
	char* ptr;
	int bytesLeft;
	int bytesSent;
	ptr = buffer;
	bytesLeft = length;
	while (bytesLeft) {
		bytesSent = send(socket, ptr, bytesLeft, 0);
		if (bytesSent < 0) {
			if (errno == EINTR) {
				continue; // continue upon interrupt
			}
			else {
				perror("write");
				return -2; // something else happened, abort
			}
		}
		else if (bytesSent == 0) {
			return -1;
		}
		ptr += bytesSent;
		bytesLeft -= bytesSent;
	}
	return 0;
}

