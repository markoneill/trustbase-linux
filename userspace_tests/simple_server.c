#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int create(int port);
void handleClient(int client);
void server_run(int serveSocket);
void printHex(unsigned char* buffer, int length);
int recv_comm(int socket, char* buffer, int length);
int send_comm(int socket, char* buffer, int length);

int main() {
	int serverSocket = create(8889);
	server_run(serverSocket);
	return 0;
}

int create(int port) {
	int serverSocket;
	struct sockaddr_in server_addr;

	// setup socket address structure
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	// create socket
	serverSocket = socket(PF_INET, SOCK_STREAM, 0);
	if (!serverSocket) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// set socket to immediately reuse port when the application closes
	int reuse = 1;
	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	// call bind to associate the socket with our local address and port
	if (bind(serverSocket, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	// convert the socket to listen for incoming connections
	if (listen(serverSocket, SOMAXCONN) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	printf("Server socket created\n");
	return serverSocket;
}

void server_run(int serverSocket) {
	int clientSocket;
	struct sockaddr_in client_addr;
	socklen_t clientlen = sizeof(client_addr);

	while ((clientSocket = accept(serverSocket, (struct sockaddr *)&client_addr, &clientlen)) > 0) {
		handleClient(clientSocket);
	}
	return;
}

void handleClient(int client) {
	int bytesWanted;
	char buffer[1024];
	char sendbuf[] = "Hello from server";
	bytesWanted = 4;
	recv_comm(client, buffer, bytesWanted);
	buffer[bytesWanted] = '\0'; // Null terminate
	printf("Received:\n");
	printHex(buffer, 20);
	send_comm(client, sendbuf, strlen(sendbuf)+1);
	close(client);
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

void printHex(unsigned char* buffer, int length) {
	int i;
	printf("\n");
	for (i = 0; i < length; i++ ) {
		printf("%02x", buffer[i]);
	}
	printf("\n");
	return;
}
