#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

int create(int port);
void handle_client(void* client_socket);
void server_run(int server_socket);
void print_hex(unsigned char* buffer, int length);
int recv_comm(int socket, unsigned char* buffer, int length);
int recv_comm_until(int socket, unsigned char** buffer, char* needle);
int send_comm(int socket, unsigned char* buffer, int length);

// Timing Attack-specific stuff
int validate_token(char* token, char* reference, int length);

#define TEMP_BUF_LEN	1024

typedef struct thread_param_t {
	int client;
} thread_param_t;

int main(int argc, char* argv[]) {
	int server_socket = create(atoi(argv[1]));
	server_run(server_socket);
	return 0;
}

int create(int port) {
	int server_socket;
	struct sockaddr_in server_addr;
	int reuse = 1;

	// setup socket address structure
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	// create socket
	server_socket = socket(PF_INET, SOCK_STREAM, 0);
	if (!server_socket) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// set socket to immediately reuse port when the application closes
	if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	// call bind to associate the socket with our local address and port
	if (bind(server_socket, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	// convert the socket to listen for incoming connections
	if (listen(server_socket, SOMAXCONN) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	printf("Server socket created\n");
	return server_socket;
}

void server_run(int server_socket) {
	pthread_t worker;
	int client_socket;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	thread_param_t param;

	// This is an intentionally bad way of threading.  Do not ever do this.
	while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len)) > 0) {
		pthread_create(&worker, NULL, handle_client, (void*)client_socket);
		//handle_client(client_socket);
	}
	return;
}

void handle_client(void* client_raw) {
	int client;
	unsigned char* buffer;
	client = (int)client_raw;
	char* good_response = "you got it!";
	char* bad_response = "nope!";
	char password[] = "mrdrumpf";
	recv_comm_until(client, &buffer, "\n");
	printf("Received: %s\n", buffer);
	if (validate_token(buffer, password, strlen(password))) {
		send_comm(client, good_response, strlen(good_response)+1);
	}
	else {
		send_comm(client, bad_response, strlen(bad_response)+1);
	}
	free(buffer);
	close(client);
}

int recv_comm_until(int socket, unsigned char** buffer, char* needle) {
	unsigned char* ptr;
	int total_bytes_read;
	int bytes_read;
	int buffer_length = TEMP_BUF_LEN;
	char temp_buffer[TEMP_BUF_LEN];
	total_bytes_read = 0;
	*buffer = (unsigned char*)calloc(sizeof(unsigned char),buffer_length);
	while (strstr(*buffer, needle) == NULL) {
		printf("Needle not yet found, buffer contains: %s\n", *buffer);
		bytes_read = recv(socket, temp_buffer, TEMP_BUF_LEN, 0);
		printf("Recieved %u bytes: %s\n", bytes_read, temp_buffer);
		if (bytes_read < 0) {
			if (errno == EINTR) {
				continue; // continue upon interrupt
			}
			else { // something else happened, abort
				return -2;
			}
		}
		else if (bytes_read == 0) {
			return -1;
		}
		
		if ((total_bytes_read + bytes_read) > buffer_length) {
			*buffer = (unsigned char*)realloc(*buffer, (total_bytes_read + bytes_read) * 2);
		}
		memcpy(&(*buffer)[total_bytes_read], temp_buffer, bytes_read);
		total_bytes_read += bytes_read;
		printf("Buffer now contains: %s\n", *buffer);
	}
	printf("Needle found\n");
	return 0;
}

int recv_comm(int socket, unsigned char* buffer, int length) {
	unsigned char* ptr;
	int bytes_left;
	int bytes_read;
	ptr = buffer;
	bytes_left = length;
	while (bytes_left) {
		bytes_read = recv(socket, ptr, bytes_left, 0);
		printf("i read %d bytes that time\n", bytes_read);
		if (bytes_read < 0) {
			if (errno == EINTR) {
				continue; // continue upon interrupt
			}
			else { // something else happened, abort
				return -2;
			}
		}
		else if (bytes_read == 0) {
			return -1;
		}
		ptr += bytes_read;
		bytes_left -= bytes_read;
	}
	return 0;
}

int send_comm(int socket, unsigned char* buffer, int length) {
	unsigned char* ptr;
	int bytes_left;
	int bytes_sent;
	ptr = buffer;
	bytes_left = length;
	while (bytes_left) {
		bytes_sent = send(socket, ptr, bytes_left, 0);
		if (bytes_sent < 0) {
			if (errno == EINTR) {
				continue; // continue upon interrupt
			}
			else {
				perror("write");
				return -2; // something else happened, abort
			}
		}
		else if (bytes_sent == 0) {
			return -1;
		}
		ptr += bytes_sent;
		bytes_left -= bytes_sent;
	}
	return 0;
}

void print_hex(unsigned char* buffer, int length) {
	int i;
	printf("\n");
	for (i = 0; i < length; i++ ) {
		printf("%02x", buffer[i]);
	}
	printf("\n");
	return;
}

// Timing attack server stuff

int validate_token(char* token, char* reference, int length) {
	int i;
	for (i = 0; i < length; i++) {
		if (token[i] != reference[i]) {
			return 0;
		}
		usleep(300000);
	}
	return 1;
}
