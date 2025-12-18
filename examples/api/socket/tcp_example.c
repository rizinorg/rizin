// SPDX-FileCopyrightText: 2025 Maijin <Maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Example: Self-contained TCP Server and Client using RzSocket
 *
 * This example demonstrates:
 * 1. Listening for TCP connections on 127.0.0.1.
 * 2. Connecting to the local server.
 * 3. Bidirectional communication.
 */

#include <rz_socket.h>
#include <rz_util.h>
#include <rz_th.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADDR "127.0.0.1"
#define PORT "9999"

static void *tcp_server_thread(void *user) {
	RzSocket *ls = rz_socket_new(false);
	if (!rz_socket_listen(ls, PORT, NULL)) {
		fprintf(stderr, "Server: Cannot listen on port %s\n", PORT);
		rz_socket_free(ls);
		return NULL;
	}

	printf("Server: Listening on %s:%s\n", ADDR, PORT);

	// Accept a connection
	RzSocket *s = rz_socket_accept(ls);
	if (s) {
		printf("Server: Accepted connection\n");
		char buf[1024];
		int len = rz_socket_read(s, (ut8 *)buf, sizeof(buf) - 1);
		if (len > 0) {
			buf[len] = 0;
			printf("Server: Received: %s\n", buf);
			rz_socket_printf(s, "Hello Client! I got your message: %s", buf);
		}
		rz_socket_free(s);
	}

	rz_socket_free(ls);
	return NULL;
}

int main(int argc, char **argv) {
	// 1. Start the server thread
	RzThread *th = rz_th_new(tcp_server_thread, NULL);
	if (!th) {
		fprintf(stderr, "Failed to create server thread\n");
		return 1;
	}

	// Give the server a moment to start
	rz_sys_sleep(1);

	// 2. Client connection
	RzSocket *s = rz_socket_new(false);
	printf("Client: Connecting to %s:%s\n", ADDR, PORT);
	if (rz_socket_connect_tcp(s, ADDR, PORT, 0)) {
		const char *msg = "Hello from TCP client!";
		printf("Client: Sending: %s\n", msg);
		rz_socket_write(s, (void *)msg, strlen(msg));

		char buf[1024];
		int len = rz_socket_read(s, (ut8 *)buf, sizeof(buf) - 1);
		if (len > 0) {
			buf[len] = 0;
			printf("Client: Received from server: %s\n", buf);
		}
		rz_socket_close(s);
	} else {
		fprintf(stderr, "Client: Failed to connect to %s:%s\n", ADDR, PORT);
	}
	rz_socket_free(s);

	// 3. Cleanup
	rz_th_wait(th);
	rz_th_free(th);

	return 0;
}
