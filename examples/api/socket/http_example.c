// SPDX-FileCopyrightText: 2025 Maijin <Maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Example: Self-contained HTTP Server and Client using RzSocket
 *
 * This example demonstrates:
 * 1. Spawning a thread for a simple HTTP server.
 * 2. Using the RzSocket HTTP API to fetch content from the local server.
 * 3. Handling the HTTP request and response.
 */

#include <rz_socket.h>
#include <rz_util.h>
#include <rz_th.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADDR "127.0.0.1"
#define PORT "8080"

static void *http_server_thread(void *user) {
	RzSocket *s = rz_socket_new(false);
	if (!rz_socket_listen(s, PORT, NULL)) {
		fprintf(stderr, "Server: Cannot listen on port %s\n", PORT);
		rz_socket_free(s);
		return NULL;
	}

	printf("Server: Listening on %s:%s\n", ADDR, PORT);

	RzSocketHTTPOptions so = { .accept_timeout = true, .timeout = 1 }; // timeout in seconds
	RzSocketHTTPRequest *hr = NULL;

	while(1) {
		hr = rz_socket_http_accept(s, &so);

		// fail ?
		if (!hr) continue;

		// handle the request.
		printf("Server: Received %s request for %s\n", hr->method, hr->path);
		const char *response_body = "<html><body><h1>Hello from Rizin!</h1></body></html>";
		rz_socket_http_response(hr, 200, response_body, strlen(response_body), NULL);
		rz_socket_http_close(hr);
	}

	rz_socket_free(s);
	return NULL;
}

int main(int argc, char **argv) {
	// 1. Start the server thread
	RzThread *th = rz_th_new(http_server_thread, NULL);
	if (!th) {
		fprintf(stderr, "Failed to create server thread\n");
		return 1;
	}

	// Give the server a moment to start
	rz_sys_sleep(1);

	// 2. Client request
	const char *url = "http://" ADDR ":" PORT "/index.html";
	int code, rlen;

	printf("Client: Fetching URL: %s\n", url);
	char *response = rz_socket_http_get(url, &code, &rlen);

	if (response) {
		printf("Client: HTTP Status: %d\n", code);
		printf("Client: Response Length: %d\n", rlen);
		printf("Client: Response Content:\n%s\n", response);
		free(response);
	} else {
		fprintf(stderr, "Client: Failed to fetch URL.\n");
	}

	// 3. Cleanup
	rz_th_wait(th);
	rz_th_free(th);

	return 0;
}
