#include <rz_socket.h>
#define MAX_LINE 2048
//#define SERVER "www.openssl.org"
#define PORT   "4433"
#define SERVER "127.0.0.1"

int main(int argc, char **argv) {
	ut8 buf[MAX_LINE + 1];

	memset(buf, 0, MAX_LINE + 1);
	RzSocket *s = rz_socket_new(true);
	if (s == NULL) {
		fprintf(stderr, "Error, cannot create new socket \n");
		return 1;
	}
	if (!rz_socket_connect_tcp(s, SERVER, PORT)) {
		fprintf(stderr, "Error, cannot connect to " SERVER "\n");
		return 1;
	}
	printf("%i\n", rz_socket_puts(s, "GET /\r\n\r\n"));
	while (rz_socket_read(s, buf, MAX_LINE) > 0)
		printf("%s", buf);
	rz_socket_free(s);
	return 0;
}
