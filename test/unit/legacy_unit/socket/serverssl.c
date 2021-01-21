#include <rz_socket.h>
#define MAX_LINE 2048
#define PORT     "4433"

int main(int argc, char **argv) {
	char buf[MAX_LINE + 1];
	RzSocket *s, *cli;

	if (argc < 2) {
		eprintf("Use %s <cert>\n", argv[0]);
		return 1;
	}
	s = rz_socket_new(true);
	if (!rz_socket_listen(s, PORT, argv[1])) {
		eprintf("Error, cant listen at port: %s\n", PORT);
		return 1;
	}
	while (1) {
		if (!(cli = rz_socket_accept(s)))
			break;
		rz_socket_read(cli, (unsigned char *)buf, 9);
		strcpy(buf, "HTTP/1.0 200 OK\r\n"
			    "Server: EKRServer\r\n\r\n"
			    "Server test page\r\n");
		rz_socket_write(cli, buf, strlen(buf));
		rz_socket_flush(cli);
		rz_socket_free(cli);
	}
	rz_socket_free(s);
	return 0;
}
