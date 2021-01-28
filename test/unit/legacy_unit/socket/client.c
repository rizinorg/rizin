#include <rz_socket.h>

int main() {
	int ret;
	char buf[1024];
	RzSocket *s = rz_socket_new(false);
	if (rz_socket_connect(s, "localhost", "9090", 0, 10)) {
		do {
			ret = rz_socket_gets(s, buf, sizeof(buf));
			eprintf("((%s))\n", buf);
		} while (ret >= 0);
	}
	rz_socket_free(s);
}
