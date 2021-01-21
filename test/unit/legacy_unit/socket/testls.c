#include <rz_socket.h>

int main() {
	int ret;
	struct rz_socket_proc_t *sp;
	char buf[256];
	char *const args[3] = { "/bin/ls", "-l", 0 };

	sp = rz_socket_proc_open(args);

	for (;;) {
		if (rz_socket_proc_ready(sp, 0, 0) < 0)
			break;
		ret = rz_socket_proc_gets(sp, buf, 128);
		if (ret > 0)
			printf("%d=\"%s\"\n", ret, buf);
		else {
			printf("%d=\n", ret);
			break;
		}
	}
	rz_socket_proc_close(sp);
	return 0;
}
