#include <rz_socket.h>

int main() {
	int ret;
	struct rz_socket_proc_t *sp;
	char buf[256];
	char *const args[4] = { "/usr/bin/telnet", "localhost", "9999", 0 };

	sp = rz_socket_proc_open(args);
	//	ret = rz_socket_proc_read(sp, buf, 128);
	rz_socket_proc_printf(sp, "GET / HTTP/1.1\r\n\r\n");
	printf("Waiting...\n");
	for (;;) {
		if (!rz_socket_proc_ready(sp, 0, 0))
			break;
		ret = rz_socket_proc_gets(sp, buf, 128);
		printf("RET=%d\n", ret);
		if (ret < 0)
			break;
		else if (ret > 0)
			printf("%d=\"%s\"\n", ret, buf);
		else
			printf("--\n");
	}
	rz_socket_proc_close(sp);
	return 0;
}
