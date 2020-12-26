// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>

static void rz_cmd(int in, int out, const char *cmd) {
        write (out, cmd, strlen (cmd) + 1);
        write (out, "\n", 1);
        int bufsz = (1024 * 64);
        unsigned char *buf = malloc (bufsz);
        if (!buf) {
                return;
        }
        while (1) {
                int n = read (in, buf, bufsz);
				buf[bufsz - 1] = '\0';
                int len = strlen ((const char *)buf);
                n = len;
                if (n < 1) {
                        break;
                }
                write (1, buf, n);
		if (n != bufsz) {
			break;
		}
        }
        free (buf);
        write (1, "\n", 1);
}

static int rz_main_rzpipe(int argc, const char **argv) {
        int i, rc = 0;
        char *_in = rz_sys_getenv ("RZ_PIPE_IN");
        char *_out = rz_sys_getenv ("RZ_PIPE_OUT");
        if (_in && _out) {
		int in = atoi (_in);
		int out = atoi (_out);
		for (i = 1; i < argc; i++) {
			rz_cmd (in, out, argv[i]);
		}
        } else {
		eprintf ("Error: RZ_PIPE_(IN|OUT) environment not set\n");
		eprintf ("Usage: rizin -c '!*rzp x' # run commands via rzpipe\n");
                rc = 1;
	}
	free (_in);
	free (_out);
        return rc;
}

int main(int argc, const char **argv) {
	if (argc > 0 && strstr (argv[0], "rzp")) {
		return rz_main_rzpipe (argc, argv);
	}
	return rz_main_rizin (argc, argv);
}