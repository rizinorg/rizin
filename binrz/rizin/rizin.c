/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <rz_main.h>
#include <rz_util.h>

#if EMSCRIPTEN__TODO
#include <emscripten.h>
static RzCore *core = NULL;

void *r2_asmjs_new(const char *cmd) {
	return rz_core_new ();
}

void r2_asmjs_free(void *core) {
	rz_core_free (core);
}

char *r2_asmjs_cmd(void *kore, const char *cmd) {
	if (kore) {
		if (!cmd) {
			rz_core_free (kore);
		}
	} else {
		if (core) {
			kore = core;
		} else {
			kore = core = rz_core_new ();
		}
	}
	return rz_core_cmd_str (kore, cmd);
}

static void wget_cb(const char *f) {
	rz_core_cmdf (core, "o %s", f);
}

void r2_asmjs_openurl(void *kore, const char *url) {
	const char *file = rz_str_lchr (url, '/');
	if (kore) {
		core = kore;
	}
	if (file) {
		emscripten_async_wget (url, file + 1, wget_cb, NULL);
	}
}
#else
static void r2cmd(int in, int out, const char *cmd) {
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
			r2cmd (in, out, argv[i]);
		}
        } else {
		eprintf ("Error: R2PIPE_(IN|OUT) environment not set\n");
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

#endif
