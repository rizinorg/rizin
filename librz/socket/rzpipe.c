// SPDX-License-Identifier: LGPL-3.0-only
/*
Usage Example:

	#include <rz_core.h>
	int main() {
		RzCoreBind rcb;
		RzCore *core = rz_core_new ();
		rz_core_bind (core, &rcb);
		rzpipe_open_corebind (&rcb);
		char *clippy = rzpipe_cmd ("?E hello");
		eprintf ("%s\n", clippy);
		free (clippy);
		rzpipe_close (rzpipe);
		rz_core_free (core);
	}
*/

#include <rz_util.h>
#include <rz_lib.h>
#include <rz_socket.h>

#define RZP_PID(x) (((RzPipe*)(x)->data)->pid)
#define RZP_INPUT(x) (((RzPipe*)(x)->data)->input[0])
#define RZP_OUTPUT(x) (((RzPipe*)(x)->data)->output[1])

#if !__WINDOWS__
static void env(const char *s, int f) {
        char *a = rz_str_newf ("%d", f);
        rz_sys_setenv (s, a);
        free (a);
}
#endif

RZ_API int rzpipe_write(RzPipe *rzpipe, const char *str) {
	char *cmd;
	int ret, len;
	if (!rzpipe || !str) {
		return -1;
	}
	len = strlen (str) + 2; /* include \n\x00 */
	cmd = malloc (len + 2);
	if (!cmd) {
		return 0;
	}
	memcpy (cmd, str, len - 1);
	strcpy (cmd + len - 2, "\n");
#if __WINDOWS__
	DWORD dwWritten = -1;
	WriteFile (rzpipe->pipe, cmd, len, &dwWritten, NULL);
	ret = (dwWritten == len);
#else
	ret = (write (rzpipe->input[1], cmd, len) == len);
#endif
	free (cmd);
	return ret;
}

/* TODO: add timeout here ? */
RZ_API char *rzpipe_read(RzPipe *rzpipe) {
	int bufsz = 0;
	char *buf = NULL;
	if (!rzpipe) {
		return NULL;
	}
	bufsz = 4096;
	buf = calloc (1, bufsz);
	if (!buf) {
		return NULL;
	}
#if __WINDOWS__
	BOOL bSuccess = FALSE;
	DWORD dwRead = 0;
	// TODO: handle > 4096 buffers here
	bSuccess = ReadFile (rzpipe->pipe, buf, bufsz, &dwRead, NULL);
	if (!bSuccess || !buf[0]) {
		return NULL;
	}
	if (dwRead > 0) {
		buf[dwRead] = 0;
	}
	buf[bufsz - 1] = 0;
#else
	char *newbuf;
	int i, rv;
	for (i = 0; i < bufsz; i++) {
		rv = read (rzpipe->output[0], buf + i, 1);
		if (i + 2 >= bufsz) {
			bufsz += 4096;
			newbuf = realloc (buf, bufsz);
			if (!newbuf) {
				RZ_FREE (buf);
				break;
			}
			buf = newbuf;
		}
		if (rv != 1 || !buf[i]) {
			break;
		}
	}
	if (buf) {
		int zpos = (i < bufsz)? i: i - 1;
		buf[zpos] = 0;
	}
#endif
	return buf;
}

RZ_API int rzpipe_close(RzPipe *rzpipe) {
	if (!rzpipe) {
		return 0;
	}
	/*
	if (rzpipe->coreb.core && !rzpipe->coreb.puts) {
		void (*rfre)(void *c) = rz_lib_dl_sym (librz, "rz_core_free");
		if (rfre) {
			rfre (rzpipe->coreb.core);
		}
	}
	*/
#if __WINDOWS__
	if (rzpipe->pipe) {
		CloseHandle (rzpipe->pipe);
		rzpipe->pipe = NULL;
	}
#else
	if (rzpipe->input[0] != -1) {
		rz_sys_pipe_close (rzpipe->input[0]);
		rzpipe->input[0] = -1;
	}
	if (rzpipe->input[1] != -1) {
		rz_sys_pipe_close (rzpipe->input[1]);
		rzpipe->input[1] = -1;
	}
	if (rzpipe->output[0] != -1) {
		rz_sys_pipe_close (rzpipe->output[0]);
		rzpipe->output[0] = -1;
	}
	if (rzpipe->output[1] != -1) {
		rz_sys_pipe_close (rzpipe->output[1]);
		rzpipe->output[1] = -1;
	}
	if (rzpipe->child != -1) {
		kill (rzpipe->child, SIGTERM);
		waitpid (rzpipe->child, NULL, 0);
		rzpipe->child = -1;
	}
#endif
	free (rzpipe);
	return 0;
}

#if __WINDOWS__
static int w32_createPipe(RzPipe *rzpipe, const char *cmd) {
	CHAR buf[1024];
	rzpipe->pipe = CreateNamedPipe (TEXT ("\\\\.\\pipe\\RZ_PIPE_IN"),
		PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE | \
		PIPE_READMODE_MESSAGE | \
		PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
		sizeof (buf), sizeof (buf), 0, NULL);
	if (rz_sys_create_child_proc_w32 (cmd, NULL, NULL, NULL)) {
		if (ConnectNamedPipe (rzpipe->pipe, NULL)) {
			return true;
		}
	}
	return false;
}
#endif

static RzPipe* rzp_open_spawn(RzPipe* rzp, const char *cmd) {
	rz_return_val_if_fail (rzp, NULL);
#if __UNIX__ || defined(__CYGWIN__)
	char *out = rz_sys_getenv ("RZ_PIPE_IN");
	char *in = rz_sys_getenv ("RZ_PIPE_OUT");
	int done = false;
	if (in && out) {
		int i_in = atoi (in);
		int i_out = atoi (out);
		if (i_in >= 0 && i_out >= 0) {
			rzp->input[0] = rzp->input[1] = i_in;
			rzp->output[0] = rzp->output[1] = i_out;
			done = true;
		}
	}
	if (!done) {
		eprintf ("Cannot find RZ_PIPE_IN or RZ_PIPE_OUT environment\n");
		RZ_FREE (rzp);
	}
	free (in);
	free (out);
	return rzp;
#else
	eprintf ("rzpipe_open(NULL) not supported on windows\n");
	return NULL;
#endif
}

static RzPipe *rzpipe_new(void) {
	RzPipe *rzpipe = RZ_NEW0 (RzPipe);
	if (rzpipe) {
#if __UNIX__
		rzpipe->input[0] = rzpipe->input[1] = -1;
		rzpipe->output[0] = rzpipe->output[1] = -1;
#endif
		rzpipe->child = -1;
	}
	return rzpipe;
}

RZ_API RzPipe *rzpipe_open_corebind(RzCoreBind *coreb) {
	RzPipe *rzpipe = rzpipe_new ();
	if (rzpipe) {
		memcpy (&rzpipe->coreb, coreb, sizeof (RzCoreBind));
	}
	return rzpipe;
}

RZ_API RzPipe *rzpipe_open_dl(const char *libr_path) {
	void *librz = rz_lib_dl_open (libr_path);
	void* (*rnew)() = rz_lib_dl_sym (librz, "rz_core_new");
	char* (*rcmd)(void *c, const char *cmd) = rz_lib_dl_sym (librz, "rz_core_cmd_str");

	if (rnew && rcmd) {
		RzPipe *rzpipe = rzpipe_new ();
		if (rzpipe) {
			rzpipe->coreb.core = rnew ();
			rzpipe->coreb.cmdstr = rcmd;
			// rzpipe->coreb.free = rfre;
		}
		return rzpipe;
	}
	eprintf ("Cannot resolve rz_core_cmd, rz_core_cmd_str, rz_core_free\n");
	return NULL;
}

RZ_API RzPipe *rzpipe_open(const char *cmd) {
	RzPipe *rzp = rzpipe_new ();
	if (!rzp) {
		return NULL;
	}
	if (RZ_STR_ISEMPTY (cmd)) {
		rzp->child = -1;
		return rzp_open_spawn (rzp, cmd);
	}
#if __WINDOWS__
	w32_createPipe (rzp, cmd);
	rzp->child = (int)(rzp->pipe);
#else
	int r = rz_sys_pipe (rzp->input, false);
	if (r != 0) {
		eprintf ("pipe failed on input\n");
		rzpipe_close (rzp);
		return NULL;
	}
	r = rz_sys_pipe (rzp->output, false);
	if (r != 0) {
		eprintf ("pipe failed on output\n");
		rzpipe_close (rzp);
		return NULL;
	}
#if LIBC_HAVE_FORK
	rzp->child = fork ();
#else
	rzp->child = -1;
#endif
	if (rzp->child == -1) {
		rzpipe_close (rzp);
		return NULL;
	}
	env ("RZ_PIPE_IN", rzp->input[0]);
	env ("RZ_PIPE_OUT", rzp->output[1]);

	if (rzp->child) {
		signed char ch = -1;
		// eprintf ("[+] rzpipeipe child is %d\n", rzpipe->child);
		if (read (rzp->output[0], &ch, 1) != 1) {
			eprintf ("Failed to read 1 byte\n");
			rzpipe_close (rzp);
			return NULL;
		}
		if (ch == -1) {
			eprintf ("[+] rzpipe link error.\n");
			rzpipe_close (rzp);
			return NULL;
		}
		// Close parent's end of pipes
		rz_sys_pipe_close (rzp->input[0]);
		rz_sys_pipe_close (rzp->output[1]);
		rzp->input[0] = -1;
		rzp->output[1] = -1;
	} else {
		int rc = 0;
		if (cmd && *cmd) {
			close (0);
			close (1);
			dup2 (rzp->input[0], 0);
			dup2 (rzp->output[1], 1);
			rz_sys_pipe_close (rzp->input[1]);
			rz_sys_pipe_close (rzp->output[0]);
			rzp->input[1] = -1;
			rzp->output[0] = -1;
			rc = rz_sandbox_system (cmd, 1);
			if (rc != 0) {
				eprintf ("return code %d for %s\n", rc, cmd);
			}
			// trigger the blocking read
			write (1, "\xff", 1);
			rz_sys_pipe_close (rzp->output[1]);
			close (0);
			close (1);
		}
		rzp->child = -1;
		rzpipe_close (rzp);
		exit (rc);
		return NULL;
	}
#endif
	return rzp;
}

RZ_API char *rzpipe_cmd(RzPipe *rzp, const char *str) {
	rz_return_val_if_fail (rzp && str, NULL);
	if (!*str || !rzpipe_write (rzp, str)) {
		perror ("rzpipe_write");
		return NULL;
	}
	return rzpipe_read (rzp);
}

RZ_API char *rzpipe_cmdf(RzPipe *rzp, const char *fmt, ...) {
	int ret, ret2;
	char *p, string[1024];
	va_list ap, ap2;
	va_start (ap, fmt);
	va_start (ap2, fmt);
	ret = vsnprintf (string, sizeof (string) - 1, fmt, ap);
	if (ret < 1 || ret >= sizeof (string)) {
		p = malloc (ret + 2);
		if (!p) {
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		ret2 = vsnprintf (p, ret + 1, fmt, ap2);
		if (ret2 < 1 || ret2 > ret + 1) {
			free (p);
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		fmt = rzpipe_cmd (rzp, p);
		free (p);
	} else {
		fmt = rzpipe_cmd (rzp, string);
	}
	va_end (ap2);
	va_end (ap);
	return (char*)fmt;
}

