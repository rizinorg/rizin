/* radare - LGPL - Copyright 2015-2020 - pancake */
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

#define R2P_PID(x) (((R2Pipe*)(x)->data)->pid)
#define R2P_INPUT(x) (((R2Pipe*)(x)->data)->input[0])
#define R2P_OUTPUT(x) (((R2Pipe*)(x)->data)->output[1])

#if !__WINDOWS__
static void env(const char *s, int f) {
        char *a = rz_str_newf ("%d", f);
        rz_sys_setenv (s, a);
        free (a);
}
#endif

RZ_API int rzpipe_write(R2Pipe *rzpipe, const char *str) {
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
RZ_API char *rzpipe_read(R2Pipe *rzpipe) {
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

RZ_API int rzpipe_close(R2Pipe *rzpipe) {
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
		close (rzpipe->input[0]);
		rzpipe->input[0] = -1;
	}
	if (rzpipe->input[1] != -1) {
		close (rzpipe->input[1]);
		rzpipe->input[1] = -1;
	}
	if (rzpipe->output[0] != -1) {
		close (rzpipe->output[0]);
		rzpipe->output[0] = -1;
	}
	if (rzpipe->output[1] != -1) {
		close (rzpipe->output[1]);
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
static int w32_createPipe(R2Pipe *rzpipe, const char *cmd) {
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

static R2Pipe* r2p_open_spawn(R2Pipe* r2p, const char *cmd) {
	rz_return_val_if_fail (r2p, NULL);
#if __UNIX__ || defined(__CYGWIN__)
	char *out = rz_sys_getenv ("RZ_PIPE_IN");
	char *in = rz_sys_getenv ("RZ_PIPE_OUT");
	int done = false;
	if (in && out) {
		int i_in = atoi (in);
		int i_out = atoi (out);
		if (i_in >= 0 && i_out >= 0) {
			r2p->input[0] = r2p->input[1] = i_in;
			r2p->output[0] = r2p->output[1] = i_out;
			done = true;
		}
	}
	if (!done) {
		eprintf ("Cannot find RZ_PIPE_IN or RZ_PIPE_OUT environment\n");
		RZ_FREE (r2p);
	}
	free (in);
	free (out);
	return r2p;
#else
	eprintf ("rzpipe_open(NULL) not supported on windows\n");
	return NULL;
#endif
}

static R2Pipe *rzpipe_new(void) {
	R2Pipe *rzpipe = RZ_NEW0 (R2Pipe);
	if (rzpipe) {
#if __UNIX__
		rzpipe->input[0] = rzpipe->input[1] = -1;
		rzpipe->output[0] = rzpipe->output[1] = -1;
#endif
		rzpipe->child = -1;
	}
	return rzpipe;
}

RZ_API R2Pipe *rzpipe_open_corebind(RzCoreBind *coreb) {
	R2Pipe *rzpipe = rzpipe_new ();
	if (rzpipe) {
		memcpy (&rzpipe->coreb, coreb, sizeof (RzCoreBind));
	}
	return rzpipe;
}

RZ_API R2Pipe *rzpipe_open_dl(const char *libr_path) {
	void *librz = rz_lib_dl_open (libr_path);
	void* (*rnew)() = rz_lib_dl_sym (librz, "rz_core_new");
	char* (*rcmd)(void *c, const char *cmd) = rz_lib_dl_sym (librz, "rz_core_cmd_str");

	if (rnew && rcmd) {
		R2Pipe *rzpipe = rzpipe_new ();
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

RZ_API R2Pipe *rzpipe_open(const char *cmd) {
	R2Pipe *r2p = rzpipe_new ();
	if (!r2p) {
		return NULL;
	}
	if (RZ_STR_ISEMPTY (cmd)) {
		r2p->child = -1;
		return r2p_open_spawn (r2p, cmd);
	}
#if __WINDOWS__
	w32_createPipe (r2p, cmd);
	r2p->child = (int)(r2p->pipe);
#else
	int r = pipe (r2p->input);
	if (r != 0) {
		eprintf ("pipe failed on input\n");
		rzpipe_close (r2p);
		return NULL;
	}
	r = pipe (r2p->output);
	if (r != 0) {
		eprintf ("pipe failed on output\n");
		rzpipe_close (r2p);
		return NULL;
	}
#if LIBC_HAVE_FORK
	r2p->child = fork ();
#else
	r2p->child = -1;
#endif
	if (r2p->child == -1) {
		rzpipe_close (r2p);
		return NULL;
	}
	env ("RZ_PIPE_IN", r2p->input[0]);
	env ("RZ_PIPE_OUT", r2p->output[1]);

	if (r2p->child) {
		char ch = -1;
		// eprintf ("[+] rzpipeipe child is %d\n", rzpipe->child);
		if (read (r2p->output[0], &ch, 1) != 1) {
			eprintf ("Failed to read 1 byte\n");
			rzpipe_close (r2p);
			return NULL;
		}
		if (ch == -1) {
			eprintf ("[+] rzpipe link error.\n");
			rzpipe_close (r2p);
			return NULL;
		}
		// Close parent's end of pipes
		close (r2p->input[0]);
		close (r2p->output[1]);
		r2p->input[0] = -1;
		r2p->output[1] = -1;
	} else {
		int rc = 0;
		if (cmd && *cmd) {
			close (0);
			close (1);
			dup2 (r2p->input[0], 0);
			dup2 (r2p->output[1], 1);
			close (r2p->input[1]);
			close (r2p->output[0]);
			r2p->input[1] = -1;
			r2p->output[0] = -1;
			rc = rz_sandbox_system (cmd, 1);
			fprintf (stderr, "return code %d for %s\n", rc, cmd);
			fflush (stderr);
			// trigger the blocking read
			write (1, "\xff", 1);
			close (r2p->output[1]);
			close (0);
			close (1);
		}
		r2p->child = -1;
		rzpipe_close (r2p);
		exit (rc);
		return NULL;
	}
#endif
	return r2p;
}

RZ_API char *rzpipe_cmd(R2Pipe *r2p, const char *str) {
	rz_return_val_if_fail (r2p && str, NULL);
	if (!*str || !rzpipe_write (r2p, str)) {
		perror ("rzpipe_write");
		return NULL;
	}
	return rzpipe_read (r2p);
}

RZ_API char *rzpipe_cmdf(R2Pipe *r2p, const char *fmt, ...) {
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
		fmt = rzpipe_cmd (r2p, p);
		free (p);
	} else {
		fmt = rzpipe_cmd (r2p, string);
	}
	va_end (ap2);
	va_end (ap);
	return (char*)fmt;
}

