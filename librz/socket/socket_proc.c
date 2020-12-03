// SPDX-License-Identifier: LGPL-3.0-only

/* XXX : move to rz_util??? rename method names.. to long? */
/* proc IO is not related to socket io.. */

#include <rz_socket.h>
#include <rz_util.h>
#include <signal.h>

#if __UNIX__
#include <sys/wait.h>
#endif

#define BUFFER_SIZE 4096

RZ_API struct rz_socket_proc_t *rz_socket_proc_open(char* const argv[]) {
#if __UNIX__ && LIBC_HAVE_FORK
	RzSocketProc *sp = RZ_NEW (RzSocketProc);

	if (!sp) {
		return NULL;
	}

	if (rz_sys_pipe (sp->fd0, true) == -1) {
		perror ("pipe");
		goto error;
	}

	if (rz_sys_pipe (sp->fd1, true) == -1) {
		perror ("pipe");
		goto error;
	}

	sp->pid = rz_sys_fork ();
	switch (sp->pid) {
	case 0:
		close (0);
		dup2 (sp->fd0[0], 0);
		close (1);
		dup2 (sp->fd1[1], 1);
		rz_sys_execv (argv[0], argv);
		exit (1);
		break;
	case -1:
		perror ("fork");
		rz_socket_proc_close (sp);
		goto error;
		//rz_socket_block_time (sp, false, 0);
	}
	return sp;
error:
	free (sp);
	return NULL;
#else
	return NULL;
#endif
}

RZ_API int rz_socket_proc_close(struct rz_socket_proc_t *sp) {
#if __UNIX__
	/* this is wrong */
	kill (sp->pid, SIGKILL);
	waitpid (sp->pid, NULL, 0); //WNOHANG);
	close (sp->fd0[0]);
	close (sp->fd0[1]);
	//close(sp->fd1[0]);
	close (sp->fd1[1]);
	//sp->fd[0] = -1;
	//sp->fd[1] = -1;
#endif
	return 0;
}

RZ_API int rz_socket_proc_read (RzSocketProc *sp, unsigned char *buf, int len) {
	RzSocket s;
	s.is_ssl = false;
	s.fd = sp->fd1[0];
	return rz_socket_read (&s, buf, len);
}

RZ_API int rz_socket_proc_gets (RzSocketProc *sp, char *buf, int size) {
	RzSocket s;
	s.is_ssl = false;
	s.fd = sp->fd1[0];
	return rz_socket_gets (&s, buf, size);
}

RZ_API int rz_socket_proc_write (RzSocketProc *sp, void *buf, int len) {
	RzSocket s;
	s.is_ssl = false;
	s.fd = sp->fd0[1];
	return rz_socket_write (&s, buf, len);
}

RZ_API void rz_socket_proc_printf (RzSocketProc *sp, const char *fmt, ...) {
	RzSocket s;
	char buf[BUFFER_SIZE];
	va_list ap;
	s.is_ssl = false;
	s.fd = sp->fd0[1];
	if (s.fd != RZ_INVALID_SOCKET) {
		va_start (ap, fmt);
		vsnprintf (buf, BUFFER_SIZE, fmt, ap);
		rz_socket_write (&s, buf, strlen(buf));
		va_end (ap);
	}
}

RZ_API int rz_socket_proc_ready (RzSocketProc *sp, int secs, int usecs) {
	RzSocket s;
	s.is_ssl = false;
	s.fd = sp->fd1[0];
	return rz_socket_ready (&s, secs, usecs);
}
