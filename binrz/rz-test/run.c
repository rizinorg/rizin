/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "rz_test.h"

#if __WINDOWS__
struct rz_test_subprocess_t {
	HANDLE stdin_write;
	HANDLE stdout_read;
	HANDLE stderr_read;
	HANDLE proc;
	int ret;
	RzStrBuf out;
	RzStrBuf err;
};

static volatile long pipe_id = 0;

static bool create_pipe_overlap(HANDLE *pipe_read, HANDLE *pipe_write, LPSECURITY_ATTRIBUTES attrs, DWORD sz, DWORD read_mode, DWORD write_mode) {
	// see https://stackoverflow.com/a/419736
	if (!sz) {
		sz = 4096;
	}
	char name[MAX_PATH];
	snprintf (name, sizeof (name), "\\\\.\\pipe\\rz_test-subproc.%d.%ld", (int)GetCurrentProcessId (), (long)InterlockedIncrement (&pipe_id));
	*pipe_read = CreateNamedPipeA (name, PIPE_ACCESS_INBOUND | read_mode, PIPE_TYPE_BYTE | PIPE_WAIT, 1, sz, sz, 120 * 1000, attrs);
	if (!*pipe_read) {
		return FALSE;
	}
	*pipe_write = CreateFileA (name, GENERIC_WRITE, 0, attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | write_mode, NULL);
	if (*pipe_write == INVALID_HANDLE_VALUE) {
		CloseHandle (*pipe_read);
		return FALSE;
	}
	return true;
}

RZ_API bool rz_test_subprocess_init(void) { return true; }
RZ_API void rz_test_subprocess_fini(void) {}

// Create an env block that inherits the current vars but overrides the given ones
static LPWCH override_env(const char *envvars[], const char *envvals[], size_t env_size) {
	LPWCH ret = NULL;
	LPWCH parent_env = NULL;
	size_t i;
	LPWSTR *wenvvars = calloc (env_size, sizeof (LPWSTR));
	LPWSTR *wenvvals = calloc (env_size, sizeof (LPWSTR));
	parent_env = GetEnvironmentStringsW ();
	if (!wenvvars || !wenvvals || !parent_env) {
		goto error;
	}

	for (i = 0; i < env_size; i++) {
		wenvvars[i] = rz_utf8_to_utf16 (envvars[i]);
		wenvvals[i] = rz_utf8_to_utf16 (envvals[i]);
		if (!wenvvars[i] || !wenvvals[i]) {
			goto error;
		}
	}

	RzVector buf;
	rz_vector_init (&buf, sizeof (wchar_t), NULL, NULL);
	LPWCH cur = parent_env;
	while (true) {
		LPWCH var_begin = cur;
		//wprintf (L"ENV: %s\n", cur);
		while (*cur && *cur != L'=') {
			cur++;
		}
		if (!*cur) {
			cur++;
			if (!*cur) {
				break;
			}
			continue;
		}
		bool overridden = false;
		for (i = 0; i < env_size; i++) {
			size_t overlen = lstrlenW (wenvvars[i]);
			size_t curlen = cur - var_begin;
			if (overlen == curlen && !memcmp (var_begin, wenvvars[i], overlen)) {
				overridden = true;
				break;
			}
		}
		while (*cur) {
			cur++;
		}
		if (!overridden) {
			rz_vector_insert_range (&buf, buf.len, var_begin, cur - var_begin + 1);
		}
		cur++;
		if (!*cur) {
			// \0\0 marks the end
			break;
		}
	}

	wchar_t c;
	for (i = 0; i < env_size; i++) {
		rz_vector_insert_range (&buf, buf.len, wenvvars[i], lstrlenW (wenvvars[i]));
		c = L'=';
		rz_vector_push (&buf, &c);
		rz_vector_insert_range (&buf, buf.len, wenvvals[i], lstrlenW (wenvvals[i]));
		c = L'\0';
		rz_vector_push (&buf, &c);
	}
	c = '\0';
	rz_vector_push (&buf, &c);
	ret = buf.a;

error:
	if (parent_env) {
		FreeEnvironmentStringsW (parent_env);
	}
	for (i = 0; i < env_size; i++) {
		if (wenvvars) {
			free (wenvvars[i]);
		}
		if (wenvvals) {
			free (wenvvals[i]);
		}
	}
	free (wenvvars);
	free (wenvvals);
	return ret;
}

RZ_API RzTestSubprocess *rz_test_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
	RzTestSubprocess *proc = NULL;
	HANDLE stdin_read = NULL;
	HANDLE stdout_write = NULL;
	HANDLE stderr_write = NULL;

	char **argv = calloc (args_size + 1, sizeof (char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)file;
	if (args_size) {
		memcpy (argv + 1, args, sizeof (char *) * args_size);
	}
	char *cmdline = rz_str_format_msvc_argv (args_size + 1, argv);
	free (argv);
	if (!cmdline) {
		return NULL;
	}

	proc = RZ_NEW0 (RzTestSubprocess);
	if (!proc) {
		goto error;
	}
	proc->ret = -1;

	SECURITY_ATTRIBUTES sattrs;
	sattrs.nLength = sizeof (sattrs);
	sattrs.bInheritHandle = TRUE;
	sattrs.lpSecurityDescriptor = NULL;

	if (!create_pipe_overlap (&proc->stdout_read, &stdout_write, &sattrs, 0, FILE_FLAG_OVERLAPPED, 0)) {
		proc->stdout_read = stdout_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stdout_read, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}
	if (!create_pipe_overlap (&proc->stderr_read, &stderr_write, &sattrs, 0, FILE_FLAG_OVERLAPPED, 0)) {
		proc->stdout_read = stderr_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stderr_read, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}
	if (!CreatePipe (&stdin_read, &proc->stdin_write, &sattrs, 0)) {
		stdin_read = proc->stdin_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stdin_write, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}

	PROCESS_INFORMATION proc_info = { 0 };
	STARTUPINFO start_info = { 0 };
	start_info.cb = sizeof (start_info);
	start_info.hStdError = stderr_write;
	start_info.hStdOutput = stdout_write;
	start_info.hStdInput = stdin_read;
	start_info.dwFlags |= STARTF_USESTDHANDLES;

	LPWSTR env = override_env (envvars, envvals, env_size);
	if (!CreateProcessA (NULL, cmdline,
			NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, env,
			NULL, &start_info, &proc_info)) {
		free (env);
		eprintf ("CreateProcess failed: %#x\n", (int)GetLastError ());
		goto error;
	}
	free (env);

	CloseHandle (proc_info.hThread);
	proc->proc = proc_info.hProcess;

beach:
	if (stdin_read) {
		CloseHandle (stdin_read);
	}
	if (stdout_write) {
		CloseHandle (stdout_write);
	}
	if (stderr_write) {
		CloseHandle (stderr_write);
	}
	free (cmdline);
	return proc;
error:
	if (proc) {
		if (proc->stdin_write) {
			CloseHandle (proc->stdin_write);
		}
		if (proc->stdout_read) {
			CloseHandle (proc->stdout_read);
		}
		if (proc->stderr_read) {
			CloseHandle (proc->stderr_read);
		}
		free (proc);
		proc = NULL;
	}
	goto beach;
}

RZ_API bool rz_test_subprocess_wait(RzTestSubprocess *proc, ut64 timeout_ms) {
	OVERLAPPED stdout_overlapped = { 0 };
	stdout_overlapped.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!stdout_overlapped.hEvent) {
		return false;
	}
	OVERLAPPED stderr_overlapped = { 0 };
	stderr_overlapped.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!stderr_overlapped.hEvent) {
		CloseHandle (stdout_overlapped.hEvent);
		return false;
	}

	ut64 timeout_us_abs = UT64_MAX;
	if (timeout_ms != UT64_MAX) {
		timeout_us_abs = rz_time_now_mono () + timeout_ms * RZ_USEC_PER_MSEC;
	}

	ut8 stdout_buf[0x500];
	ut8 stderr_buf[0x500];
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;

#define DO_READ(which) \
	if (!ReadFile (proc->which##_read, which##_buf, sizeof (which##_buf) - 1, NULL, &(which##_overlapped))) { \
		if (GetLastError () != ERROR_IO_PENDING) { \
			/* EOF or some other error */ \
			which##_eof = true; \
		} \
	}

	DO_READ (stdout)
	DO_READ (stderr)

	RzVector handles;
	rz_vector_init (&handles, sizeof (HANDLE), NULL, NULL);
	while (true) {
		rz_vector_clear (&handles);
		size_t stdout_index = 0;
		size_t stderr_index = 0;
		size_t proc_index = 0;
		if (!stdout_eof) {
			stdout_index = handles.len;
			rz_vector_push (&handles, &stdout_overlapped.hEvent);
		}
		if (!stderr_eof) {
			stderr_index = handles.len;
			rz_vector_push (&handles, &stderr_overlapped.hEvent);
		}
		if (!child_dead) {
			proc_index = handles.len;
			rz_vector_push (&handles, &proc->proc);
		}
		
		DWORD timeout = INFINITE;
		if (timeout_us_abs != UT64_MAX) {
			ut64 now = rz_time_now_mono ();
			if (now >= timeout_us_abs) {
				return false;
			}
			timeout = (DWORD)((timeout_us_abs - now) / RZ_USEC_PER_MSEC);
		}
		DWORD signaled = WaitForMultipleObjects (handles.len, handles.a, FALSE, timeout);
		if (!stdout_eof && signaled == stdout_index) {
			DWORD r;
			BOOL res = GetOverlappedResult (proc->stdout_read, &stdout_overlapped, &r, TRUE);
			if (!res) {
				stdout_eof = true;
				continue;
			}
			stdout_buf[r] = '\0';
			rz_str_remove_char (stdout_buf, '\r');
			rz_strbuf_append (&proc->out, (const char *)stdout_buf);
			ResetEvent (stdout_overlapped.hEvent);
			DO_READ (stdout)
			continue;
		}
		if (!stderr_eof && signaled == stderr_index) {
			DWORD read;
			BOOL res = GetOverlappedResult (proc->stderr_read, &stderr_overlapped, &read, TRUE);
			if (!res) {
				stderr_eof = true;
				continue;
			}
			stderr_buf[read] = '\0';
			rz_str_remove_char (stderr_buf, '\r');
			rz_strbuf_append (&proc->err, (const char *)stderr_buf);
			ResetEvent (stderr_overlapped.hEvent);
			DO_READ (stderr);
			continue;
		}
		if (!child_dead && signaled == proc_index) {
			child_dead = true;
			DWORD exit_code;
			if (GetExitCodeProcess (proc->proc, &exit_code)) {
				proc->ret = exit_code;
			}
			continue;
		}
		break;
	}
	rz_vector_clear (&handles);
	CloseHandle (stdout_overlapped.hEvent);
	CloseHandle (stderr_overlapped.hEvent);
	return stdout_eof && stderr_eof && child_dead;
}

RZ_API void rz_test_subprocess_kill(RzTestSubprocess *proc) {
	TerminateProcess (proc->proc, 255);
}

RZ_API void rz_test_subprocess_stdin_write(RzTestSubprocess *proc, const ut8 *buf, size_t buf_size) {
	DWORD read;
	WriteFile (proc->stdin_write, buf, buf_size, &read, NULL);
}


RZ_API RzTestProcessOutput *rz_test_subprocess_drain(RzTestSubprocess *proc) {
	RzTestProcessOutput *out = RZ_NEW (RzTestProcessOutput);
	if (!out) {
		return NULL;
	}
	out->out = rz_strbuf_drain_nofree (&proc->out);
	out->err = rz_strbuf_drain_nofree (&proc->err);
	out->ret = proc->ret;
	return out;
}

RZ_API void rz_test_subprocess_free(RzTestSubprocess *proc) {
	if (!proc) {
		return;
	}
	CloseHandle (proc->stdin_write);
	CloseHandle (proc->stdout_read);
	CloseHandle (proc->stderr_read);
	CloseHandle (proc->proc);
	free (proc);
}
#else

#include <errno.h>
#include <sys/wait.h>

struct rz_test_subprocess_t {
	pid_t pid;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
	int killpipe[2];
	int ret;
	RzStrBuf out;
	RzStrBuf err;
};

static RzPVector subprocs;
static RzThreadLock *subprocs_mutex;
static int sigchld_pipe[2];
static RzThread *sigchld_thread;

static void handle_sigchld(int sig) {
	ut8 b = 1;
	write (sigchld_pipe[1], &b, 1);
}

static RzThreadFunctionRet sigchld_th(RzThread *th) {
	while (true) {
		ut8 b;
		ssize_t rd = read (sigchld_pipe[0], &b, 1);
		if (rd <= 0) {
			if (rd < 0) {
				if (errno == EINTR) {
					continue;
				}
				perror ("read");
			}
			break;
		}
		if (!b) {
			break;
		}
		while (true) {
			int wstat;
			pid_t pid = waitpid (-1, &wstat, WNOHANG);
			if (pid <= 0)
				break;

			rz_test_subprocess_lock ();
			void **it;
			RzTestSubprocess *proc = NULL;
			rz_pvector_foreach (&subprocs, it) {
				RzTestSubprocess *p = *it;
				if (p->pid == pid) {
					proc = p;
					break;
				}
			}
			if (!proc) {
				rz_test_subprocess_unlock ();
				continue;
			}

			if (WIFEXITED (wstat)) {
				proc->ret = WEXITSTATUS (wstat);
			} else {
				proc->ret = -1;
			}
			ut8 r = 0;
			write (proc->killpipe[1], &r, 1);
			rz_test_subprocess_unlock ();
		}
	}
	return RZ_TH_STOP;
}

RZ_API bool rz_test_subprocess_init(void) {
	rz_pvector_init(&subprocs, NULL);
	subprocs_mutex = rz_th_lock_new (true);
	if (!subprocs_mutex) {
		return false;
	}
	if (pipe (sigchld_pipe) == -1) {
		perror ("pipe");
		rz_th_lock_free (subprocs_mutex);
		return false;
	}
	sigchld_thread = rz_th_new (sigchld_th, NULL, 0);
	if (!sigchld_thread) {
		close (sigchld_pipe [0]);
		close (sigchld_pipe [1]);
		rz_th_lock_free (subprocs_mutex);
		return false;
	}
	if (rz_sys_signal (SIGCHLD, handle_sigchld) < 0) {
		close (sigchld_pipe [0]);
		close (sigchld_pipe [1]);
		rz_th_lock_free (subprocs_mutex);
		return false;
	}
	return true;
}

RZ_API void rz_test_subprocess_fini(void) {
	rz_sys_signal (SIGCHLD, SIG_IGN);
	ut8 b = 0;
	write (sigchld_pipe[1], &b, 1);
	close (sigchld_pipe [1]);
	rz_th_wait (sigchld_thread);
	close (sigchld_pipe [0]);
	rz_th_free (sigchld_thread);
	rz_pvector_clear (&subprocs);
	rz_th_lock_free (subprocs_mutex);
}

RZ_API void rz_test_subprocess_lock(void) {
	rz_th_lock_enter (subprocs_mutex);
}

RZ_API void rz_test_subprocess_unlock(void) {
	rz_th_lock_leave (subprocs_mutex);
}

RZ_API RzTestSubprocess *rz_test_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
	char **argv = calloc (args_size + 2, sizeof (char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)file;
	if (args_size) {
		memcpy (argv + 1, args, sizeof (char *) * args_size);
	}
	// done by calloc: argv[args_size + 1] = NULL;
	rz_test_subprocess_lock ();
	RzTestSubprocess *proc = RZ_NEW0 (RzTestSubprocess);
	if (!proc) {
		goto error;
	}
	proc->killpipe[0] = proc->killpipe[1] = -1;
	proc->ret = -1;
	rz_strbuf_init (&proc->out);
	rz_strbuf_init (&proc->err);

	if (pipe (proc->killpipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl (proc->killpipe[1], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}

	int stdin_pipe[2] = { -1, -1 };
	if (pipe (stdin_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	proc->stdin_fd = stdin_pipe[1];

	int stdout_pipe[2] = { -1, -1 };
	if (pipe (stdout_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}
	proc->stdout_fd = stdout_pipe[0];

	int stderr_pipe[2] = { -1, -1 };
	if (pipe (stderr_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}
	proc->stderr_fd = stderr_pipe[0];

	proc->pid = rz_sys_fork ();
	if (proc->pid == -1) {
		// fail
		rz_th_lock_leave (subprocs_mutex);
		perror ("fork");
		free (proc);
		free (argv);
		return NULL;
	} else if (proc->pid == 0) {
		// child
		while ((dup2(stdin_pipe[0], STDIN_FILENO) == -1) && (errno == EINTR)) {}
		close (stdin_pipe[0]);
		close (stdin_pipe[1]);
		while ((dup2(stdout_pipe[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
		close (stdout_pipe[1]);
		close (stdout_pipe[0]);
		while ((dup2(stderr_pipe[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
		close (stderr_pipe[1]);
		close (stderr_pipe[0]);

		size_t i;
		for (i = 0; i < env_size; i++) {
			setenv (envvars[i], envvals[i], 1);
		}
		execvp (file, argv);
		perror ("exec");
		rz_sys_exit (-1, true);
	}
	free (argv);

	// parent
	close (stdin_pipe[0]);
	close (stdout_pipe[1]);
	close (stderr_pipe[1]);

	rz_pvector_push (&subprocs, proc);

	rz_test_subprocess_unlock ();

	return proc;
error:
	free (argv);
	if (proc && proc->killpipe[0] == -1) {
		close (proc->killpipe[0]);
	}
	if (proc && proc->killpipe[1] == -1) {
		close (proc->killpipe[1]);
	}
	free (proc);
	if (stderr_pipe[0] == -1) {
		close (stderr_pipe[0]);
	}
	if (stderr_pipe[1] == -1) {
		close (stderr_pipe[1]);
	}
	if (stdout_pipe[0] == -1) {
		close (stdout_pipe[0]);
	}
	if (stdout_pipe[1] == -1) {
		close (stdout_pipe[1]);
	}
	if (stdin_pipe[0] == -1) {
		close (stdin_pipe[0]);
	}
	if (stdin_pipe[1] == -1) {
		close (stdin_pipe[1]);
	}
	rz_test_subprocess_unlock ();
	return NULL;
}

RZ_API bool rz_test_subprocess_wait(RzTestSubprocess *proc, ut64 timeout_ms) {
	ut64 timeout_abs;
	if (timeout_ms != UT64_MAX) {
		timeout_abs = rz_time_now_mono () + timeout_ms * RZ_USEC_PER_MSEC;
	}

	int r = 0;
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;
	while (!stdout_eof || !stderr_eof || !child_dead) {
		fd_set rfds;
		FD_ZERO (&rfds);
		int nfds = 0;
		if (!stdout_eof) {
			FD_SET (proc->stdout_fd, &rfds);
			if (proc->stdout_fd > nfds) {
				nfds = proc->stdout_fd;
			}
		}
		if (!stderr_eof) {
			FD_SET (proc->stderr_fd, &rfds);
			if (proc->stderr_fd > nfds) {
				nfds = proc->stderr_fd;
			}
		}
		if (!child_dead) {
			FD_SET (proc->killpipe[0], &rfds);
			if (proc->killpipe[0] > nfds) {
				nfds = proc->killpipe[0];
			}
		}
		nfds++;

		struct timeval timeout_s;
		struct timeval *timeout = NULL;
		if (timeout_ms != UT64_MAX) {
			ut64 now = rz_time_now_mono ();
			if (now >= timeout_abs) {
				break;
			}
			ut64 usec_diff = timeout_abs - rz_time_now_mono ();
			timeout_s.tv_sec = usec_diff / RZ_USEC_PER_SEC;
			timeout_s.tv_usec = usec_diff % RZ_USEC_PER_SEC;
			timeout = &timeout_s;
		}
		r = select (nfds, &rfds, NULL, NULL, timeout);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}

		bool timedout = true;
		if (FD_ISSET (proc->stdout_fd, &rfds)) {
			timedout = false;
			char buf[0x500];
			ssize_t sz = read (proc->stdout_fd, buf, sizeof (buf));
			if (sz < 0) {
				perror ("read");
			} else if (sz == 0) {
				stdout_eof = true;
			} else {
				rz_strbuf_append_n (&proc->out, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->stderr_fd, &rfds)) {
			timedout = false;
			char buf[0x500];
			ssize_t sz = read (proc->stderr_fd, buf, sizeof (buf));
			if (sz < 0) {
				perror ("read");
				continue;
			} else if (sz == 0) {
				stderr_eof = true;
			} else {
				rz_strbuf_append_n (&proc->err, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->killpipe[0], &rfds)) {
			timedout = false;
			child_dead = true;
		}
		if (timedout) {
			break;
		}
	}
	if (r < 0) {
		perror ("select");
	}
	rz_test_subprocess_lock ();
	rz_test_subprocess_unlock ();
	return child_dead;
}

RZ_API void rz_test_subprocess_kill(RzTestSubprocess *proc) {
	kill (proc->pid, SIGKILL);
}

RZ_API void rz_test_subprocess_stdin_write(RzTestSubprocess *proc, const ut8 *buf, size_t buf_size) {
	write (proc->stdin_fd, buf, buf_size);
	close (proc->stdin_fd);
	proc->stdin_fd = -1;
}

RZ_API RzTestProcessOutput *rz_test_subprocess_drain(RzTestSubprocess *proc) {
	rz_test_subprocess_lock ();
	RzTestProcessOutput *out = RZ_NEW (RzTestProcessOutput);
	if (out) {
		out->out = rz_strbuf_drain_nofree (&proc->out);
		out->err = rz_strbuf_drain_nofree (&proc->err);
		out->ret = proc->ret;
		out->timeout = false;
	}
	rz_test_subprocess_unlock ();
	return out;
}

RZ_API void rz_test_subprocess_free(RzTestSubprocess *proc) {
	if (!proc) {
		return;
	}
	rz_test_subprocess_lock ();
	rz_pvector_remove_data (&subprocs, proc);
	rz_test_subprocess_unlock ();
	rz_strbuf_fini (&proc->out);
	rz_strbuf_fini (&proc->err);
	close (proc->killpipe[0]);
	close (proc->killpipe[1]);
	if (proc->stdin_fd != -1) {
		close (proc->stdin_fd);
	}
	close (proc->stdout_fd);
	close (proc->stderr_fd);
	free (proc);
}
#endif

RZ_API void rz_test_process_output_free(RzTestProcessOutput *out) {
	if (!out) {
		return;
	}
	free (out->out);
	free (out->err);
	free (out);
}

static RzTestProcessOutput *subprocess_runner(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	RzTestSubprocess *proc = rz_test_subprocess_start (file, args, args_size, envvars, envvals, env_size);
	if (!proc) {
		return NULL;
	}
	bool timeout = !rz_test_subprocess_wait (proc, timeout_ms);
	if (timeout) {
		rz_test_subprocess_kill (proc);
	}
	RzTestProcessOutput *out = rz_test_subprocess_drain (proc);
	if (out) {
		out->timeout = timeout;
	}
	rz_test_subprocess_free (proc);
	return out;
}

#if __WINDOWS__
static char *convert_win_cmds(const char *cmds) {
	char *r = malloc (strlen (cmds) + 1);
	if (!r) {
		return NULL;
	}
	char *p = r;
	while (*cmds) {
		if (*cmds == '!' || (*cmds == '\"' && cmds[1] == '!')) {
			// Adjust shell syntax for Windows,
			// only for lines starting with ! or "!
			char c;
			for (; c = *cmds, c; cmds++) {
				if (c == '\\') {
					// replace \$ by $
					c = *++cmds;
					if (c == '$') {
						*p++ = '$';
					} else {
						*p++ = '\\';
						*p++ = c;
					}
				} else if (c == '$') {
					// replace ${VARNAME} by %VARNAME%
					c = *++cmds;
					if (c == '{') {
						*p++ = '%';
						cmds++;
						for (; c = *cmds, c && c != '}'; *cmds++) {
							*p++ = c;
						}
						if (c) { // must check c to prevent overflow
							*p++ = '%';
						}
					} else {
						*p++ = '$';
						*p++ = c;
					}
				} else {
					*p++ = c;
					if (c == '\n') {
						cmds++;
						break;
					}
				}
			}
			continue;
		}

		// Nothing to do, just copy the line
		char *lend = strchr (cmds, '\n');
		size_t llen;
		if (lend) {
			llen = lend - cmds + 1;
		} else {
			llen = strlen (cmds);
		}
		memcpy (p, cmds, llen);
		cmds += llen;
		p += llen;
	}
	*p = '\0';
	return rz_str_replace (r, "/dev/null", "nul", true);
}
#endif

static RzTestProcessOutput *run_rz_test(RzTestRunConfig *config, ut64 timeout_ms, const char *cmds, RzList *files, RzList *extra_args, bool load_plugins, RzTestCmdRunner runner, void *user) {
	RzPVector args;
	rz_pvector_init (&args, NULL);
	rz_pvector_push (&args, "-escr.utf8=0");
	rz_pvector_push (&args, "-escr.color=0");
	rz_pvector_push (&args, "-escr.interactive=0");
	rz_pvector_push (&args, "-N");
	RzListIter *it;
	void *extra_arg, *file_arg;
	rz_list_foreach (extra_args, it, extra_arg) {
		rz_pvector_push (&args, extra_arg);
	}
	rz_pvector_push (&args, "-Qc");
#if __WINDOWS__
	char *wcmds = convert_win_cmds (cmds);
	rz_pvector_push (&args, wcmds);
#else
	rz_pvector_push (&args, (void *)cmds);
#endif
	rz_list_foreach (files, it, file_arg) {
		rz_pvector_push (&args, file_arg);
	}

	const char *envvars[] = {
#if __WINDOWS__
		"ANSICON",
#endif
		"RZ_NOPLUGINS"
	};
	const char *envvals[] = {
#if __WINDOWS__
		"1",
#endif
		"1"
	};
#if __WINDOWS__
	size_t env_size = load_plugins ? 1 : 2;
#else
	size_t env_size = load_plugins ? 0 : 1;
#endif
	RzTestProcessOutput *out = runner (config->r2_cmd, args.v.a, rz_pvector_len (&args), envvars, envvals, env_size, timeout_ms, user);
	rz_pvector_clear (&args);
#if __WINDOWS__
	free (wcmds);
#endif
	return out;
}

RZ_API RzTestProcessOutput *rz_test_run_cmd_test(RzTestRunConfig *config, RzCmdTest *test, RzTestCmdRunner runner, void *user) {
	RzList *extra_args = test->args.value ? rz_str_split_duplist (test->args.value, " ", true) : NULL;
	RzList *files = test->file.value? rz_str_split_duplist (test->file.value, "\n", true): NULL;
	RzListIter *it;
	RzListIter *tmpit;
	char *token;
	rz_list_foreach_safe (extra_args, it, tmpit, token) {
		if (!*token) {
			rz_list_delete (extra_args, it);
		}
	}
	rz_list_foreach_safe (files, it, tmpit, token) {
		if (!*token) {
			rz_list_delete (files, it);
		}
	}
	if (rz_list_empty (files)) {
		if (!files) {
			files = rz_list_new ();
		} else {
			files->free = NULL;
		}
		rz_list_push (files, "-");
	}
	ut64 timeout_ms = test->timeout.set? test->timeout.value * 1000: config->timeout_ms;
	RzTestProcessOutput *out = run_rz_test (config, timeout_ms, test->cmds.value, files, extra_args, test->load_plugins, runner, user);
	rz_list_free (extra_args);
	rz_list_free (files);
	return out;
}

RZ_API bool rz_test_check_cmd_test(RzTestProcessOutput *out, RzCmdTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *expect_out = test->expect.value;
	if (expect_out && strcmp (out->out, expect_out) != 0) {
		return false;
	}
	const char *expect_err = test->expect_err.value;
	if (expect_err && strcmp (out->err, expect_err) != 0) {
		return false;
	}
	return true;
}

#define JQ_CMD "jq"

RZ_API bool rz_test_check_jq_available(void) {
	const char *args[] = {"."};
	const char *invalid_json = "this is not json lol";
	RzTestSubprocess *proc = rz_test_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		rz_test_subprocess_stdin_write (proc, (const ut8 *)invalid_json, strlen (invalid_json));
		rz_test_subprocess_wait (proc, UT64_MAX);
	}
	bool invalid_detected = proc && proc->ret != 0;
	rz_test_subprocess_free (proc);

	const char *valid_json = "{\"this is\":\"valid json\",\"lol\":true}";
	proc = rz_test_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		rz_test_subprocess_stdin_write (proc, (const ut8 *)valid_json, strlen (valid_json));
		rz_test_subprocess_wait (proc, UT64_MAX);
	}
	bool valid_detected = proc && proc->ret == 0;
	rz_test_subprocess_free (proc);

	return invalid_detected && valid_detected;
}

RZ_API RzTestProcessOutput *rz_test_run_json_test(RzTestRunConfig *config, RzJsonTest *test, RzTestCmdRunner runner, void *user) {
	RzList *files = rz_list_new ();
	rz_list_push (files, (void *)config->json_test_file);
	RzTestProcessOutput *ret = run_rz_test (config, config->timeout_ms, test->cmd, files, NULL, test->load_plugins, runner, user);
	rz_list_free (files);
	return ret;
}

RZ_API bool rz_test_check_json_test(RzTestProcessOutput *out, RzJsonTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *args[] = {"."};
	RzTestSubprocess *proc = rz_test_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	rz_test_subprocess_stdin_write (proc, (const ut8 *)out->out, strlen (out->out));
	rz_test_subprocess_wait (proc, UT64_MAX);
	bool ret = proc->ret == 0;
	rz_test_subprocess_free (proc);
	return ret;
}

RZ_API RzAsmTestOutput *rz_test_run_asm_test(RzTestRunConfig *config, RzAsmTest *test) {
	RzAsmTestOutput *out = RZ_NEW0 (RzAsmTestOutput);
	if (!out) {
		return NULL;
	}

	RzPVector args;
	rz_pvector_init (&args, NULL);

	if (test->arch) {
		rz_pvector_push (&args, "-a");
		rz_pvector_push (&args, (void *)test->arch);
	}

	if (test->cpu) {
		rz_pvector_push (&args, "-c");
		rz_pvector_push (&args, (void *)test->cpu);
	}

	char bits[0x20];
	if (test->bits) {
		snprintf (bits, sizeof (bits), "%d", test->bits);
		rz_pvector_push (&args, "-b");
		rz_pvector_push (&args, bits);
	}

	if (test->mode & RZ_ASM_TEST_MODE_BIG_ENDIAN) {
		rz_pvector_push (&args, "-e");
	}

	char offset[0x20];
	if (test->offset) {
		rz_snprintf (offset, sizeof (offset), "0x%"PFMT64x, test->offset);
		rz_pvector_push (&args, "-o");
		rz_pvector_push (&args, offset);
	}

	RzStrBuf cmd_buf;
	rz_strbuf_init (&cmd_buf);
	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		rz_pvector_push (&args, test->disasm);
		RzTestSubprocess *proc = rz_test_subprocess_start (config->rz_asm_cmd, args.v.a, rz_pvector_len (&args), NULL, NULL, 0);
		if (!rz_test_subprocess_wait (proc, config->timeout_ms)) {
			rz_test_subprocess_kill (proc);
			out->as_timeout = true;
			goto rip;
		}
		if (proc->ret != 0) {
			goto rip;
		}
		char *hex = rz_strbuf_get (&proc->out);
		size_t hexlen = strlen (hex);
		if (!hexlen) {
			goto rip;
		}
		ut8 *bytes = malloc (hexlen);
		int byteslen = rz_hex_str2bin (hex, bytes);
		if (byteslen <= 0) {
			free (bytes);
			goto rip;
		}
		out->bytes = bytes;
		out->bytes_size = (size_t)byteslen;
rip:
		rz_pvector_pop (&args);
		rz_test_subprocess_free (proc);
	}
	if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
		char *hex = rz_hex_bin2strdup (test->bytes, test->bytes_size);
		if (!hex) {
			goto beach;
		}
		rz_pvector_push (&args, "-d");
		rz_pvector_push (&args, hex);
		RzTestSubprocess *proc = rz_test_subprocess_start (config->rz_asm_cmd, args.v.a, rz_pvector_len (&args), NULL, NULL, 0);
		if (!rz_test_subprocess_wait (proc, config->timeout_ms)) {
			rz_test_subprocess_kill (proc);
			out->disas_timeout = true;
			goto ship;
		}
		if (proc->ret != 0) {
			goto ship;
		}
		free (hex);
		char *disasm = rz_strbuf_drain_nofree (&proc->out);
		rz_str_trim (disasm);
		out->disasm = disasm;
ship:
		rz_pvector_pop (&args);
		rz_pvector_pop (&args);
		rz_test_subprocess_free (proc);
	}

beach:
	rz_pvector_clear (&args);
	rz_strbuf_fini (&cmd_buf);
	return out;
}

RZ_API bool rz_test_check_asm_test(RzAsmTestOutput *out, RzAsmTest *test) {
	if (!out) {
		return false;
	}
	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		if (!out->bytes || !test->bytes || out->bytes_size != test->bytes_size || out->as_timeout) {
			return false;
		}
		if (memcmp (out->bytes, test->bytes, test->bytes_size) != 0) {
			return false;
		}
	}
	if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
		if (!out->disasm || !test->disasm || out->as_timeout) {
			return false;
		}
		if (strcmp (out->disasm, test->disasm) != 0) {
			return false;
		}
	}
	return true;
}

RZ_API void rz_test_asm_test_output_free(RzAsmTestOutput *out) {
	if (!out) {
		return;
	}
	free (out->disasm);
	free (out->bytes);
	free (out);
}

RZ_API RzTestProcessOutput *rz_test_run_fuzz_test(RzTestRunConfig *config, RzFuzzTest *test, RzTestCmdRunner runner, void *user) {
	RzList *files = rz_list_new ();
	rz_list_push (files, test->file);
	RzTestProcessOutput *ret = run_rz_test (config, config->timeout_ms, "aaa", files, NULL, false, runner, user);
	rz_list_free (files);
	return ret;
}

RZ_API bool rz_test_check_fuzz_test(RzTestProcessOutput *out) {
	return out && out->ret == 0 && out->out && out->err && !out->timeout;
}

RZ_API char *rz_test_test_name(RzTest *test) {
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		if (test->cmd_test->name.value) {
			return strdup (test->cmd_test->name.value);
		}
		return strdup ("<unnamed>");
	case RZ_TEST_TYPE_ASM:
		return rz_str_newf ("<asm> %s", test->asm_test->disasm ? test->asm_test->disasm : "");
	case RZ_TEST_TYPE_JSON:
		return rz_str_newf ("<json> %s", test->json_test->cmd ? test->json_test->cmd: "");
	case RZ_TEST_TYPE_FUZZ:
		return rz_str_newf ("<fuzz> %s", test->fuzz_test->file);
	}
	return NULL;
}

RZ_API bool rz_test_test_broken(RzTest *test) {
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		return test->cmd_test->broken.value;
	case RZ_TEST_TYPE_ASM:
		return test->asm_test->mode & RZ_ASM_TEST_MODE_BROKEN ? true : false;
	case RZ_TEST_TYPE_JSON:
		return test->json_test->broken;
	case RZ_TEST_TYPE_FUZZ:
		return false;
	}
	return false;
}

RZ_API RzTestResultInfo *rz_test_run_test(RzTestRunConfig *config, RzTest *test) {
	RzTestResultInfo *ret = RZ_NEW0 (RzTestResultInfo);
	if (!ret) {
		return NULL;
	}
	ret->test = test;
	bool success = false;
	switch (test->type) {
	case RZ_TEST_TYPE_CMD: {
		RzCmdTest *cmd_test = test->cmd_test;
		RzTestProcessOutput *out = rz_test_run_cmd_test (config, cmd_test, subprocess_runner, NULL);
		success = rz_test_check_cmd_test (out, cmd_test);
		ret->proc_out = out;
		ret->timeout = out && out->timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_ASM: {
		RzAsmTest *asm_test = test->asm_test;
		RzAsmTestOutput *out = rz_test_run_asm_test (config, asm_test);
		success = rz_test_check_asm_test (out, asm_test);
		ret->asm_out = out;
		ret->timeout = out->as_timeout || out->disas_timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_JSON: {
		RzJsonTest *json_test = test->json_test;
		RzTestProcessOutput *out = rz_test_run_json_test (config, json_test, subprocess_runner, NULL);
		success = rz_test_check_json_test (out, json_test);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_FUZZ: {
		RzFuzzTest *fuzz_test = test->fuzz_test;
		RzTestProcessOutput *out = rz_test_run_fuzz_test (config, fuzz_test, subprocess_runner, NULL);
		success = rz_test_check_fuzz_test (out);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		ret->run_failed = !out;
	}
	}
	bool broken = rz_test_test_broken (test);
#if ASAN
# if !RZ_ASSERT_STDOUT
# error RZ_ASSERT_STDOUT undefined or 0
# endif
	RzTestProcessOutput *out = ret->proc_out;
	if (!success && test->type == RZ_TEST_TYPE_CMD && strstr (test->path, "/dbg")
	    && (!out->out ||
	        (!strstr (out->out, "WARNING:") && !strstr (out->out, "ERROR:") && !strstr (out->out, "FATAL:")))
	    && (!out->err ||
	        (!strstr (out->err, "Sanitizer") && !strstr (out->err, "runtime error:")))) {
		broken = true;
	}
#endif
	if (!success) {
		ret->result = broken ? RZ_TEST_RESULT_BROKEN : RZ_TEST_RESULT_FAILED;
	} else {
		ret->result = broken ? RZ_TEST_RESULT_FIXED : RZ_TEST_RESULT_OK;
	}
	return ret;
}

RZ_API void rz_test_test_result_info_free(RzTestResultInfo *result) {
	if (!result) {
		return;
	}
	if (result->test) {
		switch (result->test->type) {
		case RZ_TEST_TYPE_CMD:
		case RZ_TEST_TYPE_JSON:
		case RZ_TEST_TYPE_FUZZ:
			rz_test_process_output_free (result->proc_out);
			break;
		case RZ_TEST_TYPE_ASM:
			rz_test_asm_test_output_free (result->asm_out);
			break;
		}
	}
	free (result);
}
