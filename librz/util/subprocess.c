#include <rz_util.h>

#if __WINDOWS__
struct rz_subprocess_t {
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

RZ_API bool rz_subprocess_init(void) { return true; }
RZ_API void rz_subprocess_fini(void) {}
RZ_API void rz_subprocess_lock(void) {}
RZ_API void rz_subprocess_unlock(void) {}

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

RZ_API RzSubprocess *rz_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
	RzSubprocess *proc = NULL;
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

	proc = RZ_NEW0 (RzSubprocess);
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
	STARTUPINFOA start_info = { 0 };
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

RZ_API bool rz_subprocess_wait(RzSubprocess *proc, ut64 timeout_ms) {
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

RZ_API void rz_subprocess_kill(RzSubprocess *proc) {
	TerminateProcess (proc->proc, 255);
}

RZ_API void rz_subprocess_stdin_write(RzSubprocess *proc, const ut8 *buf, size_t buf_size) {
	DWORD read;
	WriteFile (proc->stdin_write, buf, buf_size, &read, NULL);
}


RZ_API RzSubprocessOutput *rz_subprocess_drain(RzSubprocess *proc) {
	RzSubprocessOutput *out = RZ_NEW (RzSubprocessOutput);
	if (!out) {
		return NULL;
	}
	out->out = rz_strbuf_drain_nofree (&proc->out);
	out->err = rz_strbuf_drain_nofree (&proc->err);
	out->ret = proc->ret;
	return out;
}

RZ_API void rz_subprocess_free(RzSubprocess *proc) {
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

struct rz_subprocess_t {
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

			rz_subprocess_lock ();
			void **it;
			RzSubprocess *proc = NULL;
			rz_pvector_foreach (&subprocs, it) {
				RzSubprocess *p = *it;
				if (p->pid == pid) {
					proc = p;
					break;
				}
			}
			if (!proc) {
				rz_subprocess_unlock ();
				continue;
			}

			if (WIFEXITED (wstat)) {
				proc->ret = WEXITSTATUS (wstat);
			} else {
				proc->ret = -1;
			}
			ut8 r = 0;
			write (proc->killpipe[1], &r, 1);
			rz_subprocess_unlock ();
		}
	}
	return RZ_TH_STOP;
}

RZ_API bool rz_subprocess_init(void) {
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

RZ_API void rz_subprocess_fini(void) {
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

RZ_API void rz_subprocess_lock(void) {
	rz_th_lock_enter (subprocs_mutex);
}

RZ_API void rz_subprocess_unlock(void) {
	rz_th_lock_leave (subprocs_mutex);
}

RZ_API RzSubprocess *rz_subprocess_start(
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
	rz_subprocess_lock ();
	RzSubprocess *proc = RZ_NEW0 (RzSubprocess);
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

	rz_subprocess_unlock ();

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
	rz_subprocess_unlock ();
	return NULL;
}

RZ_API bool rz_subprocess_wait(RzSubprocess *proc, ut64 timeout_ms) {
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
	rz_subprocess_lock ();
	rz_subprocess_unlock ();
	return child_dead;
}

RZ_API void rz_subprocess_kill(RzSubprocess *proc) {
	kill (proc->pid, SIGKILL);
}

RZ_API void rz_subprocess_stdin_write(RzSubprocess *proc, const ut8 *buf, size_t buf_size) {
	write (proc->stdin_fd, buf, buf_size);
	close (proc->stdin_fd);
	proc->stdin_fd = -1;
}

RZ_API RzSubprocessOutput *rz_subprocess_drain(RzSubprocess *proc) {
	rz_subprocess_lock ();
	RzSubprocessOutput *out = RZ_NEW (RzSubprocessOutput);
	if (out) {
		out->out = rz_strbuf_drain_nofree (&proc->out);
		out->err = rz_strbuf_drain_nofree (&proc->err);
		out->ret = proc->ret;
		out->timeout = false;
	}
	rz_subprocess_unlock ();
	return out;
}

RZ_API void rz_subprocess_free(RzSubprocess *proc) {
	if (!proc) {
		return;
	}
	rz_subprocess_lock ();
	rz_pvector_remove_data (&subprocs, proc);
	rz_subprocess_unlock ();
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

RZ_API void rz_subprocess_output_free(RzSubprocessOutput *out) {
	if (!out) {
		return;
	}
	free (out->out);
	free (out->err);
	free (out);
}