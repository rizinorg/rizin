// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util.h>

#define BUFFER_SIZE 0x500

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
	snprintf(name, sizeof(name), "\\\\.\\pipe\\rz-pipe-subproc.%d.%ld", (int)GetCurrentProcessId(), (long)InterlockedIncrement(&pipe_id));
	*pipe_read = CreateNamedPipeA(name, PIPE_ACCESS_INBOUND | read_mode, PIPE_TYPE_BYTE | PIPE_WAIT, 1, sz, sz, 120 * 1000, attrs);
	if (!*pipe_read) {
		return FALSE;
	}
	*pipe_write = CreateFileA(name, GENERIC_WRITE, 0, attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | write_mode, NULL);
	if (*pipe_write == INVALID_HANDLE_VALUE) {
		CloseHandle(*pipe_read);
		return FALSE;
	}

	SetEnvironmentVariable(TEXT("RZ_PIPE_PATH"), name);
	return true;
}

RZ_API bool rz_subprocess_init(void) {
	return true;
}
RZ_API void rz_subprocess_fini(void) {
	SetEnvironmentVariable(TEXT("RZ_PIPE_PATH"), NULL);
}

// Create an env block that inherits the current vars but overrides the given ones
static LPWCH override_env(const char *envvars[], const char *envvals[], size_t env_size) {
	LPWCH ret = NULL;
	LPWCH parent_env = NULL;
	size_t i;
	LPWSTR *wenvvars = calloc(env_size, sizeof(LPWSTR));
	LPWSTR *wenvvals = calloc(env_size, sizeof(LPWSTR));
	parent_env = GetEnvironmentStringsW();
	if (!wenvvars || !wenvvals || !parent_env) {
		goto error;
	}

	for (i = 0; i < env_size; i++) {
		wenvvars[i] = rz_utf8_to_utf16(envvars[i]);
		wenvvals[i] = rz_utf8_to_utf16(envvals[i]);
		if (!wenvvars[i] || !wenvvals[i]) {
			goto error;
		}
	}

	RzVector buf;
	rz_vector_init(&buf, sizeof(wchar_t), NULL, NULL);
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
			size_t overlen = lstrlenW(wenvvars[i]);
			size_t curlen = cur - var_begin;
			if (overlen == curlen && !memcmp(var_begin, wenvvars[i], overlen)) {
				overridden = true;
				break;
			}
		}
		while (*cur) {
			cur++;
		}
		if (!overridden) {
			rz_vector_insert_range(&buf, buf.len, var_begin, cur - var_begin + 1);
		}
		cur++;
		if (!*cur) {
			// \0\0 marks the end
			break;
		}
	}

	wchar_t c;
	for (i = 0; i < env_size; i++) {
		rz_vector_insert_range(&buf, buf.len, wenvvars[i], lstrlenW(wenvvars[i]));
		c = L'=';
		rz_vector_push(&buf, &c);
		rz_vector_insert_range(&buf, buf.len, wenvvals[i], lstrlenW(wenvvals[i]));
		c = L'\0';
		rz_vector_push(&buf, &c);
	}
	c = '\0';
	rz_vector_push(&buf, &c);
	ret = buf.a;

error:
	if (parent_env) {
		FreeEnvironmentStringsW(parent_env);
	}
	for (i = 0; i < env_size; i++) {
		if (wenvvars) {
			free(wenvvars[i]);
		}
		if (wenvvals) {
			free(wenvvals[i]);
		}
	}
	free(wenvvars);
	free(wenvvals);
	return ret;
}

static void remove_cr(char *str) {
	char *start = str;
	while (*str) {
		if (str[0] == '\r' &&
			!(str - start >= 4 && !strncmp(str - 4, RZ_CONS_CLEAR_SCREEN, 4))) {
			memmove(str, str + 1, strlen(str + 1) + 1);
			continue;
		}
		str++;
	}
}

RZ_API RzSubprocess *rz_subprocess_start_opt(RzSubprocessOpt *opt) {
	RzSubprocess *proc = NULL;
	HANDLE stdin_read = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE stdout_write = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE stderr_write = GetStdHandle(STD_ERROR_HANDLE);
	LPSTR lpFilePart;
	char cmd_exe[MAX_PATH];

	if (!rz_file_exists(opt->file) && NeedCurrentDirectoryForExePathA(opt->file)) {
		DWORD len;
		if ((len = SearchPath(NULL, opt->file, ".exe", sizeof(cmd_exe), cmd_exe, &lpFilePart)) < 1) {
			RZ_LOG_DEBUG("SearchPath failed for %s\n", opt->file);
			return NULL;
		}
	} else {
		snprintf(cmd_exe, sizeof(cmd_exe), "%s", opt->file);
	}

	char **argv = calloc(opt->args_size + 1, sizeof(char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = ""; // a space is required to work correctly.
	if (opt->args_size) {
		memcpy(argv + 1, opt->args, sizeof(char *) * opt->args_size);
	}
	char *cmdline = rz_str_format_msvc_argv(opt->args_size + 1, argv);
	free(argv);
	if (!cmdline) {
		return NULL;
	}

	proc = RZ_NEW0(RzSubprocess);
	if (!proc) {
		goto error;
	}
	proc->ret = -1;
	proc->stdout_read = NULL;
	proc->stderr_read = NULL;
	proc->stdin_write = NULL;

	SECURITY_ATTRIBUTES sattrs;
	sattrs.nLength = sizeof(sattrs);
	sattrs.bInheritHandle = TRUE;
	sattrs.lpSecurityDescriptor = NULL;

	if (opt->stdout_pipe == RZ_SUBPROCESS_PIPE_CREATE) {
		if (!create_pipe_overlap(&proc->stdout_read, &stdout_write, &sattrs, 0, FILE_FLAG_OVERLAPPED, 0)) {
			proc->stdout_read = stdout_write = NULL;
			goto error;
		}
		if (!SetHandleInformation(proc->stdout_read, HANDLE_FLAG_INHERIT, 0)) {
			goto error;
		}
	}
	if (opt->stderr_pipe == RZ_SUBPROCESS_PIPE_CREATE) {
		if (!create_pipe_overlap(&proc->stderr_read, &stderr_write, &sattrs, 0, FILE_FLAG_OVERLAPPED, 0)) {
			proc->stdout_read = stderr_write = NULL;
			goto error;
		}
		if (!SetHandleInformation(proc->stderr_read, HANDLE_FLAG_INHERIT, 0)) {
			goto error;
		}
	} else if (opt->stderr_pipe == RZ_SUBPROCESS_PIPE_STDOUT) {
		proc->stderr_read = proc->stdout_read;
		stderr_write = stdout_write;
	}

	if (opt->stdin_pipe == RZ_SUBPROCESS_PIPE_CREATE) {
		if (!CreatePipe(&stdin_read, &proc->stdin_write, &sattrs, 0)) {
			stdin_read = proc->stdin_write = NULL;
			goto error;
		}
		if (!SetHandleInformation(proc->stdin_write, HANDLE_FLAG_INHERIT, 0)) {
			goto error;
		}
	}

	PROCESS_INFORMATION proc_info = { 0 };
	STARTUPINFOA start_info = { 0 };
	start_info.cb = sizeof(start_info);
	start_info.hStdError = stderr_write;
	start_info.hStdOutput = stdout_write;
	start_info.hStdInput = stdin_read;
	start_info.dwFlags = STARTF_USESTDHANDLES;

	LPWSTR env = override_env(opt->envvars, opt->envvals, opt->env_size);
	RZ_LOG_DEBUG("%s%s\n", cmd_exe, cmdline);
	if (!CreateProcessA(
		    cmd_exe, // exe
		    cmdline, // command line
		    NULL, // process security attributes
		    NULL, // primary thread security attributes
		    TRUE, // handles are inherited
		    CREATE_UNICODE_ENVIRONMENT, // creation flags
		    env, // use parent's environment
		    NULL, // use parent's current directory
		    &start_info, // STARTUPINFO pointer
		    &proc_info)) { // receives PROCESS_INFORMATION
		free(env);
		char err_msg[256];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			err_msg, sizeof(err_msg), NULL);

		RZ_LOG_ERROR("CreateProcess failed: %#x %s\n", (int)GetLastError(), err_msg);
		goto error;
	}
	free(env);

	CloseHandle(proc_info.hThread);
	proc->proc = proc_info.hProcess;

beach:

	if (stdin_read != GetStdHandle(STD_INPUT_HANDLE)) {
		CloseHandle(stdin_read);
	}
	if (stderr_write != GetStdHandle(STD_ERROR_HANDLE) && stderr_write != stdout_write) {
		CloseHandle(stderr_write);
	}
	if (stdout_write != GetStdHandle(STD_OUTPUT_HANDLE)) {
		CloseHandle(stdout_write);
	}
	free(cmdline);
	return proc;
error:
	if (proc) {
		if (proc->stderr_read && proc->stderr_read != proc->stdout_read) {
			CloseHandle(proc->stderr_read);
		}
		if (proc->stdout_read) {
			CloseHandle(proc->stdout_read);
		}
		if (proc->stdin_write) {
			CloseHandle(proc->stdin_write);
		}
		free(proc);
		proc = NULL;
	}
	goto beach;
}

static bool do_read(HANDLE *f, ut8 *buf, size_t buf_size, size_t n_bytes, OVERLAPPED *overlapped) {
	size_t to_read = buf_size;
	if (n_bytes && to_read > n_bytes) {
		to_read = n_bytes;
	}
	if (!ReadFile(f, buf, to_read, NULL, overlapped)) {
		if (GetLastError() != ERROR_IO_PENDING) { /* EOF or some other error */
			return true;
		}
	}
	return false;
}

static RzSubprocessWaitReason subprocess_wait(RzSubprocess *proc, ut64 timeout_ms, int pipe_fd, size_t n_bytes) {
	OVERLAPPED stdout_overlapped = { 0 };
	OVERLAPPED stderr_overlapped = { 0 };
	ut64 timeout_us_abs = UT64_MAX;
	if (timeout_ms != UT64_MAX) {
		timeout_us_abs = rz_time_now_mono() + timeout_ms * RZ_USEC_PER_MSEC;
	}

	char stdout_buf[BUFFER_SIZE + 1];
	char stderr_buf[BUFFER_SIZE + 1];
	bool stdout_enabled = (pipe_fd & RZ_SUBPROCESS_STDOUT) && proc->stdout_read;
	bool stderr_enabled = (pipe_fd & RZ_SUBPROCESS_STDERR) && proc->stderr_read && proc->stderr_read != proc->stdout_read;
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;
	bool bytes_enabled = n_bytes != 0;

	if (stdout_enabled) {
		stdout_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!stdout_overlapped.hEvent) {
			return RZ_SUBPROCESS_DEAD;
		}
	}
	if (stderr_enabled) {
		stderr_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!stderr_overlapped.hEvent) {
			CloseHandle(stdout_overlapped.hEvent);
			return RZ_SUBPROCESS_DEAD;
		}
	}
	if (stdout_enabled) {
		stdout_eof = do_read(proc->stdout_read, stdout_buf, sizeof(stdout_buf) - 1, n_bytes, &stdout_overlapped);
	}
	if (stderr_enabled) {
		stderr_eof = do_read(proc->stderr_read, stderr_buf, sizeof(stderr_buf) - 1, n_bytes, &stderr_overlapped);
	}

	RzVector handles;
	rz_vector_init(&handles, sizeof(HANDLE), NULL, NULL);
	while ((!bytes_enabled || n_bytes) && !child_dead) {
		rz_vector_clear(&handles);
		size_t stdout_index = 0;
		size_t stderr_index = 0;
		size_t proc_index = 0;
		if (stdout_enabled && !stdout_eof) {
			stdout_index = handles.len;
			rz_vector_push(&handles, &stdout_overlapped.hEvent);
		}
		if (stderr_enabled && !stderr_eof) {
			stderr_index = handles.len;
			rz_vector_push(&handles, &stderr_overlapped.hEvent);
		}
		if (!child_dead) {
			proc_index = handles.len;
			rz_vector_push(&handles, &proc->proc);
		}

		DWORD timeout = INFINITE;
		if (timeout_us_abs != UT64_MAX) {
			ut64 now = rz_time_now_mono();
			if (now >= timeout_us_abs) {
				return RZ_SUBPROCESS_TIMEDOUT;
			}
			timeout = (DWORD)((timeout_us_abs - now) / RZ_USEC_PER_MSEC);
		}
		DWORD signaled = WaitForMultipleObjects(handles.len, handles.a, FALSE, timeout);
		if (stdout_enabled && !stdout_eof && signaled == stdout_index) {
			DWORD r;
			BOOL res = GetOverlappedResult(proc->stdout_read, &stdout_overlapped, &r, TRUE);
			if (!res) {
				stdout_eof = true;
				continue;
			}
			stdout_buf[r] = '\0';
			remove_cr(stdout_buf);
			rz_strbuf_append(&proc->out, (const char *)stdout_buf);
			ResetEvent(stdout_overlapped.hEvent);
			if (r >= 0 && n_bytes) {
				n_bytes -= r;
				if (n_bytes <= 0) {
					break;
				}
			}
			stdout_eof = do_read(proc->stdout_read, stdout_buf, sizeof(stdout_buf) - 1, n_bytes, &stdout_overlapped);
			continue;
		}
		if (stderr_enabled && !stderr_eof && signaled == stderr_index) {
			DWORD r;
			BOOL res = GetOverlappedResult(proc->stderr_read, &stderr_overlapped, &r, TRUE);
			if (!res) {
				stderr_eof = true;
				continue;
			}
			stderr_buf[r] = '\0';
			remove_cr(stderr_buf);
			rz_strbuf_append(&proc->err, (const char *)stderr_buf);
			if (r >= 0 && n_bytes) {
				n_bytes -= r;
				if (n_bytes <= 0) {
					break;
				}
			}
			ResetEvent(stderr_overlapped.hEvent);
			stderr_eof = do_read(proc->stderr_read, stderr_buf, sizeof(stderr_buf) - 1, n_bytes, &stderr_overlapped);
			continue;
		}
		if (!child_dead && signaled == proc_index) {
			child_dead = true;
			DWORD exit_code;
			if (GetExitCodeProcess(proc->proc, &exit_code)) {
				proc->ret = exit_code;
			}
			continue;
		}
		break;
	}
	rz_vector_clear(&handles);
	CloseHandle(stdout_overlapped.hEvent);
	CloseHandle(stderr_overlapped.hEvent);
	return child_dead ? RZ_SUBPROCESS_DEAD : RZ_SUBPROCESS_BYTESREAD;
}

RZ_API RzSubprocessWaitReason rz_subprocess_wait(RzSubprocess *proc, ut64 timeout_ms) {
	CloseHandle(proc->stdin_write);
	proc->stdin_write = NULL;
	// Empty buffers and read everything we can
	rz_strbuf_fini(&proc->out);
	rz_strbuf_init(&proc->out);
	rz_strbuf_fini(&proc->err);
	rz_strbuf_init(&proc->err);
	return subprocess_wait(proc, timeout_ms, RZ_SUBPROCESS_STDOUT | RZ_SUBPROCESS_STDERR, 0);
}

RZ_API void rz_subprocess_kill(RzSubprocess *proc) {
	TerminateProcess(proc->proc, 255);
}

RZ_API ssize_t rz_subprocess_stdin_write(RzSubprocess *proc, const ut8 *buf, size_t buf_size) {
	if (!proc->stdin_write) {
		return -1;
	}
	DWORD read;
	return WriteFile(proc->stdin_write, buf, buf_size, &read, NULL) ? buf_size : -1;
}

RZ_API RzStrBuf *rz_subprocess_stdout_read(RzSubprocess *proc, size_t n, ut64 timeout_ms) {
	rz_strbuf_fini(&proc->out);
	rz_strbuf_init(&proc->out);
	if (proc->stdout_read) {
		subprocess_wait(proc, timeout_ms, RZ_SUBPROCESS_STDOUT, n);
	}
	return &proc->out;
}

RZ_API RzStrBuf *rz_subprocess_stdout_readline(RzSubprocess *proc, ut64 timeout_ms) {
	rz_strbuf_fini(&proc->out);
	rz_strbuf_init(&proc->out);
	if (proc->stdout_read) {
		char c = '\0';
		RzSubprocessWaitReason reason;
		// FIXME: the timeout should also be checked globally here
		do {
			reason = subprocess_wait(proc, timeout_ms, RZ_SUBPROCESS_STDOUT, 1);
			c = rz_strbuf_get(&proc->out)[rz_strbuf_length(&proc->out) - 1];
		} while (c != '\n' && reason == RZ_SUBPROCESS_BYTESREAD);
	}
	return &proc->out;
}

RZ_API RzSubprocessOutput *rz_subprocess_drain(RzSubprocess *proc) {
	RzSubprocessOutput *out = RZ_NEW(RzSubprocessOutput);
	if (!out) {
		return NULL;
	}
	out->out = rz_strbuf_drain_nofree(&proc->out);
	out->err = rz_strbuf_drain_nofree(&proc->err);
	out->ret = proc->ret;
	return out;
}

RZ_API void rz_subprocess_free(RzSubprocess *proc) {
	if (!proc) {
		return;
	}
	if (proc->stdin_write) {
		CloseHandle(proc->stdin_write);
	}
	if (proc->stderr_read && proc->stderr_read != proc->stdout_read) {
		CloseHandle(proc->stderr_read);
	}
	if (proc->stdout_read) {
		CloseHandle(proc->stdout_read);
	}
	CloseHandle(proc->proc);
	free(proc);
}
#else // __WINDOWS__

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

static void subprocess_lock(void) {
	rz_th_lock_enter(subprocs_mutex);
}

static void subprocess_unlock(void) {
	rz_th_lock_leave(subprocs_mutex);
}

static void handle_sigchld(int sig) {
	ut8 b = 1;
	rz_xwrite(sigchld_pipe[1], &b, 1);
}

static RzThreadFunctionRet sigchld_th(RzThread *th) {
	while (true) {
		ut8 b;
		ssize_t rd = read(sigchld_pipe[0], &b, 1);
		if (rd <= 0) {
			if (rd < 0) {
				if (errno == EINTR) {
					continue;
				}
				perror("read");
			}
			break;
		}
		if (!b) {
			break;
		}
		while (true) {
			int wstat;
			pid_t pid = waitpid(-1, &wstat, WNOHANG);
			if (pid <= 0)
				break;

			subprocess_lock();
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
				subprocess_unlock();
				continue;
			}

			if (WIFEXITED(wstat)) {
				proc->ret = WEXITSTATUS(wstat);
			} else {
				proc->ret = -1;
			}
			ut8 r = 0;
			rz_xwrite(proc->killpipe[1], &r, 1);
			subprocess_unlock();
		}
	}
	return RZ_TH_STOP;
}

RZ_API bool rz_subprocess_init(void) {
	rz_pvector_init(&subprocs, NULL);
	subprocs_mutex = rz_th_lock_new(true);
	if (!subprocs_mutex) {
		return false;
	}
	if (rz_sys_pipe(sigchld_pipe, true) == -1) {
		perror("pipe");
		rz_th_lock_free(subprocs_mutex);
		return false;
	}
	sigchld_thread = rz_th_new(sigchld_th, NULL, 0);
	if (!sigchld_thread) {
		rz_sys_pipe_close(sigchld_pipe[0]);
		rz_sys_pipe_close(sigchld_pipe[1]);
		rz_th_lock_free(subprocs_mutex);
		return false;
	}
	if (rz_sys_signal(SIGCHLD, handle_sigchld) < 0) {
		rz_sys_pipe_close(sigchld_pipe[0]);
		rz_sys_pipe_close(sigchld_pipe[1]);
		rz_th_lock_free(subprocs_mutex);
		return false;
	}
	return true;
}

RZ_API void rz_subprocess_fini(void) {
	rz_sys_signal(SIGCHLD, SIG_IGN);
	ut8 b = 0;
	rz_xwrite(sigchld_pipe[1], &b, 1);
	rz_sys_pipe_close(sigchld_pipe[1]);
	rz_th_wait(sigchld_thread);
	rz_sys_pipe_close(sigchld_pipe[0]);
	rz_th_free(sigchld_thread);
	rz_pvector_clear(&subprocs);
	rz_th_lock_free(subprocs_mutex);
}

static char **create_child_env(const char *envvars[], const char *envvals[], size_t env_size) {
	char **ep;
	size_t new_env_size = env_size, size = 0;
	size_t *positions = RZ_NEWS(size_t, env_size);
	for (size_t i = 0; i < env_size; i++) {
		positions[i] = SIZE_MAX;
	}

	char **environ = rz_sys_get_environ();
	for (ep = environ; *ep; ep++, size++) {
		size_t j;

		for (j = 0; j < env_size; j++) {
			if (positions[j] != SIZE_MAX) {
				continue;
			}
			size_t namelen = strlen(envvars[j]);
			if (!strncmp(*ep, envvars[j], namelen) && (*ep)[namelen] == '=') {
				positions[j] = size;
				new_env_size--;
				break;
			}
		}
	}

	char **new_env = RZ_NEWS(char *, size + new_env_size + 1);
	for (size_t i = 0; i < size; i++) {
		new_env[i] = strdup(environ[i]);
	}
	for (size_t i = 0; i <= new_env_size; i++) {
		new_env[size + i] = NULL;
	}

	for (size_t i = 0; i < env_size; i++) {
		char *new_var = rz_str_newf("%s=%s", envvars[i], envvals[i]);
		if (positions[i] == SIZE_MAX) {
			// No env var exists with the same name, add it at the end
			free(new_env[size]);
			new_env[size++] = new_var;
		} else {
			// Replace the existing env var
			free(new_env[positions[i]]);
			new_env[positions[i]] = new_var;
		}
	}
	free(positions);
	return new_env;
}

static void destroy_child_env(char **child_env) {
	char **ep;
	for (ep = child_env; *ep; ep++) {
		free(*ep);
	}
	free(child_env);
}

RZ_API RzSubprocess *rz_subprocess_start_opt(RzSubprocessOpt *opt) {
	char **argv = calloc(opt->args_size + 2, sizeof(char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)opt->file;
	if (opt->args_size) {
		memcpy(argv + 1, opt->args, sizeof(char *) * opt->args_size);
	}
	// done by calloc: argv[args_size + 1] = NULL;
	subprocess_lock();
	RzSubprocess *proc = RZ_NEW0(RzSubprocess);
	if (!proc) {
		goto error;
	}
	proc->killpipe[0] = proc->killpipe[1] = -1;
	proc->ret = -1;
	proc->stdin_fd = -1;
	proc->stdout_fd = -1;
	proc->stderr_fd = -1;
	rz_strbuf_init(&proc->out);
	rz_strbuf_init(&proc->err);

	if (rz_sys_pipe(proc->killpipe, true) == -1) {
		perror("pipe");
		goto error;
	}
	if (fcntl(proc->killpipe[1], F_SETFL, O_NONBLOCK) < 0) {
		perror("fcntl");
		goto error;
	}

	int stdin_pipe[2] = { -1, -1 };
	int stdout_pipe[2] = { -1, -1 };
	int stderr_pipe[2] = { -1, -1 };
	if (opt->stdin_pipe == RZ_SUBPROCESS_PIPE_CREATE) {
		if (rz_sys_pipe(stdin_pipe, true) == -1) {
			perror("pipe");
			goto error;
		}
		proc->stdin_fd = stdin_pipe[1];
	}

	if (opt->stdout_pipe == RZ_SUBPROCESS_PIPE_CREATE) {
		if (rz_sys_pipe(stdout_pipe, true) == -1) {
			perror("pipe");
			goto error;
		}
		if (fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
			perror("fcntl");
			goto error;
		}
		proc->stdout_fd = stdout_pipe[0];
	}

	if (opt->stderr_pipe == RZ_SUBPROCESS_PIPE_CREATE) {
		if (rz_sys_pipe(stderr_pipe, true) == -1) {
			perror("pipe");
			goto error;
		}
		if (fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
			perror("fcntl");
			goto error;
		}
		proc->stderr_fd = stderr_pipe[0];
	} else if (opt->stderr_pipe == RZ_SUBPROCESS_PIPE_STDOUT) {
		stderr_pipe[0] = stdout_pipe[0];
		stderr_pipe[1] = stdout_pipe[1];
		proc->stderr_fd = proc->stdout_fd;
	}

	// Let's create the environment for the child in the parent, with malloc,
	// because we can't use functions that lock after fork
	char **child_env = create_child_env(opt->envvars, opt->envvals, opt->env_size);

	proc->pid = rz_sys_fork();
	if (proc->pid == -1) {
		// fail
		perror("fork");
		goto error;
	} else if (proc->pid == 0) {
		// child
		if (stderr_pipe[1] != -1) {
			while ((dup2(stderr_pipe[1], STDERR_FILENO) == -1) && (errno == EINTR)) {
			}
			if (proc->stderr_fd != proc->stdout_fd) {
				rz_sys_pipe_close(stderr_pipe[1]);
				rz_sys_pipe_close(stderr_pipe[0]);
			}
		}
		if (stdout_pipe[1] != -1) {
			while ((dup2(stdout_pipe[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {
			}
			rz_sys_pipe_close(stdout_pipe[1]);
			rz_sys_pipe_close(stdout_pipe[0]);
		}
		if (stdin_pipe[0] != -1) {
			while ((dup2(stdin_pipe[0], STDIN_FILENO) == -1) && (errno == EINTR)) {
			}
			rz_sys_pipe_close(stdin_pipe[0]);
			rz_sys_pipe_close(stdin_pipe[1]);
		}

		// Use the previously created environment
		rz_sys_set_environ(child_env);

		rz_sys_execvp(opt->file, argv);
		perror("exec");
		rz_sys_exit(-1, true);
	}
	destroy_child_env(child_env);
	free(argv);

	if (stdin_pipe[0] != -1) {
		rz_sys_pipe_close(stdin_pipe[0]);
	}
	if (stdout_pipe[1] != -1) {
		rz_sys_pipe_close(stdout_pipe[1]);
	}
	if (stderr_pipe[1] != -1 && proc->stderr_fd != proc->stdout_fd) {
		rz_sys_pipe_close(stderr_pipe[1]);
	}

	rz_pvector_push(&subprocs, proc);

	subprocess_unlock();

	return proc;
error:
	free(argv);
	if (proc && proc->killpipe[0] == -1) {
		rz_sys_pipe_close(proc->killpipe[0]);
	}
	if (proc && proc->killpipe[1] == -1) {
		rz_sys_pipe_close(proc->killpipe[1]);
	}
	free(proc);
	if (stderr_pipe[0] != -1 && stderr_pipe[0] != stdout_pipe[0]) {
		rz_sys_pipe_close(stderr_pipe[0]);
	}
	if (stderr_pipe[1] != -1 && stderr_pipe[1] != stdout_pipe[1]) {
		rz_sys_pipe_close(stderr_pipe[1]);
	}
	if (stdout_pipe[0] != -1) {
		rz_sys_pipe_close(stdout_pipe[0]);
	}
	if (stdout_pipe[1] != -1) {
		rz_sys_pipe_close(stdout_pipe[1]);
	}
	if (stdin_pipe[0] != -1) {
		rz_sys_pipe_close(stdin_pipe[0]);
	}
	if (stdin_pipe[1] != -1) {
		rz_sys_pipe_close(stdin_pipe[1]);
	}
	subprocess_unlock();
	return NULL;
}

static size_t read_to_strbuf(RzStrBuf *sb, int fd, bool *fd_eof, size_t n_bytes) {
	char buf[BUFFER_SIZE];
	size_t to_read = sizeof(buf);
	if (n_bytes && to_read > n_bytes) {
		to_read = n_bytes;
	}
	ssize_t sz = read(fd, buf, to_read);
	if (sz < 0) {
		perror("read");
	} else if (sz == 0) {
		*fd_eof = true;
	} else {
		rz_strbuf_append_n(sb, buf, (int)sz);
	}
	return sz;
}

/**
 * \brief Wait for subprocess to do something, for a maximum of \p timeout_ms millisecond.
 *
 * This function can be used to wait for some action from the subprocess, which
 * includes terminating or sending output to stdout/stderr. If \p n_bytes is
 * not 0, the function terminates as soon as \p n_bytes bytes have been read or
 * the timeout expires.
 *
 * \param proc Subprocess to interact with
 * \param timeout_ms Number of millisecond to wait before stopping the operation. If UT64_MAX no timeout is set
 * \param pipe_fds One of \p RZ_SUBPROCESS_STDOUT , \p RZ_SUBPROCESS_STDERR or a combination of them. Bytes are read only from those.
 * \param n_bytes Number of bytes to read. If \p pipe_fds references multiple FDs, this indicates the number to read in either of them.
 */
static RzSubprocessWaitReason subprocess_wait(RzSubprocess *proc, ut64 timeout_ms, int pipe_fd, size_t n_bytes) {
	ut64 timeout_abs;
	if (timeout_ms != UT64_MAX) {
		timeout_abs = rz_time_now_mono() + timeout_ms * RZ_USEC_PER_MSEC;
	}

	int r = 0;
	bool stdout_enabled = (pipe_fd & RZ_SUBPROCESS_STDOUT) && proc->stdout_fd != -1;
	bool stderr_enabled = (pipe_fd & RZ_SUBPROCESS_STDERR) && proc->stderr_fd != -1 && proc->stderr_fd != proc->stdout_fd;
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;
	bool timedout = true;
	bool bytes_enabled = n_bytes != 0;
	while ((!bytes_enabled || n_bytes) && ((stdout_enabled && !stdout_eof) || (stderr_enabled && !stderr_eof) || !child_dead)) {
		fd_set rfds;
		FD_ZERO(&rfds);
		int nfds = 0;
		if (stdout_enabled && !stdout_eof) {
			FD_SET(proc->stdout_fd, &rfds);
			if (proc->stdout_fd > nfds) {
				nfds = proc->stdout_fd;
			}
		}
		if (stderr_enabled && !stderr_eof) {
			FD_SET(proc->stderr_fd, &rfds);
			if (proc->stderr_fd > nfds) {
				nfds = proc->stderr_fd;
			}
		}
		if (!child_dead) {
			FD_SET(proc->killpipe[0], &rfds);
			if (proc->killpipe[0] > nfds) {
				nfds = proc->killpipe[0];
			}
		}
		nfds++;

		struct timeval timeout_s;
		struct timeval *timeout = NULL;
		if (timeout_ms != UT64_MAX) {
			ut64 now = rz_time_now_mono();
			if (now >= timeout_abs) {
				break;
			}
			ut64 usec_diff = timeout_abs - rz_time_now_mono();
			timeout_s.tv_sec = usec_diff / RZ_USEC_PER_SEC;
			timeout_s.tv_usec = usec_diff % RZ_USEC_PER_SEC;
			timeout = &timeout_s;
		}
		r = select(nfds, &rfds, NULL, NULL, timeout);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}

		timedout = true;
		if (stdout_enabled && FD_ISSET(proc->stdout_fd, &rfds)) {
			timedout = false;
			size_t r = read_to_strbuf(&proc->out, proc->stdout_fd, &stdout_eof, n_bytes);
			if (r >= 0 && n_bytes) {
				n_bytes -= r;
			}
		}
		if (stderr_enabled && FD_ISSET(proc->stderr_fd, &rfds)) {
			timedout = false;
			size_t r = read_to_strbuf(&proc->err, proc->stderr_fd, &stderr_eof, n_bytes);
			if (r >= 0 && n_bytes) {
				n_bytes -= r;
			}
		}
		if (FD_ISSET(proc->killpipe[0], &rfds)) {
			timedout = false;
			child_dead = true;
		}
		if (timedout) {
			break;
		}
	}
	if (r < 0) {
		perror("select");
	}
	if (child_dead) {
		return RZ_SUBPROCESS_DEAD;
	} else if (timedout) {
		return RZ_SUBPROCESS_TIMEDOUT;
	} else {
		return RZ_SUBPROCESS_BYTESREAD;
	}
}

/**
 * Wait until process dies or timeout expires and collect stdout + stderr.
 * No more input can be sent after this call.
 *
 * \param proc Subprocess to communicate with
 * \param timeout_ms Wait for at most this amount of millisecond
 */
RZ_API RzSubprocessWaitReason rz_subprocess_wait(RzSubprocess *proc, ut64 timeout_ms) {
	// Close subprocess stdin
	rz_sys_pipe_close(proc->stdin_fd);
	proc->stdin_fd = -1;
	// Empty buffers and read everything we can
	rz_strbuf_fini(&proc->out);
	rz_strbuf_init(&proc->out);
	rz_strbuf_fini(&proc->err);
	rz_strbuf_init(&proc->err);
	return subprocess_wait(proc, timeout_ms, RZ_SUBPROCESS_STDOUT | RZ_SUBPROCESS_STDERR, 0);
}

/**
 * Sends some data to the stdin of the subprocess and returns the number of bytes sent.
 *
 * \param proc Subprocess to communicate with
 * \param buf Data that needs to be send to the subprocess stdin
 * \param buf_size Number of bytes to send
 */
RZ_API ssize_t rz_subprocess_stdin_write(RzSubprocess *proc, const ut8 *buf, size_t buf_size) {
	if (proc->stdin_fd == -1) {
		return -1;
	}
	return write(proc->stdin_fd, buf, buf_size);
}

/**
 * Read some data from the stdout of the subprocess and returns a \p RzStrBuf
 * containing it. Callers must not free the returned pointer.
 *
 * \param proc Subprocess to communicate with
 * \param n Number of bytes to read from the subprocess' stdout
 * \param timeout_ms Wait for at most this amount of millisecond to read subprocess' stdout
 */
RZ_API RzStrBuf *rz_subprocess_stdout_read(RzSubprocess *proc, size_t n, ut64 timeout_ms) {
	rz_strbuf_fini(&proc->out);
	rz_strbuf_init(&proc->out);
	if (proc->stdout_fd != -1) {
		subprocess_wait(proc, timeout_ms, RZ_SUBPROCESS_STDOUT, n);
	}
	return &proc->out;
}

/**
 * Read one line from the stdout of the subprocess and returns a \p RzStrBuf
 * containing it. Callers must not free the returned pointer.
 *
 * \param proc Subprocess to communicate with
 * \param timeout_ms Wait for at most this amount of millisecond to read subprocess' stdout
 */
RZ_API RzStrBuf *rz_subprocess_stdout_readline(RzSubprocess *proc, ut64 timeout_ms) {
	rz_strbuf_fini(&proc->out);
	rz_strbuf_init(&proc->out);
	if (proc->stdout_fd != -1) {
		char c = '\0';
		RzSubprocessWaitReason reason;
		// FIXME: the timeout should also be checked globally here
		do {
			reason = subprocess_wait(proc, timeout_ms, RZ_SUBPROCESS_STDOUT, 1);
			c = rz_strbuf_get(&proc->out)[rz_strbuf_length(&proc->out) - 1];
		} while (c != '\n' && reason == RZ_SUBPROCESS_BYTESREAD);
	}
	return &proc->out;
}

RZ_API void rz_subprocess_kill(RzSubprocess *proc) {
	kill(proc->pid, SIGKILL);
}

RZ_API RzSubprocessOutput *rz_subprocess_drain(RzSubprocess *proc) {
	subprocess_lock();
	RzSubprocessOutput *out = RZ_NEW(RzSubprocessOutput);
	if (out) {
		out->out = rz_strbuf_drain_nofree(&proc->out);
		out->err = rz_strbuf_drain_nofree(&proc->err);
		out->ret = proc->ret;
		out->timeout = false;
	}
	subprocess_unlock();
	return out;
}

RZ_API void rz_subprocess_free(RzSubprocess *proc) {
	if (!proc) {
		return;
	}
	subprocess_lock();
	rz_pvector_remove_data(&subprocs, proc);
	subprocess_unlock();
	rz_strbuf_fini(&proc->out);
	rz_strbuf_fini(&proc->err);
	rz_sys_pipe_close(proc->killpipe[0]);
	rz_sys_pipe_close(proc->killpipe[1]);
	if (proc->stdin_fd != -1) {
		rz_sys_pipe_close(proc->stdin_fd);
	}
	if (proc->stdout_fd != -1) {
		rz_sys_pipe_close(proc->stdout_fd);
	}
	if (proc->stderr_fd != -1 && proc->stderr_fd != proc->stdout_fd) {
		rz_sys_pipe_close(proc->stderr_fd);
	}
	free(proc);
}
#endif

RZ_API int rz_subprocess_ret(RzSubprocess *proc) {
	return proc->ret;
}

RZ_API char *rz_subprocess_out(RzSubprocess *proc, int *length) {
	int bin_len = 0;
	const ut8 *bin = rz_strbuf_getbin(&proc->out, &bin_len);
	char *buf = rz_str_newlen((const char *)bin, bin_len);
	if (length) {
		*length = bin_len;
	}
	rz_strbuf_fini(&proc->out);
	return buf;
}

RZ_API char *rz_subprocess_err(RzSubprocess *proc, int *length) {
	int bin_len = 0;
	const ut8 *bin = rz_strbuf_getbin(&proc->err, &bin_len);
	char *buf = rz_str_newlen((const char *)bin, bin_len);
	if (length) {
		*length = bin_len;
	}
	rz_strbuf_fini(&proc->err);
	return buf;
}

RZ_API void rz_subprocess_output_free(RzSubprocessOutput *out) {
	if (!out) {
		return;
	}
	free(out->out);
	free(out->err);
	free(out);
}

/**
 * Start a program in a new child process with the specified parameters.
 *
 * \param file Name of the program to start. It is also evaluated against PATH
 * \param args Array of arguments to pass to the new program. It does not include argv[0]
 * \param args_size Number of arguments in the \p args array
 * \param envvars Name of environment variables that the newprocess has different from the parent
 * \param envvals Values of environment variables that the newprocess has
 * different from the parent. Elements are evaluated in parallel with \p
 * envvars, so envvals[0] specifies the value of the environment variable named
 * envvars[0] and so on.
 * \param env_size Number of environment variables in arrays \p envvars and \p envvals
 */
RZ_API RzSubprocess *rz_subprocess_start(
	const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size) {
	RzSubprocessOpt opt = {
		.file = file,
		.args = args,
		.args_size = args_size,
		.envvars = envvars,
		.envvals = envvals,
		.env_size = env_size,
		.stdin_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stdout_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stderr_pipe = RZ_SUBPROCESS_PIPE_CREATE,
	};
	return rz_subprocess_start_opt(&opt);
}
