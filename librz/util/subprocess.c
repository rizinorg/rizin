// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util.h>

#define BUFFER_SIZE 0x500

#if __WINDOWS__
#include <rz_windows.h>

#if NTDDI_VERSION >= NTDDI_VISTA
typedef _Success_(return != FALSE) BOOL(WINAPI *InitializeProcThreadAttributeList_t)(
	_Out_writes_bytes_to_opt_(*lpSize, *lpSize) LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	_In_ DWORD dwAttributeCount,
	_Reserved_ DWORD dwFlags,
	_When_(lpAttributeList == nullptr, _Out_) _When_(lpAttributeList != nullptr, _Inout_) PSIZE_T lpSize);

typedef BOOL(WINAPI *UpdateProcThreadAttribute_t)(
	_Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	_In_ DWORD dwFlags,
	_In_ DWORD_PTR Attribute,
	_In_reads_bytes_opt_(cbSize) PVOID lpValue,
	_In_ SIZE_T cbSize,
	_Out_writes_bytes_opt_(cbSize) PVOID lpPreviousValue,
	_In_opt_ PSIZE_T lpReturnSize);

typedef VOID(WINAPI *DeleteProcThreadAttributeList_t)(
	_Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);

static InitializeProcThreadAttributeList_t lpInitializeProcThreadAttributeList = NULL;
static UpdateProcThreadAttribute_t lpUpdateProcThreadAttribute = NULL;
static DeleteProcThreadAttributeList_t lpDeleteProcThreadAttributeList = NULL;
#endif

struct rz_subprocess_t {
	HANDLE stdin_write;
	HANDLE stdout_read;
	HANDLE stderr_read;
	HANDLE proc;
	int ret;
	RzStrBuf out;
	RzStrBuf err;
};

#define INVALID_POINTER_VALUE ((void *)PTRDIFF_MAX)

typedef struct subprocess_windows_t {
	RzThreadLock *subproc_mutex;
	long refcount;
	bool has_procthreadattr;
	volatile long pipe_id;
	DWORD mode_stdin;
	DWORD mode_stdout;
	DWORD mode_stderr;
} SubprocessWindows;

// This structure is used by init/fini
static SubprocessWindows subwin = { 0 };

static bool create_pipe_overlap(HANDLE *pipe_read, HANDLE *pipe_write, LPSECURITY_ATTRIBUTES attrs, DWORD sz, DWORD read_mode, DWORD write_mode) {
	// see https://stackoverflow.com/a/419736
	if (!sz) {
		sz = 4096;
	}
	WCHAR name[MAX_PATH];
	_snwprintf_s(name, _countof(name), sizeof(name), L"\\\\.\\pipe\\rz-pipe-subproc.%d.%ld", (int)GetCurrentProcessId(), (long)InterlockedIncrement(&subwin.pipe_id));
	*pipe_read = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | read_mode, PIPE_TYPE_BYTE | PIPE_WAIT, 1, sz, sz, 120 * 1000, attrs);
	if (!*pipe_read) {
		return FALSE;
	}
	*pipe_write = CreateFileW(name, GENERIC_WRITE, 0, attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | write_mode, NULL);
	if (*pipe_write == INVALID_HANDLE_VALUE) {
		CloseHandle(*pipe_read);
		return FALSE;
	}

	SetEnvironmentVariableW(L"RZ_PIPE_PATH", name);
	return true;
}

static RzThreadLock *get_subprocess_lock(void) {
	RzThreadLock *lock;
	do {
		lock = InterlockedCompareExchangePointer(&subwin.subproc_mutex, INVALID_POINTER_VALUE, INVALID_POINTER_VALUE);
	} while (!lock);
	return lock;
}

RZ_API bool rz_subprocess_init(void) {
	long ref = InterlockedIncrement(&subwin.refcount);
	RzThreadLock *lock = NULL;
	if (ref == 1) {
		lock = rz_th_lock_new(false);
		if (!lock) {
			InterlockedExchangePointer(&subwin.subproc_mutex, INVALID_POINTER_VALUE);
			InterlockedDecrement(&subwin.refcount);
			return false;
		}
		// Enter lock before making it available, so we are the first to run
		rz_th_lock_enter(lock);
		InterlockedExchangePointer(&subwin.subproc_mutex, lock);
	} else {
		// Spin until theres a lock available or lock initialization failed
		lock = get_subprocess_lock();
		if (lock == INVALID_POINTER_VALUE) {
			InterlockedDecrement(&subwin.refcount);
			return false;
		}
		rz_th_lock_enter(lock);
	}

	if (ref > 1) {
		// This is not the first call to this function, just leave
		goto leave;
	}

	// Save current console mode
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &subwin.mode_stdin);
	GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &subwin.mode_stdout);
	GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &subwin.mode_stderr);

#if NTDDI_VERSION >= NTDDI_VISTA
	if (!subwin.has_procthreadattr && IsWindowsVistaOrGreater()) {
		HMODULE kernel32 = LoadLibraryW(L"kernel32");
		if (!kernel32) {
			rz_sys_perror("LoadLibraryW(L\"kernel32\")");
			goto leave;
		}
		lpInitializeProcThreadAttributeList = (InitializeProcThreadAttributeList_t)GetProcAddress(kernel32, "InitializeProcThreadAttributeList");
		lpUpdateProcThreadAttribute = (UpdateProcThreadAttribute_t)GetProcAddress(kernel32, "UpdateProcThreadAttribute");
		lpDeleteProcThreadAttributeList = (DeleteProcThreadAttributeList_t)GetProcAddress(kernel32, "DeleteProcThreadAttributeList");
		if (lpInitializeProcThreadAttributeList && lpUpdateProcThreadAttribute && lpDeleteProcThreadAttributeList) {
			subwin.has_procthreadattr = true;
		}
		FreeLibrary(kernel32);
	}
#endif
leave:
	rz_th_lock_leave(lock);
	return true;
}
RZ_API void rz_subprocess_fini(void) {
	RzThreadLock *lock = NULL;
	do {
		if (InterlockedCompareExchange(&subwin.refcount, -1, -1) == 0) {
			// Shouldn't happen, someone called this function excessively
			rz_warn_if_reached();
			return;
		}
		lock = InterlockedExchangePointer(&subwin.subproc_mutex, NULL);
	} while (!lock);
	if (InterlockedDecrement(&subwin.refcount) > 0) {
		InterlockedExchangePointer(&subwin.subproc_mutex, lock);
		return;
	}
	SetEnvironmentVariableW(L"RZ_PIPE_PATH", NULL);
	// Restore console mode
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), subwin.mode_stdin);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), subwin.mode_stdout);
	SetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), subwin.mode_stderr);
	rz_th_lock_free(lock);
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
		// wprintf (L"ENV: %s\n", cur);
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

/**
 * \brief Start a subprocess, using the options provided in \p opt
 *
 * \param opt RzSubprocessOpt struct
 * \return RzSubprocess* The newly created subprocess
 */
RZ_API RZ_OWN RzSubprocess *rz_subprocess_start_opt(RZ_NONNULL const RzSubprocessOpt *opt) {
	RzSubprocess *proc = NULL;
	const HANDLE curr_stdin_handle = (HANDLE)_get_osfhandle(fileno(stdin));
	const HANDLE curr_stdout_handle = (HANDLE)_get_osfhandle(fileno(stdout));
	const HANDLE curr_stderr_handle = (HANDLE)_get_osfhandle(fileno(stderr));
	HANDLE stdin_read = curr_stdin_handle;
	HANDLE stdout_write = curr_stdout_handle;
	HANDLE stderr_write = curr_stderr_handle;
	LPWSTR lpFilePart;
	PWCHAR cmd_exe = RZ_NEWS0(WCHAR, MAX_PATH);
#if NTDDI_VERSION >= NTDDI_VISTA
	LPPROC_THREAD_ATTRIBUTE_LIST attr_list = NULL;
#endif
	RzThreadLock *lock = NULL;

	PWCHAR file = rz_utf8_to_utf16(opt->file);
	if (!file) {
		return NULL;
	}

	if (!rz_file_exists(opt->file)) {
		DWORD len;
		if ((len = SearchPathW(NULL, file, L".exe", MAX_PATH, cmd_exe, &lpFilePart)) < 1) {
			RZ_LOG_DEBUG("SearchPath failed for %s\n", opt->file);
			free(file);
			return NULL;
		}
		if (len > MAX_PATH) {
			PWCHAR tmp = realloc(cmd_exe, sizeof(WCHAR) * len);
			if (!tmp) {
				free(cmd_exe);
				free(file);
				return NULL;
			}
			cmd_exe = tmp;
			SearchPathW(NULL, file, L".exe", len, cmd_exe, &lpFilePart);
		}
		free(file);
	} else {
		cmd_exe = file;
	}

	char **argv = calloc(opt->args_size + 1, sizeof(char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = ""; // a space is required to work correctly.
	if (opt->args_size) {
		memcpy(argv + 1, opt->args, sizeof(char *) * opt->args_size);
	}
	char *cmd = rz_str_format_msvc_argv(opt->args_size + 1, (const char **)argv);
	free(argv);
	if (!cmd) {
		return NULL;
	}
	PWCHAR cmdline = rz_utf8_to_utf16(cmd);
	if (!cmdline) {
		goto error;
	}

	{
		char *log_executable = rz_utf16_to_utf8(cmd_exe);
		if (log_executable) {
			RZ_LOG_DEBUG("%s%s\n", log_executable, cmd);
			free(log_executable);
		}
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
	DWORD dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
	STARTUPINFOW start_info_short = { .cb = sizeof(STARTUPINFOW) };
	STARTUPINFOW *start_info = &start_info_short;
#if NTDDI_VERSION >= NTDDI_VISTA
	STARTUPINFOEXW start_infoex = { .StartupInfo.cb = sizeof(STARTUPINFOEXW) };
	if (subwin.has_procthreadattr) {
		SIZE_T attr_list_size = 0;
		if (!lpInitializeProcThreadAttributeList(NULL, 1, 0, &attr_list_size) &&
			GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			goto error;
		}
		attr_list = malloc(attr_list_size);
		if (!attr_list) {
			goto error;
		}
		if (!lpInitializeProcThreadAttributeList(attr_list, 1, 0, &attr_list_size)) {
			goto error;
		}
		HANDLE handle_list[3] = { stdin_read, stdout_write };
		if (opt->stderr_pipe != RZ_SUBPROCESS_PIPE_STDOUT) {
			handle_list[2] = stderr_write;
		}
		const int num_handles = opt->stderr_pipe != RZ_SUBPROCESS_PIPE_STDOUT ? 3 : 2;
		if (!lpUpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handle_list, num_handles * sizeof(HANDLE), NULL, NULL)) {
			goto error;
		}
		start_info = (STARTUPINFOW *)&start_infoex;
		start_infoex.lpAttributeList = attr_list;
		dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
	} else {
		lock = get_subprocess_lock();
	}
#else
	lock = get_subprocess_lock();
#endif

	start_info->hStdError = stderr_write;
	start_info->hStdOutput = stdout_write;
	start_info->hStdInput = stdin_read;
	start_info->dwFlags = STARTF_USESTDHANDLES;

	LPWSTR env = override_env(opt->envvars, opt->envvals, opt->env_size);
	if (!CreateProcessW(
		    cmd_exe, // exe
		    cmdline, // command line
		    NULL, // process security attributes
		    NULL, // primary thread security attributes
		    TRUE, // handles are inherited
		    dwCreationFlags, // creation flags
		    env, // use parent's environment
		    NULL, // use parent's current directory
		    start_info, // STARTUPINFO pointer
		    &proc_info)) { // receives PROCESS_INFORMATION
		free(env);
		rz_sys_perror("CreateProcess");
		goto error;
	}
	free(env);

	CloseHandle(proc_info.hThread);
	proc->proc = proc_info.hProcess;

beach:

	if (lock) {
		rz_th_lock_leave(lock);
	}
#if NTDDI_VERSION >= NTDDI_VISTA
	if (attr_list) {
		lpDeleteProcThreadAttributeList(attr_list);
		free(attr_list);
	}
#endif

	if (stdin_read && stdin_read != curr_stdin_handle) {
		CloseHandle(stdin_read);
	}
	if (stderr_write && stderr_write != curr_stderr_handle && stderr_write != stdout_write) {
		CloseHandle(stderr_write);
	}
	if (stdout_write && stdout_write != curr_stdout_handle) {
		CloseHandle(stdout_write);
	}
	free(cmd_exe);
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

static bool do_read(HANDLE *f, char *buf, size_t buf_size, size_t n_bytes, OVERLAPPED *overlapped) {
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

static void cancel_read(HANDLE *f, RzStrBuf *sb, char *buf, OVERLAPPED *overlapped) {
	if (!CancelIo(f)) {
		rz_sys_perror("CancelIo");
	}
	DWORD bytes_transferred;
	if (GetOverlappedResult(f, overlapped, &bytes_transferred, TRUE) || GetLastError() == ERROR_OPERATION_ABORTED) {
		rz_strbuf_append_n(sb, buf, bytes_transferred);
	} else {
		rz_sys_perror("GetOverlappedResult");
	}
	CloseHandle(overlapped->hEvent);
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
	DWORD timeout = timeout_us_abs == UT64_MAX
		? INFINITE
		: (DWORD)(timeout_us_abs / RZ_USEC_PER_MSEC);
	RzVector handles;
	bool did_once = false;
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

		if (timeout_us_abs != UT64_MAX) {
			ut64 now = rz_time_now_mono();
			if (now >= timeout_us_abs) {
				if (did_once) {
					rz_vector_clear(&handles);
					if (stdout_enabled) {
						cancel_read(proc->stderr_read, &proc->out, stdout_buf, &stderr_overlapped);
					}
					if (stderr_enabled) {
						cancel_read(proc->stderr_read, &proc->err, stderr_buf, &stderr_overlapped);
					}
					return RZ_SUBPROCESS_TIMEDOUT;
				}
				timeout = 0;
			} else {
				timeout = (DWORD)((timeout_us_abs - now) / RZ_USEC_PER_MSEC);
			}
		}
		did_once = true;
		DWORD signaled = WaitForMultipleObjects(handles.len, handles.a, FALSE, timeout);
		if (stdout_enabled && !stdout_eof && signaled == stdout_index) {
			DWORD r;
			BOOL res = GetOverlappedResult(proc->stdout_read, &stdout_overlapped, &r, TRUE);
			if (!res) {
				stdout_eof = true;
				continue;
			}
			rz_strbuf_append_n(&proc->out, (const char *)stdout_buf, r);
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
			rz_strbuf_append_n(&proc->err, (const char *)stderr_buf, r);
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
	if (stdout_overlapped.hEvent) {
		CloseHandle(stdout_overlapped.hEvent);
	}
	if (stderr_overlapped.hEvent) {
		CloseHandle(stderr_overlapped.hEvent);
	}
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
	out->out = rz_subprocess_out(proc, &out->out_len);
	out->err = rz_subprocess_err(proc, &out->err_len);
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

/**
 * \brief Unimplemented on Windows
 *
 * \return RzPty* NULL pointer until it has been implemented
 */
RZ_API RZ_OWN RzPty *rz_subprocess_openpty(RZ_BORROW RZ_NULLABLE char *slave_name, RZ_NULLABLE void /* const struct termios */ *term_params, RZ_NULLABLE void /* const struct winsize */ *win_params) {
	RZ_LOG_ERROR("openpty: Not implemented for Windows!\n");
	return NULL;
}

/**
 * \brief Unimplemented on Windows
 *
 * \return bool false
 */
RZ_API bool rz_subprocess_login_tty(RZ_BORROW RZ_NONNULL const RzPty *pty) {
	RZ_LOG_ERROR("login_tty: Not implemented for Windows!\n");
	return false;
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
	int master_fd; ///< Needed to check whether PTY
	int slave_fd;
};

typedef struct subprocess_unix_t {
	RzPVector /*<RzSubprocess *>*/ subprocs;
	RzThreadLock *subprocs_mutex;
	int sigchld_pipe[2];
	RzThread *sigchld_thread;
} SubprocessUnix;

// This structure is used by init/fini
static SubprocessUnix subnix = { 0 };

static void subprocess_lock(void) {
	rz_th_lock_enter(subnix.subprocs_mutex);
}

static void subprocess_unlock(void) {
	rz_th_lock_leave(subnix.subprocs_mutex);
}

static void handle_sigchld(int sig) {
	ut8 b = 1;
	rz_xwrite(subnix.sigchld_pipe[1], &b, 1);
}

static void *sigchld_th(void *th) {
	while (true) {
		ut8 b;
		ssize_t rd = read(subnix.sigchld_pipe[0], &b, 1);
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
			rz_pvector_foreach (&subnix.subprocs, it) {
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
	return NULL;
}

RZ_API bool rz_subprocess_init(void) {
	rz_pvector_init(&subnix.subprocs, NULL);
	subnix.subprocs_mutex = rz_th_lock_new(true);
	if (!subnix.subprocs_mutex) {
		return false;
	}
	if (rz_sys_pipe(subnix.sigchld_pipe, true) == -1) {
		perror("pipe");
		rz_th_lock_free(subnix.subprocs_mutex);
		return false;
	}
	subnix.sigchld_thread = rz_th_new(sigchld_th, NULL);
	if (!subnix.sigchld_thread) {
		rz_sys_pipe_close(subnix.sigchld_pipe[0]);
		rz_sys_pipe_close(subnix.sigchld_pipe[1]);
		rz_th_lock_free(subnix.subprocs_mutex);
		return false;
	}
	if (rz_sys_signal(SIGCHLD, handle_sigchld) < 0) {
		rz_sys_pipe_close(subnix.sigchld_pipe[0]);
		rz_sys_pipe_close(subnix.sigchld_pipe[1]);
		rz_th_lock_free(subnix.subprocs_mutex);
		return false;
	}
	return true;
}

RZ_API void rz_subprocess_fini(void) {
	rz_sys_signal(SIGCHLD, SIG_IGN);
	ut8 b = 0;
	rz_xwrite(subnix.sigchld_pipe[1], &b, 1);
	rz_sys_pipe_close(subnix.sigchld_pipe[1]);
	rz_th_wait(subnix.sigchld_thread);
	rz_sys_pipe_close(subnix.sigchld_pipe[0]);
	rz_th_free(subnix.sigchld_thread);
	rz_pvector_clear(&subnix.subprocs);
	rz_th_lock_free(subnix.subprocs_mutex);
}

static char **create_child_env(const char *envvars[], const char *envvals[], size_t env_size) {
	char **ep;
	size_t new_env_size = env_size, size = 0;
	size_t *positions = RZ_NEWS(size_t, env_size);
	if (!positions) {
		return NULL;
	}
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
	if (!new_env) {
		free(positions);
		return NULL;
	}
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
	if (!child_env) {
		return;
	}
	char **ep;
	for (ep = child_env; *ep; ep++) {
		free(*ep);
	}
	free(child_env);
}

static bool init_pipes(RzSubprocess *proc, const RzSubprocessOpt *opt, int stdin_pipe[], int stdout_pipe[], int stderr_pipe[], RzPty **new_pty) {
	RzPty *pty = opt->pty;
	if (new_pty) {
		*new_pty = NULL;
	}

	/* If we need to use a PTY, we should create one right now */
	if (!pty && (opt->stdin_pipe == RZ_SUBPROCESS_PIPE_PTY || opt->stdout_pipe == RZ_SUBPROCESS_PIPE_PTY || opt->stderr_pipe == RZ_SUBPROCESS_PIPE_PTY)) {
		pty = rz_subprocess_openpty(NULL, NULL, NULL);
		if (!pty) {
			return false;
		}
		if (new_pty) {
			*new_pty = pty;
		}
	}

	if (pty) {
		proc->master_fd = pty->master_fd;
		proc->slave_fd = pty->slave_fd;
	}

	switch (opt->stdin_pipe) {
	case RZ_SUBPROCESS_PIPE_CREATE:
		if (rz_sys_pipe(stdin_pipe, true) == -1) {
			perror("pipe");
			goto abort;
		}
		proc->stdin_fd = stdin_pipe[1];
		break;
	case RZ_SUBPROCESS_PIPE_PTY:
		stdin_pipe[0] = pty->slave_fd;
		stdin_pipe[1] = pty->master_fd;
		proc->stdin_fd = stdin_pipe[1];
		break;
	case RZ_SUBPROCESS_PIPE_STDOUT:
		RZ_LOG_ERROR("Invalid pipe option 'RZ_SUBPROCESS_PIPE_STDOUT' for stdin. Ignoring...\n");
		break;
	case RZ_SUBPROCESS_PIPE_NONE:
		break;
	}

	switch (opt->stdout_pipe) {
	case RZ_SUBPROCESS_PIPE_CREATE:
		if (rz_sys_pipe(stdout_pipe, true) == -1) {
			perror("pipe");
			goto abort;
		}
		if (fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
			perror("fcntl");
			goto abort;
		}
		proc->stdout_fd = stdout_pipe[0];
		break;
	case RZ_SUBPROCESS_PIPE_PTY:
		stdout_pipe[0] = pty->master_fd;
		stdout_pipe[1] = pty->slave_fd;
		proc->stdout_fd = stdout_pipe[0];
		break;
	case RZ_SUBPROCESS_PIPE_STDOUT:
		RZ_LOG_ERROR("Invalid pipe option 'RZ_SUBPROCESS_PIPE_STDOUT' for stdout. Ignoring...\n");
		break;
	case RZ_SUBPROCESS_PIPE_NONE:
		break;
	}

	switch (opt->stderr_pipe) {
	case RZ_SUBPROCESS_PIPE_CREATE:
		if (rz_sys_pipe(stderr_pipe, true) == -1) {
			perror("pipe");
			goto abort;
		}
		if (fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
			perror("fcntl");
			goto abort;
		}
		proc->stderr_fd = stderr_pipe[0];
		break;
	case RZ_SUBPROCESS_PIPE_PTY:
		stdout_pipe[0] = pty->master_fd;
		stdout_pipe[1] = pty->slave_fd;
		proc->stdout_fd = stdout_pipe[0];
		break;
	case RZ_SUBPROCESS_PIPE_STDOUT:
		stderr_pipe[0] = stdout_pipe[0];
		stderr_pipe[1] = stdout_pipe[1];
		proc->stderr_fd = proc->stdout_fd;
		break;
	case RZ_SUBPROCESS_PIPE_NONE:
		break;
	}

	return true;

abort:
	rz_subprocess_pty_free(pty);
	if (new_pty) {
		*new_pty = NULL;
	}
	return false;
}

/**
 * \brief Start a subprocess, using the options provided in \p opt
 *
 * \param opt RzSubprocessOpt struct
 * \return RzSubprocess* The newly created subprocess
 */
RZ_API RZ_OWN RzSubprocess *rz_subprocess_start_opt(RZ_NONNULL const RzSubprocessOpt *opt) {
	rz_return_val_if_fail(opt, NULL);

	RzSubprocess *proc = NULL;
	char **child_env = NULL;
	char **argv = calloc(opt->args_size + 2, sizeof(char *));
	RzPty *new_pty = NULL;
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)opt->file;
	if (opt->args_size) {
		memcpy(argv + 1, opt->args, sizeof(char *) * opt->args_size);
	}
	// done by calloc: argv[args_size + 1] = NULL;
	subprocess_lock();
	proc = RZ_NEW0(RzSubprocess);
	if (!proc) {
		goto error;
	}
	proc->killpipe[0] = proc->killpipe[1] = -1;
	proc->ret = -1;
	proc->stdin_fd = -1;
	proc->stdout_fd = -1;
	proc->stderr_fd = -1;
	proc->master_fd = -1;
	proc->slave_fd = -1;
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

	if (!init_pipes(proc, opt, stdin_pipe, stdout_pipe, stderr_pipe, &new_pty)) {
		goto error;
	}

	// Let's create the environment for the child in the parent, with malloc,
	// because we can't use functions that lock after fork
	child_env = create_child_env(opt->envvars, opt->envvals, opt->env_size);
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
			if (proc->stderr_fd != proc->stdout_fd && proc->stderr_fd != proc->master_fd) {
				rz_sys_pipe_close(stderr_pipe[1]);
				rz_sys_pipe_close(stderr_pipe[0]);
			}
		}

		if (stdout_pipe[1] != -1) {
			while ((dup2(stdout_pipe[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {
			}
			if (proc->stdout_fd != proc->master_fd) {
				rz_sys_pipe_close(stdout_pipe[1]);
				rz_sys_pipe_close(stdout_pipe[0]);
			}
		}
		if (stdin_pipe[0] != -1) {
			while ((dup2(stdin_pipe[0], STDIN_FILENO) == -1) && (errno == EINTR)) {
			}
			if (proc->stdin_fd != proc->master_fd) {
				rz_sys_pipe_close(stdin_pipe[0]);
				rz_sys_pipe_close(stdin_pipe[1]);
			}
		}

		if (proc->master_fd != -1 && close(proc->master_fd)) {
			perror("close");
		}
		if (proc->slave_fd != -1 && close(proc->slave_fd)) {
			perror("close");
		}

		// Use the previously created environment
		rz_sys_set_environ(child_env);

		rz_sys_execvp(opt->file, argv);
		perror("exec");
		rz_sys_exit(-1, true);
	}
	destroy_child_env(child_env);
	free(argv);

	if (!opt->make_raw || proc->slave_fd == -1) {
		goto no_term_change;
	}

#if HAVE_FORKPTY && HAVE_OPENPTY && HAVE_LOGIN_TTY
	struct termios term_params;
	/* Needed to avoid reading back the writes again from the TTY */
	if (tcgetattr(proc->slave_fd, &term_params) != 0) {
		perror("tcgetattr");
		goto no_term_change;
	}
	cfmakeraw(&term_params);
	/* This avoids ECHO, so we don't read back whatever we wrote */
	if (tcsetattr(proc->slave_fd, TCSANOW, &term_params) != 0) {
		perror("tcsetattr");
	}
#endif

no_term_change:
	if (proc->slave_fd != -1 && close(proc->slave_fd) == -1) {
		perror("close");
	}

	if (new_pty) {
		/* Free the RzPTY if we created it */
		rz_subprocess_pty_free(new_pty);
	}

	if (stdin_pipe[0] != -1 && stdin_pipe[0] != proc->slave_fd) {
		rz_sys_pipe_close(stdin_pipe[0]);
	}
	if (stdout_pipe[1] != -1 && stdout_pipe[1] != proc->slave_fd) {
		rz_sys_pipe_close(stdout_pipe[1]);
	}
	if (stderr_pipe[1] != -1 && proc->stderr_fd != proc->stdout_fd && stderr_pipe[1] != proc->slave_fd) {
		rz_sys_pipe_close(stderr_pipe[1]);
	}

	rz_pvector_push(&subnix.subprocs, proc);
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
	if (stderr_pipe[0] != -1 && stderr_pipe[0] != stdout_pipe[0] && !(proc && stderr_pipe[0] == proc->master_fd)) {
		rz_sys_pipe_close(stderr_pipe[0]);
	}
	if (stderr_pipe[1] != -1 && stderr_pipe[1] != stdout_pipe[1] && !(proc && stderr_pipe[1] == proc->slave_fd)) {
		rz_sys_pipe_close(stderr_pipe[1]);
	}
	if (stdout_pipe[0] != -1 && !(proc && stdout_pipe[0] == proc->master_fd)) {
		rz_sys_pipe_close(stdout_pipe[0]);
	}
	if (stdout_pipe[1] != -1 && !(proc && stdout_pipe[1] == proc->slave_fd)) {
		rz_sys_pipe_close(stdout_pipe[1]);
	}
	if (stdin_pipe[0] != -1 && !(proc && stdin_pipe[0] == proc->slave_fd)) {
		rz_sys_pipe_close(stdin_pipe[0]);
	}
	if (stdin_pipe[1] != -1 && !(proc && stdin_pipe[1] == proc->master_fd)) {
		rz_sys_pipe_close(stdin_pipe[1]);
	}
	if (proc && proc->master_fd != -1) {
		close(proc->master_fd);
	}
	if (proc && proc->slave_fd != -1) {
		close(proc->slave_fd);
	}
	free(proc);

	if (new_pty) {
		/* Free the RzPTY if we created it */
		rz_subprocess_pty_free(new_pty);
	}

	destroy_child_env(child_env);
	subprocess_unlock();
	return NULL;
}

static size_t read_to_strbuf(RzStrBuf *sb, int fd, bool *fd_eof, size_t n_bytes, bool is_pty) {
	char buf[BUFFER_SIZE];
	size_t to_read = sizeof(buf);
	if (n_bytes && to_read > n_bytes) {
		to_read = n_bytes;
	}
	ssize_t sz = read(fd, buf, to_read);
	if (sz == 0 || (is_pty && sz == -1 && errno == EIO)) {
		/* In case of PTY, EIO (input/output error) denotes EOF, hence the manual checking */
		*fd_eof = true;
	} else if (sz < 0) {
		perror("read");
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
	ut64 timeout_abs = UT64_MAX;
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

	/* Check if stdout and stderr are connected to a PTY */
	bool stdout_pty = proc->stdout_fd != -1 && proc->stdout_fd == proc->master_fd;
	bool stderr_pty = proc->stderr_fd != -1 && proc->stderr_fd == proc->master_fd;

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
			size_t r = read_to_strbuf(&proc->out, proc->stdout_fd, &stdout_eof, n_bytes, stdout_pty);
			if (r > 0 && n_bytes) {
				n_bytes -= r;
			}
		}
		if (stderr_enabled && FD_ISSET(proc->stderr_fd, &rfds)) {
			timedout = false;
			size_t r = read_to_strbuf(&proc->err, proc->stderr_fd, &stderr_eof, n_bytes, stderr_pty);
			if (r > 0 && n_bytes) {
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
	/* Should not close proc->stdin_fd if the fork mode was PTY
	(because it might point to the master fd, which needs to stay open to get the std{out,err}) */
	if (proc->stdin_fd != -1 && proc->stdin_fd != proc->master_fd) {
		// Close subprocess stdin to tell it that no more input will come from us
		rz_sys_pipe_close(proc->stdin_fd);
		proc->stdin_fd = -1;
	}
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
	ssize_t written = -1;
	if (proc->stdin_fd == -1) {
		return written;
	}
	rz_sys_signal(SIGPIPE, SIG_IGN);
	written = write(proc->stdin_fd, buf, buf_size);
	rz_sys_signal(SIGPIPE, SIG_DFL);
	return written;
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
RZ_API RZ_BORROW RzStrBuf *rz_subprocess_stdout_readline(RzSubprocess *proc, ut64 timeout_ms) {
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
		out->out = rz_subprocess_out(proc, &out->out_len);
		out->err = rz_subprocess_err(proc, &out->err_len);
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
	rz_pvector_remove_data(&subnix.subprocs, proc);
	subprocess_unlock();
	rz_strbuf_fini(&proc->out);
	rz_strbuf_fini(&proc->err);
	rz_sys_pipe_close(proc->killpipe[0]);
	rz_sys_pipe_close(proc->killpipe[1]);

	if (proc->master_fd != -1) {
		rz_sys_pipe_close(proc->master_fd);
	}
	if (proc->stdin_fd != -1 && proc->stdin_fd != proc->master_fd) {
		rz_sys_pipe_close(proc->stdin_fd);
	}
	if (proc->stdout_fd != -1 && proc->stdout_fd != proc->master_fd) {
		rz_sys_pipe_close(proc->stdout_fd);
	}
	if (proc->stderr_fd != -1 && proc->stderr_fd != proc->stdout_fd && proc->stderr_fd != proc->master_fd) {
		rz_sys_pipe_close(proc->stderr_fd);
	}
	free(proc);
}

/**
 * \brief Call openpty(3) with the provided arguments
 *
 * \param slave_name The name of the slave PTY is stored in this
 * This is marked as RZ_BORROW, so it's ownership no longer stays with the caller
 * and is now owned by the returned RzPty struct
 *
 * \param term_params Terminal attributes (struct termios) for the forked process
 * \param win_params Window attributes (struct winsize) for the forked process
 *
 * \return RzPty*
 */
RZ_API RZ_OWN RzPty *rz_subprocess_openpty(RZ_BORROW RZ_NULLABLE char *slave_name, RZ_NULLABLE void /* const struct termios */ *term_params, RZ_NULLABLE void /* const struct winsize */ *win_params) {
	RzPty *pty = RZ_NEW0(RzPty);
	int ret = rz_sys_openpty(&pty->master_fd, &pty->slave_fd, slave_name, NULL, NULL);

	if (ret == -1) {
		perror("openpty");
		RZ_FREE(pty);
		return NULL;
	}

	return pty;
}

/**
 * \brief Call login_tty(3) on the provided \p pty
 *
 * \param pty RzPty struct
 * \return bool true if login_tty succeeded, false otherwise
 */
RZ_API bool rz_subprocess_login_tty(RZ_BORROW RZ_NONNULL const RzPty *pty) {
	rz_return_val_if_fail(pty, false);

	int ret = rz_sys_login_tty(pty->slave_fd);
	if (ret == -1) {
		perror("login_tty");
		return false;
	}

	return true;
}

/**
 * \brief Closes the file descriptors associated with \p pty
 *
 * \param pty RzPty struct
 * \return void
 *
 * No need to call this after you've used the \p pty in `rz_subprocess_start_opt`,
 * since the file descriptors would already have been correctly closed
 */
RZ_API void rz_subprocess_close_pty(RZ_BORROW RZ_NONNULL const RzPty *pty) {
	if (close(pty->master_fd) == -1) {
		perror("close");
	}
	if (close(pty->slave_fd) == -1) {
		perror("close");
	}
}

/**
 * \brief Free the \p pty
 *
 * \param pty RzPty struct
 * \return void
 */
RZ_API void rz_subprocess_pty_free(RZ_OWN RzPty *pty) {
	if (!pty) {
		return;
	}

	RZ_FREE(pty->name);
	free(pty);
}

#endif

RZ_API int rz_subprocess_ret(RzSubprocess *proc) {
	return proc->ret;
}

RZ_API ut8 *rz_subprocess_out(RzSubprocess *proc, int *length) {
	int bin_len = 0;
	const ut8 *bin = rz_strbuf_getbin(&proc->out, &bin_len);
	ut8 *buf = (ut8 *)rz_str_newlen((const char *)bin, bin_len);
	if (length) {
		*length = bin_len;
	}
	rz_strbuf_fini(&proc->out);
	return buf;
}

RZ_API ut8 *rz_subprocess_err(RzSubprocess *proc, int *length) {
	int bin_len = 0;
	const ut8 *bin = rz_strbuf_getbin(&proc->err, &bin_len);
	ut8 *buf = (ut8 *)rz_str_newlen((const char *)bin, bin_len);
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
		.pty = NULL,
		.make_raw = /* does not matter */ false
	};
	return rz_subprocess_start_opt(&opt);
}
