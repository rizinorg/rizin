// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <stdlib.h>
#include <string.h>
#if defined(__NetBSD__)
#include <sys/param.h>
#include <sys/sysctl.h>
#endif
#if defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/sysctl.h>
#endif
#if defined(__DragonFly__)
#include <sys/param.h>
#include <sys/sysctl.h>
#endif
#if defined(__OpenBSD__)
#include <sys/sysctl.h>
#include <sys/stat.h>
#endif
#if defined(__HAIKU__)
#include <kernel/image.h>
#include <sys/param.h>
#endif
#include <sys/types.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>

static char **env = NULL;

#if HAVE_BACKTRACE
#include <execinfo.h>
#endif
#if __APPLE__
#include <errno.h>

#if HAVE_ENVIRON || __APPLE__
#include <execinfo.h>
#endif
// iOS don't have this we can't hardcode
// #include <crt_externs.h>
extern char ***_NSGetEnviron(void);
#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE 1024
int proc_pidpath(int pid, void *buffer, ut32 buffersize);
// #  include <libproc.h>
#endif
#endif
#if __UNIX__
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
extern char **environ;

#ifdef __HAIKU__
#define Sleep sleep
#endif
#endif
#if __WINDOWS__
#include <io.h>
#include <rz_windows.h>
#include <VersionHelpers.h>
#include <signal.h>
#define TMP_BUFSIZE 4096
#ifdef _MSC_VER
#include <psapi.h>
#include <process.h> // to allow getpid under windows msvc compilation
#include <direct.h> // to allow getcwd under windows msvc compilation
#endif
#endif

/* For "openpty" family of funtcions */
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
#if defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <util.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <libutil.h>
#else
#include <pty.h>
#include <utmp.h>
#endif
#endif

RZ_LIB_VERSION(rz_util);

#ifdef __x86_64__
#ifdef _MSC_VER
#define RZ_SYS_ASM_START_ROP() \
	eprintf("rz_sys_run_rop: Unsupported arch\n");
#else
#define RZ_SYS_ASM_START_ROP() \
	__asm__ __volatile__("leaq %0, %%rsp; ret" \
			     : \
			     : "m"(*bufptr));
#endif
#elif __i386__
#ifdef _MSC_VER
#define RZ_SYS_ASM_START_ROP() \
	__asm { \
		__asm lea esp, bufptr\
		__asm ret \
	}
#else
#define RZ_SYS_ASM_START_ROP() \
	__asm__ __volatile__("leal %0, %%esp; ret" \
			     : \
			     : "m"(*bufptr));
#endif
#else
#define RZ_SYS_ASM_START_ROP() \
	eprintf("rz_sys_run_rop: Unsupported arch\n");
#endif

static const struct {
	const char *name;
	ut64 bit;
} arch_bit_array[] = {
	{ "x86", RZ_SYS_ARCH_X86 },
	{ "arm", RZ_SYS_ARCH_ARM },
	{ "ppc", RZ_SYS_ARCH_PPC },
	{ "m68k", RZ_SYS_ARCH_M68K },
	{ "java", RZ_SYS_ARCH_JAVA },
	{ "mips", RZ_SYS_ARCH_MIPS },
	{ "sparc", RZ_SYS_ARCH_SPARC },
	{ "xap", RZ_SYS_ARCH_XAP },
	{ "tms320", RZ_SYS_ARCH_TMS320 },
	{ "msil", RZ_SYS_ARCH_MSIL },
	{ "objd", RZ_SYS_ARCH_OBJD },
	{ "bf", RZ_SYS_ARCH_BF },
	{ "sh", RZ_SYS_ARCH_SH },
	{ "avr", RZ_SYS_ARCH_AVR },
	{ "dalvik", RZ_SYS_ARCH_DALVIK },
	{ "z80", RZ_SYS_ARCH_Z80 },
	{ "arc", RZ_SYS_ARCH_ARC },
	{ "i8080", RZ_SYS_ARCH_I8080 },
	{ "rar", RZ_SYS_ARCH_RAR },
	{ "lm32", RZ_SYS_ARCH_LM32 },
	{ "v850", RZ_SYS_ARCH_V850 },
	{ NULL, 0 }
};

#if HAVE_SIGACTION
RZ_API int rz_sys_sigaction(int *sig, void (*handler)(int)) {
	struct sigaction sigact = {};
	int ret, i;

	if (!sig) {
		return -EINVAL;
	}

	sigact.sa_handler = handler;
	sigemptyset(&sigact.sa_mask);

	for (i = 0; sig[i] != 0; i++) {
		sigaddset(&sigact.sa_mask, sig[i]);
	}

	for (i = 0; sig[i] != 0; i++) {
		ret = sigaction(sig[i], &sigact, NULL);
		if (ret) {
			eprintf("Failed to set signal handler for signal '%d': %s\n", sig[i], strerror(errno));
			return ret;
		}
	}

	return 0;
}
#else
RZ_API int rz_sys_sigaction(int *sig, void (*handler)(int)) {
	if (!sig) {
		return -EINVAL;
	}
	size_t i;
	for (i = 0; sig[i] != 0; i++) {
		void (*ret)(int) = signal(sig[i], handler);
		if (ret == SIG_ERR) {
			eprintf("Failed to set signal handler for signal '%d': %s\n", sig[i], strerror(errno));
			return -1;
		}
	}
	return 0;
}
#endif

RZ_API int rz_sys_signal(int sig, void (*handler)(int)) {
	int s[2] = { sig, 0 };
	return rz_sys_sigaction(s, handler);
}

RZ_API void rz_sys_exit(int status, bool nocleanup) {
	if (nocleanup) {
		_exit(status);
	} else {
		exit(status);
	}
}

#if __WINDOWS__
static HANDLE sys_opendir(const char *path, WIN32_FIND_DATAW *entry) {
	rz_return_val_if_fail(path, NULL);
	wchar_t dir[MAX_PATH];
	wchar_t *wcpath = 0;
	static bool win_ver_initialized = false;
	static bool is_win_7_or_greater = false;
	if (!win_ver_initialized) {
		is_win_7_or_greater = IsWindows7OrGreater();
		win_ver_initialized = true;
	}
	if (!(wcpath = rz_utf8_to_utf16(path))) {
		return NULL;
	}
	swprintf(dir, MAX_PATH, L"%ls\\*.*", wcpath);
	free(wcpath);
	return FindFirstFileExW(dir, is_win_7_or_greater ? FindExInfoBasic : FindExInfoStandard, entry, FindExSearchNameMatch, NULL, 0);
}
#else
static DIR *sys_opendir(const char *path) {
	rz_return_val_if_fail(path, NULL);
	return opendir(path);
}
#endif

RZ_API RzList /*<char *>*/ *rz_sys_dir(const char *path) {
	RzList *list = NULL;
#if __WINDOWS__
	WIN32_FIND_DATAW entry;
	char *cfname;
	HANDLE fh = sys_opendir(path, &entry);
	if (fh == INVALID_HANDLE_VALUE) {
		// IFDGB eprintf ("Cannot open directory %ls\n", wcpath);
		return list;
	}
	list = rz_list_newf(free);
	if (list) {
		do {
			if ((cfname = rz_utf16_to_utf8(entry.cFileName))) {
				rz_list_append(list, cfname);
			}
		} while (FindNextFileW(fh, &entry));
	}
	FindClose(fh);
#else
	struct dirent *entry;
	DIR *dir = sys_opendir(path);
	if (dir) {
		list = rz_list_new();
		if (list) {
			list->free = free;
			while ((entry = readdir(dir))) {
				rz_list_append(list, strdup(entry->d_name));
			}
		}
		closedir(dir);
	}
#endif
	return list;
}

RZ_API char *rz_sys_cmd_strf(const char *fmt, ...) {
	char *ret, cmd[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	ret = rz_sys_cmd_str(cmd, NULL, NULL);
	va_end(ap);
	return ret;
}

/**
 * \brief Print the backtrace at the point this function is called from.
 */
RZ_API void rz_sys_backtrace(void) {
#if HAVE_BACKTRACE
	void *array[10];
	size_t size = backtrace(array, 10);
	eprintf("Backtrace %zd stack frames.\n", size);
	backtrace_symbols_fd(array, size, 2);
#elif __APPLE__
	void **fp = (void **)__builtin_frame_address(0);
	void *saved_pc = __builtin_return_address(0);
	void *saved_fp = __builtin_frame_address(1);
	int depth = 0;

	eprintf("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	fp = saved_fp;
	while (fp) {
		saved_fp = *fp;
		fp = saved_fp;
		if (!*fp) {
			break;
		}
		saved_pc = *(fp + 2);
		eprintf("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	}
#else
#ifdef _MSC_VER
#pragma message("TODO: rz_sys_bt : unimplemented")
#else
#warning TODO: rz_sys_bt : unimplemented
#endif
#endif
}

/**
 * \brief Sleep for \p secs seconds
 */
RZ_API int rz_sys_sleep(int secs) {
#if HAVE_CLOCK_NANOSLEEP && defined(CLOCK_MONOTONIC)
	struct timespec rqtp;
	rqtp.tv_sec = secs;
	rqtp.tv_nsec = 0;
	return clock_nanosleep(CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif __UNIX__
	return sleep(secs);
#else
	Sleep(secs * 1000); // W32
	return 0;
#endif
}

/**
 * \brief Sleep for \p usecs microseconds
 */
RZ_API int rz_sys_usleep(int usecs) {
#if HAVE_CLOCK_NANOSLEEP && defined(CLOCK_MONOTONIC)
	struct timespec rqtp;
	rqtp.tv_sec = usecs / 1000000;
	rqtp.tv_nsec = (usecs - (rqtp.tv_sec * 1000000)) * 1000;
	return clock_nanosleep(CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif __UNIX__
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc return void for usleep
	usleep(usecs);
	return 0;
#else
	return usleep(usecs);
#endif
#else
	// w32 api uses milliseconds
	usecs /= 1000;
	Sleep(usecs); // W32
	return 0;
#endif
}

/**
 * \brief Clean all environment variables in the calling process.
 *
 * Please note that environment variables should not be used to store sensitive
 * info as they might be kept elsewhere and there is no access control over that
 * data.
 */
RZ_API int rz_sys_clearenv(void) {
#if __UNIX__
#if __APPLE__ && !HAVE_ENVIRON
	/* do nothing */
	if (!env) {
		rz_sys_env_init();
		return 0;
	}
	char **e = env;
	while (*e) {
		*e++ = NULL;
	}
#else
	if (!environ) {
		return 0;
	}
	while (*environ) {
		*environ++ = NULL;
	}
#endif
	return 0;
#else
#ifdef __WINDOWS__
	LPWCH env = GetEnvironmentStringsW();
	LPWCH var = env;
	while (*var) {
		wchar_t *eq = wcschr(var, L'=');
		if (!eq) {
			FreeEnvironmentStringsW(env);
			return -1;
		}
		const size_t len = eq - var;
		if (!len) {
			var += wcslen(var) + 1;
			continue;
		}
		wchar_t *v = RZ_NEWS0(wchar_t, len + 1);
		if (!v) {
			return -1;
		}
		wcsncpy(v, var, len);
		if (_wputenv_s(v, L"")) {
			free(v);
			break;
		}
		free(v);
		var += wcslen(var) + 1;
	}
	FreeEnvironmentStringsW(env);
#else
#warning rz_sys_clearenv : unimplemented for this platform
#endif
	return 0;
#endif
}

/**
 * \brief Set an environment variable in the calling process
 */
RZ_API int rz_sys_setenv(const char *key, const char *value) {
	if (!key) {
		return 0;
	}
#if __UNIX__
	if (!value) {
		unsetenv(key);
		return 0;
	}
	return setenv(key, value, 1);
#elif __WINDOWS__
	LPWSTR key_ = rz_utf8_to_utf16(key);
	LPWSTR value_ = value ? rz_utf8_to_utf16(value) : L"";
	bool ret = !_wputenv_s(key_, value_);
	free(key_);
	if (value) {
		free(value_);
	}
	return ret ? 0 : -1;
#else
#warning rz_sys_setenv : unimplemented for this platform
	return 0;
#endif
}

#if __UNIX__
static char *crash_handler_cmd = NULL;

static void signal_handler(int signum) {
	char cmd[1024];
	if (!crash_handler_cmd) {
		return;
	}
	snprintf(cmd, sizeof(cmd) - 1, crash_handler_cmd, getpid());
	rz_sys_backtrace();
	exit(rz_sys_system(cmd));
}

static int checkcmd(const char *c) {
	char oc = 0;
	for (; *c; c++) {
		if (oc == '%') {
			if (*c != 'd' && *c != '%') {
				return 0;
			}
		}
		oc = *c;
	}
	return 1;
}
#endif

RZ_API int rz_sys_crash_handler(const char *cmd) {
#ifndef __WINDOWS__
	int sig[] = { SIGINT, SIGSEGV, SIGBUS, SIGQUIT, SIGHUP, 0 };

	if (!checkcmd(cmd)) {
		return false;
	}
#if HAVE_BACKTRACE
	void *array[1];
	/* call this outside of the signal handler to init it safely */
	backtrace(array, 1);
#endif

	free(crash_handler_cmd);
	crash_handler_cmd = strdup(cmd);

	rz_sys_sigaction(sig, signal_handler);
#else
#pragma message("rz_sys_crash_handler : unimplemented for this platform")
#endif
	return true;
}

/**
 * \brief Get the value of an environment variable named \p key or NULL if none exists.
 */
RZ_API char *rz_sys_getenv(const char *key) {
#if __WINDOWS__
	if (!key) {
		return NULL;
	}
	wchar_t *val;
	wchar_t *wkey = rz_utf8_to_utf16(key);
	if (_wdupenv_s(&val, NULL, wkey) || !val) {
		free(wkey);
		return NULL;
	}
	free(wkey);
	char *ret = rz_utf16_to_utf8(val);
	free(val);
	return ret;
#else
	char *b;
	if (!key) {
		return NULL;
	}
	b = getenv(key);
	return b ? strdup(b) : NULL;
#endif
}

/**
 * \brief Return true if the environment variable has the value 1, false otherwise
 */
RZ_API bool rz_sys_getenv_asbool(const char *key) {
	char *env = rz_sys_getenv(key);
	const bool res = (env && *env == '1');
	free(env);
	return res;
}

/**
 * \brief Get current working directory
 */
RZ_API char *rz_sys_getdir(void) {
#if __WINDOWS__
	return _getcwd(NULL, 0);
#else
	return getcwd(NULL, 0);
#endif
}

/**
 * \brief Change current directory to \p s, taking care of home expansion ~.
 */
RZ_API bool rz_sys_chdir(RZ_NONNULL const char *s) {
	rz_return_val_if_fail(s, false);
	char *homepath = rz_path_home_expand(s);
	if (homepath) {
		int ret = chdir(homepath);
		free(homepath);
		return ret == 0;
	}
	return chdir(s) == 0;
}

/**
 * \brief Enable or disable ASLR for the calling process
 */
RZ_API bool rz_sys_aslr(int val) {
	bool ret = true;
#if __linux__
	const char *rva = "/proc/sys/kernel/randomize_va_space";
	char buf[3] = { 0 };
	snprintf(buf, sizeof(buf), "%d\n", val != 0 ? 2 : 0);
	int fd = rz_sys_open(rva, O_WRONLY, 0644);
	if (fd != -1) {
		if (write(fd, (ut8 *)buf, sizeof(buf)) != sizeof(buf)) {
			eprintf("Failed to set RVA\n");
			ret = false;
		}
		close(fd);
	}
#elif __FreeBSD__ && __FreeBSD_version >= 1300000
	size_t vlen = sizeof(val);
	if (sysctlbyname("kern.elf32.aslr.enable", NULL, 0, &val, vlen) == -1) {
		eprintf("Failed to set RVA 32 bits\n");
		return false;
	}

#if __LP64__
	if (sysctlbyname("kern.elf64.aslr.enable", NULL, 0, &val, vlen) == -1) {
		eprintf("Failed to set RVA 64 bits\n");
		ret = false;
	}
#endif
#elif __NetBSD__
	size_t vlen = sizeof(val);
	if (sysctlbyname("security.pax.aslr.enabled", NULL, 0, &val, vlen) == -1) {
		eprintf("Failed to set RVA\n");
		ret = false;
	}
#elif __DragonFly__
	size_t vlen = sizeof(val);
	if (sysctlbyname("vm.randomize_mmap", NULL, 0, &val, vlen) == -1) {
		eprintf("Failed to set RVA\n");
		ret = false;
	}
#elif __DragonFly__
#endif
	return ret;
}

RZ_API int rz_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	int argc;
	char **argv = rz_str_argv(cmd, &argc);
	if (!argv) {
		return false;
	}
	RzSubprocessOpt opts = {
		.file = argv[0],
		.args = (const char **)&argv[1],
		.args_size = argc - 1,
		.envvars = NULL,
		.envvals = NULL,
		.env_size = 0,
		.stdin_pipe = input ? RZ_SUBPROCESS_PIPE_CREATE : RZ_SUBPROCESS_PIPE_NONE,
		.stdout_pipe = output ? RZ_SUBPROCESS_PIPE_CREATE : RZ_SUBPROCESS_PIPE_NONE,
		.stderr_pipe = sterr ? RZ_SUBPROCESS_PIPE_CREATE : RZ_SUBPROCESS_PIPE_NONE,
	};

	if (!rz_subprocess_init()) {
		RZ_LOG_ERROR("Failed to initialize subprocess\n");
		return false;
	}
	RzSubprocess *subprocess = rz_subprocess_start_opt(&opts);
	if (!subprocess) {
		rz_subprocess_fini();
		return false;
	}
	if (input) {
		rz_subprocess_stdin_write(subprocess, (ut8 *)input, strlen(input) + 1);
	}
	rz_subprocess_wait(subprocess, UT64_MAX);
	if (output) {
		*output = (char *)rz_subprocess_out(subprocess, len);
	}
	if (sterr) {
		*sterr = (char *)rz_subprocess_err(subprocess, NULL);
	}
	rz_subprocess_free(subprocess);
	rz_subprocess_fini();
	rz_str_argv_free(argv);
	return true;
}

RZ_API int rz_sys_cmdf(const char *fmt, ...) {
	int ret;
	char cmd[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	ret = rz_sys_system(cmd);
	va_end(ap);
	return ret;
}

RZ_API int rz_sys_cmdbg(const char *str) {
#if __UNIX__
	int ret, pid = rz_sys_fork();
	if (pid == -1) {
		return -1;
	}
	if (pid) {
		return pid;
	}
	char *bin_sh = rz_file_binsh();
	ret = rz_sys_execl(bin_sh, "sh", "-c", str, (const char *)NULL);
	free(bin_sh);
	eprintf("{exit: %d, pid: %d, cmd: \"%s\"}", ret, pid, str);
	exit(0);
	return -1;
#else
#ifdef _MSC_VER
#pragma message("rz_sys_cmdbg is not implemented for this platform")
#else
#warning rz_sys_cmdbg is not implemented for this platform
#endif
	return -1;
#endif
}

RZ_API char *rz_sys_cmd_str(const char *cmd, const char *input, int *len) {
	char *output = NULL;
	if (rz_sys_cmd_str_full(cmd, input, &output, len, NULL)) {
		return output;
	}
	free(output);
	return NULL;
}

RZ_API bool rz_sys_mkdir(const char *dir) {
	bool ret;

#if __WINDOWS__
	wchar_t *dir_utf16 = rz_utf8_to_utf16(dir);
	ret = _wmkdir(dir_utf16) != -1;
	free(dir_utf16);
#else
	ret = mkdir(dir, 0755) != -1;
#endif
	return ret;
}

RZ_API bool rz_sys_mkdirp(const char *dir) {
	bool ret = true;
	char slash = RZ_SYS_DIR[0];
	char *path = strdup(dir), *ptr = path;
	if (!path) {
		eprintf("rz_sys_mkdirp: Unable to allocate memory\n");
		return false;
	}
	if (*ptr == slash) {
		ptr++;
	}
#if __WINDOWS__
	{
		char *p = strstr(ptr, ":\\");
		if (p) {
			ptr = p + 3;
		}
	}
#endif
	for (;;) {
		// find next slash
		for (; *ptr; ptr++) {
			if (*ptr == '/' || *ptr == '\\') {
				slash = *ptr;
				break;
			}
		}
		if (!*ptr) {
			break;
		}
		*ptr = 0;
		if (!rz_sys_mkdir(path) && rz_sys_mkdir_failed()) {
			eprintf("rz_sys_mkdirp: fail '%s' of '%s'\n", path, dir);
			free(path);
			return false;
		}
		*ptr = slash;
		ptr++;
	}
	if (!rz_sys_mkdir(path) && rz_sys_mkdir_failed()) {
		ret = false;
	}
	free(path);
	return ret;
}

RZ_API void rz_sys_perror_str(const char *fun) {
#if __UNIX__
#pragma push_macro("perror")
#undef perror
	perror(fun);
#pragma pop_macro("perror")
#elif __WINDOWS__
	LPTSTR lpMsgBuf;
	DWORD dw = GetLastError();

	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			    FORMAT_MESSAGE_FROM_SYSTEM |
			    FORMAT_MESSAGE_IGNORE_INSERTS,
		    NULL,
		    dw,
		    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		    (LPTSTR)&lpMsgBuf,
		    0, NULL)) {
		char *err = rz_sys_conv_win_to_utf8(lpMsgBuf);
		if (err) {
			eprintf("%s: (%#lx) %s%s", fun, dw, err,
				rz_str_endswith(err, "\n") ? "" : "\n");
			free(err);
		}
		LocalFree(lpMsgBuf);
	} else {
		eprintf("%s\n", fun);
	}
#endif
}

RZ_API bool rz_sys_arch_match(const char *archstr, const char *arch) {
	char *ptr;
	if (!archstr || !arch || !*archstr || !*arch) {
		return true;
	}
	if (!strcmp(archstr, "*") || !strcmp(archstr, "any")) {
		return true;
	}
	if (!strcmp(archstr, arch)) {
		return true;
	}
	if ((ptr = strstr(archstr, arch))) {
		char p = ptr[strlen(arch)];
		if (!p || p == ',') {
			return true;
		}
	}
	return false;
}

RZ_API int rz_sys_arch_id(const char *arch) {
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (!strcmp(arch, arch_bit_array[i].name)) {
			return arch_bit_array[i].bit;
		}
	}
	return 0;
}

RZ_API const char *rz_sys_arch_str(int arch) {
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (arch & arch_bit_array[i].bit) {
			return arch_bit_array[i].name;
		}
	}
	return "none";
}

#define USE_FORK 0
RZ_API int rz_sys_run(const ut8 *buf, int len) {
	const int sz = 4096;
	int pdelta, ret, (*cb)();
#if USE_FORK
	int st, pid;
#endif
	// TODO: define RZ_SYS_ALIGN_FORWARD in rz_util.h
	ut8 *ptr, *p = malloc((sz + len) << 1);
	ptr = p;
	pdelta = ((size_t)(p)) & (4096 - 1);
	if (pdelta) {
		ptr += (4096 - pdelta);
	}
	if (!ptr || !buf) {
		eprintf("rz_sys_run: Cannot run empty buffer\n");
		free(p);
		return false;
	}
	memcpy(ptr, buf, len);
	rz_mem_protect(ptr, sz, "rx");
	// rz_mem_protect (ptr, sz, "rwx"); // try, ignore if fail
	cb = (int (*)())ptr;
#if USE_FORK
#if __UNIX__
	pid = rz_sys_fork();
#else
	pid = -1;
#endif
	if (pid < 0) {
		return cb();
	}
	if (!pid) {
		ret = cb();
		exit(ret);
		return ret;
	}
	st = 0;
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st)) {
		int num = WTERMSIG(st);
		eprintf("Got signal %d\n", num);
		ret = num;
	} else {
		ret = WEXITSTATUS(st);
	}
#else
	ret = (*cb)();
#endif
	free(p);
	return ret;
}

RZ_API int rz_sys_run_rop(const ut8 *buf, int len) {
#if USE_FORK
	int st;
#endif
	// TODO: define RZ_SYS_ALIGN_FORWARD in rz_util.h
	ut8 *bufptr = malloc(len);
	if (!bufptr) {
		eprintf("rz_sys_run_rop: Cannot allocate buffer\n");
		return false;
	}

	if (!buf) {
		eprintf("rz_sys_run_rop: Cannot execute empty rop chain\n");
		free(bufptr);
		return false;
	}
	memcpy(bufptr, buf, len);
#if USE_FORK
#if __UNIX__
	pid_t pid = rz_sys_fork();
#else
	pid = -1;
#endif
	if (pid < 0) {
		RZ_SYS_ASM_START_ROP();
	} else {
		RZ_SYS_ASM_START_ROP();
		exit(0);
		return 0;
	}
	st = 0;
	if (waitpid(pid, &st, 0) == -1) {
		eprintf("rz_sys_run_rop: waitpid failed\n");
		free(bufptr);
		return -1;
	}
	if (WIFSIGNALED(st)) {
		int num = WTERMSIG(st);
		eprintf("Got signal %d\n", num);
		ret = num;
	} else {
		ret = WEXITSTATUS(st);
	}
#else
	RZ_SYS_ASM_START_ROP();
#endif
	free(bufptr);
	return 0;
}

RZ_API bool rz_is_heap(void *p) {
	void *q = malloc(8);
	ut64 mask = UT64_MAX;
	mask >>= 16;
	mask <<= 16;
	free(q);
	return (((ut64)(size_t)p) == mask);
}

RZ_API char *rz_sys_pid_to_path(int pid) {
#if __WINDOWS__
	// TODO: add maximum path length support
	HANDLE processHandle;
	const DWORD maxlength = MAX_PATH;
	WCHAR filename[MAX_PATH];
	char *result = NULL;

	processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!processHandle) {
		eprintf("rz_sys_pid_to_path: Cannot open process.\n");
		return NULL;
	}
	DWORD length = GetModuleFileNameExW(processHandle, NULL, filename, maxlength);
	if (length == 0) {
		// Upon failure fallback to GetProcessImageFileName
		length = GetProcessImageFileNameW(processHandle, filename, maxlength);
		CloseHandle(processHandle);
		if (length == 0) {
			eprintf("rz_sys_pid_to_path: Error calling GetProcessImageFileName\n");
			return NULL;
		}
		// Convert NT path to win32 path
		char *name = rz_utf16_to_utf8(filename);
		if (!name) {
			eprintf("rz_sys_pid_to_path: Error converting to utf8\n");
			return NULL;
		}
		char *tmp = strchr(name + 1, '\\');
		if (!tmp) {
			free(name);
			eprintf("rz_sys_pid_to_path: Malformed NT path\n");
			return NULL;
		}
		tmp = strchr(tmp + 1, '\\');
		if (!tmp) {
			free(name);
			eprintf("rz_sys_pid_to_path: Malformed NT path\n");
			return NULL;
		}
		length = tmp - name;
		tmp = malloc(length + 1);
		if (!tmp) {
			free(name);
			eprintf("rz_sys_pid_to_path: Error allocating memory\n");
			return NULL;
		}
		strncpy(tmp, name, length);
		tmp[length] = '\0';
		WCHAR device[MAX_PATH];
		for (WCHAR drv[] = L"A:"; drv[0] <= L'Z'; drv[0]++) {
			if (QueryDosDeviceW(drv, device, maxlength) > 0) {
				char *dvc = rz_utf16_to_utf8(device);
				if (!dvc) {
					free(name);
					free(tmp);
					eprintf("rz_sys_pid_to_path: Error converting to utf8\n");
					return NULL;
				}
				if (!strcmp(tmp, dvc)) {
					free(tmp);
					free(dvc);
					char *d = rz_utf16_to_utf8(drv);
					if (!d) {
						free(name);
						eprintf("rz_sys_pid_to_path: Error converting to utf8\n");
						return NULL;
					}
					tmp = rz_str_newf("%s%s", d, &name[length]);
					free(d);
					if (!tmp) {
						free(name);
						eprintf("rz_sys_pid_to_path: Error calling rz_str_newf\n");
						return NULL;
					}
					result = strdup(tmp);
					break;
				}
				free(dvc);
			}
		}
		free(name);
		free(tmp);
	} else {
		CloseHandle(processHandle);
		result = rz_utf16_to_utf8(filename);
	}
	return result;
#elif __APPLE__
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	pathbuf[0] = 0;
	int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
	if (ret <= 0) {
		return NULL;
	}
	return strdup(pathbuf);
#else
	int ret;
#if __FreeBSD__ || __DragonFly__
	char pathbuf[PATH_MAX];
	size_t pathbufl = sizeof(pathbuf);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid };
	ret = sysctl(mib, 4, pathbuf, &pathbufl, NULL, 0);
	if (ret != 0) {
		return NULL;
	}
#elif __OpenBSD__
	// Taken from https://stackoverflow.com/questions/31494901/how-to-get-the-executable-path-on-openbsd
	char pathbuf[PATH_MAX];
	int mib[4] = { CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_ARGV };
	size_t len;

	pathbuf[0] = '\0';
	ret = sysctl(mib, 4, NULL, &len, NULL, 0);
	if (ret < 0) {
		return NULL;
	}
	char **argv = malloc(len);
	ret = sysctl(mib, 4, argv, &len, NULL, 0);
	if (ret < 0) {
		free(argv);
		return NULL;
	}
	const char *comm = argv[0];
	int ok = 0;
	if (*comm == '/' || *comm == '.') {
		if (!realpath(comm, pathbuf)) {
			free(argv);
			return NULL;
		}
	} else {
		char *sp;
		char *xpath = strdup(getenv("PATH"));
		char *path = strtok_r(xpath, ":", &sp);
		struct stat st;

		if (!xpath) {
			free(argv);
			return NULL;
		}

		while (path) {
			snprintf(pathbuf, PATH_MAX, "%s/%s", path, comm);
			if (!stat(pathbuf, &st) && (st.st_mode & S_IXUSR)) {
				ok = 1;
				break;
			}
			path = strtok_r(NULL, ":", &sp);
		}
		free(xpath);
	}

	if (ok) {
		char *p = strrchr(pathbuf, '/');
		if (p) {
			*p = '\0';
		}
	}
	free(argv);
#elif __HAIKU__
	char pathbuf[MAXPATHLEN];
	int32_t group = 0;
	image_info ii;

	while (get_next_image_info((team_id)pid, &group, &ii) == B_OK) {
		if (ii.type == B_APP_IMAGE) {
			break;
		}
	}

	if (ii.type == B_APP_IMAGE) {
		rz_str_ncpy(pathbuf, ii.name, MAXPATHLEN);
	} else {
		pathbuf[0] = '\0';
	}
#else
	char buf[128], pathbuf[1024];
	snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
	ret = readlink(buf, pathbuf, sizeof(pathbuf) - 1);
	if (ret < 1) {
		return NULL;
	}
	pathbuf[ret] = 0;
#endif
	return strdup(pathbuf);
#endif
}

RZ_API void rz_sys_env_init(void) {
	char **envp = rz_sys_get_environ();
	if (envp) {
		env = envp;
	}
}

RZ_API char **rz_sys_get_environ(void) {
#if __APPLE__ && !HAVE_ENVIRON
	env = *_NSGetEnviron();
#elif HAVE_ENVIRON
	env = environ;
#endif
	// return environ if available??
	if (!env) {
		env = rz_sys_dlsym(NULL, "environ");
	}
	return env;
}

RZ_API void rz_sys_set_environ(char **e) {
	env = e;
#if __APPLE__ && !HAVE_ENVIRON
	*_NSGetEnviron() = e;
#elif __WINDOWS__
	char **oe = e;
	rz_sys_clearenv();
	while (*e) {
		char *var = *e;
		char *val = strchr(var, '=');
		wchar_t *val_utf16 = NULL;
		if (*val) {
			*val++ = '\0';
		}
		rz_sys_setenv(var, val);
		free(*e);
		e++;
	}
	free(oe);
	env = environ;
#elif HAVE_ENVIRON
	environ = e;
#endif
}

RZ_API char *rz_sys_whoami(char *buf) {
	char _buf[32];
	int pid = getpid();
	int hasbuf = (buf) ? 1 : 0;
	if (!hasbuf) {
		buf = _buf;
	}
	sprintf(buf, "pid%d", pid);
	return hasbuf ? buf : strdup(buf);
}

RZ_API int rz_sys_getpid(void) {
#if __UNIX__
	return getpid();
#elif __WINDOWS__
	return GetCurrentProcessId();
#else
#warning rz_sys_getpid not implemented for this platform
	return -1;
#endif
}

RZ_API RSysInfo *rz_sys_info(void) {
#if __UNIX__
	struct utsname un = { { 0 } };
	if (uname(&un) != -1) {
		RSysInfo *si = RZ_NEW0(RSysInfo);
		if (si) {
			si->sysname = strdup(un.sysname);
			si->nodename = strdup(un.nodename);
			si->release = strdup(un.release);
			si->version = strdup(un.version);
			si->machine = strdup(un.machine);
			return si;
		}
	}
#elif __WINDOWS__
	HKEY key;
	DWORD type;
	DWORD size;
	DWORD major;
	DWORD minor;
	char tmp[256] = { 0 };
	RSysInfo *si = RZ_NEW0(RSysInfo);
	if (!si) {
		return NULL;
	}

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
		    KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
		rz_sys_perror("rz_sys_info/RegOpenKeyExA");
		rz_sys_info_free(si);
		return NULL;
	}

	size = sizeof(tmp);
	if (RegQueryValueExA(key, "ProductName", NULL, &type,
		    (LPBYTE)&tmp, &size) != ERROR_SUCCESS ||
		type != REG_SZ) {
		goto beach;
	}
	si->sysname = strdup(tmp);

	size = sizeof(major);
	if (RegQueryValueExA(key, "CurrentMajorVersionNumber", NULL, &type,
		    (LPBYTE)&major, &size) != ERROR_SUCCESS ||
		type != REG_DWORD) {
		goto beach;
	}
	size = sizeof(minor);
	if (RegQueryValueExA(key, "CurrentMinorVersionNumber", NULL, &type,
		    (LPBYTE)&minor, &size) != ERROR_SUCCESS ||
		type != REG_DWORD) {
		goto beach;
	}

	size = sizeof(tmp);
	if (RegQueryValueExA(key, "CurrentBuild", NULL, &type,
		    (LPBYTE)&tmp, &size) != ERROR_SUCCESS ||
		type != REG_SZ) {
		goto beach;
	}
	si->version = rz_str_newf("%lu.%lu.%s", major, minor, tmp);

	size = sizeof(tmp);
	if (RegQueryValueExA(key, "ReleaseId", NULL, &type,
		    (LPBYTE)tmp, &size) != ERROR_SUCCESS ||
		type != REG_SZ) {
		goto beach;
	}
	si->release = strdup(tmp);
beach:
	RegCloseKey(key);
	return si;
#endif
	return NULL;
}

RZ_API void rz_sys_info_free(RSysInfo *si) {
	free(si->sysname);
	free(si->nodename);
	free(si->release);
	free(si->version);
	free(si->machine);
	free(si);
}

#if __UNIX__ && HAVE_PIPE2
#include <fcntl.h>
#include <unistd.h>

RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec) {
	return pipe2(pipefd, close_on_exec ? O_CLOEXEC : 0);
}

RZ_API int rz_sys_pipe_close(int fd) {
	return close(fd);
}
#elif __UNIX__ && HAVE_PIPE && defined(O_CLOEXEC)
// Use this lock to wraps pipe, close, exec*, system to ensure all pipe file
// descriptors are either created AND set as CLOEXEC or not created at all.
static RzThreadLock *sys_pipe_mutex;
static bool is_child = false;

#ifdef RZ_DEFINE_CONSTRUCTOR_NEEDS_PRAGMA
#pragma RZ_DEFINE_CONSTRUCTOR_PRAGMA_ARGS(sys_pipe_constructor)
#endif
RZ_DEFINE_CONSTRUCTOR(sys_pipe_constructor)
static void sys_pipe_constructor(void) {
	sys_pipe_mutex = rz_th_lock_new(true);
}

#ifdef RZ_DEFINE_DESTRUCTOR_NEEDS_PRAGMA
#pragma RZ_DEFINE_DESTRUCTOR_PRAGMA_ARGS(sys_pipe_destructor)
#endif
RZ_DEFINE_DESTRUCTOR(sys_pipe_destructor)
static void sys_pipe_destructor(void) {
	rz_th_lock_free(sys_pipe_mutex);
}

static bool set_close_on_exec(int fd) {
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		return false;
	}
	flags |= FD_CLOEXEC;
	return fcntl(fd, F_SETFD, flags) != -1;
}

static void parent_lock_enter(void) {
	if (!is_child) {
		rz_th_lock_enter(sys_pipe_mutex);
	}
}

static void parent_lock_leave(void) {
	if (!is_child) {
		rz_th_lock_leave(sys_pipe_mutex);
	}
}

/**
 * \brief Create a pipe and use O_CLOEXEC flag when \p close_on_exec is true
 *
 * If \p rz_sys functions are used to exec/system the new process, no race
 * condition happen even on systems that don't support atomic creation of pipes
 * with O_CLOEXEC.
 */
RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec) {
	int res = -1;
	parent_lock_enter();
	if ((res = pipe(pipefd)) == -1) {
		perror("pipe");
		goto err;
	}
	if (close_on_exec && (!set_close_on_exec(pipefd[0]) || !set_close_on_exec(pipefd[1]))) {
		perror("close-on-exec");
		close(pipefd[0]);
		close(pipefd[1]);
		goto err;
	}
err:
	parent_lock_leave();
	return res;
}

/**
 * \brief Close a file descriptor previously created pipe \p rz_sys_pipe
 */
RZ_API int rz_sys_pipe_close(int fd) {
	return close(fd);
}

#elif __UNIX__ && HAVE_PIPE
#include <ht_uu.h>
static HtUU *fd2close;
// Use this lock to wraps pipe, close, exec*, system to ensure all pipe file
// descriptors are either created AND added to fd2close or not created at all.
static RzThreadLock *sys_pipe_mutex;
static bool is_child = false;

#ifdef RZ_DEFINE_CONSTRUCTOR_NEEDS_PRAGMA
#pragma RZ_DEFINE_CONSTRUCTOR_PRAGMA_ARGS(sys_pipe_constructor)
#endif
RZ_DEFINE_CONSTRUCTOR(sys_pipe_constructor)
static void sys_pipe_constructor(void) {
	sys_pipe_mutex = rz_th_lock_new(false);
	fd2close = ht_uu_new0();
}

#ifdef RZ_DEFINE_DESTRUCTOR_NEEDS_PRAGMA
#pragma RZ_DEFINE_DESTRUCTOR_PRAGMA_ARGS(sys_pipe_destructor)
#endif
RZ_DEFINE_DESTRUCTOR(sys_pipe_destructor)
static void sys_pipe_destructor(void) {
	ht_uu_free(fd2close);
	rz_th_lock_free(sys_pipe_mutex);
}

static void parent_lock_enter(void) {
	if (!is_child) {
		rz_th_lock_enter(sys_pipe_mutex);
	}
}

static void parent_lock_leave(void) {
	if (!is_child) {
		rz_th_lock_leave(sys_pipe_mutex);
	}
}

static bool set_close_on_exec(int fd, bool close_on_exec) {
	bool res = ht_uu_insert(fd2close, fd, close_on_exec);
	rz_warn_if_fail(res);
	return res;
}

static bool close_on_exec_fd_cb(void *user, const ut64 key, const ut64 val) {
	bool close_on_exec = (bool)val;
	if (close_on_exec) {
		close((int)key);
	}
	return true;
}

static void close_fds(void) {
	ht_uu_foreach(fd2close, close_on_exec_fd_cb, NULL);
}

/**
 * \brief Create a pipe and simulates the O_CLOEXEC flag when \p close_on_exec is true
 *
 * If \p rz_sys functions are used to exec/system a new process, pipes created
 * with this function would be closed before executing the new executable,
 * making sure these file descriptors don't leak.
 */
RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec) {
	int res = -1;
	parent_lock_enter();
	if ((res = pipe(pipefd)) == -1) {
		perror("pipe");
		goto err;
	}
	if (!set_close_on_exec(pipefd[0], close_on_exec) || !set_close_on_exec(pipefd[1], close_on_exec)) {
		perror("close-on-exec");
		close(pipefd[0]);
		close(pipefd[1]);
		goto err;
	}
err:
	parent_lock_leave();
	return res;
}

/**
 * \brief Close a file descriptor previously created pipe \p rz_sys_pipe
 *
 * This is necessary to ensure that the file descriptor is not "closed again"
 * when an \p rz_sys exec/system is executed later.
 */
RZ_API int rz_sys_pipe_close(int fd) {
	parent_lock_enter();
	bool deleted = ht_uu_delete(fd2close, fd);
	rz_warn_if_fail(deleted);
	int res = close(fd);
	parent_lock_leave();
	return res;
}
#elif HAVE_PIPE
RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec) {
	return pipe(pipefd);
}

RZ_API int rz_sys_pipe_close(int fd) {
	return close(fd);
}
#elif __WINDOWS__
RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec) {
	return _pipe(pipefd, 0x1000, O_TEXT);
}

RZ_API int rz_sys_pipe_close(int fd) {
	return _close(fd);
}
#else
RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec) {
	return -1;
}

RZ_API int rz_sys_pipe_close(int fd) {
	return -1;
}
#endif

#if __UNIX__ && HAVE_EXECV && HAVE_PIPE && defined(O_CLOEXEC) && !HAVE_PIPE2
RZ_API int rz_sys_execv(const char *pathname, char *const argv[]) {
	parent_lock_enter();
	int res = execv(pathname, argv);
	parent_lock_leave();
	return res;
}
#elif __UNIX__ && HAVE_EXECV && HAVE_PIPE && !HAVE_PIPE2
RZ_API int rz_sys_execv(const char *pathname, char *const argv[]) {
	parent_lock_enter();
	close_fds();
	int res = execv(pathname, argv);
	parent_lock_leave();
	return res;
}
#elif !HAVE_EXECV
RZ_API int rz_sys_execv(const char *pathname, char *const argv[]) {
	return -1;
}
#endif

#if __UNIX__ && HAVE_EXECVE && HAVE_PIPE && defined(O_CLOEXEC) && !HAVE_PIPE2
RZ_API int rz_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	parent_lock_enter();
	int res = execve(pathname, argv, envp);
	parent_lock_leave();
	return res;
}
#elif __UNIX__ && HAVE_EXECVE && HAVE_PIPE && !HAVE_PIPE2
RZ_API int rz_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	parent_lock_enter();
	close_fds();
	int res = execve(pathname, argv, envp);
	parent_lock_leave();
	return res;
}
#elif !HAVE_EXECVE
RZ_API int rz_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	return -1;
}
#endif

#if __UNIX__ && HAVE_EXECVP && HAVE_PIPE && defined(O_CLOEXEC) && !HAVE_PIPE2
RZ_API int rz_sys_execvp(const char *file, char *const argv[]) {
	parent_lock_enter();
	int res = execvp(file, argv);
	parent_lock_leave();
	return res;
}
#elif __UNIX__ && HAVE_EXECVP && HAVE_PIPE && !HAVE_PIPE2
RZ_API int rz_sys_execvp(const char *file, char *const argv[]) {
	parent_lock_enter();
	close_fds();
	int res = execvp(file, argv);
	parent_lock_leave();
	return res;
}
#elif !HAVE_EXECVP
RZ_API int rz_sys_execvp(const char *file, char *const argv[]) {
	return -1;
}
#endif

#if __UNIX__ && HAVE_EXECL && HAVE_PIPE && defined(O_CLOEXEC) && !HAVE_PIPE2
RZ_API int rz_sys_execl(const char *pathname, const char *arg, ...) {
	va_list count_args, args;
	va_start(args, arg);
	va_copy(count_args, args);
	size_t i, argc = 0;
	while (va_arg(count_args, char *) != NULL) {
		argc++;
	}
	va_end(count_args);
	char **argv = RZ_NEWS0(char *, argc + 2);
	argv[0] = strdup(pathname);
	for (i = 1; i <= argc; i++) {
		argv[i] = va_arg(args, char *);
	}
	va_end(args);
	parent_lock_enter();
	int res = execv(pathname, argv);
	parent_lock_leave();
	return res;
}
#elif __UNIX__ && HAVE_EXECL && HAVE_PIPE && !HAVE_PIPE2
RZ_API int rz_sys_execl(const char *pathname, const char *arg, ...) {
	va_list count_args, args;
	va_start(args, arg);
	va_copy(count_args, args);
	size_t i, argc = 0;
	while (va_arg(count_args, char *) != NULL) {
		argc++;
	}
	va_end(count_args);
	char **argv = RZ_NEWS0(char *, argc + 2);
	argv[0] = strdup(pathname);
	for (i = 1; i <= argc; i++) {
		argv[i] = va_arg(args, char *);
	}
	va_end(args);

	parent_lock_enter();
	close_fds();
	int res = execv(pathname, argv);
	parent_lock_leave();
	return res;
}
#elif !HAVE_EXECL
RZ_API int rz_sys_execl(const char *pathname, const char *arg, ...) {
	return -1;
}
#endif

#if __UNIX__ && HAVE_SYSTEM && HAVE_PIPE && defined(O_CLOEXEC) && !HAVE_PIPE2
RZ_API int rz_sys_system(const char *command) {
	parent_lock_enter();
	int res = system(command);
	parent_lock_leave();
	return res;
}
#elif __UNIX__ && HAVE_SYSTEM && HAVE_PIPE && !HAVE_PIPE2
RZ_API int rz_sys_system(const char *command) {
	parent_lock_enter();
	close_fds();
	int res = system(command);
	parent_lock_leave();
	return res;
}
#elif !HAVE_SYSTEM && APPLE_SDK_IPHONEOS
#include <spawn.h>
RZ_API int rz_sys_system(const char *command) {
	int argc;
	char *cmd = strdup(command);
	char **argv = rz_str_argv(cmd, &argc);
	if (argv) {
		char *argv0 = rz_file_path(argv[0]);
		pid_t pid = 0;
		int r = posix_spawn(&pid, argv0, NULL, NULL, argv, NULL);
		int status;
		int s = waitpid(pid, &status, 0);
		return WEXITSTATUS(s);
	}
}
#elif !HAVE_SYSTEM && HAVE_FORK
#include <spawn.h>
RZ_API int rz_sys_system(const char *command) {
	if (!strchr(command, '|')) {
		char **argv, *cmd = strdup(command);
		int rc, pid, argc;
		char *isbg = strchr(cmd, '&');
		// XXX this is hacky
		if (isbg) {
			*isbg = 0;
		}
		argv = rz_str_argv(cmd, &argc);
		if (argv) {
			char *argv0 = rz_file_path(argv[0]);
			if (!argv0) {
				eprintf("Cannot find '%s'\n", argv[0]);
				return -1;
			}
			pid = 0;
			posix_spawn(&pid, argv0, NULL, NULL, argv, NULL);
			if (isbg) {
				// XXX. wait for children
				rc = 0;
			} else {
				rc = waitpid(pid, NULL, 0);
			}
			rz_str_argv_free(argv);
			free(argv0);
			return rc;
		}
		eprintf("Error parsing command arguments\n");
		return -1;
	}
	int child = rz_sys_fork();
	if (child == -1) {
		return -1;
	}
	if (child) {
		return waitpid(child, NULL, 0);
	}
	char *bin_sh = rz_file_binsh();
	if (rz_sys_execl(bin_sh, "sh", "-c", command, (const char *)NULL) == -1) {
		perror("execl");
	}
	free(bin_sh);
	exit(1);
}
#elif !HAVE_SYSTEM
RZ_API int rz_sys_system(const char *command) {
	return -1;
}
#endif

#if HAVE_FORK
RZ_API int rz_sys_fork(void) {
#if __UNIX__ && HAVE_PIPE && !HAVE_PIPE2
	parent_lock_enter();
#endif
	pid_t child = fork();
	if (child == -1) {
		perror("fork");
	}
#if __UNIX__ && HAVE_PIPE && !HAVE_PIPE2
	if (child == 0) {
		is_child = true;
	} else if (child > 0) {
		parent_lock_leave();
	}
#endif
	return child;
}
#else
RZ_API int rz_sys_fork(void) {
	return -1;
}
#endif

/**
 * \brief Wrapper for forkpty(3)
 *
 * \param amaster The master end of the PTY is stored here
 * \param name The name of the slave end of the PTY is stored here
 * \param termp (const struct termios) The terminal attributes
 * \param winp (const struct winsize) The window size attributes
 *
 * \return int (pid_t) PID of the forked process
 */
RZ_API /* pid_t */ int rz_sys_forkpty(int *amaster, char *name, void /* const struct termios */ *termp, void /* const struct winsize */ *winp) {
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
	pid_t ret = forkpty(amaster, name, termp, winp);
	if (ret == -1) {
		perror("forkpty");
	}
	return ret;
#else
	RZ_LOG_ERROR("forkpty() not found\n");
	return -1;
#endif
}

/**
 * \brief Wrapper for openpty(3)
 *
 * \param amaster The master end of the PTY is stored here
 * \param aslave The slave end of the PTY is stored here
 * \param name The name of the slave end of the PTY is stored here
 * \param termp (const struct termios) The terminal attributes
 * \param winp (const struct winsize) The window size attributes
 *
 * \return int Return code
 */
RZ_API int rz_sys_openpty(int *amaster, int *aslave, char *name, void /* const struct termios */ *termp, void /* const struct winsize */ *winp) {
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
	int ret = openpty(amaster, aslave, name, termp, winp);
	if (ret == -1) {
		perror("openpty");
	}
	return ret;
#else
	RZ_LOG_ERROR("openpty() not found\n");
	return -1;
#endif
}

/**
 * \brief Wrapper for login_tty(3)
 *
 * \param fd File descriptor for the slave end of the PTY; To be made the controlling terminal
 * \return int Return code
 */
RZ_API int rz_sys_login_tty(int fd) {
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
	int ret = login_tty(fd);
	if (ret == -1) {
		perror("login_tty");
	}
	return ret;
#else
	RZ_LOG_ERROR("login_tty() not found\n");
	return -1;
#endif
}

RZ_API int rz_sys_truncate_fd(int fd, ut64 length) {
#ifdef _MSC_VER
	return _chsize_s(fd, length);
#else
	return ftruncate(fd, (off_t)length);
#endif
}

RZ_API int rz_sys_truncate(const char *file, int sz) {
#if __WINDOWS__
	int fd = rz_sys_open(file, O_RDWR, 0644);
	if (fd == -1) {
		return false;
	}
	int r = rz_sys_truncate_fd(fd, sz);
	if (r != 0) {
		eprintf("Could not resize '%s' file\n", file);
		close(fd);
		return false;
	}
	close(fd);
	return true;
#else
	return truncate(file, sz) == 0;
#endif
}

/**
 * \brief Convert rizin permissions (RZ_PERM_*) to posix permissions that can be passed to \b rz_sys_open .
 *
 * \b rz_sys_open accepts posix permissions for now, not the arch-independent
 * ones provided by RZ_PERM_*. This function is an helper to convert from rizin
 * permissions to posix ones.
 */
RZ_API int rz_sys_open_perms(int rizin_perms) {
	int res = 0;
	if ((rizin_perms & RZ_PERM_R) && (rizin_perms & RZ_PERM_W)) {
		res |= O_RDWR;
		// NOTE: O_CREAT is added here because Rizin for now assumes Write means
		// ability to create a file as well.
		res |= O_CREAT;
	} else if (rizin_perms & RZ_PERM_R) {
		res |= O_RDONLY;
	} else if (rizin_perms & RZ_PERM_W) {
		res |= O_WRONLY;
		// NOTE: O_CREAT is added here because Rizin for now assumes Write means
		// ability to create a file as well.
		res |= O_CREAT;
	}
	if (rizin_perms & RZ_PERM_CREAT) {
		res |= O_CREAT;
	}
	return res;
}

/* perm <-> mode */
RZ_API int rz_sys_open(const char *path, int perm, int mode) {
	rz_return_val_if_fail(path, -1);
	char *epath = rz_path_home_expand(path);
	int ret = -1;
#if __WINDOWS__
	if (!strcmp(path, "/dev/null")) {
		path = "NUL";
	}
	{
		DWORD flags = 0;
		DWORD sharing = FILE_SHARE_READ;
		if (perm & O_RANDOM) {
			flags = FILE_FLAG_RANDOM_ACCESS;
		} else if (perm & O_SEQUENTIAL) {
			flags = FILE_FLAG_SEQUENTIAL_SCAN;
		}
		if (perm & O_TEMPORARY) {
			flags |= FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY;
			sharing |= FILE_SHARE_DELETE;
		} else if (perm & _O_SHORT_LIVED) {
			flags |= FILE_ATTRIBUTE_TEMPORARY;
		} else {
			flags |= FILE_ATTRIBUTE_NORMAL;
		}
		DWORD creation = 0;
		bool read_only = false;
		if (perm & O_CREAT) {
			if (perm & O_EXCL) {
				creation = CREATE_NEW;
			} else {
				creation = OPEN_ALWAYS;
			}
			if (mode & S_IREAD && !(mode & S_IWRITE)) {
				flags = FILE_ATTRIBUTE_READONLY;
				read_only = true;
			}
		} else if (perm & O_TRUNC) {
			creation = TRUNCATE_EXISTING;
		}
		if (!creation || !strcasecmp("NUL", path)) {
			creation = OPEN_EXISTING;
		}
		DWORD permission = 0;
		if (perm & O_WRONLY) {
			permission = GENERIC_WRITE;
		} else if (perm & O_RDWR) {
			permission = GENERIC_WRITE | GENERIC_READ;
		} else {
			permission = GENERIC_READ;
		}
		if (perm & O_APPEND) {
			permission |= FILE_APPEND_DATA;
		}
		if (!read_only) {
			sharing |= FILE_SHARE_WRITE;
		}

		wchar_t *wepath = rz_utf8_to_utf16(epath);
		if (!wepath) {
			free(epath);
			return -1;
		}
		HANDLE h = CreateFileW(wepath, permission, sharing, NULL, creation, flags, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			ret = _open_osfhandle((intptr_t)h, perm);
		}
		free(wepath);
	}
#else // __WINDOWS__
	ret = open(epath, perm, mode);
#endif // __WINDOWS__
	free(epath);
	return ret;
}

RZ_API FILE *rz_sys_fopen(const char *path, const char *mode) {
	rz_return_val_if_fail(path && mode, NULL);
	FILE *ret = NULL;
	char *epath = rz_path_home_expand(path);
	if ((strchr(mode, 'w') || strchr(mode, 'a') || rz_file_is_regular(epath))) {
#if __WINDOWS__
		wchar_t *wepath = rz_utf8_to_utf16(epath);
		if (!wepath) {
			free(epath);
			return ret;
		}
		wchar_t *wmode = rz_utf8_to_utf16(mode);
		if (!wmode) {
			free(wepath);
			free(epath);
			return ret;
		}
		ret = _wfopen(wepath, wmode);
		free(wmode);
		free(wepath);
#else // __WINDOWS__
		ret = fopen(epath, mode);
#endif // __WINDOWS__
	}
	free(epath);
	return ret;
}

/**
 * \brief Send signal \p sig to process with pid \p pid.
 *
 * \param pid PID of the process to send the signal to
 * \param sig Signal to send to the process.
 * \return 0 on success, -1 on failure.
 */
RZ_API int rz_sys_kill(int pid, int sig) {
	rz_return_val_if_fail(pid != -1, -1);
#if __UNIX__
	return kill(pid, sig);
#else
	return -1;
#endif
}

/**
 * \brief Send SIGTSTP signal to every process in this process group
 *
 * \return true if at least one signal was sent, false otherwise
 */
RZ_API bool rz_sys_stop(void) {
#if __UNIX__
	return !rz_sys_kill(0, SIGTSTP);
#else
	return false;
#endif
}

/**
 * \brief Implementation across systems to open a dynamic library
 */
RZ_API void *rz_sys_dlopen(RZ_NULLABLE const char *libname) {
	void *ret = NULL;
#if WANT_DYLINK
#if __UNIX__
	if (libname) {
		ret = dlopen(libname, RTLD_GLOBAL | RTLD_LAZY);
	} else {
		ret = dlopen(NULL, RTLD_NOW);
	}
	if (!ret) {
		RZ_LOG_ERROR("rz_sys_dlopen: error: %s (%s)\n", libname, dlerror());
	}
#elif __WINDOWS__
	LPTSTR libname_;
	if (libname && *libname) {
		libname_ = rz_sys_conv_utf8_to_win(libname);
	} else {
		libname_ = calloc(MAX_PATH, sizeof(TCHAR));
		if (!libname_) {
			RZ_LOG_ERROR("lib/rz_sys_dlopen: Failed to allocate memory.\n");
			return NULL;
		}
		if (!GetModuleFileName(NULL, libname_, MAX_PATH)) {
			libname_[0] = '\0';
		}
	}
	ret = LoadLibrary(libname_);
	free(libname_);
	if (!ret) {
		RZ_LOG_ERROR("rz_sys_dlopen: error: %s\n", libname);
	}
#endif
#endif
	return ret;
}

/**
 * \brief Implementation across systems to get the address of a symbol in a
 * dynamic library
 */
RZ_API void *rz_sys_dlsym(void *handler, const char *name) {
#if WANT_DYLINK
#if __UNIX__
	return dlsym(handler, name);
#elif __WINDOWS__
	return GetProcAddress(handler, name);
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

/**
 * \brief Implementation across systems to close a previously opened dynamic
 * library.
 */
RZ_API int rz_sys_dlclose(void *handler) {
#if __UNIX__
	return dlclose(handler);
#else
	return handler ? 0 : -1;
#endif
}
