// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <stdlib.h>
#include <string.h>
#if defined(__NetBSD__)
# include <sys/param.h>
# include <sys/sysctl.h>
# if __NetBSD_Prereq__(7,0,0)
#  define NETBSD_WITH_BACKTRACE
# endif
#endif
#if defined(__FreeBSD__)
# include <sys/param.h>
# include <sys/sysctl.h>
# if __FreeBSD_version >= 1000000
#  define FREEBSD_WITH_BACKTRACE
# endif
#endif
#if defined(__DragonFly__)
# include <sys/param.h>
# include <sys/sysctl.h>
#endif
#if defined(__HAIKU__)
# include <kernel/image.h>
# include <sys/param.h>
#endif
#include <sys/types.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>

static char** env = NULL;

#if (__linux__ && __GNU_LIBRARY__) || defined(NETBSD_WITH_BACKTRACE) || \
  defined(FREEBSD_WITH_BACKTRACE) || __DragonFly__ || __sun || __HAIKU__
# include <execinfo.h>
#endif
#if __APPLE__
#include <errno.h>
#ifdef __MAC_10_8
#define HAVE_ENVIRON 1
#else
#define HAVE_ENVIRON 0
#endif

#if HAVE_ENVIRON
#include <execinfo.h>
#endif
// iOS don't have this we can't hardcode
// #include <crt_externs.h>
extern char ***_NSGetEnviron(void);
# ifndef PROC_PIDPATHINFO_MAXSIZE
#  define PROC_PIDPATHINFO_MAXSIZE 1024
int proc_pidpath(int pid, void * buffer, ut32 buffersize);
//#  include <libproc.h>
# endif
#endif
#if __UNIX__
# include <sys/utsname.h>
# include <sys/wait.h>
# include <sys/stat.h>
# include <errno.h>
# include <signal.h>
extern char **environ;

#ifdef __HAIKU__
# define Sleep sleep
#endif
#endif
#if __WINDOWS__
# include <io.h>
# include <winbase.h>
# include <signal.h>
#define TMP_BUFSIZE	4096
#ifdef _MSC_VER
#include <psapi.h>
#include <process.h>  // to allow getpid under windows msvc compilation
#include <direct.h>  // to allow getcwd under windows msvc compilation
#endif
#endif

RZ_LIB_VERSION(rz_util);

#ifdef __x86_64__
# ifdef _MSC_VER
#  define RZ_SYS_ASM_START_ROP() \
	 eprintf ("rz_sys_run_rop: Unsupported arch\n");
# else
#  define RZ_SYS_ASM_START_ROP() \
	 __asm__ __volatile__ ("leaq %0, %%rsp; ret" \
				: \
				: "m" (*bufptr));
# endif
#elif __i386__
# ifdef _MSC_VER
#  define RZ_SYS_ASM_START_ROP() \
	__asm \
	{ \
		__asm lea esp, bufptr\
		__asm ret\
	}
# else
#  define RZ_SYS_ASM_START_ROP() \
	__asm__ __volatile__ ("leal %0, %%esp; ret" \
				: \
				: "m" (*bufptr));
# endif
#else
# define RZ_SYS_ASM_START_ROP() \
	eprintf ("rz_sys_run_rop: Unsupported arch\n");
#endif

static const struct {const char* name; ut64 bit;} arch_bit_array[] = {
    {"x86", RZ_SYS_ARCH_X86},
    {"arm", RZ_SYS_ARCH_ARM},
    {"ppc", RZ_SYS_ARCH_PPC},
    {"m68k", RZ_SYS_ARCH_M68K},
    {"java", RZ_SYS_ARCH_JAVA},
    {"mips", RZ_SYS_ARCH_MIPS},
    {"sparc", RZ_SYS_ARCH_SPARC},
    {"xap", RZ_SYS_ARCH_XAP},
    {"tms320", RZ_SYS_ARCH_TMS320},
    {"msil", RZ_SYS_ARCH_MSIL},
    {"objd", RZ_SYS_ARCH_OBJD},
    {"bf", RZ_SYS_ARCH_BF},
    {"sh", RZ_SYS_ARCH_SH},
    {"avr", RZ_SYS_ARCH_AVR},
    {"dalvik", RZ_SYS_ARCH_DALVIK},
    {"z80", RZ_SYS_ARCH_Z80},
    {"arc", RZ_SYS_ARCH_ARC},
    {"i8080", RZ_SYS_ARCH_I8080},
    {"rar", RZ_SYS_ARCH_RAR},
    {"lm32", RZ_SYS_ARCH_LM32},
    {"v850", RZ_SYS_ARCH_V850},
    {NULL, 0}
};

RZ_API int rz_sys_fork(void) {
#if HAVE_FORK
#if __WINDOWS__
	return -1;
#else
	return fork ();
#endif
#else
	return -1;
#endif
}

#if HAVE_SIGACTION
RZ_API int rz_sys_sigaction(int *sig, void (*handler) (int)) {
	struct sigaction sigact = { };
	int ret, i;

	if (!sig) {
		return -EINVAL;
	}

	sigact.sa_handler = handler;
	sigemptyset (&sigact.sa_mask);

	for (i = 0; sig[i] != 0; i++) {
		sigaddset (&sigact.sa_mask, sig[i]);
	}

	for (i = 0; sig[i] != 0; i++) {
		ret = sigaction (sig[i], &sigact, NULL);
		if (ret) {
			eprintf ("Failed to set signal handler for signal '%d': %s\n", sig[i], strerror(errno));
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
		void (*ret)(int) = signal (sig[i], handler);
		if (ret == SIG_ERR) {
			eprintf ("Failed to set signal handler for signal '%d': %s\n", sig[i], strerror(errno));
			return -1;
		}
	}
	return 0;
}
#endif

RZ_API int rz_sys_signal(int sig, void (*handler) (int)) {
	int s[2] = { sig, 0 };
	return rz_sys_sigaction (s, handler);
}

RZ_API void rz_sys_exit(int status, bool nocleanup) {
	if (nocleanup) {
		_exit (status);
	} else {
		exit (status);
	}
}

RZ_API int rz_sys_truncate(const char *file, int sz) {
#if __WINDOWS__
	int fd = rz_sandbox_open (file, O_RDWR, 0644);
	if (fd == -1) {
		return false;
	}
#ifdef _MSC_VER
	int r = _chsize (fd, sz);
#else
	int r = ftruncate (fd, sz);
#endif
	if (r != 0) {
		eprintf ("Could not resize '%s' file\n", file);
		close (fd);
		return false;
	}
	close (fd);
	return true;
#else
	if (rz_sandbox_enable (0)) {
		return false;
	}
	return truncate (file, sz) == 0;
#endif
}

RZ_API RzList *rz_sys_dir(const char *path) {
	RzList *list = NULL;
#if __WINDOWS__
	WIN32_FIND_DATAW entry;
	char *cfname;
	HANDLE fh = rz_sandbox_opendir (path, &entry);
	if (fh == INVALID_HANDLE_VALUE) {
		//IFDGB eprintf ("Cannot open directory %ls\n", wcpath);
		return list;
	}
	list = rz_list_newf (free);
	if (list) {
		do {
			if ((cfname = rz_utf16_to_utf8 (entry.cFileName))) {
				rz_list_append (list, strdup (cfname));
				free (cfname);
			}
		} while (FindNextFileW (fh, &entry));
	}
	FindClose (fh);
#else
	struct dirent *entry;
	DIR *dir = rz_sandbox_opendir (path);
	if (dir) {
		list = rz_list_new ();
		if (list) {
			list->free = free;
			while ((entry = readdir (dir))) {
				rz_list_append (list, strdup (entry->d_name));
			}
		}
		closedir (dir);
	}
#endif
	return list;
}

RZ_API char *rz_sys_cmd_strf(const char *fmt, ...) {
	char *ret, cmd[4096];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = rz_sys_cmd_str (cmd, NULL, NULL);
	va_end (ap);
	return ret;
}

#ifdef __MAC_10_7
#define APPLE_WITH_BACKTRACE 1
#endif
#ifdef __IPHONE_4_0
#define APPLE_WITH_BACKTRACE 1
#endif

#if (__linux__ && __GNU_LIBRARY__) || (__APPLE__ && APPLE_WITH_BACKTRACE) || \
  defined(NETBSD_WITH_BACKTRACE) || defined(FREEBSD_WITH_BACKTRACE) || \
  __DragonFly__ || __sun || __HAIKU__
#define HAVE_BACKTRACE 1
#endif

RZ_API void rz_sys_backtrace(void) {
#ifdef HAVE_BACKTRACE
	void *array[10];
	size_t size = backtrace (array, 10);
	eprintf ("Backtrace %zd stack frames.\n", size);
	backtrace_symbols_fd (array, size, 2);
#elif __APPLE__
	void **fp = (void **) __builtin_frame_address (0);
	void *saved_pc = __builtin_return_address (0);
	void *saved_fp = __builtin_frame_address (1);
	int depth = 0;

	printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	fp = saved_fp;
	while (fp) {
		saved_fp = *fp;
		fp = saved_fp;
		if (!*fp) {
			break;
		}
		saved_pc = *(fp + 2);
		printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	}
#else
#ifdef _MSC_VER
#pragma message ("TODO: rz_sys_bt : unimplemented")
#else
#warning TODO: rz_sys_bt : unimplemented
#endif
#endif
}

RZ_API int rz_sys_sleep(int secs) {
#if HAS_CLOCK_NANOSLEEP
	struct timespec rqtp;
	rqtp.tv_sec = secs;
	rqtp.tv_nsec = 0;
	return clock_nanosleep (CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif __UNIX__
	return sleep (secs);
#else
	Sleep (secs * 1000); // W32
	return 0;
#endif
}

RZ_API int rz_sys_usleep(int usecs) {
#if HAS_CLOCK_NANOSLEEP
	struct timespec rqtp;
	rqtp.tv_sec = usecs / 1000000;
	rqtp.tv_nsec = (usecs - (rqtp.tv_sec * 1000000)) * 1000;
	return clock_nanosleep (CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif __UNIX__
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc return void for usleep
	usleep (usecs);
	return 0;
#else
	return usleep (usecs);
#endif
#else
	// w32 api uses milliseconds
	usecs /= 1000;
	Sleep (usecs); // W32
	return 0;
#endif
}

RZ_API int rz_sys_clearenv(void) {
#if __UNIX__
#if __APPLE__ && !HAVE_ENVIRON
	/* do nothing */
	if (!env) {
		rz_sys_env_init ();
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
#ifdef _MSC_VER
#pragma message ("rz_sys_clearenv : unimplemented for this platform")
#else
#warning rz_sys_clearenv : unimplemented for this platform
#endif
	return 0;
#endif
}

RZ_API int rz_sys_setenv(const char *key, const char *value) {
	if (!key) {
		return 0;
	}
#if __UNIX__
	if (!value) {
		unsetenv (key);
		return 0;
	}
	return setenv (key, value, 1);
#elif __WINDOWS__
	LPTSTR key_ = rz_sys_conv_utf8_to_win (key);
	LPTSTR value_ = rz_sys_conv_utf8_to_win (value);
	int ret = SetEnvironmentVariable (key_, value_);
	if (!ret) {
		rz_sys_perror ("rz_sys_setenv/SetEnvironmentVariable");
	}
	free (key_);
	free (value_);
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
	snprintf (cmd, sizeof(cmd) - 1, crash_handler_cmd, getpid ());
	rz_sys_backtrace ();
	exit (rz_sys_cmd (cmd));
}

static int checkcmd(const char *c) {
	char oc = 0;
	for (;*c;c++) {
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

	if (!checkcmd (cmd)) {
		return false;
	}
#ifdef HAVE_BACKTRACE
	void *array[1];
	/* call this outside of the signal handler to init it safely */
	backtrace (array, 1);
#endif

	free (crash_handler_cmd);
	crash_handler_cmd = strdup (cmd);

	rz_sys_sigaction (sig, signal_handler);
#else
#pragma message ("rz_sys_crash_handler : unimplemented for this platform")
#endif
	return true;
}

RZ_API char *rz_sys_getenv(const char *key) {
#if __WINDOWS__
	DWORD dwRet;
	LPTSTR envbuf = NULL, key_ = NULL, tmp_ptr;
	char *val = NULL;

	if (!key) {
		return NULL;
	}
	envbuf = (LPTSTR)malloc (sizeof (TCHAR) * TMP_BUFSIZE);
	if (!envbuf) {
		goto err_r_sys_get_env;
	}
	key_ = rz_sys_conv_utf8_to_win (key);
	dwRet = GetEnvironmentVariable (key_, envbuf, TMP_BUFSIZE);
	if (dwRet == 0) {
		if (GetLastError () == ERROR_ENVVAR_NOT_FOUND) {
			goto err_r_sys_get_env;
		}
	} else if (TMP_BUFSIZE < dwRet) {
		tmp_ptr = (LPTSTR)realloc (envbuf, dwRet * sizeof (TCHAR));
		if (!tmp_ptr) {
			goto err_r_sys_get_env;
		}
		envbuf = tmp_ptr;
		dwRet = GetEnvironmentVariable (key_, envbuf, dwRet);
		if (!dwRet) {
			goto err_r_sys_get_env;
		}
	}
	val = rz_sys_conv_win_to_utf8_l (envbuf, (int)dwRet);
err_r_sys_get_env:
	free (key_);
	free (envbuf);
	return val;
#else
	char *b;
	if (!key) {
		return NULL;
	}
	b = getenv (key);
	return b? strdup (b): NULL;
#endif
}

RZ_API bool rz_sys_getenv_asbool(const char *key) {
	char *env = rz_sys_getenv (key);
	const bool res = (env && *env == '1');
	free (env);
	return res;
}

RZ_API char *rz_sys_getdir(void) {
#if __WINDOWS__
	return _getcwd (NULL, 0);
#else
	return getcwd (NULL, 0);
#endif
}

RZ_API int rz_sys_chdir(const char *s) {
	return rz_sandbox_chdir (s)==0;
}

RZ_API bool rz_sys_aslr(int val) {
	bool ret = true;
#if __linux__
	const char *rva = "/proc/sys/kernel/randomize_va_space";
	char buf[3] = {0};
	snprintf(buf, sizeof (buf), "%d\n", val != 0 ? 2 : 0);
	int fd = rz_sandbox_open (rva, O_WRONLY, 0644);
	if (fd != -1) {
		if (rz_sandbox_write (fd, (ut8 *)buf, sizeof (buf)) != sizeof (buf)) {
			eprintf ("Failed to set RVA\n");
			ret = false;
		}
		close (fd);
	}
#elif __FreeBSD__ && __FreeBSD_version >= 1300000
	size_t vlen = sizeof (val);
	if (sysctlbyname ("kern.elf32.aslr.enable", NULL, 0, &val, vlen) == -1) {
		eprintf ("Failed to set RVA 32 bits\n");
		return false;
	}

#if __LP64__
	if (sysctlbyname ("kern.elf64.aslr.enable", NULL, 0, &val, vlen) == -1) {
		eprintf ("Failed to set RVA 64 bits\n");
		ret = false;
	}
#endif
#elif __NetBSD__
	size_t vlen = sizeof (val);
	if (sysctlbyname ("security.pax.aslr.enabled", NULL, 0, &val, vlen) == -1) {
		eprintf ("Failed to set RVA\n");
		ret = false;
	}
#elif __DragonFly__
	size_t vlen = sizeof (val);
	if (sysctlbyname ("vm.randomize_mmap", NULL, 0, &val, vlen) == -1) {
		eprintf ("Failed to set RVA\n");
		ret = false;
	}
#elif __DragonFly__
#endif
	return ret;
}

RZ_API int rz_sys_thp_mode(void) {
#if __linux__
	const char *thp = "/sys/kernel/mm/transparent_hugepage/enabled";
	int ret = 0;
	char *val = rz_file_slurp (thp, NULL);
	if (val) {
		if (strstr (val, "[madvise]")) {
			ret = 1;
		} else if (strstr (val, "[always]")) {
			ret = 2;
		}
		free (val);
	}

	return ret;
#else
  return 0;
#endif
}

#if __UNIX__
RZ_API int rz_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	char *mysterr = NULL;
	if (!sterr) {
		sterr = &mysterr;
	}
	char buffer[1024], *outputptr = NULL;
	char *inputptr = (char *)input;
	int pid, bytes = 0, status;
	int sh_in[2], sh_out[2], sh_err[2];

	if (len) {
		*len = 0;
	}
	if (rz_sys_pipe (sh_in, true)) {
		return false;
	}
	if (output) {
		if (rz_sys_pipe (sh_out, true)) {
			rz_sys_pipe_close (sh_in[0]);
			rz_sys_pipe_close (sh_in[1]);
			rz_sys_pipe_close (sh_out[0]);
			rz_sys_pipe_close (sh_out[1]);
			return false;
		}
	}
	if (rz_sys_pipe (sh_err, true)) {
		rz_sys_pipe_close (sh_in[0]);
		rz_sys_pipe_close (sh_in[1]);
		return false;
	}

	switch ((pid = rz_sys_fork ())) {
	case -1:
		return false;
	case 0:
		while ((dup2(sh_in[0], STDIN_FILENO) == -1) && (errno == EINTR)) {}
		rz_sys_pipe_close (sh_in[0]);
		rz_sys_pipe_close (sh_in[1]);
		if (output) {
			while ((dup2 (sh_out[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
			rz_sys_pipe_close (sh_out[0]);
			rz_sys_pipe_close (sh_out[1]);
		}
		if (sterr) {
			while ((dup2(sh_err[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
			rz_sys_pipe_close (sh_err[0]);
			rz_sys_pipe_close (sh_err[1]);
		} else {
			close (2);
		}
		exit (rz_sandbox_system (cmd, 0));
	default:
		outputptr = strdup ("");
		if (!outputptr) {
			return false;
		}
		if (sterr) {
			*sterr = strdup ("");
			if (!*sterr) {
				free (outputptr);
				return false;
			}
		}
		if (output) {
			rz_sys_pipe_close (sh_out[1]);
		}
		rz_sys_pipe_close (sh_err[1]);
		rz_sys_pipe_close (sh_in[0]);
		if (!inputptr || !*inputptr) {
			rz_sys_pipe_close (sh_in[1]);
			sh_in[1] = -1;
		}
		// we should handle broken pipes somehow better
		rz_sys_signal (SIGPIPE, SIG_IGN);
		size_t err_len = 0, out_len = 0;
		for (;;) {
			fd_set rfds, wfds;
			int nfd;
			FD_ZERO (&rfds);
			FD_ZERO (&wfds);
			if (output) {
				FD_SET (sh_out[0], &rfds);
			}
			if (sterr) {
				FD_SET (sh_err[0], &rfds);
			}
			if (inputptr && *inputptr) {
				FD_SET (sh_in[1], &wfds);
			}
			memset (buffer, 0, sizeof (buffer));
			nfd = select (sh_err[0] + 1, &rfds, &wfds, NULL, NULL);
			if (nfd < 0) {
				break;
			}
			if (output && FD_ISSET (sh_out[0], &rfds)) {
				if ((bytes = read (sh_out[0], buffer, sizeof (buffer))) < 1) {
					break;
				}
				char *tmp = realloc (outputptr, out_len + bytes + 1);
				if (!tmp) {
					RZ_FREE (outputptr);
					break;
				}
				outputptr = tmp;
				memcpy (outputptr + out_len, buffer, bytes);
				out_len += bytes;
			} else if (FD_ISSET (sh_err[0], &rfds) && sterr) {
				if ((bytes = read (sh_err[0], buffer, sizeof (buffer))) < 1) {
					break;
				}
				char *tmp = realloc (*sterr, err_len + bytes + 1);
				if (!tmp) {
					RZ_FREE (*sterr);
					break;
				}
				*sterr = tmp;
				memcpy (*sterr + err_len, buffer, bytes);
				err_len += bytes;
			} else if (FD_ISSET (sh_in[1], &wfds) && inputptr && *inputptr) {
				int inputptr_len = strlen (inputptr);
				bytes = write (sh_in[1], inputptr, inputptr_len);
				if (bytes != inputptr_len) {
					break;
				}
				inputptr += bytes;
				if (!*inputptr) {
					rz_sys_pipe_close (sh_in[1]);
					/* If neither stdout nor stderr should be captured,
					 * abort now - nothing more to do for select(). */
					if (!output && !sterr) {
						break;
					}
				}
			}
		}
		if (output) {
			rz_sys_pipe_close (sh_out[0]);
		}
		rz_sys_pipe_close (sh_err[0]);
		if (sh_in[1] != -1) {
			rz_sys_pipe_close (sh_in[1]);
		}
		waitpid (pid, &status, 0);
		bool ret = true;
		if (status) {
			// char *escmd = rz_str_escape (cmd);
			// eprintf ("error code %d (%s): %s\n", WEXITSTATUS (status), escmd, *sterr);
			// eprintf ("(%s)\n", output);
			// eprintf ("%s: failed command '%s'\n", __func__, escmd);
			// free (escmd);
			ret = false;
		}

		if (len) {
			*len = out_len;
		}
		if (*sterr) {
			(*sterr)[err_len] = 0;
		}
		if (outputptr) {
			outputptr[out_len] = 0;
		}
		if (output) {
			*output = outputptr;
		} else {
			free (outputptr);
		}
		return ret;
	}
	return false;
}
#elif __WINDOWS__
RZ_API int rz_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	return rz_sys_cmd_str_full_w32 (cmd, input, output, len, sterr);
}
#else
RZ_API int rz_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	eprintf ("rz_sys_cmd_str: not yet implemented for this platform\n");
	return false;
}
#endif

RZ_API int rz_sys_cmdf(const char *fmt, ...) {
	int ret;
	char cmd[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = rz_sys_cmd (cmd);
	va_end (ap);
	return ret;
}

RZ_API int rz_sys_cmdbg (const char *str) {
#if __UNIX__
	int ret, pid = rz_sys_fork ();
	if (pid == -1) {
		return -1;
	}
	if (pid) {
		return pid;
	}
	ret = rz_sandbox_system (str, 0);
	eprintf ("{exit: %d, pid: %d, cmd: \"%s\"}", ret, pid, str);
	exit (0);
	return -1;
#else
#ifdef _MSC_VER
#pragma message ("rz_sys_cmdbg is not implemented for this platform")
#else
#warning rz_sys_cmdbg is not implemented for this platform
#endif
	return -1;
#endif
}

RZ_API int rz_sys_cmd(const char *str) {
	if (rz_sandbox_enable (0)) {
		return false;
	}
	return rz_sandbox_system (str, 1);
}

RZ_API char *rz_sys_cmd_str(const char *cmd, const char *input, int *len) {
	char *output = NULL;
	if (rz_sys_cmd_str_full (cmd, input, &output, len, NULL)) {
		return output;
	}
	free (output);
	return NULL;
}

RZ_API bool rz_sys_mkdir(const char *dir) {
	bool ret;

	if (rz_sandbox_enable (0)) {
		return false;
	}
#if __WINDOWS__
	LPTSTR dir_ = rz_sys_conv_utf8_to_win (dir);

	ret = CreateDirectory (dir_, NULL) != 0;
	free (dir_);
#else
	ret = mkdir (dir, 0755) != -1;
#endif
	return ret;
}

RZ_API bool rz_sys_mkdirp(const char *dir) {
	bool ret = true;
	char slash = RZ_SYS_DIR[0];
	char *path = strdup (dir), *ptr = path;
	if (!path) {
		eprintf ("rz_sys_mkdirp: Unable to allocate memory\n");
		return false;
	}
	if (*ptr == slash) {
		ptr++;
	}
#if __WINDOWS__
	{
		char *p = strstr (ptr, ":\\");
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
		if (!rz_sys_mkdir (path) && rz_sys_mkdir_failed ()) {
			eprintf ("rz_sys_mkdirp: fail '%s' of '%s'\n", path, dir);
			free (path);
			return false;
		}
		*ptr = slash;
		ptr++;
	}
	if (!rz_sys_mkdir (path) && rz_sys_mkdir_failed ()) {
		ret = false;
	}
	free (path);
	return ret;
}

RZ_API void rz_sys_perror_str(const char *fun) {
#if __UNIX__
#pragma push_macro("perror")
#undef perror
	perror (fun);
#pragma pop_macro("perror")
#elif __WINDOWS__
	LPTSTR lpMsgBuf;
	DWORD dw = GetLastError();

	if (FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL )) {
		char *err = rz_sys_conv_win_to_utf8 (lpMsgBuf);
		if (err) {
			eprintf ("%s: (%#lx) %s%s", fun, dw, err,
			         rz_str_endswith (err, "\n") ? "" : "\n");
			free (err);
		}
		LocalFree (lpMsgBuf);
	} else {
		eprintf ("%s\n", fun);
	}
#endif
}

RZ_API bool rz_sys_arch_match(const char *archstr, const char *arch) {
	char *ptr;
	if (!archstr || !arch || !*archstr || !*arch) {
		return true;
	}
	if (!strcmp (archstr, "*") || !strcmp (archstr, "any")) {
		return true;
	}
	if (!strcmp (archstr, arch)) {
		return true;
	}
	if ((ptr = strstr (archstr, arch))) {
		char p = ptr[strlen (arch)];
		if (!p || p==',') {
			return true;
		}
	}
	return false;
}

RZ_API int rz_sys_arch_id(const char *arch) {
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (!strcmp (arch, arch_bit_array[i].name)) {
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
	ut8 *ptr, *p = malloc ((sz + len) << 1);
	ptr = p;
	pdelta = ((size_t)(p)) & (4096 - 1);
	if (pdelta) {
		ptr += (4096 - pdelta);
	}
	if (!ptr || !buf) {
		eprintf ("rz_sys_run: Cannot run empty buffer\n");
		free (p);
		return false;
	}
	memcpy (ptr, buf, len);
	rz_mem_protect (ptr, sz, "rx");
	//rz_mem_protect (ptr, sz, "rwx"); // try, ignore if fail
	cb = (int (*)())ptr;
#if USE_FORK
#if __UNIX__
	pid = rz_sys_fork ();
#else
	pid = -1;
#endif
	if (pid < 0) {
		return cb ();
	}
	if (!pid) {
		ret = cb ();
		exit (ret);
		return ret;
	}
	st = 0;
	waitpid (pid, &st, 0);
	if (WIFSIGNALED (st)) {
		int num = WTERMSIG(st);
		eprintf ("Got signal %d\n", num);
		ret = num;
	} else {
		ret = WEXITSTATUS (st);
	}
#else
	ret = (*cb) ();
#endif
	free (p);
	return ret;
}

RZ_API int rz_sys_run_rop(const ut8 *buf, int len) {
#if USE_FORK
	int st;
#endif
	// TODO: define RZ_SYS_ALIGN_FORWARD in rz_util.h
	ut8 *bufptr = malloc (len);
	if (!bufptr) {
		eprintf ("rz_sys_run_rop: Cannot allocate buffer\n");
		return false;
	}

	if (!buf) {
		eprintf ("rz_sys_run_rop: Cannot execute empty rop chain\n");
		free (bufptr);
		return false;
	}
	memcpy (bufptr, buf, len);
#if USE_FORK
#if __UNIX__
	pid_t pid = rz_sys_fork ();
#else
	pid = -1;
#endif
	if (pid < 0) {
		RZ_SYS_ASM_START_ROP ();
	} else {
		RZ_SYS_ASM_START_ROP ();
		exit (0);
                return 0;
	}
	st = 0;
	if (waitpid (pid, &st, 0) == -1) {
            eprintf ("rz_sys_run_rop: waitpid failed\n");
            free (bufptr);
            return -1;
        }
	if (WIFSIGNALED (st)) {
		int num = WTERMSIG (st);
		eprintf ("Got signal %d\n", num);
		ret = num;
	} else {
		ret = WEXITSTATUS (st);
	}
#else
	RZ_SYS_ASM_START_ROP ();
#endif
	free (bufptr);
	return 0;
}

RZ_API bool rz_is_heap (void *p) {
	void *q = malloc (8);
	ut64 mask = UT64_MAX;
	ut64 addr = (ut64)(size_t)q;
	addr >>= 16;
	addr <<= 16;
	mask >>= 16;
	mask <<= 16;
	free (q);
	return (((ut64)(size_t)p) == mask);
}

RZ_API char *rz_sys_pid_to_path(int pid) {
#if __WINDOWS__
	// TODO: add maximum path length support
	HANDLE processHandle;
	const DWORD maxlength = MAX_PATH;
	TCHAR filename[MAX_PATH];
	char *result = NULL;

	processHandle = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!processHandle) {
		eprintf ("rz_sys_pid_to_path: Cannot open process.\n");
		return NULL;
	}
	DWORD length = GetModuleFileNameEx (processHandle, NULL, filename, maxlength);
	if (length == 0) {
		// Upon failure fallback to GetProcessImageFileName
		length = GetProcessImageFileName (processHandle, filename, maxlength);
		CloseHandle (processHandle);
		if (length == 0) {
			eprintf ("rz_sys_pid_to_path: Error calling GetProcessImageFileName\n");
			return NULL;
		}
		// Convert NT path to win32 path
		char *name = rz_sys_conv_win_to_utf8 (filename);
		if (!name) {
			eprintf ("rz_sys_pid_to_path: Error converting to utf8\n");
			return NULL;
		}
		char *tmp = strchr (name + 1, '\\');
		if (!tmp) {
			free (name);
			eprintf ("rz_sys_pid_to_path: Malformed NT path\n");
			return NULL;
		}
		tmp = strchr (tmp + 1, '\\');
		if (!tmp) {
			free (name);
			eprintf ("rz_sys_pid_to_path: Malformed NT path\n");
			return NULL;
		}
		length = tmp - name;
		tmp = malloc (length + 1);
		if (!tmp) {
			free (name);
			eprintf ("rz_sys_pid_to_path: Error allocating memory\n");
			return NULL;
		}
		strncpy (tmp, name, length);
		tmp[length] = '\0';
		TCHAR device[MAX_PATH];
		for (TCHAR drv[] = TEXT("A:"); drv[0] <= TEXT('Z'); drv[0]++) {
			if (QueryDosDevice (drv, device, maxlength) > 0) {
				char *dvc = rz_sys_conv_win_to_utf8 (device);
				if (!dvc) {
					free (name);
					free (tmp);
					eprintf ("rz_sys_pid_to_path: Error converting to utf8\n");
					return NULL;
				}
				if (!strcmp (tmp, dvc)) {
					free (tmp);
					free (dvc);
					char *d = rz_sys_conv_win_to_utf8 (drv);
					if (!d) {
						free (name);
						eprintf ("rz_sys_pid_to_path: Error converting to utf8\n");
						return NULL;
					}
					tmp = rz_str_newf ("%s%s", d, &name[length]);
					free (d);
					if (!tmp) {
						free (name);
						eprintf ("rz_sys_pid_to_path: Error calling rz_str_newf\n");
						return NULL;
					}
					result = strdup (tmp);
					break;
				}
				free (dvc);
			}
		}
		free (name);
		free (tmp);
	} else {
		CloseHandle (processHandle);
		result = rz_sys_conv_win_to_utf8 (filename);
	}
	return result;
#elif __APPLE__
#if __POWERPC__
#warning TODO getpidproc
	return NULL;
#else
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	pathbuf[0] = 0;
	int ret = proc_pidpath (pid, pathbuf, sizeof (pathbuf));
	if (ret <= 0) {
		return NULL;
	}
	return strdup (pathbuf);
#endif
#else
	int ret;
#if __FreeBSD__ || __DragonFly__
	char pathbuf[PATH_MAX];
	size_t pathbufl = sizeof (pathbuf);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid};
	ret = sysctl (mib, 4, pathbuf, &pathbufl, NULL, 0);
	if (ret != 0) {
		return NULL;
	}
#elif __HAIKU__
	char pathbuf[MAXPATHLEN];
	int32_t group = 0;
	image_info ii;

	while (get_next_image_info ((team_id)pid, &group, &ii) == B_OK) {
		if (ii.type == B_APP_IMAGE) {
			break;
		}
	}

	if (ii.type == B_APP_IMAGE) {
		rz_str_ncpy (pathbuf, ii.name, MAXPATHLEN);
	} else {
		pathbuf[0] = '\0';
	}
#else
	char buf[128], pathbuf[1024];
	snprintf (buf, sizeof (buf), "/proc/%d/exe", pid);
	ret = readlink (buf, pathbuf, sizeof (pathbuf)-1);
	if (ret < 1) {
		return NULL;
	}
	pathbuf[ret] = 0;
#endif
	return strdup (pathbuf);
#endif
}

RZ_API void rz_sys_env_init(void) {
	char **envp = rz_sys_get_environ ();
	if (envp) {
		rz_sys_set_environ (envp);
	}
}

RZ_API char **rz_sys_get_environ(void) {
#if __APPLE__ && !HAVE_ENVIRON
	env = *_NSGetEnviron();
#else
	env = environ;
#endif
	// return environ if available??
	if (!env) {
		env = rz_lib_dl_sym (NULL, "environ");
	}
	return env;
}

RZ_API void rz_sys_set_environ(char **e) {
	env = e;
}

RZ_API char *rz_sys_whoami (char *buf) {
	char _buf[32];
	int pid = getpid ();
	int hasbuf = (buf)? 1: 0;
	if (!hasbuf) {
		buf = _buf;
	}
	sprintf (buf, "pid%d", pid);
	return hasbuf? buf: strdup (buf);
}

RZ_API int rz_sys_getpid(void) {
#if __UNIX__
	return getpid ();
#elif __WINDOWS__
	return GetCurrentProcessId();
#else
#warning rz_sys_getpid not implemented for this platform
	return -1;
#endif
}

RZ_API bool rz_sys_tts(const char *txt, bool bg) {
	int i;
	rz_return_val_if_fail (txt, false);
	const char *says[] = {
		"say", "termux-tts-speak", NULL
	};
	for (i = 0; says[i]; i++) {
		char *sayPath = rz_file_path (says[i]);
		if (sayPath) {
			char *line = rz_str_replace (strdup (txt), "'", "\"", 1);
			rz_sys_cmdf ("\"%s\" '%s'%s", sayPath, line, bg? " &": "");
			free (line);
			free (sayPath);
			return true;
		}
	}
	return false;
}

RZ_API const char *rz_sys_prefix(const char *pfx) {
	static char *prefix = NULL;
	if (!prefix) {
#if __WINDOWS__
		prefix = rz_sys_get_src_dir_w32 ();
		if (!prefix) {
			prefix = strdup (RZ_PREFIX);
		}
#else
		prefix = strdup (RZ_PREFIX);
#endif
	}
	if (pfx) {
		free (prefix);
		prefix = strdup (pfx);
	}
	return prefix;
}

RZ_API RSysInfo *rz_sys_info(void) {
#if __UNIX__
	struct utsname un = {{0}};
	if (uname (&un) != -1) {
		RSysInfo *si = RZ_NEW0 (RSysInfo);
		if (si) {
			si->sysname  = strdup (un.sysname);
			si->nodename = strdup (un.nodename);
			si->release  = strdup (un.release);
			si->version  = strdup (un.version);
			si->machine  = strdup (un.machine);
			return si;
		}
	}
#elif __WINDOWS__
	HKEY key;
	DWORD type;
	DWORD size;
	DWORD major;
	DWORD minor;
	char tmp[256] = {0};
	RSysInfo *si = RZ_NEW0 (RSysInfo);
	if (!si) {
		return NULL;
	}

	if (RegOpenKeyExA (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
		KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
		rz_sys_perror ("rz_sys_info/RegOpenKeyExA");
		rz_sys_info_free (si);
		return NULL;
	}

	size = sizeof (tmp);
	if (RegQueryValueExA (key, "ProductName", NULL, &type,
		(LPBYTE)&tmp, &size) != ERROR_SUCCESS
		|| type != REG_SZ) {
		goto beach;
	}
	si->sysname = strdup (tmp);

	size = sizeof (major);
	if (RegQueryValueExA (key, "CurrentMajorVersionNumber", NULL, &type,
		(LPBYTE)&major, &size) != ERROR_SUCCESS
		|| type != REG_DWORD) {
		goto beach;
	}
	size = sizeof (minor);
	if (RegQueryValueExA (key, "CurrentMinorVersionNumber", NULL, &type,
		(LPBYTE)&minor, &size) != ERROR_SUCCESS
		|| type != REG_DWORD) {
		goto beach;
	}

	size = sizeof (tmp);
	if (RegQueryValueExA (key, "CurrentBuild", NULL, &type,
		(LPBYTE)&tmp, &size) != ERROR_SUCCESS
		|| type != REG_SZ) {
		goto beach;
	}
	si->version = rz_str_newf ("%lu.%lu.%s", major, minor, tmp);

	size = sizeof (tmp);
	if (RegQueryValueExA (key, "ReleaseId", NULL, &type,
		(LPBYTE)tmp, &size) != ERROR_SUCCESS
		|| type != REG_SZ) {
		goto beach;
	}
	si->release = strdup (tmp);
beach:
	RegCloseKey (key);
	return si;
#endif
	return NULL;
}

RZ_API void rz_sys_info_free(RSysInfo *si) {
	free (si->sysname);
	free (si->nodename);
	free (si->release);
	free (si->version);
	free (si->machine);
	free (si);
}

#if __UNIX__
#if HAVE_PIPE2
#elif defined(O_CLOEXEC)
static RzThreadLock *sys_pipe_mutex;

__attribute__ ((constructor)) static void sys_pipe_constructor(void) {
	sys_pipe_mutex = rz_th_lock_new (true);
}

__attribute__ ((destructor)) static void sys_pipe_destructor(void) {
	rz_th_lock_free (sys_pipe_mutex);
}

static bool set_close_on_exec(int fd) {
	int flags = fcntl (fd, F_GETFD);
	if (flags == -1) {
		return false;
	}
	flags |= FD_CLOEXEC;
	return fcntl (fd, F_SETFD, flags) != -1;
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
	rz_th_lock_enter (sys_pipe_mutex);
	if ((res = pipe (pipefd)) == -1) {
		perror ("pipe");
		goto err;
	}
	if (close_on_exec && (!set_close_on_exec (pipefd[0]) || !set_close_on_exec (pipefd[1]))) {
		perror ("close-on-exec");
		close (pipefd[0]);
		close (pipefd[1]);
		goto err;
	}
err:
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

/**
 * \brief Close a file descriptor previously created pipe \p rz_sys_pipe
 */
RZ_API int rz_sys_pipe_close(int fd) {
	return close (fd);
}

RZ_API int rz_sys_execv(const char *pathname, char *const argv[]) {
	rz_th_lock_enter (sys_pipe_mutex);
	int res = execv (pathname, argv);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	rz_th_lock_enter (sys_pipe_mutex);
	int res = execve (pathname, argv, envp);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execvp(const char *file, char *const argv[]) {
	rz_th_lock_enter (sys_pipe_mutex);
	int res = execvp (file, argv);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execl(const char *pathname, const char *arg, ...) {
	va_list count_args, args;
	va_start (args, arg);
	va_copy (count_args, args);
	size_t i, argc = 0;
	while (va_arg (count_args, char *) != NULL) {
		argc++;
	}
	va_end (count_args);
	char **argv = RZ_NEWS0 (char *, argc + 2);
	argv[0] = strdup (pathname);
	for (i = 1; i <= argc; i++) {
		argv[i] = va_arg (args, char *);
	}
	va_end (args);
	rz_th_lock_enter (sys_pipe_mutex);
	int res = execv (pathname, argv);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_system(const char *command) {
	rz_th_lock_enter (sys_pipe_mutex);
	int res = system (command);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}
#else
#include <ht_uu.h>
static HtUU *fd2close;
static RzThreadLock *sys_pipe_mutex;

static void prepare_atfork(void) {
	rz_th_lock_enter (sys_pipe_mutex);
}

static void parent_atfork(void) {
	rz_th_lock_leave (sys_pipe_mutex);
}

static void child_atfork(void) {
	rz_th_lock_leave (sys_pipe_mutex);
}

__attribute__ ((constructor)) static void sys_pipe_constructor(void) {
	sys_pipe_mutex = rz_th_lock_new (false);
	pthread_atfork(prepare_atfork, parent_atfork, child_atfork);
	fd2close = ht_uu_new0 ();
}

__attribute__ ((destructor)) static void sys_pipe_destructor(void) {
	ht_uu_free (fd2close);
	rz_th_lock_free (sys_pipe_mutex);
}

static bool set_close_on_exec(int fd, bool close_on_exec) {
	bool res = ht_uu_insert (fd2close, fd, close_on_exec);
	rz_warn_if_fail (res);
	return res;
}

static bool close_on_exec_fd_cb(void *user, const ut64 key, const ut64 val) {
	bool close_on_exec = (bool)val;
	if (close_on_exec) {
		close ((int)key);
	}
	return true;
}

static void close_fds(void) {
	ht_uu_foreach (fd2close, close_on_exec_fd_cb, NULL);
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
	rz_th_lock_enter (sys_pipe_mutex);
	if ((res = pipe (pipefd)) == -1) {
		perror ("pipe");
		goto err;
	}
	if (!set_close_on_exec (pipefd[0], close_on_exec) || !set_close_on_exec (pipefd[1], close_on_exec)) {
		perror ("close-on-exec");
		close (pipefd[0]);
		close (pipefd[1]);
		goto err;
	}
err:
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

/**
 * \brief Close a file descriptor previously created pipe \p rz_sys_pipe
 *
 * This is necessary to ensure that the file descriptor is not "closed again"
 * when an \p rz_sys exec/system is executed later.
 */
RZ_API int rz_sys_pipe_close(int fd) {
	rz_th_lock_enter (sys_pipe_mutex);
	bool deleted = ht_uu_delete (fd2close, fd);
	rz_warn_if_fail (deleted);
	int res = close (fd);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execv(const char *pathname, char *const argv[]) {
	rz_th_lock_enter (sys_pipe_mutex);
	close_fds ();
	int res = execv (pathname, argv);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	rz_th_lock_enter (sys_pipe_mutex);
	close_fds ();
	int res = execve (pathname, argv, envp);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execvp(const char *file, char *const argv[]) {
	rz_th_lock_enter (sys_pipe_mutex);
	close_fds ();
	int res = execvp (file, argv);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_execl(const char *pathname, const char *arg, ...) {
	va_list count_args, args;
	va_start (args, arg);
	va_copy (count_args, args);
	size_t i, argc = 0;
	while (va_arg (count_args, char *) != NULL) {
		argc++;
	}
	va_end (count_args);
	char **argv = RZ_NEWS0 (char *, argc + 2);
	argv[0] = strdup (pathname);
	for (i = 1; i <= argc; i++) {
		argv[i] = va_arg (args, char *);
	}
	va_end (args);

	rz_th_lock_enter (sys_pipe_mutex);
	close_fds ();
	int res = execv (pathname, argv);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}

RZ_API int rz_sys_system(const char *command) {
	rz_th_lock_enter (sys_pipe_mutex);
	close_fds ();
	int res = system (command);
	rz_th_lock_leave (sys_pipe_mutex);
	return res;
}
#endif
#endif