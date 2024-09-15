// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/* this helper api is here because it depends on rz_util and rz_socket */
/* we should find a better place for it. rz_io? */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <rz_socket.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_cons.h>
#include <sys/stat.h>
#include <sys/types.h>

#if __APPLE__ && HAVE_FORK
#include <spawn.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif

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

#if __UNIX__
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <grp.h>
#include <errno.h>
#if defined(__sun)
#include <sys/filio.h>
#endif /* __sun */
#endif /* __UNIX__ */
#ifdef _MSC_VER
#include <direct.h> // to compile chdir in msvc windows
#include <process.h> // to compile execv in msvc windows
#define pid_t int
#endif

#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
static int (*dyn_openpty)(int *amaster, int *aslave, char *name, struct termios *termp, struct winsize *winp) = NULL;
static int (*dyn_login_tty)(int fd) = NULL;
static id_t (*dyn_forkpty)(int *amaster, char *name, struct termios *termp, struct winsize *winp) = NULL;
static void dyn_init(void) {
	if (!dyn_openpty) {
		dyn_openpty = rz_sys_dlsym(NULL, "openpty");
	}
	if (!dyn_login_tty) {
		dyn_openpty = rz_sys_dlsym(NULL, "login_tty");
	}
	if (!dyn_forkpty) {
		dyn_openpty = rz_sys_dlsym(NULL, "forkpty");
	}
}

#endif

RZ_API RzRunProfile *rz_run_new(const char *str) {
	RzRunProfile *p = RZ_NEW0(RzRunProfile);
	if (p) {
		rz_run_reset(p);
		if (str) {
			rz_run_parsefile(p, str);
		}
	}
	return p;
}

RZ_API void rz_run_reset(RzRunProfile *p) {
	rz_return_if_fail(p);
	memset(p, 0, sizeof(RzRunProfile));
	p->_aslr = -1;
}

RZ_API bool rz_run_parse(RzRunProfile *pf, const char *profile) {
	rz_return_val_if_fail(pf && profile, false);
	char *p, *o, *str = rz_str_dup(profile);
	if (!str) {
		return false;
	}
	rz_str_replace_char(str, '\r', 0);
	p = str;
	while (p) {
		if ((o = strchr(p, '\n'))) {
			*o++ = 0;
		}
		rz_run_parseline(pf, p);
		p = o;
	}
	free(str);
	return true;
}

RZ_API void rz_run_free(RzRunProfile *r) {
	if (r) {
		free(r->_system);
		free(r->_program);
		free(r->_runlib);
		free(r->_runlib_fcn);
		free(r->_stdio);
		free(r->_stdin);
		free(r->_stdout);
		free(r->_stderr);
		free(r->_chgdir);
		free(r->_chroot);
		free(r->_libpath);
		free(r->_preload);
		free(r->_input);
		free(r);
	}
}

#if __UNIX__
static void set_limit(int n, int a, ut64 b) {
	if (n) {
		struct rlimit cl = { b, b };
		setrlimit(RLIMIT_CORE, &cl);
	} else {
		struct rlimit cl = { 0, 0 };
		setrlimit(a, &cl);
	}
}
#endif

static char *resolve_value(const char *src, size_t *result_len) {
	size_t src_len = strlen(src);
	size_t copy_len = 0;
	if (src_len < 1) {
		return NULL;
	}
	char *copy = NULL;
	char delimiter = 0;

	if (src[0] == '\'' || src[0] == '"') {
		delimiter = src[0];
		if (src_len < 2 || src[src_len - 1] != delimiter) {
			// the quoted string must have an end
			RZ_LOG_ERROR("rz-run: missing `%c` at the end of the value `%s`\n", delimiter, src);
			return NULL;
		}
		copy = rz_str_ndup(src + 1, src_len - 2);
		src_len -= 2;
		if (delimiter == '\'') {
			// pass single-quoted string unaltered
			copy_len = src_len;
			goto end_resolve;
		}
	} else {
		copy = rz_str_dup(src);
	}

	copy_len = src_len = rz_str_unescape(copy);
	if (src_len < 1) {
		goto end_resolve;
	}
	const char *end = copy + src_len;

	switch (*copy) {
	case '@': {
		char *at_end = NULL;
		size_t at_size = strtol(copy + 1, &at_end, 10);
		if (!at_size || *at_end != '@') {
			RZ_LOG_ERROR("rz-run: invalid @<num>@ in `%s`\n", copy);
			free(copy);
			return NULL;
		}
		at_end++;
		size_t suffix_len = end - at_end;
		if (suffix_len < 1) {
			RZ_LOG_ERROR("rz-run: invalid string after @<num>@ in `%s`\n", copy);
			free(copy);
			return NULL;
		}
		char *buf = malloc(at_size + 1);
		if (buf) {
			buf[at_size] = 0;
			for (size_t i = 0; i < at_size; i++) {
				buf[i] = at_end[i % suffix_len];
			}
		}
		free(copy);
		copy = buf;
		copy_len = at_size;
		break;
	}
	case '`': {
		char *backtick_end = strchr(src + 1, '`');
		if (!backtick_end) {
			RZ_LOG_ERROR("rz-run: missing `\n");
			free(copy);
			return NULL;
		}
		size_t msg_len = backtick_end - (copy + 1);
		if (msg_len < 1) {
			free(copy);
			return rz_str_dup("");
		}
		*backtick_end = 0;
		char *tmp = rz_sys_cmd_str(copy + 1, NULL, NULL);
		free(copy);
		rz_str_trim_tail(tmp);
		copy = tmp;
		copy_len = strlen(copy);
		break;
	}
	case '!': {
		char *tmp = rz_sys_cmd_str(copy + 1, NULL, NULL);
		free(copy);
		rz_str_trim_tail(tmp);
		copy = tmp;
		copy_len = strlen(copy);
		break;
	}
	case ':': {
		if (copy[1] != '!') {
			src_len--;
			memmove(copy, copy + 1, src_len);
			copy[src_len] = 0;
		} else {
			if (copy + 2 >= end) {
				RZ_LOG_ERROR("rz-run: missing strin after `!` in `%s`\n", copy);
				free(copy);
				return NULL;
			}
			char *tmp = rz_sys_cmd_str(copy + 2, NULL, NULL);
			free(copy);
			rz_str_trim_tail(tmp);
			copy = tmp;
			src_len = strlen(copy);
		}
		if (src_len < 2 || (src_len & 1)) {
			RZ_LOG_ERROR("rz-run: invalid hexpair string `%s`\n", copy);
			free(copy);
			return NULL;
		}
		ut8 *buf = calloc(1, src_len);
		int len = rz_hex_str2bin(copy, buf);
		if (len < 1) {
			RZ_LOG_ERROR("rz-run: invalid hexpair string `%s`\n", copy);
			free(copy);
			return NULL;
		}
		free(copy);
		copy = (char *)buf;
		copy_len = src_len >> 1;
		break;
	}
	default:
		break;
	}

end_resolve:
	if (result_len) {
		*result_len = copy_len;
	}
	return copy;
}

static bool parse_bool(const char *value) {
	return !rz_str_casecmp(value, "yes") ||
		!rz_str_casecmp(value, "on") ||
		!rz_str_casecmp(value, "true") ||
		!rz_str_casecmp(value, "1");
}

#if __APPLE__
#else
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
static void restore_saved_fd(int saved, bool restore, int fd) {
	if (saved == -1) {
		return;
	}
	if (restore) {
		dup2(saved, fd);
	}
	close(saved);
}
#endif

static int handle_redirection_proc(const char *cmd, bool in, bool out, bool err) {
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
	if (!dyn_forkpty) {
		// No forkpty api found, maybe we should fallback to just fork without any pty allocated
		return -1;
	}
	// use PTY to redirect I/O because pipes can be problematic in
	// case of interactive programs.
	int saved_stdin = dup(STDIN_FILENO);
	if (saved_stdin == -1) {
		return -1;
	}
	int saved_stdout = dup(STDOUT_FILENO);
	if (saved_stdout == -1) {
		close(saved_stdin);
		return -1;
	}

	int fdm, pid = dyn_forkpty(&fdm, NULL, NULL, NULL);
	if (pid == -1) {
		close(saved_stdin);
		close(saved_stdout);
		return -1;
	}
	const char *tn = ttyname(fdm);
	if (!tn) {
		close(saved_stdin);
		close(saved_stdout);
		return -1;
	}
	int fds = open(tn, O_RDWR);
	if (fds == -1) {
		close(saved_stdin);
		close(saved_stdout);
		return -1;
	}
	if (pid == 0) {
		close(fdm);
		// child process
		if (in) {
			dup2(fds, STDIN_FILENO);
		}
		if (out) {
			dup2(fds, STDOUT_FILENO);
		}
		// child - program to run

		// necessary because otherwise you can read the same thing you
		// wrote on fdm.
		struct termios t;
		tcgetattr(fds, &t);
		cfmakeraw(&t);
		tcsetattr(fds, TCSANOW, &t);

		int code = rz_sys_system(cmd);
		restore_saved_fd(saved_stdin, in, STDIN_FILENO);
		restore_saved_fd(saved_stdout, out, STDOUT_FILENO);
		exit(code);
	} else {
		close(fds);
		if (in) {
			dup2(fdm, STDIN_FILENO);
		}
		if (out) {
			dup2(fdm, STDOUT_FILENO);
		}
		// parent process
		int status;
		waitpid(pid, &status, 0);
	}

	// parent
	close(saved_stdin);
	close(saved_stdout);
	return 0;
#else
#ifdef _MSC_VER
#pragma message("TODO: handle_redirection_proc: Not implemented for this platform")
#else
#warning handle_redirection_proc : unimplemented for this platform
#endif
	return -1;
#endif
}
#endif

static int handle_redirection(const char *cmd, bool in, bool out, bool err) {
#if __APPLE__
	// XXX handle this in other layer since things changes a little bit
	// this seems like a really good place to refactor stuff
	return 0;
#else
	if (!cmd || !*cmd) {
		return 0;
	}
	if (cmd[0] == '"') {
#if __UNIX__
		if (in) {
			int pipes[2];
			if (rz_sys_pipe(pipes, true) != -1) {
				size_t cmdl = strlen(cmd) - 2;
				if (write(pipes[1], cmd + 1, cmdl) != cmdl) {
					RZ_LOG_ERROR("rz-run: cannot write to the pipe\n");
					close(0);
					return 1;
				}
				if (write(pipes[1], "\n", 1) != 1) {
					RZ_LOG_ERROR("rz-run: cannot write to the pipe\n");
					close(0);
					return 1;
				}
				while ((dup2(pipes[0], STDIN_FILENO) == -1) && (errno == EINTR)) {
				}
				rz_sys_pipe_close(pipes[0]);
				rz_sys_pipe_close(pipes[1]);
			} else {
				RZ_LOG_ERROR("rz-run: cannot create pipe\n");
			}
		}
#else
#ifdef _MSC_VER
#pragma message("string redirection handle not yet done")
#else
#warning quoted string redirection handle not yet done
#endif
#endif
	} else if (cmd[0] == '!') {
		// redirection to a process
		return handle_redirection_proc(cmd + 1, in, out, err);
	} else {
		// redirection to a file
		int f, flag = 0, mode = 0;
		flag |= in ? O_RDONLY : 0;
		flag |= out ? O_WRONLY | O_CREAT : 0;
		flag |= err ? O_WRONLY | O_CREAT : 0;
#ifdef __WINDOWS__
		mode = _S_IREAD | _S_IWRITE;
#else
		mode = S_IRUSR | S_IWUSR;
#endif
		f = open(cmd, flag, mode);
		if (f < 0) {
			RZ_LOG_ERROR("rz-run: cannot open: %s\n", cmd);
			return 1;
		}
#define DUP(x) \
	{ \
		close(x); \
		dup2(f, x); \
	}
		if (in) {
			DUP(0);
		}
		if (out) {
			DUP(1);
		}
		if (err) {
			DUP(2);
		}
		close(f);
	}
	return 0;
#endif
}

RZ_API bool rz_run_parsefile(RzRunProfile *p, const char *b) {
	rz_return_val_if_fail(p && b, false);
	char *s = rz_file_slurp(b, NULL);
	if (s) {
		bool ret = rz_run_parse(p, s);
		free(s);
		return ret;
	}
	return 0;
}

static bool parse_key_value(const char *input, char **key, char **value) {
	char *s_key = NULL, *s_value = NULL;
	size_t length = input ? strlen(input) : 0;
	if (length < 1 || *input == '#') {
		return false;
	}

	const char *end = input + length;
	const char *equal = strchr(input, '=');
	if (!equal || equal + 1 >= end) {
		return false;
	}

	s_key = rz_str_ndup(input, equal - input);
	if (equal[1] == '$') {
		s_value = rz_sys_getenv(equal + 1);
	} else {
		s_value = rz_str_dup(equal + 1);
	}

	if (!s_key || !s_value) {
		free(s_key);
		free(s_value);
		return false;
	}

	*key = s_key;
	*value = s_value;
	return true;
}

RZ_API bool rz_run_parseline(RzRunProfile *p, const char *b) {
	if (RZ_STR_ISEMPTY(b)) {
		return true;
	} else if (!strcmp(b, "clearenv")) {
		rz_sys_clearenv();
		return true;
	}

	char *key = NULL, *value = NULL;
	if (!parse_key_value(b, &key, &value)) {
		return false;
	}

	if (!strcmp(key, "program")) {
		p->_args[0] = rz_str_dup(value);
		p->_program = rz_str_dup(value);
	} else if (!strcmp(key, "daemon")) {
		p->_daemon = true;
	} else if (!strcmp(key, "system")) {
		p->_system = rz_str_dup(value);
	} else if (!strcmp(key, "runlib")) {
		p->_runlib = rz_str_dup(value);
	} else if (!strcmp(key, "runlib.fcn")) {
		p->_runlib_fcn = rz_str_dup(value);
	} else if (!strcmp(key, "aslr")) {
		p->_aslr = parse_bool(value);
	} else if (!strcmp(key, "pid")) {
		p->_pid = parse_bool(value);
	} else if (!strcmp(key, "pidfile")) {
		p->_pidfile = rz_str_dup(value);
	} else if (!strcmp(key, "connect")) {
		p->_connect = rz_str_dup(value);
	} else if (!strcmp(key, "listen")) {
		p->_listen = rz_str_dup(value);
	} else if (!strcmp(key, "pty")) {
		p->_pty = parse_bool(value);
	} else if (!strcmp(key, "stdio")) {
		if (value[0] == '!') {
			p->_stdio = rz_str_dup(value);
		} else {
			p->_stdout = rz_str_dup(value);
			p->_stderr = rz_str_dup(value);
			p->_stdin = rz_str_dup(value);
		}
	} else if (!strcmp(key, "stdout")) {
		p->_stdout = rz_str_dup(value);
	} else if (!strcmp(key, "stdin")) {
		p->_stdin = rz_str_dup(value);
	} else if (!strcmp(key, "stderr")) {
		p->_stderr = rz_str_dup(value);
	} else if (!strcmp(key, "input")) {
		p->_input = rz_str_dup(value);
	} else if (!strcmp(key, "chdir")) {
		p->_chgdir = rz_str_dup(value);
	} else if (!strcmp(key, "core")) {
		p->_docore = parse_bool(value);
	} else if (!strcmp(key, "fork")) {
		p->_dofork = parse_bool(value);
	} else if (!strcmp(key, "sleep")) {
		p->_rzsleep = atoi(value);
	} else if (!strcmp(key, "maxstack")) {
		p->_maxstack = atoi(value);
	} else if (!strcmp(key, "maxproc")) {
		p->_maxproc = atoi(value);
	} else if (!strcmp(key, "maxfd")) {
		p->_maxfd = atoi(value);
	} else if (!strcmp(key, "bits")) {
		p->_bits = atoi(value);
	} else if (!strcmp(key, "chroot")) {
		p->_chroot = rz_str_dup(value);
	} else if (!strcmp(key, "libpath")) {
		p->_libpath = rz_str_dup(value);
	} else if (!strcmp(key, "preload")) {
		p->_preload = rz_str_dup(value);
	} else if (!strcmp(key, "rzpreload")) {
		p->_rzpreload = parse_bool(value);
	} else if (!strcmp(key, "setuid")) {
		p->_setuid = rz_str_dup(value);
	} else if (!strcmp(key, "seteuid")) {
		p->_seteuid = rz_str_dup(value);
	} else if (!strcmp(key, "setgid")) {
		p->_setgid = rz_str_dup(value);
	} else if (!strcmp(key, "setegid")) {
		p->_setegid = rz_str_dup(value);
	} else if (!strcmp(key, "nice")) {
		p->_nice = atoi(value);
	} else if (!strcmp(key, "timeout")) {
		p->_timeout = atoi(value);
	} else if (!strcmp(key, "timeoutsig")) {
		p->_timeout_sig = rz_signal_from_string(value);
	} else if (!memcmp(b, "arg", 3)) {
		int n = atoi(b + 3);
		if (n >= 0 && n < RZ_RUN_PROFILE_NARGS) {
			p->_args[n] = resolve_value(value, NULL);
			p->_argc++;
		} else {
			RZ_LOG_ERROR("rz-run: out of bounds args index: %d\n", n);
		}
	} else if (!strcmp(key, "envfile")) {
		char *p, buf[1024];
		size_t len;
		FILE *fd = rz_sys_fopen(value, "r");
		if (!fd) {
			RZ_LOG_ERROR("rz-run: cannot open '%s'\n", value);
			free(key);
			free(value);
			return false;
		}
		for (;;) {
			if (!fgets(buf, sizeof(buf), fd)) {
				break;
			}
			if (feof(fd)) {
				break;
			}
			p = strchr(buf, '=');
			if (p) {
				*p++ = 0;
				len = strlen(p);
				if (len > 0 && p[len - 1] == '\n') {
					p[len - 1] = 0;
				}
				if (len > 1 && p[len - 2] == '\r') {
					p[len - 2] = 0;
				}
				rz_sys_setenv(buf, p);
			}
		}
		fclose(fd);
	} else if (!strcmp(key, "unsetenv")) {
		rz_sys_setenv(value, NULL);
	} else if (!strcmp(key, "setenv")) {
		char *key2 = NULL, *value2 = NULL;
		if (!parse_key_value(value, &key2, &value2)) {
			free(key);
			free(value);
			return false;
		}
		char *V = resolve_value(value2, NULL);
		if (V) {
			rz_sys_setenv(key2, V);
			free(V);
		}
		free(key2);
		free(value2);
	}
	free(key);
	free(value);
	return true;
}

#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
static int fd_forward(int in_fd, int out_fd, char **buff) {
	int size = 0;

	if (ioctl(in_fd, FIONREAD, &size) == -1) {
		perror("ioctl");
		return -1;
	}
	if (!size) { // child process exited or socket is closed
		return -1;
	}

	char *new_buff = realloc(*buff, size);
	if (!new_buff) {
		RZ_LOG_ERROR("rz-run: Failed to allocate buffer for redirection");
		return -1;
	}
	*buff = new_buff;
	if (read(in_fd, *buff, size) != size) {
		perror("read");
		return -1;
	}
	if (write(out_fd, *buff, size) != size) {
		perror("write");
		return -1;
	}

	return 0;
}
#endif

static int redirect_socket_to_stdio(RzSocket *sock) {
	close(0);
	close(1);
	close(2);

	dup2(sock->fd, 0);
	dup2(sock->fd, 1);
	dup2(sock->fd, 2);

	return 0;
}

#if __WINDOWS__
static void *exit_process(void *user) {
	int timeout = (int)(void *)user;
	rz_sys_sleep(timeout);
	RZ_LOG_DEBUG("rz_run: Interrupted by timeout\n");
	exit(0);
	return NULL;
}
#endif

static int redirect_socket_to_pty(RzSocket *sock) {
#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
	// directly duplicating the fds using dup2() creates problems
	// in case of interactive applications
	int fdm, fds;

	if (!dyn_openpty || (dyn_openpty && dyn_openpty(&fdm, &fds, NULL, NULL, NULL) == -1)) {
		perror("opening pty");
		return -1;
	}

	pid_t child_pid = rz_sys_fork();

	if (child_pid == -1) {
		RZ_LOG_ERROR("rz-run: cannot fork\n");
		close(fdm);
		close(fds);
		return -1;
	}

	if (child_pid == 0) {
		// child process
		close(fds);

		char *buff = NULL;
		int sockfd = sock->fd;
		int max_fd = fdm > sockfd ? fdm : sockfd;

		while (true) {
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(fdm, &readfds);
			FD_SET(sockfd, &readfds);

			if (select(max_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
				perror("select error");
				break;
			}

			if (FD_ISSET(fdm, &readfds)) {
				if (fd_forward(fdm, sockfd, &buff) != 0) {
					break;
				}
			}

			if (FD_ISSET(sockfd, &readfds)) {
				if (fd_forward(sockfd, fdm, &buff) != 0) {
					break;
				}
			}
		}

		free(buff);
		close(fdm);
		rz_socket_free(sock);
		exit(0);
	}

	// parent
	rz_socket_close_fd(sock);
	if (dyn_login_tty) {
		dyn_login_tty(fds);
	}
	close(fdm);

	// disable the echo on slave stdin
	struct termios t;
	tcgetattr(0, &t);
	cfmakeraw(&t);
	tcsetattr(0, TCSANOW, &t);

	return 0;
#else
	// Fallback to socket to I/O redirection
	return redirect_socket_to_stdio(sock);
#endif
}

RZ_API int rz_run_config_env(RzRunProfile *p) {
	int ret;

#if HAVE_OPENPTY && HAVE_FORKPTY && HAVE_LOGIN_TTY
	dyn_init();
#endif

	if (!p->_program && !p->_system && !p->_runlib) {
		RZ_LOG_ERROR("rz-run: No program, system or runlib rule defined\n");
		return 1;
	}
	// when IO is redirected to a process, handle them together
	if (handle_redirection(p->_stdio, true, true, false) != 0) {
		return 1;
	}
	if (handle_redirection(p->_stdin, true, false, false) != 0) {
		return 1;
	}
	if (handle_redirection(p->_stdout, false, true, false) != 0) {
		return 1;
	}
	if (handle_redirection(p->_stderr, false, false, true) != 0) {
		return 1;
	}
	if (p->_aslr != -1) {
		rz_sys_aslr(p->_aslr);
	}
#if __UNIX__
	set_limit(p->_docore, RLIMIT_CORE, RLIM_INFINITY);
	if (p->_maxfd) {
		set_limit(p->_maxfd, RLIMIT_NOFILE, p->_maxfd);
	}
#ifdef RLIMIT_NPROC
	if (p->_maxproc) {
		set_limit(p->_maxproc, RLIMIT_NPROC, p->_maxproc);
	}
#endif
	if (p->_maxstack) {
		set_limit(p->_maxstack, RLIMIT_STACK, p->_maxstack);
	}
#else
	if (p->_docore || p->_maxfd || p->_maxproc || p->_maxstack)
		RZ_LOG_WARN("rz-run: setrlimits not supported for this platform\n");
#endif
	if (p->_connect) {
		char *q = strchr(p->_connect, ':');
		if (q) {
			RzSocket *fd = rz_socket_new(0);
			*q = 0;
			if (!rz_socket_connect_tcp(fd, p->_connect, q + 1, 30)) {
				RZ_LOG_ERROR("rz-run: cannot connect\n");
				return 1;
			}
			if (p->_pty) {
				if (redirect_socket_to_pty(fd) != 0) {
					RZ_LOG_ERROR("rz-run: socket redirection failed\n");
					rz_socket_free(fd);
					return 1;
				}
			} else {
				redirect_socket_to_stdio(fd);
			}
		} else {
			RZ_LOG_ERROR("rz-run: Invalid format for connect. missing ':'\n");
			return 1;
		}
	}
	if (p->_listen) {
		RzSocket *child, *fd = rz_socket_new(0);
		bool is_child = false;
		if (!rz_socket_listen(fd, p->_listen, NULL)) {
			RZ_LOG_ERROR("rz-run: cannot listen\n");
			rz_socket_free(fd);
			return 1;
		}
		while (true) {
			child = rz_socket_accept(fd);
			if (child) {
				is_child = true;

				if (p->_dofork && !p->_dodebug) {
					pid_t child_pid = rz_sys_fork();
					if (child_pid == -1) {
						RZ_LOG_ERROR("rz-run: cannot fork\n");
						rz_socket_free(child);
						rz_socket_free(fd);
						return 1;
					} else if (child_pid != 0) {
						// parent code
						is_child = false;
					}
				}

				if (is_child) {
					rz_socket_close_fd(fd);
					RZ_LOG_ERROR("rz-run: connected\n");
					if (p->_pty) {
						if (redirect_socket_to_pty(child) != 0) {
							RZ_LOG_ERROR("rz-run: socket redirection failed\n");
							rz_socket_free(child);
							rz_socket_free(fd);
							return 1;
						}
					} else {
						redirect_socket_to_stdio(child);
					}
					break;
				} else {
					rz_socket_close_fd(child);
				}
			}
		}
		if (!is_child) {
			rz_socket_free(child);
		}
		rz_socket_free(fd);
	}
	if (p->_rzsleep != 0) {
		rz_sys_sleep(p->_rzsleep);
	}
#if __UNIX__
	if (p->_chroot) {
		if (chdir(p->_chroot) == -1) {
			RZ_LOG_ERROR("rz-run: cannot chdir to chroot in %s\n", p->_chroot);
			return 1;
		} else {
			if (chroot(".") == -1) {
				RZ_LOG_ERROR("rz-run: cannot chroot to %s\n", p->_chroot);
				return 1;
			} else {
				// Silenting pedantic meson flags...
				if (chdir("/") == -1) {
					RZ_LOG_ERROR("rz-run: cannot chdir to /\n");
					return 1;
				}
				if (p->_chgdir) {
					if (chdir(p->_chgdir) == -1) {
						RZ_LOG_ERROR("rz-run: cannot chdir after chroot to %s\n", p->_chgdir);
						return 1;
					}
				}
			}
		}
	} else if (p->_chgdir) {
		if (chdir(p->_chgdir) == -1) {
			RZ_LOG_ERROR("rz-run: cannot chdir after chroot to %s\n", p->_chgdir);
			return 1;
		}
	}
#else
	if (p->_chgdir) {
		ret = chdir(p->_chgdir);
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_chroot) {
		ret = chdir(p->_chroot);
		if (ret < 0) {
			return 1;
		}
	}
#endif
#if __UNIX__
	if (p->_setuid) {
		ret = setgroups(0, NULL);
		if (ret < 0) {
			return 1;
		}
		ret = setuid(atoi(p->_setuid));
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_seteuid) {
		ret = seteuid(atoi(p->_seteuid));
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_setgid) {
		ret = setgid(atoi(p->_setgid));
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_input) {
		int f2[2];
		if (rz_sys_pipe(f2, true) != -1) {
			close(0);
			dup2(f2[0], 0);
		} else {
			RZ_LOG_ERROR("rz-run: cannot create pipe\n");
			return 1;
		}
		size_t inpl = 0;
		char *inp = resolve_value(p->_input, &inpl);
		if (inp) {
			if (write(f2[1], inp, inpl) != inpl) {
				RZ_LOG_ERROR("rz-run: cannot write to the pipe\n");
			}
			rz_sys_pipe_close(f2[1]);
			free(inp);
		} else {
			RZ_LOG_ERROR("rz-run: Invalid input\n");
		}
	}
#endif
	if (p->_rzpreload) {
		if (p->_preload) {
			RZ_LOG_WARN("rz-run: only one library can be opened at a time\n");
			free(p->_preload);
		}
		char *libdir = rz_path_libdir();
		p->_preload = rz_file_path_join(libdir, "librz." RZ_LIB_EXT);
		free(libdir);
	}
	if (p->_libpath) {
#if __WINDOWS__
		RZ_LOG_ERROR("rz-run: libpath unsupported for this platform\n");
#elif __HAIKU__
		char *orig = rz_sys_getenv("LIBRARY_PATH");
		char *newlib = rz_str_newf("%s:%s", p->_libpath, orig);
		rz_sys_setenv("LIBRARY_PATH", newlib);
		free(newlib);
		free(orig);
#elif __APPLE__
		rz_sys_setenv("DYLD_LIBRARY_PATH", p->_libpath);
#else
		rz_sys_setenv("LD_LIBRARY_PATH", p->_libpath);
#endif
	}
	if (p->_preload) {
#if __APPLE__
		// 10.6
#ifndef __MAC_10_7
		rz_sys_setenv("DYLD_PRELOAD", p->_preload);
#endif
		rz_sys_setenv("DYLD_INSERT_LIBRARIES", p->_preload);
		// 10.8
		rz_sys_setenv("DYLD_FORCE_FLAT_NAMESPACE", "1");
#else
		rz_sys_setenv("LD_PRELOAD", p->_preload);
#endif
	}
	if (p->_timeout) {
#if __UNIX__
		int mypid = getpid();
		if (!rz_sys_fork()) {
			int use_signal = p->_timeout_sig;
			if (use_signal < 1) {
				use_signal = SIGKILL;
			}
			sleep(p->_timeout);
			if (!kill(mypid, 0)) {
				// eprintf ("\nrz_run: Interrupted by timeout\n");
			}
			kill(mypid, use_signal);
			exit(0);
		}
#else
		if (p->_timeout_sig < 1 || p->_timeout_sig == 9) {
			rz_th_new(exit_process, (void *)p->_timeout);
		} else {
			RZ_LOG_ERROR("rz-run: timeout with signal not supported for this platform\n");
		}
#endif
	}
	return 0;
}

// NOTE: return value is like in unix return code (0 = ok, 1 = not ok)
RZ_API int rz_run_start(RzRunProfile *p) {
	if (p->_execve) {
		exit(rz_sys_execv(p->_program, (char *const *)p->_args));
	}
#if __APPLE__ && HAVE_FORK
	posix_spawnattr_t attr = { 0 };
	pid_t pid = -1;
	int ret;
	posix_spawnattr_init(&attr);
	if (p->_args[0]) {
		char **envp = rz_sys_get_environ();
		short spflags = POSIX_SPAWN_SETEXEC;

		// https://opensource.apple.com/source/gdb/gdb-2831/src/gdb/macosx/macosx-nat-inferior.c.auto.html
		if (p->_aslr != -1 && p->_aslr) {
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
			spflags |= _POSIX_SPAWN_DISABLE_ASLR;
#undef _POSIX_SPAWN_DISABLE_ASLR
		}
		(void)posix_spawnattr_setflags(&attr, spflags);
		if (p->_bits) {
			size_t copied = 1;
			cpu_type_t cpu;
#if __i386__ || __x86_64__
			cpu = CPU_TYPE_I386;
			if (p->_bits == 64) {
				cpu |= CPU_ARCH_ABI64;
			}
#else
			cpu = CPU_TYPE_ANY;
#endif
			posix_spawnattr_setbinpref_np(
				&attr, 1, &cpu, &copied);
		}
		ret = posix_spawnp(&pid, p->_args[0], NULL, &attr, p->_args, envp);
		if (ret) {
			RZ_LOG_ERROR("rz-run: posix_spawnp: %s\n", strerror(ret));
		}
		exit(ret);
	}
#endif
	if (p->_system) {
		if (p->_pid) {
			RZ_LOG_ERROR("rz-run: PID: Cannot determine pid with 'system' directive. Use 'program'.\n");
		}
		if (p->_daemon) {
#if __WINDOWS__
			//		eprintf ("PID: Cannot determine pid with 'system' directive. Use 'program'.\n");
#else
			pid_t child = rz_sys_fork();
			if (child == -1) {
				perror("fork");
				exit(1);
			}
			if (child) {
				if (p->_pidfile) {
					char pidstr[32];
					snprintf(pidstr, sizeof(pidstr), "%d\n", child);
					rz_file_dump(p->_pidfile,
						(const ut8 *)pidstr,
						strlen(pidstr), 0);
				}
				exit(0);
			}
			setsid();
			if (p->_timeout) {
#if __UNIX__
				int mypid = getpid();
				if (!rz_sys_fork()) {
					int use_signal = p->_timeout_sig;
					if (use_signal < 1) {
						use_signal = SIGKILL;
					}
					sleep(p->_timeout);
					if (!kill(mypid, 0)) {
						// eprintf ("\nrz_run: Interrupted by timeout\n");
					}
					kill(mypid, use_signal);
					exit(0);
				}
#else
				RZ_LOG_ERROR("rz-run: timeout not supported for this platform\n");
#endif
			}
#endif
#if __UNIX__
			close(0);
			close(1);
			char *bin_sh = rz_file_binsh();
			int ret = rz_sys_execl(bin_sh, "sh", "-c", p->_system, NULL);
			free(bin_sh);
			exit(ret);
#else
			exit(rz_sys_system(p->_system));
#endif
		} else {
			if (p->_pidfile) {
				RZ_LOG_WARN("pidfile doesnt work with 'system'.\n");
			}
			exit(rz_sys_system(p->_system));
		}
	}
	if (p->_program) {
		if (!rz_file_exists(p->_program)) {
			char *progpath = rz_file_path(p->_program);
			if (progpath && *progpath) {
				free(p->_program);
				p->_program = progpath;
			} else {
				free(progpath);
				RZ_LOG_ERROR("rz-run: %s: file not found\n", p->_program);
				return 1;
			}
		}
#if __UNIX__
		// XXX HACK close all non-tty fds
		{
			int i;
			for (i = 3; i < 1024; i++) {
				close(i);
			}
		}
		// TODO: use posix_spawn
		if (p->_setgid) {
			int ret = setgid(atoi(p->_setgid));
			if (ret < 0) {
				return 1;
			}
		}
		if (p->_pid) {
			RZ_LOG_WARN("rz-run: PID: %d\n", getpid());
		}
		if (p->_pidfile) {
			char pidstr[32];
			snprintf(pidstr, sizeof(pidstr), "%d\n", getpid());
			rz_file_dump(p->_pidfile,
				(const ut8 *)pidstr,
				strlen(pidstr), 0);
		}
#endif

		if (p->_nice) {
#if HAVE_NICE
			if (nice(p->_nice) == -1) {
				return 1;
			}
#else
			RZ_LOG_ERROR("rz-run: nice not supported for this platform\n");
#endif
		}
		if (p->_daemon) {
#if __WINDOWS__
			RZ_LOG_ERROR("rz-run: PID: Cannot determine pid with 'system' directive. Use 'program'.\n");
#else
			pid_t child = rz_sys_fork();
			if (child == -1) {
				perror("fork");
				exit(1);
			}
			if (child) {
				if (p->_pidfile) {
					char pidstr[32];
					snprintf(pidstr, sizeof(pidstr), "%d\n", child);
					rz_file_dump(p->_pidfile,
						(const ut8 *)pidstr,
						strlen(pidstr), 0);
					exit(0);
				}
			}
			setsid();
			exit(rz_sys_execv(p->_program, (char *const *)p->_args));
#endif
		}
		exit(rz_sys_execv(p->_program, (char *const *)p->_args));
	}
	if (p->_runlib) {
		if (!p->_runlib_fcn) {
			RZ_LOG_ERROR("rz-run: no function specified. Please set runlib.fcn\n");
			return 1;
		}
		void *addr = rz_sys_dlopen(p->_runlib);
		if (!addr) {
			RZ_LOG_ERROR("rz-run: could not load the library '%s'\n", p->_runlib);
			return 1;
		}
		void (*fcn)(void) = rz_sys_dlsym(addr, p->_runlib_fcn);
		if (!fcn) {
			RZ_LOG_ERROR("rz-run: could not find the function '%s'\n", p->_runlib_fcn);
			return 1;
		}
		switch (p->_argc) {
		case 0:
			fcn();
			break;
		case 1:
			rz_run_call1(fcn, p->_args[1]);
			break;
		case 2:
			rz_run_call2(fcn, p->_args[1], p->_args[2]);
			break;
		case 3:
			rz_run_call3(fcn, p->_args[1], p->_args[2], p->_args[3]);
			break;
		case 4:
			rz_run_call4(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4]);
			break;
		case 5:
			rz_run_call5(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5]);
			break;
		case 6:
			rz_run_call6(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6]);
			break;
		case 7:
			rz_run_call7(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7]);
			break;
		case 8:
			rz_run_call8(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7], p->_args[8]);
			break;
		case 9:
			rz_run_call9(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7], p->_args[8], p->_args[9]);
			break;
		case 10:
			rz_run_call10(fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7], p->_args[8], p->_args[9], p->_args[10]);
			break;
		default:
			RZ_LOG_ERROR("rz-run: too many arguments.\n");
			return 1;
		}
		rz_sys_dlclose(addr);
	}
	return 0;
}

RZ_API char *rz_run_get_environ_profile(char **env) {
	if (!env) {
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	while (*env) {
		char *k = rz_str_dup(*env);
		char *v = strchr(k, '=');
		if (v) {
			*v++ = 0;
			RzStrEscOptions opt = { 0 };
			opt.show_asciidot = false;
			opt.esc_bslash = true;
			v = rz_str_escape_8bit(v, true, &opt);
			if (v) {
				rz_strbuf_appendf(sb, "setenv=%s='%s'\n", k, v);
				free(v);
			}
		}
		free(k);
		env++;
	}
	return rz_strbuf_drain(sb);
}
