// SPDX-FileCopyrightText: 2017-2020 polsha3 <polsha3@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include <signal.h>
#include <stddef.h>

static struct {
	const char *name;
	int code;
} signals[] = {
	{ "SIGINT", SIGINT },
	{ "SIGILL", SIGILL },
	{ "SIGABRT", SIGABRT },
	{ "SIGFPE", SIGFPE },
	{ "SIGSEGV", SIGSEGV },
	{ "SIGTERM", SIGTERM },
#if __LINUX__
	{ "SIGSTKFLT", SIGSTKFLT },
	{ "SIGWINCH", SIGWINCH },
	{ "SIGIO", SIGIO },
	{ "SIGPWR", SIGPWR },
	{ "SIGPOLL", SIGPOLL },
#endif
#if !__WINDOWS__
	{ "SIGHUP", SIGHUP },
	{ "SIGQUIT", SIGQUIT },
	{ "SIGTRAP", SIGTRAP },
	{ "SIGBUS", SIGBUS },
	{ "SIGKILL", SIGKILL },
	{ "SIGUSR1", SIGUSR1 },
	{ "SIGUSR2", SIGUSR2 },
	{ "SIGPIPE", SIGPIPE },
	{ "SIGALRM", SIGALRM },
	{ "SIGCHLD", SIGCHLD },
	{ "SIGCONT", SIGCONT },
	{ "SIGSTOP", SIGSTOP },
	{ "SIGTSTP", SIGTSTP },
	{ "SIGTTIN", SIGTTIN },
	{ "SIGTTOU", SIGTTOU },
	{ "SIGURG", SIGURG },
	{ "SIGXCPU", SIGXCPU },
	{ "SIGXFSZ", SIGXFSZ },
	{ "SIGVTALRM", SIGVTALRM },
	{ "SIGPROF", SIGPROF },
	{ "SIGSYS", SIGSYS },
#endif
	{ NULL }
};

RZ_API int rz_signal_from_string(const char *e) {
	int i;
	for (i = 1; signals[i].name; i++) {
		const char *str = signals[i].name;
		if (!strcmp(e, str)) {
			return signals[i].code;
		}
	}
	return atoi(e);
}

RZ_API const char *rz_signal_to_string(int code) {
	int i;
	for (i = 1; signals[i].name; i++) {
		if (signals[i].code == code) {
			return signals[i].name;
		}
	}
	return NULL;
}

#if HAVE_PTHREAD
RZ_API void rz_signal_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask) {
	pthread_sigmask(how, newmask, oldmask);
}
#endif
