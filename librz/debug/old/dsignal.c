// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

#define DB dbg->sgnls

// TODO: this must be done by the debugger plugin
// which is stored already in SDB.. but this is faster :P
static struct {
	const char *k;
	const char *v;
} signals[] = {
	// hardcoded from linux
	{ "SIGHUP", "1" },
	{ "SIGINT", "2" },
	{ "SIGQUIT", "3" },
	{ "SIGILL", "4" },
	{ "SIGTRAP", "5" },
	{ "SIGABRT", "6" },
	// { "SIGIOT", "6" },
	{ "SIGBUS", "7" },
	{ "SIGFPE", "8" },
	{ "SIGKILL", "9" },
	{ "SIGUSR1", "10" },
	{ "SIGSEGV", "11" },
	{ "SIGUSR2", "12" },
	{ "SIGPIPE", "13" },
	{ "SIGALRM", "14" },
	{ "SIGTERM", "15" },
	{ "SIGSTKFLT", "16" },
	{ "SIGCHLD", "17" },
	{ "SIGCONT", "18" },
	{ "SIGSTOP", "19" },
	{ "SIGTSTP", "20" },
	{ "SIGTTIN", "21" },
	{ "SIGTTOU", "22" },
	{ "SIGURG", "23" },
	{ "SIGXCPU", "24" },
	{ "SIGXFSZ", "25" },
	{ "SIGVTALRM", "26" },
	{ "SIGPROF", "27" },
	{ "SIGWINCH", "28" },
	{ "SIGIO", "29" },
	{ "SIGPOLL", "SIGIO" },
	{ "SIGLOST", "29" },
	{ "SIGPWR", "30" },
	{ "SIGSYS", "31" },
	{ "SIGRTMIN", "32" },
	{ "SIGRTMAX", "NSIG" },
	{ NULL }
};

RZ_API void rz_debug_signal_init(RzDebug *dbg) {
	int i;
	// XXX
	DB = sdb_new(NULL, "signals", 0);
	for (i = 0; signals[i].k; i++) {
		sdb_set(DB, signals[i].k, signals[i].v);
		sdb_set(DB, signals[i].v, signals[i].k);
	}
}

RZ_API int rz_debug_signal_send(RzDebug *dbg, int num) {
	return rz_sys_kill(dbg->pid, num);
}

RZ_API void rz_debug_signal_setup(RzDebug *dbg, int num, int opt) {
	sdb_queryf(DB, "cfg.%d=%d", num, opt);
}

RZ_API int rz_debug_signal_what(RzDebug *dbg, int num) {
	char k[32];
	snprintf(k, sizeof(k), "cfg.%d", num);
	return sdb_num_get(DB, k);
}

RZ_API int rz_debug_signal_set(RzDebug *dbg, int num, ut64 addr) {
	// TODO
	// rz_debug_syscall (dbg, "signal", "addr");
	return 0;
}

/* TODO rename to _kill_ -> _signal_ */
RZ_API RzList /*<void *>*/ *rz_debug_kill_list(RzDebug *dbg) {
	if (dbg->cur->kill_list) {
		return dbg->cur->kill_list(dbg);
	}
	return NULL;
}
