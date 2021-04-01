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
		sdb_set(DB, signals[i].k, signals[i].v, 0);
		sdb_set(DB, signals[i].v, signals[i].k, 0);
	}
}

static bool siglistcb(void *p, const char *k, const char *v) {
	static char key[32] = "cfg.";
	RzDebug *dbg = (RzDebug *)p;
	int opt, mode = dbg->_mode;
	if (atoi(k) > 0) {
		strncpy(key + 4, k, 20);
		opt = sdb_num_get(DB, key, 0);
		if (opt) {
			rz_cons_printf("%s %s", k, v);
			if (opt & RZ_DBG_SIGNAL_CONT) {
				rz_cons_strcat(" cont");
			}
			if (opt & RZ_DBG_SIGNAL_SKIP) {
				rz_cons_strcat(" skip");
			}
			rz_cons_newline();
		} else {
			if (mode == 0) {
				rz_cons_printf("%s %s\n", k, v);
			}
		}
	}
	return true;
}

struct debug_pj {
	RzDebug *dbg;
	PJ *pj;
};

static bool siglistjsoncb(void *p, const char *k, const char *v) {
	static char key[32] = "cfg.";
	struct debug_pj *dpj = (struct debug_pj *)p;
	int opt;
	if (atoi(k) > 0) {
		strncpy(key + 4, k, 20);
		opt = (int)sdb_num_get(dpj->dbg->sgnls, key, 0);
		if (dpj->dbg->_mode == 2) {
			dpj->dbg->_mode = 0;
		}
		pj_o(dpj->pj);
		pj_ks(dpj->pj, "signum", k);
		pj_ks(dpj->pj, "name", v);
		if (opt & RZ_DBG_SIGNAL_CONT) {
			pj_ks(dpj->pj, "option", "cont");
		} else if (opt & RZ_DBG_SIGNAL_SKIP) {
			pj_ks(dpj->pj, "option", "skip");
		} else {
			pj_knull(dpj->pj, "option");
		}
		pj_end(dpj->pj);
	}
	return true;
}

RZ_API void rz_debug_signal_list(RzDebug *dbg, RzOutputMode mode) {
	dbg->_mode = mode;
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = pj_new();
		if (!pj) {
			break;
		}
		struct debug_pj dpj = { dbg, pj };
		pj_a(pj);
		sdb_foreach(DB, siglistjsoncb, &dpj);
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
	default:
		sdb_foreach(DB, siglistcb, dbg);
		break;
	}
	dbg->_mode = 0;
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
	return sdb_num_get(DB, k, 0);
}

RZ_API int rz_debug_signal_set(RzDebug *dbg, int num, ut64 addr) {
	// TODO
	// rz_debug_syscall (dbg, "signal", "addr");
	return 0;
}

/* TODO rename to _kill_ -> _signal_ */
RZ_API RzList *rz_debug_kill_list(RzDebug *dbg) {
	if (dbg->h->kill_list) {
		return dbg->h->kill_list(dbg);
	}
	return NULL;
}

RZ_API int rz_debug_kill_setup(RzDebug *dbg, int sig, int action) {
	eprintf("TODO: set signal handlers of child\n");
	// TODO: must inject code to call signal()
#if 0
	if (dbg->h->kill_setup)
		return dbg->h->kill_setup (dbg, sig, action);
#endif
	// TODO: implement rz_debug_kill_setup
	return false;
}
