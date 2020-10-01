/* radare - LGPL - Copyright 2014-2020 - pancake */

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
	DB = sdb_new (NULL, "signals", 0);
	for (i=0; signals[i].k; i++) {
		sdb_set (DB, signals[i].k, signals[i].v, 0);
		sdb_set (DB, signals[i].v, signals[i].k, 0);
	}
}

static bool siglistcb (void *p, const char *k, const char *v) {
	static char key[32] = "cfg.";
	RzDebug *dbg = (RzDebug *)p;
	int opt, mode = dbg->_mode;
	if (atoi (k) > 0) {
		strncpy (key + 4, k, 20);
		opt = sdb_num_get (DB, key, 0);
		if (opt) {
			rz_cons_printf ("%s %s", k, v);
			if (opt & R_DBG_SIGNAL_CONT) {
				rz_cons_strcat (" cont");
			}
			if (opt & R_DBG_SIGNAL_SKIP) {
				rz_cons_strcat (" skip");
			}
			rz_cons_newline ();
		} else {
			if (mode == 0) {
				rz_cons_printf ("%s %s\n", k, v);
			}
		}
	}
	return true;
}

static bool siglistjsoncb (void *p, const char *k, const char *v) {
	static char key[32] = "cfg.";
	RzDebug *dbg = (RzDebug *)p;
	int opt;
	if (atoi (k)>0) {
		strncpy (key + 4, k, 20);
		opt = (int)sdb_num_get (DB, key, 0);
		if (dbg->_mode == 2) {
			dbg->_mode = 0;
		} else {
			rz_cons_strcat (",");
		}
		rz_cons_printf ("{\"signum\":\"%s\",\"name\":\"%s\",\"option\":", k, v);
		if (opt & R_DBG_SIGNAL_CONT) {
			rz_cons_strcat ("\"cont\"");
		} else if (opt & R_DBG_SIGNAL_SKIP) {
			rz_cons_strcat ("\"skip\"");
		} else {
			rz_cons_strcat ("null");
		}
		rz_cons_strcat ("}");
	}
	return true;
}

RZ_API void rz_debug_signal_list(RzDebug *dbg, int mode) {
	dbg->_mode = mode;
	switch (mode) {
	case 0:
	case 1:
		sdb_foreach (DB, siglistcb, dbg);
		break;
	case 2:
		rz_cons_strcat ("[");
		sdb_foreach (DB, siglistjsoncb, dbg);
		rz_cons_strcat ("]");
		rz_cons_newline();
		break;
	}
	dbg->_mode = 0;
}

RZ_API int rz_debug_signal_send(RzDebug *dbg, int num) {
	return rz_sandbox_kill (dbg->pid, num);
}

RZ_API void rz_debug_signal_setup(RzDebug *dbg, int num, int opt) {
	sdb_queryf (DB, "cfg.%d=%d", num, opt);
}

RZ_API int rz_debug_signal_what(RzDebug *dbg, int num) {
	char k[32];
	snprintf (k, sizeof (k), "cfg.%d", num);
	return sdb_num_get (DB, k, 0);
}

RZ_API int rz_debug_signal_set(RzDebug *dbg, int num, ut64 addr) {
	// TODO
	// rz_debug_syscall (dbg, "signal", "addr");
	return 0;
}

/* TODO rename to _kill_ -> _signal_ */
RZ_API RzList *rz_debug_kill_list(RzDebug *dbg) {
	if (dbg->h->kill_list) {
		return dbg->h->kill_list (dbg);
	}
	return NULL;
}

RZ_API int rz_debug_kill_setup(RzDebug *dbg, int sig, int action) {
	eprintf ("TODO: set signal handlers of child\n");
	// TODO: must inject code to call signal()
#if 0
	if (dbg->h->kill_setup)
		return dbg->h->kill_setup (dbg, sig, action);
#endif
	// TODO: implement rz_debug_kill_setup
	return false;
}
