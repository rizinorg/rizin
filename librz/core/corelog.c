/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <rz_core.h>

RZ_API int rz_core_log_list(RzCore *core, int n, int nth, char fmt) {
	int printed = 0;
	int count = 0, i, idx, id = core->log->first;
	RStrpool *sp = core->log->sp;
	char *str = sp->str;

	if (fmt == 'j') {
		rz_cons_printf ("[");
	}
	for (i = idx = 0; str && *str; i++, id++) {
		if ((n && n <= id) || !n) {
			switch (fmt) {
			case 'j':
				rz_cons_printf ("%s[%d,\"%s\"]",
					printed? ",": "", id, str);
				break;
			case 't':
				rz_cons_println (str);
				break;
			case '*':
				rz_cons_printf ("\"T %s\"\n", str);
				break;
			default:
				rz_cons_printf ("%d %s\n", id, str);
				break;
			}
			printed++;
			if (nth && printed >= nth) {
				break;
			}
		}
		str = rz_strpool_next (sp, idx);
		if (!str) {
			break;
		}
		idx = rz_strpool_get_index (sp, str);
		count++;
	}
	if (fmt == 'j') {
		rz_cons_printf ("]\n");
	}
	return count;
}

RZ_API RzCoreLog *rz_core_log_new(void) {
	RzCoreLog *log = RZ_NEW0 (RzCoreLog);
	if (!log) {
		return NULL;
	}
	rz_core_log_init (log);
	return log;
}

RZ_API void rz_core_log_init(RzCoreLog *log) {
	log->first = 1;
	log->last = 1;
	log->sp = rz_strpool_new (0);
}

RZ_API void rz_core_log_free(RzCoreLog *log) {
	rz_strpool_free (log->sp);
	free (log);
}

RZ_API bool rz_core_log_run(RzCore *core, const char *_buf, RzCoreLogCallback runLine) {
	char *obuf = strdup (_buf);
	char *buf = obuf;
	while (buf) {
		char *nl = strchr (buf, '\n');
		if (nl) {
			*nl = 0;
		}
		char *sp = strchr (buf, ' ');
		if (sp) {
			runLine (core, atoi (buf), sp + 1);
		}
		if (nl) {
			buf = nl + 1;
		} else {
			break;
		}
	}
	free (obuf);
	return true;
}

RZ_API char *rz_core_log_get(RzCore *core, int index) {
	const char *host = rz_config_get (core->config, "http.sync");
	if (host && *host) {
		char *url = index > 0
			? rz_str_newf ("%s/cmd/T%%20%d", host, index)
			: rz_str_newf ("%s/cmd/T", host);
		char *res = rz_socket_http_get (url, NULL, NULL);
		free (url);
		return res? res: strdup ("");
	}
	return NULL;
}

RZ_API void rz_core_log_add(RzCore *core, const char *msg) {
	static bool inProcess = false;
	rz_strpool_append (core->log->sp, msg);
	core->log->last++;
	if (core->cmdlog && *core->cmdlog) {
		if (inProcess) {
			// avoid infinite recursive calls
			return;
		}
		inProcess = true;
		rz_core_cmd0 (core, core->cmdlog);
		inProcess = false;
	}
}

RZ_API void rz_core_log_del(RzCore *core, int n) {
	int idx;
	if (n > 0) {
		if (n + 1 >= core->log->last) {
			core->log->first = core->log->last;
			rz_strpool_empty (core->log->sp);
			return;
		}
		if (n < core->log->first) {
			return;
		}
		idx = n - core->log->first;
		if (idx < 0) {
			return;
		}
		core->log->first += idx + 1;
		char *msg = rz_strpool_get_i (core->log->sp, idx);
		// if (idx >= core->log->last) {
		if (!msg || !*msg) {
			core->log->first = core->log->last;
			rz_strpool_empty (core->log->sp);
		} else {
			rz_strpool_slice (core->log->sp, idx);
		}
	} else {
		core->log->first = core->log->last;
		rz_strpool_empty (core->log->sp);
	}
}
