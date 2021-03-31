// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API RzDebugPid *rz_debug_pid_new(const char *path, int pid, int uid, char status, ut64 pc) {
	RzDebugPid *p = RZ_NEW0(RzDebugPid);
	if (!p) {
		return NULL;
	}
	p->path = strdup(path);
	p->pid = pid;
	p->uid = uid;
	p->status = status;
	p->runnable = true;
	p->pc = pc;
	return p;
}

RZ_API RzDebugPid *rz_debug_pid_free(RzDebugPid *pid) {
	free(pid->path);
	free(pid);
	return NULL;
}

RZ_API RzList *rz_debug_pids(RzDebug *dbg, int pid) {
	if (dbg && dbg->h && dbg->h->pids) {
		return dbg->h->pids(dbg, pid);
	}
	return NULL;
}

// TODO: deprecate list/iterate functions from core apis? keep them for easiness?
RZ_API int rz_debug_pid_list(RzDebug *dbg, int pid, char fmt) {
	RzList *list;
	RzListIter *iter;
	RzDebugPid *p;
	if (dbg && dbg->h && dbg->h->pids) {
		list = dbg->h->pids(dbg, RZ_MAX(0, pid));
		if (!list) {
			return false;
		}
		PJ *j = pj_new();
		pj_a(j);
		rz_list_foreach (list, iter, p) {
			switch (fmt) {
			case 'j':
				pj_o(j);
				pj_kb(j, "current", dbg->pid == p->pid);
				pj_ki(j, "ppid", p->ppid);
				pj_ki(j, "pid", p->pid);
				pj_ki(j, "uid", p->uid);
				pj_ks(j, "status", &p->status);
				pj_ks(j, "path", p->path);
				pj_end(j);
				break;
			default:
				dbg->cb_printf(" %c %d ppid:%d uid:%d %c %s\n",
					dbg->pid == p->pid ? '*' : '-',
					p->pid, p->ppid, p->uid, p->status, p->path);
				break;
			}
		}
		pj_end(j);
		if (fmt == 'j') {
			dbg->cb_printf("%s", pj_string(j));
		}
		pj_free(j);
		rz_list_free(list);
	}
	return false;
}

RZ_API int rz_debug_thread_list(RzDebug *dbg, int pid, char fmt) {
	RzList *list;
	RzListIter *iter;
	RzDebugPid *p;
	RzAnalysisFunction *fcn = NULL;
	RzDebugMap *map = NULL;
	RzStrBuf *path = NULL;
	if (pid == -1) {
		return false;
	}
	if (dbg && dbg->h && dbg->h->threads) {
		list = dbg->h->threads(dbg, pid);
		if (!list) {
			return false;
		}
		PJ *j = pj_new();
		pj_a(j);
		rz_list_foreach (list, iter, p) {
			path = rz_strbuf_new("");
			if (p->pc != 0) {
				map = rz_debug_map_get(dbg, p->pc);
				if (map && map->name && map->name[0]) {
					rz_strbuf_appendf(path, "%s ", map->name);
				}

				rz_strbuf_appendf(path, "(0x%" PFMT64x ")", p->pc);

				fcn = rz_analysis_get_fcn_in(dbg->analysis, p->pc, 0);
				if (fcn) {
					rz_strbuf_appendf(path, " in %s+0x%" PFMT64x, fcn->name, (p->pc - fcn->addr));
				}
			}
			switch (fmt) {
			case 'j':
				pj_o(j);
				pj_kb(j, "current", dbg->tid == p->pid);
				pj_ki(j, "pid", p->pid);
				pj_ks(j, "status", &p->status);
				pj_ks(j, "path", rz_strbuf_get(path));
				pj_end(j);
				break;
			default:
				dbg->cb_printf(" %c %d %c %s\n",
					dbg->tid == p->pid ? '*' : '-',
					p->pid, p->status, rz_strbuf_get(path));
				break;
			}
			rz_strbuf_free(path);
		}
		pj_end(j);
		if (fmt == 'j') {
			dbg->cb_printf("%s", pj_string(j));
		}
		pj_free(j);
		rz_list_free(list);
	}
	return false;
}

/* processes */
RZ_API int rz_debug_pid_parent(RzDebugPid *pid) {
	// fork in child
	return 0;
}

#if 0
RZ_API int rz_debug_pid_del(struct rz_debug_t *dbg) {
	// kill da child
	return true;
}

/* threads */
RZ_API int rz_debug_pid_add_thread(struct rz_debug_t *dbg) {
	// create a thread in process
	return true;
}

RZ_API int rz_debug_pid_del_thread(struct rz_debug_t *dbg) {
	// kill a thread in process
	return true;
}
#endif

/* status */
RZ_API int rz_debug_pid_set_state(struct rz_debug_t *dbg, int status) {
	return true;
}

/* status */
RZ_API struct rz_debug_pid_t *rz_debug_pid_get_status(struct rz_debug_t *dbg, int pid) {
	return NULL;
}
