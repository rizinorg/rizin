// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API RzDebugPid *rz_debug_pid_new(const char *path, int pid, int uid, char status, ut64 pc) {
	RzDebugPid *p = RZ_NEW0(RzDebugPid);
	if (!p) {
		return NULL;
	}
	p->path = rz_str_dup(path);
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

RZ_API RzList /*<RzDebugPid *>*/ *rz_debug_pids(RzDebug *dbg, int pid) {
	if (dbg && dbg->cur && dbg->cur->pids) {
		return dbg->cur->pids(dbg, pid);
	}
	return NULL;
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
