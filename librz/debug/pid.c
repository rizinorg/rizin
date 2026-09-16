// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API RzDebugProcess *rz_debug_pid_new(const char *path, int pid, int uid, char status, ut64 pc) {
	RzDebugProcess *p = RZ_NEW0(RzDebugProcess);
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

RZ_API RzDebugProcess *rz_debug_pid_free(RzDebugProcess *pid) {
	free(pid->path);
	free(pid);
	return NULL;
}

RZ_API RzList /*<RzDebugProcess *>*/ *rz_debug_pids(RzDebug *dbg, int pid) {
	if (dbg && dbg->cur && dbg->cur->pids) {
		return dbg->cur->pids(dbg, pid);
	}
	return NULL;
}

/* processes */
RZ_API int rz_debug_pid_parent(RzDebugProcess *pid) {
	// fork in child
	return 0;
}

/* status */
RZ_API int rz_debug_pid_set_state(struct rz_debug_t *dbg, int status) {
	return true;
}

/* status */
RZ_API struct rz_debug_pid_t *rz_debug_pid_get_status(struct rz_debug_t *dbg, int pid) {
	return NULL;
}

RZ_API RzDebugThread *rz_debug_thread_new(int tid, int pid, RzDebugThreadState state, ut64 pc) {
	RzDebugThread *th = RZ_NEW0(RzDebugThread);
	if (!th) {
		return NULL;
	}
	th->tid = tid;
	th->process_pid = pid;
	th->pc = pc;
	th->state = state;

	return th;
}

RZ_API RzDebugThread *rz_debug_thread_free(RzDebugThread *th) {
	free(th->native);
	free(th);
	return NULL;
}
