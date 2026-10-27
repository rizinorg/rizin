// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

/**
 * \brief Creates a new process.
 * \param path Executable path, may be NULL.
 * \param pid Process ID.
 * \param uid User ID owning the process.
 * \param state Initial process state.
 * \return The new process, or NULL on allocation failure.
 */
RZ_API RZ_OWN RzDebugProcess *rz_debug_process_new(RZ_NULLABLE const char *path, int pid, int uid, RzDebugProcessState state) {
	RzDebugProcess *process = RZ_NEW0(RzDebugProcess);
	if (!process) {
		return NULL;
	}
	process->path = rz_str_dup(path);
	process->pid = pid;
	process->uid = uid;
	process->state = state;
	process->runnable = true;
	return process;
}

/**
 * \brief Frees a process together with the threads it owns.
 * \param process The process to free, may be NULL.
 */
RZ_API void rz_debug_process_free(RZ_NULLABLE RzDebugProcess *process) {
	if (!process) {
		return;
	}
	rz_list_free(process->threads);
	free(process->path);
	free(process);
}

/**
 * \brief Lists processes from the current debug plugin.
 * \param dbg The debug context.
 * \param pid Process ID to list with its children, or 0 for all processes.
 * \return List of processes, or NULL if the plugin does not support it.
 */
RZ_API RZ_OWN RzList /*<RzDebugProcess *>*/ *rz_debug_process_list(RZ_NONNULL RzDebug *dbg, int pid) {
	rz_return_val_if_fail(dbg, NULL);
	if (dbg->cur && dbg->cur->pids) {
		return dbg->cur->pids(dbg, pid);
	}
	return NULL;
}

/**
 * \brief Finds a tracked process by its ID.
 * \param dbg The debug context.
 * \param pid Process ID.
 * \return The process, or NULL if it is not tracked.
 */
RZ_API RZ_BORROW RzDebugProcess *rz_debug_process_find(RZ_NONNULL RzDebug *dbg, int pid) {
	rz_return_val_if_fail(dbg, NULL);
	RzListIter *it;
	RzDebugProcess *process;
	rz_list_foreach (dbg->processes, it, process) {
		if (process->pid == pid) {
			return process;
		}
	}
	return NULL;
}

/**
 * \brief Removes a tracked process and frees it together with its threads.
 * \param dbg The debug context.
 * \param pid Process ID.
 */
RZ_API void rz_debug_process_remove(RZ_NONNULL RzDebug *dbg, int pid) {
	rz_return_if_fail(dbg);
	RzDebugProcess *process = rz_debug_process_find(dbg, pid);
	if (!process) {
		return;
	}
	RzListIter *it;
	RzDebugThread *thread;
	rz_list_foreach (process->threads, it, thread) {
		ht_up_delete(dbg->threads, (ut64)thread->tid); // unindex before the free
	}
	rz_list_delete_val(dbg->processes, process);
	// rz_list_delete_data(dbg->processes, process);
	if (pid == dbg->pid) {
		dbg->n_threads = 0;
	}
}

/**
 * \brief Creates a new thread.
 * \param tid Thread ID.
 * \param process_pid ID of the process owning the thread.
 * \param state Initial thread state.
 * \param pc Program counter of the thread.
 * \return The new thread, or NULL on allocation failure.
 */
RZ_API RZ_OWN RzDebugThread *rz_debug_thread_new(int tid, int process_pid, RzDebugThreadState state, ut64 pc) {
	RzDebugThread *thread = RZ_NEW0(RzDebugThread);
	if (!thread) {
		return NULL;
	}
	thread->tid = tid;
	thread->process_pid = process_pid;
	thread->state = state;
	thread->pc = pc;
	return thread;
}

/**
 * \brief Frees a thread and its OS-specific data.
 * \param thread The thread to free, may be NULL.
 */
RZ_API void rz_debug_thread_free(RZ_NULLABLE RzDebugThread *thread) {
	if (!thread) {
		return;
	}
	free(thread->native);
	free(thread);
}

/**
 * \brief Finds a tracked thread by its ID.
 * \param dbg The debug context.
 * \param tid Thread ID.
 * \return The thread, or NULL if it is not tracked.
 */
RZ_API RZ_BORROW RzDebugThread *rz_debug_thread_find(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, NULL);
	return dbg->threads ? ht_up_find(dbg->threads, (ut64)tid, NULL) : NULL;
}

/**
 * \brief Gets the ID of the process owning a thread.
 * \param dbg The debug context.
 * \param tid Thread ID.
 * \return The owning process ID, or dbg->pid if the thread is not tracked.
 */
RZ_API int rz_debug_thread_owner_pid(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, -1);
	RzDebugThread *thread = rz_debug_thread_find(dbg, tid);
	return thread ? thread->process_pid : dbg->pid;
}

/**
 * \brief Adds a thread to a process and indexes it by its ID.
 * \param dbg The debug context.
 * \param process The process that takes ownership of the thread.
 * \param thread The thread to add.
 * \return True on success, false otherwise (ownership is not taken on failure).
 */
RZ_API bool rz_debug_thread_add(RZ_NONNULL RzDebug *dbg, RZ_NONNULL RzDebugProcess *process, RZ_NONNULL RZ_OWN RzDebugThread *thread) {
	rz_return_val_if_fail(dbg && process && thread, false);
	if (!dbg->threads && !(dbg->threads = ht_up_new(NULL, NULL))) { // non-owning index
		return false;
	}
	if (!process->threads && !(process->threads = rz_list_newf((RzListFree)rz_debug_thread_free))) {
		return false;
	}
	if (!rz_list_append(process->threads, thread)) {
		return false;
	}
	ht_up_update(dbg->threads, (ut64)thread->tid, thread);
	if (process->pid == dbg->pid) {
		dbg->n_threads = rz_list_length(process->threads);
	}
	return true;
}

/**
 * \brief Removes a tracked thread from its process and frees it.
 * \param dbg The debug context.
 * \param tid Thread ID.
 */
RZ_API void rz_debug_thread_remove(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_if_fail(dbg);
	RzDebugThread *thread = rz_debug_thread_find(dbg, tid);
	if (!thread) {
		return;
	}
	ht_up_delete(dbg->threads, (ut64)tid); // unindex before the free
	RzDebugProcess *process = rz_debug_process_find(dbg, thread->process_pid);
	if (process && process->threads) {
		rz_list_delete_val(process->threads, thread);
		// rz_list_delete_data(process->threads, thread);
		if (process->pid == dbg->pid) {
			dbg->n_threads = rz_list_length(process->threads);
		}
	}
}

/**
 * \brief Switches to the first thread in the given debug context.
 * \param debug The debug context.
 */
RZ_API void rz_debug_switch_to_first_thread(RZ_NONNULL RzDebug *dbg) {
	rz_return_if_fail(dbg);
	RzDebugProcess *proc = rz_debug_process_find(dbg, dbg->pid);
	RzList *threads = proc->threads;
	if (rz_list_length(threads) > 0) {
		RzDebugThread *th = rz_list_first_val(threads);
		rz_debug_select(dbg, dbg->pid, th->tid);
	}
	rz_list_free(threads);
}