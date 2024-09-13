// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

#include "xnu_debug.h"
#include "xnu_threads.h"

static void xnu_thread_free(xnu_thread_t *thread) {
	kern_return_t kr;
	if (!thread) {
		return;
	}
	free(thread->name);
	// if we free our thread from the list we need to decrement the ref
	// count
	kr = mach_port_deallocate(mach_task_self(), thread->port);
	if (kr != KERN_SUCCESS) {
		eprintf("failed to deallocate thread port\n");
	}
	free(thread);
}

RZ_IPI bool rz_xnu_thread_get_drx(RzXnuDebug *ctx, xnu_thread_t *thread) {
	rz_return_val_if_fail(ctx && thread, false);
	kern_return_t rc;
#if __x86_64__ || __i386__
	thread->flavor = x86_DEBUG_STATE;
	thread->count = x86_DEBUG_STATE_COUNT;
	thread->state_size = ctx->cpu == CPU_TYPE_X86_64
		? sizeof(x86_debug_state64_t)
		: sizeof(x86_debug_state32_t);
	thread->state = &thread->drx.uds;
	rc = thread_get_state(thread->port, thread->flavor,
		(thread_state_t)&thread->drx, &thread->count);
#elif __arm64__ || __arm64 || __aarch64 || __aarch64__
	if (ctx->cpu == CPU_TYPE_ARM64) {
		thread->count = ARM_DEBUG_STATE64_COUNT;
		thread->flavor = ARM_DEBUG_STATE64;
		rc = thread_get_state(thread->port, thread->flavor,
			(thread_state_t)&thread->debug.drx64,
			&thread->count);
	} else {
		thread->count = ARM_DEBUG_STATE32_COUNT;
		thread->flavor = ARM_DEBUG_STATE32;
		rc = thread_get_state(thread->port, thread->flavor,
			(thread_state_t)&thread->debug.drx32,
			&thread->count);
	}
#elif __arm__ || __arm || __armv7__
	thread->count = ARM_DEBUG_STATE_COUNT;
	thread->flavor = ARM_DEBUG_STATE;
	rc = thread_get_state(thread->port, thread->flavor,
		(thread_state_t)&thread->debug.drx,
		&thread->count);
#else
#warning xnu_thread_get_drx: Unsupported architecture
	rc = KERN_FAILURE;
#endif
	if (rc != KERN_SUCCESS) {
		LOG_MACH_ERROR("thread_get_state", rc);
		thread->count = 0;
		return false;
	}
	return true;
}

RZ_IPI bool rz_xnu_thread_set_drx(RzXnuDebug *ctx, xnu_thread_t *thread) {
	rz_return_val_if_fail(ctx && thread, false);
	kern_return_t rc;
#if __i386__ || __x86_64__
	x86_debug_state_t *regs = &thread->drx;
	if (!regs) {
		return false;
	}
	thread->flavor = x86_DEBUG_STATE;
	thread->count = x86_DEBUG_STATE_COUNT;
	if (ctx->cpu == CPU_TYPE_X86_64) {
		regs->dsh.flavor = x86_DEBUG_STATE64;
		regs->dsh.count = x86_DEBUG_STATE64_COUNT;
	} else {
		regs->dsh.flavor = x86_DEBUG_STATE32;
		regs->dsh.count = x86_DEBUG_STATE32_COUNT;
	}
	rc = thread_set_state(thread->port, thread->flavor,
		(thread_state_t)regs, thread->count);
#elif __arm64__ || __arm64 || __aarch64 || __aarch64__
	if (ctx->cpu == CPU_TYPE_ARM64) {
		thread->count = ARM_DEBUG_STATE64_COUNT;
		thread->flavor = ARM_DEBUG_STATE64;
		rc = thread_set_state(thread->port, thread->flavor,
			(thread_state_t)&thread->debug.drx64,
			thread->count);
	} else {
		thread->count = ARM_DEBUG_STATE32_COUNT;
		thread->flavor = ARM_DEBUG_STATE32;
		rc = thread_set_state(thread->port, thread->flavor,
			(thread_state_t)&thread->debug.drx32,
			thread->count);
	}
#elif __arm__ || __arm || __armv7__
	thread->count = ARM_DEBUG_STATE_COUNT;
	thread->flavor = ARM_DEBUG_STATE;
	rc = thread_set_state(thread->port, thread->flavor,
		(thread_state_t)&thread->debug.drx,
		&thread->count);
#elif __POWERPC__
/* not supported */
#ifndef PPC_DEBUG_STATE32
#define PPC_DEBUG_STATE32 1
#endif
	// ppc_debug_state_t *regs;
	// thread->flavor = PPC_DEBUG_STATE32;
	// thread->count  = RZ_MIN (thread->count, sizeof (regs->uds.ds32));
	return false;
#else
	regs->dsh.flavor = 0;
	thread->count = 0;
#endif
	if (rc != KERN_SUCCESS) {
		LOG_MACH_ERROR("thread_set_state", rc);
		thread->count = 0;
		return false;
	}
	return true;
}

RZ_IPI bool rz_xnu_thread_set_gpr(RzXnuDebug *ctx, xnu_thread_t *thread) {
	rz_return_val_if_fail(ctx && thread, false);
	kern_return_t rc;
	RZ_REG_T *regs = (RZ_REG_T *)&thread->gpr;
	if (!regs) {
		return false;
	}
#if __i386__ || __x86_64__
	// thread->flavor is used in a switch+case but in regs->tsh.flavor we
	// specify
	thread->state = &regs->uts;
	// thread->state = regs;
	thread->flavor = x86_THREAD_STATE;
	thread->count = x86_THREAD_STATE_COUNT;
	if (ctx->cpu == CPU_TYPE_X86_64) {
		regs->tsh.flavor = x86_THREAD_STATE64;
		regs->tsh.count = x86_THREAD_STATE64_COUNT;
	} else {
		regs->tsh.flavor = x86_THREAD_STATE32;
		regs->tsh.count = x86_THREAD_STATE32_COUNT;
	}
#elif __arm64 || __aarch64 || __arm64__ || __aarch64__
#if 0
	/* unified doesnt seems to work */
	thread->flavor = ARM_UNIFIED_THREAD_STATE;
	thread->count = ARM_UNIFIED_THREAD_STATE_COUNT;
#endif
	thread->state = &regs;
	if (ctx->cpu == CPU_TYPE_ARM64) {
		thread->flavor = ARM_THREAD_STATE64;
		thread->count = ARM_THREAD_STATE64_COUNT;
		thread->state_size = sizeof(arm_thread_state64_t);
	} else {
		thread->flavor = ARM_THREAD_STATE32;
		thread->count = ARM_THREAD_STATE32_COUNT;
		thread->state_size = sizeof(arm_thread_state32_t);
	}
#elif __arm || __arm__ || __armv7__
	thread->flavor = ARM_THREAD_STATE;
	thread->count = ARM_THREAD_STATE_COUNT;
	thread->state_size = sizeof(arm_thread_state_t);

#endif
	rc = thread_set_state(thread->port, thread->flavor,
		(thread_state_t)regs, thread->count);
	if (rc != KERN_SUCCESS) {
		LOG_MACH_ERROR("thread_set_state", rc);
		thread->count = 0;
		return false;
	}
	return true;
}

RZ_IPI bool rz_xnu_thread_get_gpr(RzXnuDebug *ctx, xnu_thread_t *thread) {
	rz_return_val_if_fail(ctx && thread, false);
	RZ_REG_T *regs = &thread->gpr;
	if (!regs) {
		return false;
	}
	kern_return_t rc;
#if __POWERPC__
	thread->state = regs;
#elif __arm64 || __aarch64 || __aarch64__ || __arm64__
	thread->state = regs;
	if (ctx->cpu == CPU_TYPE_ARM64) {
		thread->flavor = ARM_THREAD_STATE64;
		thread->count = ARM_THREAD_STATE64_COUNT;
		thread->state_size = sizeof(arm_thread_state64_t);
	} else {
		thread->flavor = ARM_THREAD_STATE;
		thread->count = ARM_THREAD_STATE_COUNT;
		thread->state_size = sizeof(arm_thread_state32_t);
	}
#elif __arm || __arm__ || __armv7__
	thread->state = regs;
	thread->flavor = ARM_THREAD_STATE;
	thread->count = ARM_THREAD_STATE_COUNT;
	thread->state_size = sizeof(arm_thread_state_t);
#elif __x86_64__ || __i386__
	thread->state = &regs->uts;
	thread->flavor = x86_THREAD_STATE;
	thread->count = x86_THREAD_STATE_COUNT;
	thread->state_size = (ctx->cpu == CPU_TYPE_X86_64) ? sizeof(x86_thread_state64_t) : sizeof(x86_thread_state32_t);
#endif
	rc = thread_get_state(thread->port, thread->flavor,
		(thread_state_t)regs, &thread->count);
	if (rc != KERN_SUCCESS) {
		LOG_MACH_ERROR("thread_get_state", rc);
		thread->count = 0;
		return false;
	}
	return true;
}

static bool xnu_fill_info_thread(RzDebug *dbg, xnu_thread_t *thread) {
#if !defined(MAC_OS_X_VERSION_10_6)
	// THREAD_IDENTIFIER_INFO introduced in 10.6
	// TODO: use e.g. only basic info as a fallback here
	thread->name = rz_str_dup("unknown");
	return false;
#else
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	thread_identifier_info_data_t identifier_info;
	kern_return_t kr = thread_info(thread->port, THREAD_BASIC_INFO,
		(thread_info_t)&thread->basic_info, &count);
	if (kr != KERN_SUCCESS) {
		eprintf("Fail to get thread_basic_info\n");
		return false;
	}
	count = THREAD_IDENTIFIER_INFO_COUNT;
	kr = thread_info(thread->port, THREAD_IDENTIFIER_INFO,
		(thread_info_t)&identifier_info, &count);
	if (kr != KERN_SUCCESS) {
		eprintf("Fail to get thread_identifier_info\n");
		return false;
	}
	RZ_FREE(thread->name);
#if TARGET_OS_IPHONE
	// TODO proc_pidinfo here
	thread->name = rz_str_dup("unknown");
#else
	struct proc_threadinfo proc_threadinfo;
	int ret_proc = proc_pidinfo(dbg->pid, PROC_PIDTHREADINFO,
		identifier_info.thread_handle,
		&proc_threadinfo, PROC_PIDTHREADINFO_SIZE);
	if (ret_proc && proc_threadinfo.pth_name[0]) {
		thread->name = rz_str_dup(proc_threadinfo.pth_name);
	} else {
		thread->name = rz_str_dup("unknown");
	}
#endif
#endif
	return true;
}

static xnu_thread_t *xnu_get_thread_with_info(RzDebug *dbg, thread_t port) {
	xnu_thread_t *thread = RZ_NEW0(xnu_thread_t);
	if (!thread) {
		return NULL;
	}
	thread->port = port;
	if (!xnu_fill_info_thread(dbg, thread)) {
		free(thread->name);
		thread->name = rz_str_dup("unknown");
	}
	return thread;
}

static int xnu_update_thread_info(RzDebug *dbg, xnu_thread_t *thread) {
	if (!xnu_fill_info_thread(dbg, thread)) {
		free(thread->name);
		thread->name = rz_str_dup("unknown");
	}
	return true;
}

static int thread_find(thread_t *port, xnu_thread_t *a, void *user) {
	return (a && port && (a->port == *port)) ? 0 : 1;
}

RZ_IPI int rz_xnu_update_thread_list(RzDebug *dbg) {
	rz_return_val_if_fail(dbg && dbg->plugin_data, false);
	RzXnuDebug *ctx = dbg->plugin_data;
	thread_array_t thread_list = NULL;
	unsigned int thread_count = 0;
	xnu_thread_t *thread;
	kern_return_t kr;
	task_t task;
	int i;

	if (!dbg->threads) {
		dbg->threads = rz_list_newf((RzListFree)&xnu_thread_free);
		if (!dbg->threads) {
			return false;
		}
	}
	// ok we have the list that will hold our threads, now is time to get
	// them
	task = pid_to_task(ctx, dbg->pid);
	if (!task) {
		return false;
	}
	kr = task_threads(task, &thread_list, &thread_count);
	if (kr != KERN_SUCCESS) {
		// we can get into this when the process has terminated but we
		// still hold the old task because we are caching it
		eprintf("Failed to get list of task's threads\n");
		return false;
	}
	if (rz_list_empty(dbg->threads)) {
		// it's the first time write all threads inside the list
		for (i = 0; i < thread_count; i++) {
			thread = xnu_get_thread_with_info(dbg, thread_list[i]);
			if (!thread) {
				eprintf("Failed to fill_thread\n");
				continue;
			}
			if (!rz_list_append(dbg->threads, thread)) {
				eprintf("Failed to add thread to list\n");
				xnu_thread_free(thread);
			}
		}
	} else {
		RzListIter *iter, *iter2;
		// first pass to get rid of those threads that are not longer
		// alive
		rz_list_foreach_safe (dbg->threads, iter, iter2, thread) {
			bool flag = true; // this flag will denote when delete
					  // a thread
			for (i = 0; i < thread_count; i++) {
				if (thread->port == thread_list[i]) {
					flag = false;
					break;
				}
			}
			if (flag) {
				// it is not longer alive so remove from the
				// list
				rz_list_delete(dbg->threads, iter);
			} else {
				// otherwise update the info
				xnu_update_thread_info(dbg, thread);
			}
		}
		// ok now we have to insert those threads that we don't have
		for (i = 0; i < thread_count; i++) {
			xnu_thread_t *t;
			iter = rz_list_find(dbg->threads, &thread_list[i],
				(RzListComparator)&thread_find, NULL);
			// it means is already in our list
			if (iter) {
				// free the ownership over the thread
				kr = mach_port_deallocate(mach_task_self(),
					thread_list[i]);
				if (kr != KERN_SUCCESS) {
					eprintf("Failed to deallocate port\n");
				}
				continue;
			}
			// otherwise insert it
			t = xnu_get_thread_with_info(dbg, thread_list[i]);
			rz_list_append(dbg->threads, t);
		}
	}
	// once that is over we need to free the buffer
	(void)vm_deallocate(mach_task_self(), (mach_vm_address_t)thread_list,
		thread_count * sizeof(thread_t));
	return true;
}

RZ_IPI xnu_thread_t *rz_xnu_get_thread(RzDebug *dbg, int tid) {
	if (!dbg || tid < 0) {
		return NULL;
	}
	if (!rz_xnu_update_thread_list(dbg)) {
		eprintf("Failed to update thread_list xnu_udpate_thread_list\n");
		return NULL;
	}
	// TODO get the current thread
	RzListIter *it = rz_list_find(dbg->threads, (const void *)(size_t)&tid,
		(RzListComparator)&thread_find, NULL);
	if (!it) {
		tid = rz_xnu_get_cur_thread(dbg);
		it = rz_list_find(dbg->threads, (const void *)(size_t)&tid,
			(RzListComparator)&thread_find, NULL);
		if (!it) {
			eprintf("Thread not found get_xnu_thread\n");
			return NULL;
		}
	}
	return (xnu_thread_t *)rz_list_iter_get_data(it);
}

/* XXX: right now it just returns the first thread, not the one selected in dbg->tid */
RZ_IPI thread_t rz_xnu_get_cur_thread(RzDebug *dbg) {
	rz_return_val_if_fail(dbg && dbg->plugin_data, -1);
	RzXnuDebug *ctx = dbg->plugin_data;
	thread_t th;
	thread_array_t threads = NULL;
	unsigned int n_threads = 0;
	task_t t = pid_to_task(ctx, dbg->pid);
	if (!t) {
		return -1;
	}
	if (task_threads(t, &threads, &n_threads) != KERN_SUCCESS) {
		return -1;
	}
	if (n_threads > 0) {
		memcpy(&th, threads, sizeof(th));
	} else {
		th = -1;
	}
	vm_deallocate(mach_task_self(), (vm_address_t)threads, n_threads * sizeof(thread_act_t));
	return th;
}
