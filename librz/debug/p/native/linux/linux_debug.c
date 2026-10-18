// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include "linux_debug.h"
#include "../procfs.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>

#include "linux_ptrace.h"
#include "rz_debug.h"

#ifdef __GLIBC__
#define HAVE_YMM 1
#else
#define HAVE_YMM 0
#endif

#define PROC_NAME_SZ   1024
#define PROC_REGION_SZ 100
// PROC_REGION_SZ - 2 (used for `0x`). Due to how RZ_STR_DEF works this can't be
// computed.
#define PROC_REGION_LEFT_SZ 98
#define PROC_PERM_SZ        5
#define PROC_UNKSTR_SZ      128

#if (__i386__ || __x86_64__) && defined(PTRACE_GETREGSET) && defined(NT_X86_XSTATE)
long rz_debug_ptrace_get_x86_xstate(RzDebug *dbg, pid_t pid, struct iovec *iov) {
	if (!dbg->nt_x86_xstate_supported) {
		return -1;
	}

	long res = rz_debug_ptrace(dbg, PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, iov);
	if (res == -1) {
		if (errno == ENODEV) {
			// Ignore ENODEV error because it means the kernel does not support
			// NT_X86_XSTATE.
			dbg->nt_x86_xstate_supported = false;
			rz_sys_perror("PTRACE_GETREGSET/NT_X86_XSTATE");
			return -1;
		}

		rz_sys_perror("rz_debug_ptrace_get_x86_xstate");
		return -1;
	}
	return res;
}
#else
long rz_debug_ptrace_get_x86_xstate(RzDebug *dbg, pid_t pid, struct iovec *iov) {
	return -1;
}
#endif

static void linux_detach_all(RzDebug *dbg);
static char *read_link(int pid, const char *file);
static bool linux_attach_single_pid(RzDebug *dbg, int ptid);
static void linux_remove_thread(RzDebug *dbg, int tid);
static void linux_add_new_thread(RzDebug *dbg, int pid, int tid);
static bool linux_stop_thread(RzDebug *dbg, int tid);
static bool linux_kill_thread(int tid, int signo);
static void linux_dbg_wait_break(RzDebug *dbg);
static RzDebugReasonType linux_handle_new_task(RzDebug *dbg, int tid);
static RzDebugThread *fill_thread_state_info(const char *info, int tid, int process_pid);
static ut64 linux_get_pc_for_tid(RzDebug *dbg, int tid);
RzDebugProcess *fill_pid_info(const char *info, const char *path, int tid);

static RzDebugProcess *linux_find_process(RzDebug *dbg, int pid) {
	RzListIter *it;
	RzDebugProcess *p;
	rz_list_foreach (dbg->processes, it, p) {
		if (p->pid == pid) {
			return p;
		}
	}
	return NULL;
}

static RzDebugThread *linux_find_thread(RzDebug *dbg, int tid) {
	return dbg->threads ? (RzDebugThread *)ht_up_find(dbg->threads, (ut64)tid, NULL) : NULL;
}

static int linux_owner_pid(RzDebug *dbg, int tid) {
	RzDebugThread *th = linux_find_thread(dbg, tid);
	return th ? th->process_pid : dbg->pid;
}

/* thread list of the debugged (main) process, or NULL */
static RzList *linux_cur_threads(RzDebug *dbg) {
	RzDebugProcess *p = linux_find_process(dbg, dbg->pid);
	return p ? p->threads : NULL;
}

/* The ONLY way to add a thread: list owns it, index points to it. */
static bool linux_thread_add(RzDebug *dbg, RzDebugProcess *proc, RzDebugThread *th) {
	if (!dbg->threads) {
		dbg->threads = ht_up_new(NULL, rz_debug_thread_free); // non-owning; check the signature in your rizin version
		if (!dbg->threads) {
			return false;
		}
	}
	if (!proc->threads) {
		proc->threads = rz_list_newf((RzListFree)&rz_debug_thread_free);
		if (!proc->threads) {
			return false;
		}
	}
	if (!rz_list_append(proc->threads, th)) {
		return false;
	}
	ht_up_update(dbg->threads, (ut64)th->tid, th);
	if (proc->pid == dbg->pid) {
		dbg->n_threads = rz_list_length(proc->threads);
	}
	return true;
}

/* The ONLY way to remove a thread: unindex BEFORE the list frees it. */
static void linux_remove_thread(RzDebug *dbg, int tid) {
	RzDebugThread *th = linux_find_thread(dbg, tid);
	if (!th) {
		return;
	}
	ht_up_delete(dbg->threads, (ut64)tid);
	RzDebugProcess *proc = linux_find_process(dbg, th->process_pid);
	if (proc && proc->threads) {
		rz_list_delete_data(proc->threads, th); // free callback frees th
		if (proc->pid == dbg->pid) {
			dbg->n_threads = rz_list_length(proc->threads);
		}
	}
}

static void linux_remove_process(RzDebug *dbg, int pid) {
	RzDebugProcess *proc = linux_find_process(dbg, pid);
	if (!proc) {
		return;
	}
	RzListIter *it;
	RzDebugThread *th;
	rz_list_foreach (proc->threads, it, th) {
		ht_up_delete(dbg->threads, (ut64)th->tid);
	}
	rz_list_delete_data(dbg->processes, proc); // rz_debug_pid_free must free proc->threads
	if (pid == dbg->pid) {
		dbg->n_threads = 0;
	}
}

static RzDebugProcess *linux_new_process_info(int pid) {
	char path[PATH_MAX] = { 0 }, info[PATH_MAX] = { 0 };
	procfs_pid_slurp(pid, "cmdline", path, sizeof(path));
	if (!procfs_pid_slurp(pid, "status", info, sizeof(info))) {
		return fill_pid_info(info, path, pid);
	}
	return rz_debug_pid_new(path, pid, 0, RZ_DBG_PROC_STOP);
}

int linux_handle_signals(RzDebug *dbg, int tid) {
	siginfo_t siginfo = { 0 };
	int ret = rz_debug_ptrace(dbg, PTRACE_GETSIGINFO, tid, 0, (rz_ptrace_data_t)(size_t)&siginfo);
	if (ret == -1) {
		/* ESRCH means the process already went away :-/ */
		if (errno == ESRCH) {
			dbg->reason.type = RZ_DEBUG_REASON_DEAD;
			return true;
		}
		rz_sys_perror("ptrace GETSIGINFO");
		return false;
	}

	if (siginfo.si_signo > 0) {
		// siginfo_t newsiginfo = {0};
		// ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason.type = RZ_DEBUG_REASON_SIGNAL;
		dbg->reason.signum = siginfo.si_signo;
		dbg->stopaddr = (ut64)(size_t)siginfo.si_addr;
		// dbg->errno = siginfo.si_errno;
		//  siginfo.si_code -> HWBKPT, USER, KERNEL or WHAT
		//  TODO: DO MORE RDEBUGREASON HERE
		switch (dbg->reason.signum) {
		case SIGTRAP: {
			if (dbg->glob_libs || dbg->glob_unlibs) {
				ut64 pc_addr = rz_debug_reg_get(dbg, "PC");
				RzBreakpointItem *b = rz_bp_get_ending_at(dbg->bp, pc_addr);
				if (b && b->internal) {
					char *p = strstr(b->data, "dbg.");
					if (p) {
						if (rz_str_startswith(p, "dbg.libs")) {
							const char *name;
							if (strstr(b->data, "sym.imp.dlopen")) {
								name = rz_reg_get_name(dbg->reg, RZ_REG_NAME_A0);
							} else {
								name = rz_reg_get_name(dbg->reg, RZ_REG_NAME_A1);
							}
							b->data = rz_str_appendf(b->data, ";ps@r:%s", name);
							dbg->reason.type = RZ_DEBUG_REASON_NEW_LIB;
							break;
						} else if (rz_str_startswith(p, "dbg.unlibs")) {
							dbg->reason.type = RZ_DEBUG_REASON_EXIT_LIB;
							break;
						}
					}
				}
			}
			if (dbg->reason.type != RZ_DEBUG_REASON_NEW_LIB &&
				dbg->reason.type != RZ_DEBUG_REASON_EXIT_LIB) {
				if (siginfo.si_code == TRAP_TRACE) {
					dbg->reason.type = RZ_DEBUG_REASON_STEP;
				} else {
					dbg->reason.bp_addr = (ut64)(size_t)siginfo.si_addr;
					dbg->reason.type = RZ_DEBUG_REASON_BREAKPOINT;
					// Switch to the thread that hit the breakpoint
					rz_debug_select(dbg, dbg->pid, tid);
					dbg->tid = tid;
				}
			}
		} break;
		case SIGINT:
			dbg->reason.type = RZ_DEBUG_REASON_USERSUSP;
			break;
		case SIGABRT: // 6 / SIGIOT // SIGABRT
			dbg->reason.type = RZ_DEBUG_REASON_ABORT;
			break;
		case SIGSEGV:
			dbg->reason.type = RZ_DEBUG_REASON_SEGFAULT;
			break;
		case SIGCHLD:
			dbg->reason.type = RZ_DEBUG_REASON_SIGNAL;
			break;
		default:
			break;
		}
		if (dbg->reason.signum != SIGTRAP &&
			(dbg->reason.signum != SIGINT || !rz_interrupt_is_breaked(dbg->intr))) {
			rz_cons_printf(dbg->cons, "[+] SIGNAL %d errno=%d addr=0x%08" PFMT64x " code=%d si_pid=%d ret=%d\n",
				siginfo.si_signo, siginfo.si_errno,
				(ut64)(size_t)siginfo.si_addr, siginfo.si_code, siginfo.si_pid, ret);
		}
		return true;
	}
	return false;
}

#if __ANDROID__
#undef PT_GETEVENTMSG
#define PT_GETEVENTMSG
#endif

// Used to remove breakpoints before detaching from a fork, without it the child
// will die upon hitting a breakpoint while not being traced
static void linux_remove_fork_bps(RzDebug *dbg) {
	RzListIter *iter;
	RzBreakpointItem *b;
	int prev_pid = dbg->pid;
	int prev_tid = dbg->tid;

	// Set dbg tid to the new child temporarily
	dbg->pid = dbg->forked_pid;
	dbg->tid = dbg->forked_pid;
	rz_debug_select(dbg, dbg->forked_pid, dbg->forked_pid);

	// Unset all hw breakpoints in the child process
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_DRX, false);
	rz_list_foreach (dbg->bp->bps, iter, b) {
		rz_debug_drx_unset(dbg, rz_bp_get_index_at(dbg->bp, b->addr));
	}
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_DRX, true);

	// Unset software breakpoints in the child process
	rz_debug_bp_update(dbg);
	rz_bp_restore(dbg->bp, false);

	// Return to the parent
	dbg->pid = prev_pid;
	dbg->tid = prev_tid;
	rz_debug_select(dbg, dbg->pid, dbg->pid);

	// Restore sw breakpoints in the parent
	rz_bp_restore(dbg->bp, true);
}

#ifdef PT_GETEVENTMSG
/*
 * \brief Handle PTRACE_EVENT_* when receiving SIGTRAP
 *
 * \param dowait Do waitpid to consume any signal in the newly created task
 * \return RzDebugReasonType,
 * - RZ_DEBUG_REASON_UNKNOWN if the ptrace_event cannot be handled,
 * - RZ_DEBUG_REASON_ERROR if a ptrace command failed.
 *
 * NOTE: This API was added in Linux 2.5.46
 */
RzDebugReasonType linux_ptrace_event(RzDebug *dbg, int ptid, int status, bool dowait) {
	ut32 pt_evt;
#if __powerpc64__ || __arm64__ || __aarch64__ || __x86_64__ || (__riscv && __riscv_xlen == 64)
	ut64 data;
#else
	ut32 data;
#endif
	/* we only handle stops with SIGTRAP here */
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}

	pt_evt = status >> 16;
	switch (pt_evt) {
	case 0:
		/* NOTE: this case is handled by linux_handle_signals */
		break;
	case PTRACE_EVENT_CLONE:
		if (rz_debug_ptrace(dbg, PTRACE_GETEVENTMSG, ptid, 0, (rz_ptrace_data_t)(size_t)&data) == -1) {
			rz_sys_perror("ptrace GETEVENTMSG");
			return RZ_DEBUG_REASON_ERROR;
		}
		if (dowait) {
			if (waitpid((int)data, &status, 0) == -1) {
				perror("waitpid");
			}
		}
		/* the new thread belongs to whichever process the cloning thread belongs to */
		linux_add_new_thread(dbg, linux_owner_pid(dbg, ptid), (int)data);
		if (dbg->trace_clone) {
			rz_debug_select(dbg, dbg->pid, (int)data);
		}
		rz_cons_printf(dbg->cons, "(%d) Created thread %d\n", ptid, (int)data);
		return RZ_DEBUG_REASON_NEW_TID;
	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_FORK:
		if (rz_debug_ptrace(dbg, PTRACE_GETEVENTMSG, ptid, 0, (rz_ptrace_data_t)(size_t)&data) == -1) {
			rz_sys_perror("ptrace GETEVENTMSG");
			return RZ_DEBUG_REASON_ERROR;
		}
		dbg->forked_pid = data;
		if (dowait) {
			if (waitpid(dbg->forked_pid, &status, 0) == -1) {
				perror("waitpid");
			}
		}
		RzDebugProcess *forked_child = linux_new_process_info((int)data);
		if (forked_child) {
			forked_child->state = RZ_DBG_PROC_STOP;
			if (!dbg->processes || !rz_list_append(dbg->processes, forked_child)) {
				rz_debug_pid_free(forked_child);
			} else {
				RzDebugThread *main_th = rz_debug_thread_new((int)data, (int)data, RZ_DBG_THREAD_STOP, 0);
				if (main_th) {
					main_th->pc = linux_get_pc_for_tid(dbg, (int)data);
					if (!linux_thread_add(dbg, forked_child, main_th)) {
						rz_debug_thread_free(main_th);
					}
				}
			}
		}
		RZ_LOG_WARN("(%d) Created process %d\n", ptid, (int)data);
		if (!dbg->trace_forks && !dbg->follow_child) {
			linux_remove_fork_bps(dbg);
		}
		return RZ_DEBUG_REASON_NEW_PID;
	case PTRACE_EVENT_EXIT:
		// Get the exit status of the exiting task
		if (rz_debug_ptrace(dbg, PTRACE_GETEVENTMSG, ptid, 0, (rz_ptrace_data_t)(size_t)&data) == -1) {
			rz_sys_perror("ptrace GETEVENTMSG");
			return RZ_DEBUG_REASON_ERROR;
		}
		// TODO: Check other processes exit if dbg->trace_forks is on
		if (ptid != dbg->pid) {
			RZ_LOG_WARN("(%d) Thread exited with status=0x%" PFMT64x "\n", ptid, (ut64)data);
			return RZ_DEBUG_REASON_EXIT_TID;
		} else {
			RZ_LOG_WARN("(%d) Process exited with status=0x%" PFMT64x "\n", ptid, (ut64)data);
			return RZ_DEBUG_REASON_EXIT_PID;
		}
	default:
		RZ_LOG_ERROR("Unknown PTRACE_EVENT encountered: %d\n", pt_evt);
		break;
	}
	return RZ_DEBUG_REASON_UNKNOWN;
}
#endif

/*
 * \brief Search for the parent of the newly created task and
 * handle the pending SIGTRAP with PTRACE_EVENT_*
 *
 * \param tid, TID of the new task
 * \return RzDebugReasonType, Debug reason
 */
static RzDebugReasonType linux_handle_new_task(RzDebug *dbg, int tid) {
	int ret, status;
	RzListIter *pit, *it;
	RzDebugProcess *proc;
	RzDebugThread *th;
	rz_list_foreach (dbg->processes, pit, proc) {
		rz_list_foreach (proc->threads, it, th) {
			if (th->tid == tid) {
				continue;
			}
			siginfo_t siginfo = { 0 };
			ret = rz_debug_ptrace(dbg, PTRACE_GETSIGINFO, th->tid, 0, (rz_ptrace_data_t)(size_t)&siginfo);
			if (ret == -1) {
				continue;
			}
#ifdef PT_GETEVENTMSG
			if (siginfo.si_signo == SIGTRAP) {
				int pt_evt = siginfo.si_code >> 8;
				switch (pt_evt) {
				case PTRACE_EVENT_CLONE:
				case PTRACE_EVENT_VFORK:
				case PTRACE_EVENT_FORK:
					ret = waitpid(th->tid, &status, 0);
					return linux_ptrace_event(dbg, ret, status, false);
				default:
					break;
				}
			}
#endif
		}
	}
	return RZ_DEBUG_REASON_UNKNOWN;
}

int linux_step(RzDebug *dbg) {
	int ret = false;
	int pid = dbg->tid;
	ret = rz_debug_ptrace(dbg, PTRACE_SINGLESTEP, pid, 0, 0);
	// XXX(jjd): why?? //linux_handle_signals (dbg);
	if (ret == -1) {
		perror("native-singlestep");
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}

bool linux_set_options(RzDebug *dbg, int pid) {
	int traceflags = 0;
	traceflags |= PTRACE_O_TRACEFORK;
	traceflags |= PTRACE_O_TRACEVFORK;
	traceflags |= PTRACE_O_TRACECLONE;
	if (dbg->trace_forks) {
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	if (dbg->trace_aftersyscall) {
		traceflags |= PTRACE_O_TRACEEXIT;
	}
	/* SIGTRAP | 0x80 on signal handler .. not supported on all archs */
	traceflags |= PTRACE_O_TRACESYSGOOD;

	// PTRACE_SETOPTIONS can fail because of the asynchronous nature of ptrace
	// If the target is traced, the loop will always end with success
	while (rz_debug_ptrace(dbg, PTRACE_SETOPTIONS, pid, 0, (rz_ptrace_data_t)(size_t)traceflags) == -1) {
		void *bed = rz_interrupt_sleep_begin(dbg->intr);
		usleep(1000);
		rz_interrupt_sleep_end(dbg->intr, bed);
	}
	return true;
}

static void linux_detach_all(RzDebug *dbg) {
	RzList *th_list = linux_cur_threads(dbg);
	RzDebugThread *th;
	RzListIter *it;
	rz_list_foreach (th_list, it, th) {
		if (th->tid != dbg->pid) {
			if (rz_debug_ptrace(dbg, PTRACE_DETACH, th->tid, NULL, (rz_ptrace_data_t)(size_t)NULL) == -1) {
				perror("PTRACE_DETACH");
			}
		}
	}
	if (rz_debug_ptrace(dbg, PTRACE_DETACH, dbg->pid, NULL, (rz_ptrace_data_t)(size_t)NULL) == -1) {
		perror("PTRACE_DETACH");
	}
}

bool linux_attach_new_process(RzDebug *dbg, int pid) {
	linux_detach_all(dbg);
	linux_remove_process(dbg, dbg->pid); // unindexes its threads, then frees them

	if (!linux_attach(dbg, pid)) {
		return false;
	}
	dbg->pid = pid;
	dbg->tid = pid;
	rz_debug_select(dbg, pid, pid);
	return true;
}

bool linux_select(RzDebug *dbg, int pid, int tid) {
	if (dbg->pid != -1 && dbg->pid != pid) {
		/* already a tracee via a fork event: nothing to attach */
		if (linux_find_process(dbg, pid)) {
			return true;
		}
		return linux_attach_new_process(dbg, pid);
	}
	return linux_attach(dbg, tid);
}

static void linux_dbg_wait_break(RzDebug *dbg) {
	// Get the debugger and debuggee process group ID
	pid_t dpgid = getpgid(0);
	if (dpgid == -1) {
		rz_sys_perror("getpgid");
		return;
	}
	pid_t tpgid = getpgid(dbg->pid);
	if (tpgid == -1) {
		rz_sys_perror("getpgid");
		return;
	}

	// If the debuggee process is created by the debugger, do nothing because
	// SIGINT is already sent to both the debugger and debuggee in the same
	// process group.

	// If the debuggee is attached by the debugger, send SIGINT to the debuggee
	// in another process group.
	if (dpgid != tpgid) {
		if (!linux_kill_thread(dbg->pid, SIGINT)) {
			RZ_LOG_ERROR("Could not interrupt pid (%d)\n", dbg->pid);
		}
	}
}

RzDebugReasonType linux_dbg_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	int tid = 0;
	int status, flags = __WALL;
	int ret = -1;

	if (pid == -1) {
		flags |= WNOHANG;
	}

	for (;;) {
		rz_interrupt_break_push(dbg->intr, (RzInterruptBreakCallback)linux_dbg_wait_break, dbg);
		void *bed = rz_interrupt_sleep_begin(dbg->intr);
		if (dbg->continue_all_threads) {
			ret = waitpid(-1, &status, flags);
		} else {
			ret = waitpid(pid, &status, flags);
		}
		rz_interrupt_sleep_end(dbg->intr, bed);
		rz_interrupt_break_pop(dbg->intr);

		if (ret < 0) {
			// Continue when interrupted by user;
			if (errno == EINTR) {
				continue;
			}
			perror("waitpid");
			break;
		} else if (ret == 0) {
			// Unset WNOHANG to call next waitpid in blocking mode.
			flags &= ~WNOHANG;
		} else {
			tid = ret;

			// Handle SIGTRAP with PTRACE_EVENT_*
			reason = linux_ptrace_event(dbg, tid, status, true);
			if (reason != RZ_DEBUG_REASON_UNKNOWN) {
				break;
			}

			if (WIFEXITED(status)) {
				if (tid == dbg->pid) {
					linux_remove_process(dbg, tid);
					reason = RZ_DEBUG_REASON_DEAD;
					RZ_LOG_WARN("(%d) Process terminated with status %d\n", tid, WEXITSTATUS(status));
					break;
				} else {
					RZ_LOG_WARN("(%d) Child terminated with status %d\n", tid, WEXITSTATUS(status));
					if (linux_find_process(dbg, tid)) {
						linux_remove_process(dbg, tid);
					} else {
						linux_remove_thread(dbg, tid);
					}
					continue;
				}
			} else if (WIFSIGNALED(status)) {
				RZ_LOG_WARN("child received signal %d\n", WTERMSIG(status));
				reason = RZ_DEBUG_REASON_SIGNAL;
				} else if (WIFSTOPPED(status)) {
				if (!linux_find_thread(dbg, tid) && WSTOPSIG(status) == SIGSTOP) {
					reason = linux_handle_new_task(dbg, tid);
					if (reason != RZ_DEBUG_REASON_UNKNOWN) {
						break;
					}
				}

				if (linux_handle_signals(dbg, tid)) {
					reason = dbg->reason.type;
				} else {
					RZ_LOG_ERROR("can't handle signals\n");
					return RZ_DEBUG_REASON_ERROR;
				}
#ifdef WIFCONTINUED
			} else if (WIFCONTINUED(status)) {
				RZ_LOG_WARN("child continued...\n");
				reason = RZ_DEBUG_REASON_NONE;
#endif
			} else if (status == 1) {
				RZ_LOG_WARN("debugger is dead with status 1\n");
				reason = RZ_DEBUG_REASON_DEAD;
			} else if (status == 0) {
				RZ_LOG_WARN("debugger is dead with status 0\n");
				reason = RZ_DEBUG_REASON_DEAD;
			} else {
				if (ret != tid) {
					reason = RZ_DEBUG_REASON_NEW_PID;
				} else {
					RZ_LOG_ERROR("returning from wait without knowing why...\n");
				}
			}
			if (reason != RZ_DEBUG_REASON_UNKNOWN) {
				break;
			}
		}
	}
	dbg->reason.tid = tid;
	return reason;
}

static void linux_add_new_thread(RzDebug *dbg, int pid, int tid) {
	char info[1024] = { 0 };
	RzDebugThread *tid_info;

	RzDebugProcess *proc = linux_find_process(dbg, pid);
	if (!proc) {
		return;
	}
	if (!procfs_pid_slurp(tid, "status", info, sizeof(info))) {
		tid_info = fill_thread_state_info(info, tid, pid);
	} else {
		tid_info = rz_debug_thread_new(tid, pid, RZ_DBG_THREAD_STOP, 0);
	}
	if (!tid_info) {
		return;
	}
	tid_info->pc = linux_get_pc_for_tid(dbg, tid);
#if !__ANDROID__
	tid_info->tls_base = get_linux_tls_val(dbg, tid);
#endif
	linux_set_options(dbg, tid);
	if (!linux_thread_add(dbg, proc, tid_info)) {
		rz_debug_thread_free(tid_info);
	}
}

static bool linux_kill_thread(int tid, int signo) {
	int ret = syscall(__NR_tkill, tid, signo);

	if (ret == -1) {
		perror("tkill");
		return false;
	}

	return true;
}

bool linux_stop_threads(RzDebug *dbg, int except) {
	bool ret = true;
	RzDebugThread *th;
	RzListIter *it;
	rz_list_foreach (linux_cur_threads(dbg), it, th) {
		if (th->tid && th->tid != except) {
			if (!linux_stop_thread(dbg, th->tid)) {
				ret = false;
			}
		}
	}
	return ret;
}


static bool linux_attach_single_pid(RzDebug *dbg, int ptid) {
	siginfo_t sig = { 0 };

	if (ptid < 0) {
		return false;
	}

	// Safely check if the PID has already been attached to avoid printing errors.
	// Attaching to a process that has already been started with PTRACE_TRACEME.
	// sets errno to "Operation not permitted" which may be misleading.
	// GETSIGINFO can be called multiple times and would fail without attachment.
	if (rz_debug_ptrace(dbg, PTRACE_GETSIGINFO, ptid, NULL,
		    (rz_ptrace_data_t)&sig) == -1) {
		if (rz_debug_ptrace(dbg, PTRACE_ATTACH, ptid, NULL, NULL) == -1) {
			perror("ptrace (PT_ATTACH)");
			return false;
		}

		// Make sure SIGSTOP is delivered and wait for it since we can't affect the pid
		// until it hits SIGSTOP.
		if (!linux_stop_thread(dbg, ptid)) {   // was: if (!(dbg, ptid))
			RZ_LOG_ERROR("Could not stop pid (%d)\n", ptid);
			return false;
		}
	}

	if (!linux_set_options(dbg, ptid)) {
		RZ_LOG_ERROR("failed set_options on %d\n", ptid);
		return false;
	}
	return true;
}

/* Builds the process entry for pid, its owned thread list, and indexes every thread. */
static bool linux_build_main_process(RzDebug *dbg, int pid) {
	rz_return_val_if_fail(dbg && dbg->processes, false);
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	dbg->pid = pid;
	list = linux_thread_list(dbg, pid, list);
	if (!list) {
		return false;
	}
	RzDebugProcess *proc = linux_new_process_info(pid);
	if (!proc || !rz_list_append(dbg->processes, proc)) {
		rz_debug_pid_free(proc);
		rz_list_free(list);
		return false;
	}
	/* move the threads into the process, indexing each one */
	RzListIter *it;
	RzDebugThread *th;
	list->free = NULL; // ownership moves to proc->threads
	rz_list_foreach (list, it, th) {
		if (!linux_thread_add(dbg, proc, th)) {
			rz_debug_thread_free(th);
		}
	}
	rz_list_free(list);
	return true;
}

int linux_attach(RzDebug *dbg, int tid) {
	if (!linux_find_process(dbg, dbg->pid)) {
		linux_build_main_process(dbg, tid);
	} else if (!linux_find_thread(dbg, tid)) {
		linux_attach_single_pid(dbg, tid);
	}
	return tid;
}

static char *read_link(int pid, const char *file) {
	char path[1024] = { 0 };
	char buf[1024] = { 0 };

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, file);
	int ret = readlink(path, buf, sizeof(buf));
	if (ret > 0) {
		buf[sizeof(buf) - 1] = '\0';
		return rz_str_dup(buf);
	}
	return NULL;
}

RzDebugInfo *linux_info(RzDebug *dbg, const char *arg) {
	char proc_buff[1024];
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;

	RzDebugProcess *proc = linux_find_process(dbg, dbg->pid);
	rdi->uid = proc ? proc->uid : -1;
	rdi->gid = proc ? proc->gid : -1;
	rdi->status = proc ? proc->state : RZ_DBG_PROC_STOP;

	rdi->cwd = read_link(rdi->pid, "cwd");
	rdi->exe = read_link(rdi->pid, "exe");
	snprintf(proc_buff, sizeof(proc_buff), "/proc/%d/cmdline", rdi->pid);
	rdi->cmdline = rz_file_slurp(proc_buff, NULL);
	snprintf(proc_buff, sizeof(proc_buff), "/proc/%d/stack", rdi->pid);
	rdi->kernel_stack = rz_file_slurp(proc_buff, NULL);

	return rdi;
}

RzDebugProcess *fill_pid_info(const char *info, const char *path, int tid) {
	RzDebugProcess *pid_info = RZ_NEW0(RzDebugProcess);
	if (!pid_info) {
		return NULL;
	}
	pid_info->state = RZ_DBG_PROC_UNKNOWN;
	const char *ptr = strstr(info, "State:");
	if (ptr) {
		switch (*(ptr + 7)) {
		case 'R': pid_info->state = RZ_DBG_PROC_RUN; break;
		case 'S': pid_info->state = RZ_DBG_PROC_SLEEP; break;
		case 'D': pid_info->state = RZ_DBG_PROC_WAIT; break;
		case 'T':
		case 't': pid_info->state = RZ_DBG_PROC_STOP; break;
		case 'Z': pid_info->state = RZ_DBG_PROC_ZOMBIE; break;
		case 'X':
		case 'x': pid_info->state = RZ_DBG_PROC_DEAD; break;
		default: pid_info->state = RZ_DBG_PROC_UNKNOWN; break;
		}
	}
	ptr = strstr(info, "PPid:");
	if (ptr) {
		pid_info->ppid = atoi(ptr + 5);
	}
	ptr = strstr(info, "Uid:");
	if (ptr) {
		pid_info->uid = atoi(ptr + 5);
	}
	ptr = strstr(info, "Gid:");
	if (ptr) {
		pid_info->gid = atoi(ptr + 5);
	}
	pid_info->pid = tid;
	pid_info->path = rz_str_dup(path);
	pid_info->runnable = true;
	return pid_info;
}

RzList /*<RzDebugProcess *>*/ *linux_pid_list(int pid, RzList /*<RzDebugProcess *>*/ *list) {
	list->free = (RzListFree)&rz_debug_pid_free;
	struct dirent *de = NULL;
	DIR *dh = opendir("/proc");
	if (!dh) {
		rz_sys_perror("opendir /proc");
		rz_list_free(list);
		return NULL;
	}
	while ((de = readdir(dh))) {
		int i = atoi(de->d_name);
		if (i <= 0) {
			continue;
		}
		RzDebugProcess *pid_info = linux_new_process_info(i);
		if (!pid_info) {
			continue;
		}
		// Unless pid 0 is requested, only add the requested pid and its child processes
		if (0 == pid || i == pid || pid_info->ppid == pid) {
			rz_list_append(list, pid_info);
		} else {
			rz_debug_pid_free(pid_info); // was leaked before
		}
	}
	closedir(dh);
	return list;
}

/**
 * \brief Find the TLS base for the provided thread ID
 * \param dbg RzDebug Pointer.
 * \param tid Thread ID.
 * \return TLS base addr
 */
RZ_API ut64 get_linux_tls_val(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	ut64 tls = 0;

#if !__ANDROID__
	int prev_tid = dbg->tid;

	if (dbg->tid != tid) {
		linux_attach_single_pid(dbg, tid);
		dbg->tid = tid;
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	}

#if __x86_64__
	RzRegItem *ri = rz_reg_get(dbg->reg, "fs", RZ_REG_TYPE_ANY);
	RZ_DEBUG_REG_T regs;
	// Fetch gs_base from a ptrace call
	if (ri == NULL && !strcmp(dbg->arch, "x86")) {
		if (rz_debug_ptrace(dbg, PTRACE_GETREGS, dbg->tid, NULL, &regs) != -1) {
			tls = regs.gs_base;
		}
	} else {
		tls = rz_reg_get_value(dbg->reg, ri);
	}
#elif __aarch64__
	struct iovec iovec = { 0 };
	ut64 reg;

	iovec.iov_base = &reg;
	iovec.iov_len = sizeof(reg);
	RzRegItem *ri = rz_reg_get(dbg->reg, "tpidr_el0", RZ_REG_TYPE_ANY);
	if (ri == NULL && rz_debug_ptrace(dbg, PTRACE_GETREGSET, dbg->tid, (void *)NT_ARM_TLS, &iovec) != -1) {
		tls = reg;
	} else {
		tls = rz_reg_get_value(dbg->reg, ri);
	}
#endif
	// Must execute this block everytime
	if (prev_tid != tid) {                 // was: dbg->tid != tid (always false here)
		linux_attach_single_pid(dbg, prev_tid);
		dbg->tid = prev_tid;
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	}
#endif

	return tls;
}

static ut64 linux_get_pc_for_tid(RzDebug *dbg, int tid) {
	int prev_tid = dbg->tid;
	if (prev_tid != tid) {
		linux_attach_single_pid(dbg, tid);
		dbg->tid = tid;
	}
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	ut64 pc = rz_debug_reg_get_by_role(dbg, RZ_REG_NAME_PC);
	if (prev_tid != tid) {
		linux_attach_single_pid(dbg, prev_tid);
		dbg->tid = prev_tid;
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	}
	return pc;
}

static RzDebugThreadState linux_parse_thread_state(const char *info) {
	const char *ptr = strstr(info, "State:");
	if (!ptr) {
		return RZ_DBG_THREAD_UNKNOWN;
	}
	switch (*(ptr + 7)) {
	case 'R':
		return RZ_DBG_THREAD_RUN;
	case 'S':
		return RZ_DBG_THREAD_SLEEP;
	case 'D':
		return RZ_DBG_THREAD_WAIT;
	case 'T':
	case 't':
		return RZ_DBG_THREAD_STOP;
	case 'Z':
		return RZ_DBG_THREAD_ZOMBIE;
	case 'X':
	case 'x':
		return RZ_DBG_THREAD_DEAD;
	default:
		return RZ_DBG_THREAD_UNKNOWN;
	}
}

static RzDebugThread *fill_thread_state_info(const char *info, int tid, int process_pid) {
	RzDebugThread *thread_info = RZ_NEW0(RzDebugThread);
	if (!thread_info) {
		return NULL;
	}
	thread_info->tid = tid;
	thread_info->process_pid = process_pid;
	thread_info->state = linux_parse_thread_state(info);
	return thread_info;
}

RzList /*<RzDebugThread *>*/ *linux_thread_list(RzDebug *dbg, int pid, RzList /*<RzDebugThread *>*/ *list) {
	char *ptr, buf[PATH_MAX];

	if (!pid) {
		rz_list_free(list);
		return NULL;
	}

	list->free = (RzListFree)&rz_debug_thread_free;

	snprintf(buf, sizeof(buf), "/proc/%d/task", pid);
	if (rz_file_is_directory(buf)) {
		struct dirent *de;
		DIR *dh = opendir(buf);
		if (!dh) {
			return list;
		}
		rz_debug_map_sync(dbg);

		while ((de = readdir(dh))) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
				continue;
			}
			int tid = atoi(de->d_name);
			char info[PATH_MAX];

			if (procfs_pid_slurp(tid, "status", info, sizeof(info)) == -1) {
				continue;
			}
			ptr = strstr(info, "Tgid:");
			if (ptr && atoi(ptr + 5) != pid) {
				continue;
			}

			RzDebugThread *thread_info = fill_thread_state_info(info, tid, pid);
			if (!thread_info) {
				continue;
			}
			thread_info->pc = linux_get_pc_for_tid(dbg, tid);
#if !__ANDROID__
			thread_info->tls_base = get_linux_tls_val(dbg, tid);
#endif
			rz_list_append(list, thread_info);
		}
		dbg->n_threads = rz_list_length(list);
		closedir(dh);
		/* no restore here: both helpers restore dbg->tid before returning */
	} else {
		/* Some Linux configurations hide threads from /proc; brute-force fallback.
		 * No ptrace switching here, so pc/tls stay zeroed. */
#undef MAXPID
#define MAXPID 99999
		for (int i = pid; i < MAXPID; i++) {
			if (procfs_pid_slurp(i, "status", buf, sizeof(buf)) == -1) {
				continue;
			}
			ptr = strstr(buf, "Tgid:");
			if (!ptr || atoi(ptr + 5) != pid) {
				continue;
			}
			RzDebugThread *thread_info = fill_thread_state_info(buf, i, pid);
			if (thread_info) {
				rz_list_append(list, thread_info);
			}
		}
	}
	return list;
}

#define PRINT_FPU(fpregs) \
	rz_cons_printf(dbg->cons, "cwd = 0x%04x  ; control   ", (fpregs).cwd); \
	rz_cons_printf(dbg->cons, "swd = 0x%04x  ; status\n", (fpregs).swd); \
	rz_cons_printf(dbg->cons, "ftw = 0x%04x              ", (fpregs).ftw); \
	rz_cons_printf(dbg->cons, "fop = 0x%04x\n", (fpregs).fop); \
	rz_cons_printf(dbg->cons, "rip = 0x%016" PFMT64x "  ", (ut64)(fpregs).rip); \
	rz_cons_printf(dbg->cons, "rdp = 0x%016" PFMT64x "\n", (ut64)(fpregs).rdp); \
	rz_cons_printf(dbg->cons, "mxcsr = 0x%08x        ", (fpregs).mxcsr); \
	rz_cons_printf(dbg->cons, "mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)

#define PRINT_FPU_NOXMM(fpregs) \
	rz_cons_printf(dbg->cons, "cwd = 0x%04lx  ; control   ", (fpregs).cwd); \
	rz_cons_printf(dbg->cons, "swd = 0x%04lx  ; status\n", (fpregs).swd); \
	rz_cons_printf(dbg->cons, "twd = 0x%04lx              ", (fpregs).twd); \
	rz_cons_printf(dbg->cons, "fip = 0x%04lx          \n", (fpregs).fip); \
	rz_cons_printf(dbg->cons, "fcs = 0x%04lx              ", (fpregs).fcs); \
	rz_cons_printf(dbg->cons, "foo = 0x%04lx          \n", (fpregs).foo); \
	rz_cons_printf(dbg->cons, "fos = 0x%04lx              ", (fpregs).fos)

static void print_fpu(RzDebug *dbg, void *f) {
#if __x86_64__
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
#if __ANDROID__
	PRINT_FPU(fpregs);
	for (int i = 0; i < 8; i++) {
		ut64 *b = (ut64 *)&fpregs.st_space[i * 4];
		ut32 *c = (ut32 *)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		rz_cons_printf(dbg->cons, "st%d =%0.3lg (0x%016" PFMT64x ") | %0.3f (%08x) | "
					  "%0.3f (%08x) \n",
			i,
			(double)*((double *)&fpregs.st_space[i * 4]), *b, (float)f[0],
			c[0], (float)f[1], c[1]);
	}
#else
	rz_cons_printf(dbg->cons, "---- x86-64 ----\n");
	PRINT_FPU(fpregs);
	rz_cons_printf(dbg->cons, "size = 0x%08x\n", (ut32)sizeof(fpregs));
	for (int i = 0; i < 16; i++) {
		ut32 *a = (ut32 *)&fpregs.xmm_space;
		a = a + (i * 4);
		rz_cons_printf(dbg->cons, "xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
			(int)a[2], (int)a[3]);
		if (i < 8) {
			ut64 *st_u64 = (ut64 *)&fpregs.st_space[i * 4];
			ut8 *st_u8 = (ut8 *)&fpregs.st_space[i * 4];
			long double *st_ld = (long double *)&fpregs.st_space[i * 4];
			rz_cons_printf(dbg->cons, "mm%d = 0x%016" PFMT64x " | st%d = ", i, *st_u64, i);
			// print as hex TBYTE - always little endian
			for (int j = 9; j >= 0; j--) {
				rz_cons_printf(dbg->cons, "%02x", st_u8[j]);
			}
			// Using %Lf and %Le even though we do not show the extra precision to avoid another cast
			// %f with (double)*st_ld would also work
			rz_cons_printf(dbg->cons, " %Le %Lf\n", *st_ld, *st_ld);
		} else {
			rz_cons_printf(dbg->cons, "\n");
		}
	}
#endif // __ANDROID__
#elif __i386__
#if __ANDROID__
	struct user_fpxregs_struct fpxregs = *(struct user_fpxregs_struct *)f;
	rz_cons_printf(dbg->cons, "---- x86-32 ----\n");
	rz_cons_printf(dbg->cons, "cwd = 0x%04x  ; control   ", fpxregs.cwd);
	rz_cons_printf(dbg->cons, "swd = 0x%04x  ; status\n", fpxregs.swd);
	rz_cons_printf(dbg->cons, "twd = 0x%04x ", fpxregs.twd);
	rz_cons_printf(dbg->cons, "fop = 0x%04x\n", fpxregs.fop);
	rz_cons_printf(dbg->cons, "fip = 0x%08x\n", (ut32)fpxregs.fip);
	rz_cons_printf(dbg->cons, "fcs = 0x%08x\n", (ut32)fpxregs.fcs);
	rz_cons_printf(dbg->cons, "foo = 0x%08x\n", (ut32)fpxregs.foo);
	rz_cons_printf(dbg->cons, "fos = 0x%08x\n", (ut32)fpxregs.fos);
	rz_cons_printf(dbg->cons, "mxcsr = 0x%08x\n", (ut32)fpxregs.mxcsr);
	for (int i = 0; i < 8; i++) {
		ut32 *a = (ut32 *)(&fpxregs.xmm_space);
		ut64 *b = (ut64 *)(&fpxregs.st_space[i * 4]);
		ut32 *c = (ut32 *)&fpxregs.st_space;
		float *f = (float *)&fpxregs.st_space;
		a = a + (i * 4);
		c = c + (i * 4);
		f = f + (i * 4);
		rz_cons_printf(dbg->cons, "xmm%d = %08x %08x %08x %08x   ", i, (int)a[0],
			(int)a[1], (int)a[2], (int)a[3]);
		rz_cons_printf(dbg->cons, "st%d = %0.3lg (0x%016" PFMT64x ") | %0.3f (0x%08x) | "
					  "%0.3f (0x%08x)\n",
			i,
			(double)*((double *)(&fpxregs.st_space[i * 4])), b[0],
			f[0], c[0], f[1], c[1]);
	}
#else
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	rz_cons_printf(dbg->cons, "---- x86-32-noxmm ----\n");
	PRINT_FPU_NOXMM(fpregs);
	for (int i = 0; i < 8; i++) {
		ut64 *b = (ut64 *)(&fpregs.st_space[i * 4]);
		double *d = (double *)b;
		ut32 *c = (ut32 *)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		rz_cons_printf(dbg->cons, "st%d = %0.3lg (0x%016" PFMT64x ") | %0.3f (0x%08x) | "
					  "%0.3f (0x%08x)\n",
			i, d[0], b[0], f[0], c[0], f[1], c[1]);
	}
#endif
#else
#warning print_fpu not implemented for this platform
#endif
}

int linux_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	bool showfpu = false;
	int pid = dbg->tid;
	int ret = 0;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
	switch (type) {
	case RZ_REG_TYPE_DRX:
#if __POWERPC__
		// no drx for powerpc
		return false;
#elif __i386__ || __x86_64__
#if !__ANDROID__
	{
		int i;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			long ret = rz_debug_ptrace(dbg, PTRACE_PEEKUSER, pid,
				(void *)rz_offsetof(struct user, u_debugreg[i]), 0);
			if ((i + 1) * sizeof(ret) > size) {
				RZ_LOG_ERROR("linux_reg_get: Buffer too small %d\n", size);
				break;
			}
			memcpy(buf + (i * sizeof(ret)), &ret, sizeof(ret));
		}
		struct user a;
		return sizeof(a.u_debugreg);
	}
#else
#warning Android X86 does not support DRX
#endif
#endif
		return true;
		break;
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM:
#if __POWERPC__
		return false;
#elif __x86_64__ || __i386__
	{
		struct user_fpregs_struct fpregs;
		if (type == RZ_REG_TYPE_FPU) {
#if __x86_64__
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (ret != 0) {
				rz_sys_perror("PTRACE_GETFPREGS");
				return false;
			}
			if (showfpu) {
				print_fpu(dbg, (void *)&fpregs);
			}
			size = RZ_MIN(sizeof(fpregs), size);
			memcpy(buf, &fpregs, size);
			return size;
#elif __i386__
#if !__ANDROID__
			struct user_fpxregs_struct fpxregs;
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret == 0) {
				if (showfpu) {
					print_fpu(dbg, (void *)&fpxregs);
				}
				size = RZ_MIN(sizeof(fpxregs), size);
				memcpy(buf, &fpxregs, size);
				return size;
			} else {
				ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) {
					print_fpu(dbg, (void *)&fpregs);
				}
				if (ret != 0) {
					rz_sys_perror("PTRACE_GETFPREGS");
					return false;
				}
				size = RZ_MIN(sizeof(fpregs), size);
				memcpy(buf, &fpregs, size);
				return size;
			}
#else
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) {
				print_fpu(dbg, (void *)&fpregs);
			}
			if (ret != 0) {
				rz_sys_perror("PTRACE_GETFPREGS");
				return false;
			}
			size = RZ_MIN(sizeof(fpregs), size);
			memcpy(buf, &fpregs, size);
			return size;
#endif // !__ANDROID__
#endif // __i386__
		}
	}
#else
#warning getfpregs not implemented for this platform
#endif
		break;
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR: {
		RZ_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
#if (__arm64__ || __aarch64__ || __s390x__) && defined(PTRACE_GETREGSET)
		struct iovec io = {
			.iov_base = &regs,
			.iov_len = sizeof(regs)
		};
		ret = rz_debug_ptrace(dbg, PTRACE_GETREGSET, pid, (void *)(size_t)NT_PRSTATUS, &io);
		if (ret != 0) {
			rz_sys_perror("PTRACE_GETREGSET");
			return false;
		}
#elif __BSD__ && (__POWERPC__ || __sparc__)
		ret = rz_debug_ptrace(dbg, PTRACE_GETREGS, pid, &regs, NULL);
#else
		/* linux -{arm/mips/riscv/x86/x86_64} */
		ret = rz_debug_ptrace(dbg, PTRACE_GETREGS, pid, NULL, &regs);
#endif
		/*
		 * if perror here says 'no such process' and the
		 * process exists still.. is because there's a missing call
		 * to 'wait'. and the process is not yet available to accept
		 * more ptrace queries.
		 */
		if (ret != 0) {
			rz_sys_perror("PTRACE_GETREGS");
			return false;
		}
		size = RZ_MIN(sizeof(regs), size);
		memcpy(buf, &regs, size);
		return size;
	} break;
	case RZ_REG_TYPE_YMM: {
#if HAVE_YMM && __x86_64__ && defined(PTRACE_GETREGSET)
		ut32 ymm_space[128]; // full ymm registers
		struct _xstate xstate;
		struct iovec iov;
		iov.iov_base = &xstate;
		iov.iov_len = sizeof(struct _xstate);
		ret = rz_debug_ptrace_get_x86_xstate(dbg, pid, &iov);
		if (ret == -1) {
			return false;
		}
		// stitch together xstate.fpstate._xmm and xstate.ymmh assuming LE
		int ri, rj;
		for (ri = 0; ri < 16; ri++) {
			for (rj = 0; rj < 4; rj++) {
#ifdef __ANDROID__
				ymm_space[ri * 8 + rj] = ((struct _libc_fpstate *)&xstate.fpstate)->_xmm[ri].element[rj];
#else
				ymm_space[ri * 8 + rj] = xstate.fpstate._xmm[ri].element[rj];
#endif
			}
			for (rj = 0; rj < 4; rj++) {
				ymm_space[ri * 8 + (rj + 4)] = xstate.ymmh.ymmh_space[ri * 4 + rj];
			}
		}
		size = RZ_MIN(sizeof(ymm_space), size);
		memcpy(buf, &ymm_space, size);
		return size;
#endif
		return false;
	} break;
	}
	return false;
}

int linux_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int pid = dbg->tid;

	if (type == RZ_REG_TYPE_DRX) {
#if !__ANDROID__ && (__i386__ || __x86_64__)
		int i;
		long *val = (long *)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			if (rz_debug_ptrace(dbg, PTRACE_POKEUSER, pid,
				    (void *)rz_offsetof(struct user, u_debugreg[i]), (rz_ptrace_data_t)val[i])) {
				RZ_LOG_ERROR("ptrace error for dr %d\n", i);
				rz_sys_perror("ptrace POKEUSER");
			}
		}
		return sizeof(RZ_DEBUG_REG_T);
#else
		return false;
#endif
	}
	if (type == RZ_REG_TYPE_GPR) {
#if __arm64__ || __aarch64__ || __s390x__
		struct iovec io = {
			.iov_base = (void *)buf,
			.iov_len = sizeof(RZ_DEBUG_REG_T)
		};
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGSET, pid, (void *)(size_t)NT_PRSTATUS, (rz_ptrace_data_t)(size_t)&io);
#elif __sparc__ // in sparc data is ignored
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGS, pid, buf, NULL);
#elif __POWERPC__
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGS, pid, 0, (void *)buf);
#else
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGS, pid, 0, (void *)buf);
#endif
#if DEAD_CODE
		if (size > sizeof(RZ_DEBUG_REG_T)) {
			size = sizeof(RZ_DEBUG_REG_T);
		}
#endif
		if (ret == -1) {
			rz_sys_perror("reg_write");
			return false;
		}
		return true;
	}
	if (type == RZ_REG_TYPE_FPU) {
#if __i386__ || __x86_64__
		int ret = rz_debug_ptrace(dbg, PTRACE_SETFPREGS, pid, 0, (void *)buf);
		return (ret != 0) ? false : true;
#endif
	}
	return false;
}

RzList /*<RzDebugDesc *>*/ *linux_desc_list(int pid) {
	RzList *ret = NULL;
	char path[512], file[512], buf[512];
	struct dirent *de;
	RzDebugDesc *desc;
	int type, perm;
	int len, len2;
	struct stat st;
	DIR *dd = NULL;

	rz_strf(path, "/proc/%i/fd/", pid);
	if (!(dd = opendir(path))) {
		rz_sys_perror("opendir /proc/x/fd");
		return NULL;
	}
	ret = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!ret) {
		closedir(dd);
		return NULL;
	}
	while ((de = (struct dirent *)readdir(dd))) {
		if (de->d_name[0] == '.') {
			continue;
		}
		len = strlen(path);
		len2 = strlen(de->d_name);
		if (len + len2 + 1 >= sizeof(file)) {
			RZ_LOG_ERROR("Filename is too long.\n");
			goto fail;
		}
		memcpy(file, path, len);
		memcpy(file + len, de->d_name, len2 + 1);
		buf[0] = 0;
		if (readlink(file, buf, sizeof(buf) - 1) == -1) {
			RZ_LOG_ERROR("readlink %s failed.\n", file);
			goto fail;
		}
		buf[sizeof(buf) - 1] = 0;
		type = perm = 0;
		if (stat(file, &st) != -1) {
			type = st.st_mode & S_IFIFO ? 'P' :
#ifdef S_IFSOCK
				st.st_mode & S_IFSOCK ? 'S'
				:
#endif
				st.st_mode & S_IFCHR ? 'C'
						     : '-';
		}
		if (lstat(path, &st) != -1) {
			if (st.st_mode & S_IRUSR) {
				perm |= RZ_PERM_R;
			}
			if (st.st_mode & S_IWUSR) {
				perm |= RZ_PERM_W;
			}
		}
		// TODO: Offset
		desc = rz_debug_desc_new(atoi(de->d_name), buf, perm, type, 0);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}
	closedir(dd);
	return ret;

fail:
	rz_list_free(ret);
	closedir(dd);
	return NULL;
}

static int sys_thp_mode(void) {
	size_t i;
	const char *thp[] = {
		"/sys/kernel/mm/transparent_hugepage/enabled",
		"/sys/kernel/mm/redhat_transparent_hugepage/enabled",
	};
	int ret = 0;

	for (i = 0; i < RZ_ARRAY_SIZE(thp); i++) {
		char *val = rz_file_slurp(thp[i], NULL);
		if (val) {
			if (strstr(val, "[madvise]")) {
				ret = 1;
			} else if (strstr(val, "[always]")) {
				ret = 2;
			}
			free(val);
			break;
		}
	}

	return ret;
}

static int linux_map_thp(RzDebug *dbg, ut64 addr, int size) {
#if defined(MADV_HUGEPAGE)
	RzBuffer *buf = NULL;
	char code[1024];
	int ret = true;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	// In architectures where rizin is supported, arm and x86, it is 2MB
	const size_t thpsize = 1 << 21;

	if ((size % thpsize)) {
		RZ_LOG_ERROR("size not a power of huge pages size\n");
		return false;
	}
	// In always mode, is more into mmap syscall level
	// even though the address might not have the 'hg'
	// vmflags
	if (sys_thp_mode() != 1) {
		RZ_LOG_ERROR("transparent huge page mode is not in madvise mode\n");
		return false;
	}

	int num = 0;
	RzSyscall *rsys = rz_analysis_get_syscall(dbg->analysis);
	if (!rz_syscall_get_num(rsys, "madvise", &num)) {
		return false;
	}

	snprintf(code, sizeof(code),
		"sc_madvise@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_madvise(0x%08" PFMT64x ",%d, %d);break;\n"
		"}\n",
		num, addr, size, MADV_HUGEPAGE);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		RZ_LOG_ERROR("Cannot compile.\n");
		goto err_linux_map_thp;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		RZ_LOG_ERROR("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_thp;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		ret = rz_debug_execute(dbg, tmp, tmpsz, 1) == 0;
		rz_reg_arena_pop(dbg->reg);
	}
err_linux_map_thp:
	return ret;
#else
	return false;
#endif
}

RzDebugMap *linux_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	RzBuffer *buf = NULL;
	RzDebugMap *map = NULL;
	char code[1024], *sc_name;
	int num;
	/* force to usage of x86.as, not yet working x86.nz */
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};

	/* NOTE: Since kernel 2.4,  that  system  call  has  been  superseded  by
		 mmap2(2 and  nowadays  the  glibc  mmap()  wrapper  function invokes
		 mmap2(2)). If arch is x86_32 then usage mmap2() */
	if (!strcmp(dbg->arch, "x86") && dbg->bits == 4) {
		sc_name = "mmap2";
	} else {
		sc_name = "mmap";
	}

	RzSyscall *rsys = rz_analysis_get_syscall(dbg->analysis);
	if (!rz_syscall_get_num(rsys, sc_name, &num)) {
		goto err_linux_map_alloc;
	}
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
	snprintf(code, sizeof(code),
		"sc_mmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_mmap(0x%08" PFMT64x ",%d,%d,%d,%d,%d);break;\n"
		"}\n",
		num, addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		RZ_LOG_ERROR("Cannot compile egg code for map allocation.\n");
		goto err_linux_map_alloc;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		RZ_LOG_ERROR("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_alloc;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		ut64 map_addr;

		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		map_addr = rz_debug_execute(dbg, tmp, tmpsz, 1);
		rz_reg_arena_pop(dbg->reg);
		if (map_addr != (ut64)-1) {
			if (thp) {
				if (!linux_map_thp(dbg, map_addr, size)) {
					RZ_LOG_ERROR("map promotion to huge page failed\n");
				}
			}
			rz_debug_map_sync(dbg);
			map = rz_debug_map_get(dbg, map_addr);
		}
	}
err_linux_map_alloc:
	return map;
}

int linux_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	RzBuffer *buf = NULL;
	char code[1024];
	int ret = 0;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	int num = 0;
	RzSyscall *rsys = rz_analysis_get_syscall(dbg->analysis);
	if (!rz_syscall_get_num(rsys, "munmap", &num)) {
		goto err_linux_map_dealloc;
	}

	snprintf(code, sizeof(code),
		"sc_munmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_munmap(0x%08" PFMT64x ",%d);break;\n"
		"}\n",
		num, addr, size);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		RZ_LOG_ERROR("Cannot compile egg code for map deallocation.\n");
		goto err_linux_map_dealloc;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		RZ_LOG_ERROR("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_dealloc;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		ret = rz_debug_execute(dbg, tmp, tmpsz, 1) == 0;
		rz_reg_arena_pop(dbg->reg);
	}
err_linux_map_dealloc:
	return ret;
}

static void _map_free(RzDebugMap *map) {
	if (!map) {
		return;
	}
	free(map->name);
	free(map->file);
	free(map);
}

RzList /*<RzDebugMap *>*/ *linux_map_get(RzDebug *dbg) {
	RzList *list = NULL;
	RzDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024], name[PROC_NAME_SZ + 1];
	char region[PROC_REGION_SZ + 1], region2[PROC_REGION_SZ + 1], perms[PROC_PERM_SZ + 1];
	FILE *fd;
	if (dbg->pid == -1) {
		// eprintf ("rz_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}
	/* prepend 0x prefix */
	region[0] = region2[0] = '0';
	region[1] = region2[1] = 'x';

	snprintf(path, sizeof(path), "/proc/%d/maps", dbg->pid);

	fd = rz_sys_fopen(path, "r");
	if (!fd) {
		char *errmsg = rz_str_newf("Cannot open '%s'", path);
		rz_sys_perror(errmsg);
		free(errmsg);
		return NULL;
	}

	list = rz_list_new();
	if (!list) {
		fclose(fd);
		return NULL;
	}
	list->free = (RzListFree)_map_free;
	while (!feof(fd)) {
		size_t line_len;
		bool map_is_shared = false;
		ut64 map_start, map_end;

		if (!fgets(line, sizeof(line), fd)) {
			break;
		}
		/* kill the newline if we got one */
		line_len = strlen(line);
		if (line[line_len - 1] == '\n') {
			line[line_len - 1] = '\0';
			line_len--;
		}
		/* maps files should not have empty lines */
		if (line_len == 0) {
			break;
		}

		ut64 offset = 0;
		// 7fc8124c4000-7fc81278d000 r--p 00000000 fc:00 17043921 /usr/lib/locale/locale-archive
		i = sscanf(line, "%" RZ_STR_DEF(PROC_REGION_LEFT_SZ) "s %" RZ_STR_DEF(PROC_PERM_SZ) "s %08" PFMT64x " %*s %*s %" RZ_STR_DEF(PROC_NAME_SZ) "[^\n]", &region[2], perms, &offset, name);

		if (i == 3) {
			name[0] = '\0';
		} else if (i != 4) {
			RZ_LOG_ERROR("%s: Unable to parse \"%s\"\n", __func__, path);
			RZ_LOG_ERROR("%s: problematic line: %s\n", __func__, line);
			rz_list_free(list);
			return NULL;
		}

		/* split the region in two */
		pos_c = strchr(&region[2], '-');
		if (!pos_c) { // should this be an error?
			continue;
		}
		strncpy(&region2[2], pos_c + 1, sizeof(region2) - 2 - 1);
		// Terminate the start token at the '-'. rz_num_get() now parses
		// its whole argument strictly, so an un-split "0x<start>-<end>"
		// would evaluate as a subtraction - with the leading-zero <end>
		// read as C-style octal - instead of yielding the start address.
		*pos_c = 0;

		if (!*name) {
			snprintf(name, sizeof(name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; i < 5 && perms[i]; i++) {
			switch (perms[i]) {
			case 'r': perm |= RZ_PERM_R; break;
			case 'w': perm |= RZ_PERM_W; break;
			case 'x': perm |= RZ_PERM_X; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}

		map_start = rz_num_get(NULL, region);
		map_end = rz_num_get(NULL, region2);
		if (map_start == map_end || map_end == 0) {
			RZ_LOG_WARN("%s: ignoring invalid map size: %s - %s\n", __func__, region, region2);
			continue;
		}
		map = rz_debug_map_new(name, map_start, map_end, perm, 0);
		if (!map) {
			break;
		}
		map->offset = offset;
		map->shared = map_is_shared;
		map->file = rz_str_dup(name);
		rz_list_append(list, map);
	}
	fclose(fd);
	return list;
}

static int io_perms_to_prot(int io_perms) {
	int prot_perms = PROT_NONE;

	if (io_perms & RZ_PERM_R) {
		prot_perms |= PROT_READ;
	}
	if (io_perms & RZ_PERM_W) {
		prot_perms |= PROT_WRITE;
	}
	if (io_perms & RZ_PERM_X) {
		prot_perms |= PROT_EXEC;
	}
	return prot_perms;
}

int linux_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	RzBuffer *buf = NULL;
	char code[1024];
	int num;

	RzSyscall *rsys = rz_analysis_get_syscall(dbg->analysis);
	if (!rz_syscall_get_num(rsys, "mprotect", &num)) {
		return false;
	}
	snprintf(code, sizeof(code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%p,%d,%d);\n"
		":int3\n"
		"}\n",
		num, (void *)(size_t)addr, size, io_perms_to_prot(perms));

	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		RZ_LOG_ERROR("Cannot compile egg code for mprotect.\n");
		return false;
	}
	if (!rz_egg_assemble(dbg->egg)) {
		RZ_LOG_ERROR("rz_egg_assemble: invalid assembly\n");
		return false;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		rz_debug_execute(dbg, tmp, tmpsz, 1);
		rz_reg_arena_pop(dbg->reg);
		return true;
	}

	return false;
}
