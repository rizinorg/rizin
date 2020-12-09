// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_debug.h>
#include <rz_drx.h>
#include <rz_asm.h>
#include <rz_core.h>
#include <rz_reg.h>
#include <rz_lib.h>
#include <rz_analysis.h>
#include <signal.h>
#include <sys/types.h>

#if DEBUGGER

#include "native/drx.c" // x86 specific
#include "rz_cons.h"

static int rz_debug_native_continue (RzDebug *dbg, int pid, int tid, int sig);
static int rz_debug_native_reg_read (RzDebug *dbg, int type, ut8 *buf, int size);
static int rz_debug_native_reg_write (RzDebug *dbg, int type, const ut8* buf, int size);

#include "native/bt.c"

#if __UNIX__
# include <errno.h>
# if !defined (__HAIKU__) && !defined (__sun)
#  include <sys/ptrace.h>
# endif
# include <sys/wait.h>
# include <signal.h>
#endif

#if __WINDOWS__
//#include <windows.h>
#include "native/windows/windows_debug.h"
// TODO: Move these onto windows.h?
RZ_API RzList *rz_w32_dbg_modules(RzDebug *); //ugly!
RZ_API RzList *rz_w32_dbg_maps(RzDebug *);
#define RZ_DEBUG_REG_T CONTEXT
#ifdef NTSTATUS
#undef NTSTATUS
#endif
#ifndef NTSTATUS
#define NTSTATUS int
#endif

#elif __BSD__
#include "native/bsd/bsd_debug.h"
#include "native/procfs.h"

#elif __APPLE__
#include <sys/resource.h>
#include "native/xnu/xnu_debug.h"

#elif __sun

# define RZ_DEBUG_REG_T gregset_t
# undef DEBUGGER
# define DEBUGGER 0
# warning No debugger support for SunOS yet

#elif __linux__
#include <sys/mman.h>
#include "native/linux/linux_debug.h"
#include "native/procfs.h"
# ifdef __ANDROID__
#  define WAIT_ANY -1
#  ifndef WIFCONTINUED
#   define WIFCONTINUED(s) ((s) == 0xffff)
#  endif
# endif
#if (__x86_64__ || __i386__ || __arm__ || __arm64__) && !defined(__ANDROID__)
#include "native/linux/linux_coredump.h"
#endif
#else // OS

#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // ARCH

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

#endif /* IF DEBUGGER */

/* begin of debugger code */
#if DEBUGGER

#if !__WINDOWS__ && !(__linux__ && !defined(WAIT_ON_ALL_CHILDREN))
static int rz_debug_handle_signals(RzDebug *dbg) {
#if __KFBSD__
	return bsd_handle_signals (dbg);
#else
	eprintf ("Warning: signal handling is not supported on this platform\n");
	return 0;
#endif
}
#endif

//this is temporal
#if __APPLE__ || __linux__

static char *rz_debug_native_reg_profile (RzDebug *dbg) {
#if __APPLE__
	return xnu_reg_profile (dbg);
#elif __linux__
	return linux_reg_profile (dbg);
#endif
}
#else

#include "native/reg.c" // x86 specific

#endif
static int rz_debug_native_step (RzDebug *dbg) {
#if __APPLE__
	return xnu_step (dbg);
#elif __WINDOWS__
	return w32_step (dbg);
#elif __BSD__
	int ret = ptrace (PT_STEP, dbg->pid, (caddr_t)1, 0);
	if (ret != 0) {
		perror ("native-singlestep");
		return false;
	}
	return true;
#else // linux
	return linux_step (dbg);
#endif
}

// return thread id
static int rz_debug_native_attach (RzDebug *dbg, int pid) {
#if 0
	if (!dbg || pid == dbg->pid)
		return dbg->tid;
#endif
#if __APPLE__
	return xnu_attach (dbg, pid);
#elif __WINDOWS__
	return w32_attach (dbg, pid);
#elif __linux__ || __ANDROID__
	return linux_attach (dbg, pid);
#elif __KFBSD__
	if (ptrace (PT_ATTACH, pid, 0, 0) != -1) {
		perror ("ptrace (PT_ATTACH)");
	}
	return pid;
#else
	int ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret != -1) {
		eprintf ("Trying to attach to %d\n", pid);
		perror ("ptrace (PT_ATTACH)");
	}
	return pid;
#endif
}

static int rz_debug_native_detach (RzDebug *dbg, int pid) {
#if __APPLE__
	return xnu_detach (dbg, pid);
#elif __WINDOWS__
	return w32_detach (dbg, pid);
#elif __BSD__
	return ptrace (PT_DETACH, pid, NULL, 0);
#else
	return rz_debug_ptrace (dbg, PTRACE_DETACH, pid, NULL, (rz_ptrace_data_t)(size_t)0);
#endif
}

#if __WINDOWS__
static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	return w32_select (dbg, pid, tid);
}
#elif __linux__
static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	return linux_select (dbg, pid, tid);
}
#endif

static int rz_debug_native_continue_syscall (RzDebug *dbg, int pid, int num) {
// XXX: num is ignored
#if __linux__
	linux_set_options (dbg, pid);
	return rz_debug_ptrace (dbg, PTRACE_SYSCALL, pid, 0, 0);
#elif __BSD__
	ut64 pc = rz_debug_reg_get (dbg, "PC");
	errno = 0;
	return ptrace (PTRACE_SYSCALL, pid, (void*)(size_t)pc, 0) == 0;
#else
	eprintf ("TODO: continue syscall not implemented yet\n");
	return -1;
#endif
}

#if !__WINDOWS__ && !__APPLE__ && !__BSD__
/* Callback to trigger SIGINT signal */
static void interrupt_process(RzDebug *dbg) {
	rz_debug_kill (dbg, dbg->pid, dbg->tid, SIGINT);
	rz_cons_break_pop ();
}
#endif

static int rz_debug_native_stop(RzDebug *dbg) {
#if __linux__
	// Stop all running threads except the thread reported by waitpid
	return linux_stop_threads (dbg, dbg->reason.tid);
#else
	return 0;
#endif
}

/* TODO: specify thread? */
/* TODO: must return true/false */
static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
#if __APPLE__
	bool ret = xnu_continue (dbg, pid, tid, sig);
	if (!ret) {
		return -1;
	}
	return tid;
#elif __WINDOWS__
	return w32_continue (dbg, pid, tid, sig);
#elif __BSD__
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	ut64 pc = rz_debug_reg_get (dbg, "PC");
	return ptrace (PTRACE_CONT, pid, (void*)(size_t)pc, (int)(size_t)data) == 0;
#else
	int contsig = dbg->reason.signum;
	int ret = -1;

	if (sig != -1) {
		contsig = sig;
	}
	/* SIGINT handler for attached processes: dbg.consbreak (disabled by default) */
	if (dbg->consbreak) {
		rz_cons_break_push ((RzConsBreak)interrupt_process, dbg);
	}

	if (dbg->continue_all_threads && dbg->n_threads && dbg->threads) {
		RzDebugPid *th;
		RzListIter *it;
		rz_list_foreach (dbg->threads, it, th) {
			ret = rz_debug_ptrace (dbg, PTRACE_CONT, th->pid, 0, 0);
			if (ret) {
				eprintf ("Error: (%d) is running or dead.\n", th->pid);
			}
		}
	} else {
		ret = rz_debug_ptrace (dbg, PTRACE_CONT, tid, NULL, (rz_ptrace_data_t)(size_t)contsig);
		if (ret) {
			rz_sys_perror ("PTRACE_CONT");
		}
	}
	//return ret >= 0 ? tid : false;
	return tid;
#endif
}

static RzDebugInfo* rz_debug_native_info (RzDebug *dbg, const char *arg) {
#if __APPLE__
	return xnu_info (dbg, arg);
#elif __WINDOWS__
	return w32_info (dbg, arg);
#elif __linux__
	return linux_info (dbg, arg);
#elif __KFBSD__ || __OpenBSD__ || __NetBSD__
	return bsd_info (dbg, arg);
#else
	return NULL;
#endif
}

#if __WINDOWS__
static bool tracelib(RzDebug *dbg, const char *mode, PLIB_ITEM item) {
	const char *needle = NULL;
	int tmp = 0;
	if (mode) {
		switch (mode[0]) {
		case 'l': needle = dbg->glob_libs; break;
		case 'u': needle = dbg->glob_unlibs; break;
		}
	}
	rz_cons_printf ("(%d) %sing library at 0x%p (%s) %s\n", item->pid, mode,
		item->BaseOfDll, item->Path, item->Name);
	rz_cons_flush ();
	if (needle && strlen (needle)) {
		tmp = rz_str_glob (item->Name, needle);
	}
	return !mode || !needle || tmp ;
}
#endif

/*
 * Wait for an event and start trying to figure out what to do with it.
 *
 * Returns RZ_DEBUG_REASON_*
 */
#if __WINDOWS__
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	// Store the original TID to attempt to switch back after handling events that
	// require switching to the event's thread that shouldn't bother the user
	int orig_tid = dbg->tid;
	bool restore_thread = false;
	W32DbgWInst *wrap = dbg->user;

	if (pid == -1) {
		eprintf ("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = w32_dbg_wait (dbg, pid);
	if (reason == RZ_DEBUG_REASON_NEW_LIB) {
		RzDebugInfo *r = rz_debug_native_info (dbg, "");
		if (r && r->lib) {
			if (tracelib (dbg, "load", r->lib)) {
				reason = RZ_DEBUG_REASON_TRAP;
			}

			/* Check if autoload PDB is set, and load PDB information if yes */
			RzCore *core = dbg->corebind.core;
			bool autoload_pdb = dbg->corebind.cfggeti (core, "pdb.autoload");
			if (autoload_pdb) {
				PLIB_ITEM lib = r->lib;
				dbg->corebind.cmdf (core, "\"o \\\"%s\\\" 0x%p\"", lib->Path, lib->BaseOfDll);
				char *o_res = dbg->corebind.cmdstrf (core, "o~+%s", lib->Name);
				int fd = atoi (o_res);
				free (o_res);
				if (fd) {
					char *pdb_file = dbg->corebind.cmdstr (core, "i~dbg_file");
					if (pdb_file && (rz_str_trim (pdb_file), *pdb_file)) {
						if (!rz_file_exists (pdb_file + 9)) {
							dbg->corebind.cmdf (core, "idpd");
						}
						dbg->corebind.cmdf (core, "idp");
					}
					dbg->corebind.cmdf (core, "o-%d", fd);
				}
			}
			rz_debug_info_free (r);
		} else {
			rz_cons_printf ("Loading unknown library.\n");
			rz_cons_flush ();
		}
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_EXIT_LIB) {
		RzDebugInfo *r = rz_debug_native_info (dbg, "");
		if (r && r->lib) {
			if (tracelib (dbg, "unload", r->lib)) {
				reason = RZ_DEBUG_REASON_TRAP;
			}
			rz_debug_info_free (r);
		} else {
			rz_cons_printf ("Unloading unknown library.\n");
			rz_cons_flush ();
		}
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_NEW_TID) {
		RzDebugInfo *r = rz_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			rz_cons_printf ("(%d) Created thread %d (start @ %p) (teb @ %p)\n", item->pid, item->tid, item->lpStartAddress, item->lpThreadLocalBase);
			rz_cons_flush ();

			rz_debug_info_free (r);
		}
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_EXIT_TID) {
		RzDebugInfo *r = rz_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			rz_cons_printf ("(%d) Finished thread %d Exit code %lu\n", (ut32)item->pid, (ut32)item->tid, item->dwExitCode);
			rz_cons_flush ();

			rz_debug_info_free (r);
		}
		if (dbg->tid != orig_tid) {
			restore_thread = true;
		}
	} else if (reason == RZ_DEBUG_REASON_DEAD) {
		RzDebugInfo *r = rz_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			rz_cons_printf ("(%d) Finished process with exit code %lu\n", dbg->main_pid, item->dwExitCode);
			rz_cons_flush ();
			rz_debug_info_free (r);
		}
		dbg->pid = -1;
		dbg->tid = -1;
	} else if (reason == RZ_DEBUG_REASON_USERSUSP && dbg->tid != orig_tid) {
		RzDebugInfo *r = rz_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			rz_cons_printf ("(%d) Created DebugBreak thread %d (start @ %p)\n", item->pid, item->tid, item->lpStartAddress);
			rz_cons_flush ();

			rz_debug_info_free (r);
		}
		// DebugProcessBreak creates a new thread that will trigger a breakpoint. We record the
		// tid here to ignore it once the breakpoint is hit.
		wrap->break_tid = dbg->tid;
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_BREAKPOINT && dbg->tid == wrap->break_tid) {
		wrap->break_tid = -2;
		reason = RZ_DEBUG_REASON_NONE;
		restore_thread = true;
	}

	if (restore_thread) {
		// Attempt to return to the original thread after handling the event
		dbg->tid = w32_select(dbg, dbg->pid, orig_tid);
		if (dbg->tid == -1) {
			dbg->pid = -1;
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			rz_io_system (dbg->iob.io, sdb_fmt ("pid %d", dbg->tid));
			if (dbg->tid != orig_tid) {
				reason = RZ_DEBUG_REASON_UNKNOWN;
			}
		}
	}

	dbg->reason.tid = pid;
	dbg->reason.type = reason;
	return reason;
}
// FIXME: Should WAIT_ON_ALL_CHILDREN be a compilation flag instead of runtime debug config?
#elif __linux__ && !defined(WAIT_ON_ALL_CHILDREN) // __WINDOWS__
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		eprintf ("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = linux_dbg_wait (dbg, dbg->tid);
	dbg->reason.type = reason;
	return reason;
}
#else // if __WINDOWS__ & elif __linux__ && !defined (WAIT_ON_ALL_CHILDREN)
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		eprintf ("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

#if __APPLE__
	rz_cons_break_push (NULL, NULL);
	do {
		reason = xnu_wait (dbg, pid);
		if (reason == RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED) {
			if (rz_cons_is_breaked ()) {
				// Perhaps check the inferior is still alive,
				// otherwise xnu_stop will fail.
				reason = xnu_stop (dbg, pid)
					? RZ_DEBUG_REASON_USERSUSP
					: RZ_DEBUG_REASON_UNKNOWN;
			} else {
				// Weird; we'll retry the wait.
				continue;
			}
		}
		break;
	} while (true);
	rz_cons_break_pop ();
#else
	int status = -1;
	// XXX: this is blocking, ^C will be ignored
#ifdef WAIT_ON_ALL_CHILDREN
	int ret = waitpid (-1, &status, WAITPID_FLAGS);
#else
	int ret = waitpid (-1, &status, 0);
	if (ret != -1) {
		reason = RZ_DEBUG_REASON_TRAP;
	}
#endif // WAIT_ON_ALL_CHILDREN
	if (ret == -1) {
		rz_sys_perror ("waitpid");
		return RZ_DEBUG_REASON_ERROR;
	}

	//eprintf ("rz_debug_native_wait: status=%d (0x%x) (return=%d)\n", status, status, ret);

#ifdef WAIT_ON_ALL_CHILDREN
	if (ret != pid) {
		reason = RZ_DEBUG_REASON_NEW_PID;
		eprintf ("switching to pid %d\n", ret);
		rz_debug_select (dbg, ret, ret);
	}
#endif // WAIT_ON_ALL_CHILDREN
	// TODO: switch status and handle reasons here
	// FIXME: Remove linux handling from this function?
#if __linux__ && defined(PT_GETEVENTMSG)
	reason = linux_ptrace_event (dbg, pid, status, true);
#endif // __linux__

	/* propagate errors */
	if (reason == RZ_DEBUG_REASON_ERROR) {
		return reason;
	}

	/* we don't know what to do yet, let's try harder to figure it out. */
#if __FreeBSD__
	if (reason == RZ_DEBUG_REASON_TRAP) {
#else
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
#endif
		if (WIFEXITED (status)) {
			eprintf ("child exited with status %d\n", WEXITSTATUS (status));
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (WIFSIGNALED (status)) {
			eprintf ("child received signal %d\n", WTERMSIG (status));
			reason = RZ_DEBUG_REASON_SIGNAL;
		} else if (WIFSTOPPED (status)) {
			if (WSTOPSIG (status) != SIGTRAP &&
				WSTOPSIG (status) != SIGSTOP) {
				eprintf ("Child stopped with signal %d\n", WSTOPSIG (status));
			}

			/* the ptrace documentation says GETSIGINFO is only necessary for
			 * differentiating the various stops.
			 *
			 * this might modify dbg->reason.signum
			 */
#if __OpenBSD__ || __NetBSD__
			reason = RZ_DEBUG_REASON_BREAKPOINT;
#else
			if (rz_debug_handle_signals (dbg) != 0) {
				return RZ_DEBUG_REASON_ERROR;
			}
			reason = dbg->reason.type;
#endif
#ifdef WIFCONTINUED
		} else if (WIFCONTINUED (status)) {
			eprintf ("child continued...\n");
			reason = RZ_DEBUG_REASON_NONE;
#endif
		} else if (status == 1) {
			/* XXX(jjd): does this actually happen? */
			eprintf ("debugger is dead with status 1!\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (status == 0) {
			/* XXX(jjd): does this actually happen? */
			eprintf ("debugger is dead with status 0\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			if (ret != pid) {
				reason = RZ_DEBUG_REASON_NEW_PID;
			} else {
				/* ugh. still don't know :-/ */
				eprintf ("returning from wait without knowing why...\n");
			}
		}
	}

	/* if we still don't know what to do, we have a problem... */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		eprintf ("%s: no idea what happened...\n", __func__);
		reason = RZ_DEBUG_REASON_ERROR;
	}
#endif // __APPLE__
	dbg->reason.tid = pid;
	dbg->reason.type = reason;
	return reason;
}
#endif // __WINDOWS__

#undef MAXPID
#define MAXPID 99999

static RzList *rz_debug_native_tids (RzDebug *dbg, int pid) {
	printf ("TODO: Threads: \n");
	// T
	return NULL;
}

static RzList *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new ();
	if (!list) {
		return NULL;
	}
#if __APPLE__
	if (pid) {
		RzDebugPid *p = xnu_get_pid (pid);
		if (p) {
			rz_list_append (list, p);
		}
	} else {
		int i;
		for (i = 1; i < MAXPID; i++) {
			RzDebugPid *p = xnu_get_pid (i);
			if (p) {
				rz_list_append (list, p);
			}
		}
	}
#elif __WINDOWS__
	return w32_pid_list (dbg, pid, list);
#elif __linux__
	return linux_pid_list (pid, list);
#else /* rest is BSD */
	return bsd_pid_list (dbg, pid, list);
#endif
	return list;
}

static RzList *rz_debug_native_threads (RzDebug *dbg, int pid) {
	RzList *list = rz_list_new ();
	if (!list) {
		eprintf ("No list?\n");
		return NULL;
	}
#if __APPLE__
	return xnu_thread_list (dbg, pid, list);
#elif __WINDOWS__
	return w32_thread_list (dbg, pid, list);
#elif __linux__
	return linux_thread_list (dbg, pid, list);
#else
	return bsd_thread_list (dbg, pid, list);
#endif
}

#if __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__ || __DragonFly__

//Function to read register from Linux, BSD, Android systems
static int bsd_reg_read (RzDebug *dbg, int type, ut8* buf, int size) {
	int showfpu = false;
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	switch (type) {
	case RZ_REG_TYPE_DRX:
#if __i386__ || __x86_64__
#if __KFBSD__
	{
		// TODO
		struct dbreg dbr;
		ret = ptrace (PT_GETDBREGS, pid, (caddr_t)&dbr, sizeof(dbr));
		if (ret != 0) return false;
		// XXX: maybe the register map is not correct, must review
	}
#endif
#endif
		return true;
		break;
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM:
		break;
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR:
		{
		RZ_DEBUG_REG_T regs;
		memset (&regs, 0, sizeof(regs));
		memset (buf, 0, size);
		#if __NetBSD__ || __OpenBSD__
			ret = ptrace (PTRACE_GETREGS, pid, (caddr_t)&regs, sizeof (regs));
		#elif __KFBSD__
			ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
		#else
			#warning not implemented for this platform
			ret = 1;
		#endif
		// if perror here says 'no such process' and the
		// process exists still.. is because there's a
		// missing call to 'wait'. and the process is not
		// yet available to accept more ptrace queries.
		if (ret != 0) return false;
		if (sizeof(regs) < size) size = sizeof(regs);
		memcpy (buf, &regs, size);
		return sizeof(regs);
		}
		break;
	}
	return true;
}
#endif // if __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__



// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static int rz_debug_native_reg_read (RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
#if __APPLE__
	return xnu_reg_read (dbg, type, buf, size);
#elif __WINDOWS__
	return w32_reg_read (dbg, type, buf, size);
#elif __linux__
	return linux_reg_read (dbg, type, buf, size);
#elif __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__ || __DragonFly__
	return bsd_reg_read (dbg, type, buf, size);
#else
	#warning dbg-native not supported for this platform
	return false;
#endif
}

static int rz_debug_native_reg_write (RzDebug *dbg, int type, const ut8* buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
#if __APPLE__
		return xnu_reg_write (dbg, type, buf, size);
#elif __WINDOWS__
		return w32_reg_write (dbg, type, buf, size);
#elif __linux__
		return linux_reg_write (dbg, type, buf, size);
#else
		return bsd_reg_write (dbg, type, buf, size);
#endif
#else // i386/x86-64
		return false;
#endif
	} else if (type == RZ_REG_TYPE_GPR) {
#if __APPLE__
		return xnu_reg_write (dbg, type, buf, size);
#elif __WINDOWS__
		return w32_reg_write (dbg, type, buf, size);
#elif __linux__
		return linux_reg_write (dbg, type, buf, size);
#elif __sun
		int ret = ptrace (PTRACE_SETREGS, dbg->pid,
			(void*)(size_t)buf, sizeof (RZ_DEBUG_REG_T));
		if (sizeof (RZ_DEBUG_REG_T) < size)
			size = sizeof (RZ_DEBUG_REG_T);
		return ret == 0;
#else
		return bsd_reg_write (dbg, type, buf, size);
#endif
	} else if (type == RZ_REG_TYPE_FPU) {
#if __linux__
		return linux_reg_write (dbg, type, buf, size);
#elif __APPLE__
		return false;
#elif __WINDOWS__
		return false;
#else
		return bsd_reg_write (dbg, type, buf, size);
#endif
	} //else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}

#if __linux__
static int io_perms_to_prot (int io_perms) {
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


static int linux_map_thp (RzDebug *dbg, ut64 addr, int size) {
#if !defined(__ANDROID__) && defined(MADV_HUGEPAGE)
	RzBuffer *buf = NULL;
	char code[1024];
	int ret = true;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	// In architectures where rizin is supported, arm and x86, it is 2MB
	const size_t thpsize = 1<<21;

	if ((size%thpsize)) {
		eprintf ("size not a power of huge pages size\n");
		return false;
	}

	// In always mode, is more into mmap syscall level
	// even though the address might not have the 'hg'
	// vmflags
	if (rz_sys_thp_mode() != 1) {
		eprintf ("transparent huge page mode is not in madvise mode\n");
		return false;
	}

	int num = rz_syscall_get_num (dbg->analysis->syscall, "madvise");

	snprintf (code, sizeof (code),
		"sc_madvise@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_madvise(0x%08" PFMT64x ",%d, %d);break;\n"
		"}\n",
		num, addr, size, MADV_HUGEPAGE);
	rz_egg_reset (dbg->egg);
	rz_egg_setup (dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load (dbg->egg, code, 0);
	if (!rz_egg_compile (dbg->egg)) {
		eprintf ("Cannot compile.\n");
		goto err_linux_map_thp;
	}
	if (!rz_egg_assemble_asm (dbg->egg, asm_list)) {
		eprintf ("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_thp;
	}
	buf = rz_egg_get_bin (dbg->egg);
	if (buf) {
		rz_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data (buf, &tmpsz);
		ret = rz_debug_execute (dbg, tmp, tmpsz, 1) == 0;
		rz_reg_arena_pop (dbg->reg);
	}
err_linux_map_thp:
	return ret;
#else
	return false;
#endif
}

static RzDebugMap* linux_map_alloc (RzDebug *dbg, ut64 addr, int size, bool thp) {
	RzBuffer *buf = NULL;
	RzDebugMap* map = NULL;
	char code[1024], *sc_name;
	int num;
	/* force to usage of x86.as, not yet working x86.nz */
	char *asm_list[] = {
			"x86", "x86.as",
			"x64", "x86.as",
			NULL};

	/* NOTE: Since kernel 2.4,  that  system  call  has  been  superseded  by
       		 mmap2(2 and  nowadays  the  glibc  mmap()  wrapper  function invokes
       		 mmap2(2)). If arch is x86_32 then usage mmap2() */
	if (!strcmp (dbg->arch, "x86") && dbg->bits == 4) {
		sc_name = "mmap2";
	} else {
		sc_name = "mmap";
	}
	num = rz_syscall_get_num (dbg->analysis->syscall, sc_name);
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
	snprintf (code, sizeof (code),
		"sc_mmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_mmap(0x%08"PFMT64x",%d,%d,%d,%d,%d);break;\n"
		"}\n",
		num, addr, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	rz_egg_reset (dbg->egg);
	rz_egg_setup (dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load (dbg->egg, code, 0);
	if (!rz_egg_compile (dbg->egg)) {
		eprintf ("Cannot compile.\n");
		goto err_linux_map_alloc;
	}
	if (!rz_egg_assemble_asm (dbg->egg, asm_list)) {
		eprintf ("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_alloc;
	}
	buf = rz_egg_get_bin (dbg->egg);
	if (buf) {
		ut64 map_addr;

		rz_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data (buf, &tmpsz);
		map_addr = rz_debug_execute (dbg, tmp, tmpsz, 1);
		rz_reg_arena_pop (dbg->reg);
		if (map_addr != (ut64)-1) {
			if (thp) {
				if (!linux_map_thp (dbg, map_addr, size)) {
					// Not overly dramatic
					eprintf ("map promotion to huge page failed\n");
				}
			}
			rz_debug_map_sync (dbg);
			map = rz_debug_map_get (dbg, map_addr);
		}
	}
err_linux_map_alloc:
	return map;
}

static int linux_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	RzBuffer *buf = NULL;
	char code[1024];
	int ret = 0;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	int num = rz_syscall_get_num (dbg->analysis->syscall, "munmap");

	snprintf (code, sizeof (code),
		"sc_munmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_munmap(0x%08" PFMT64x ",%d);break;\n"
		"}\n",
		num, addr, size);
	rz_egg_reset (dbg->egg);
	rz_egg_setup (dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load (dbg->egg, code, 0);
	if (!rz_egg_compile (dbg->egg)) {
		eprintf ("Cannot compile.\n");
		goto err_linux_map_dealloc;
	}
	if (!rz_egg_assemble_asm (dbg->egg, asm_list)) {
		eprintf ("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_dealloc;
	}
	buf = rz_egg_get_bin (dbg->egg);
	if (buf) {
		rz_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data (buf, &tmpsz);
		ret = rz_debug_execute (dbg, tmp, tmpsz, 1) == 0;
		rz_reg_arena_pop (dbg->reg);
	}
err_linux_map_dealloc:
	return ret;
}
#endif

static RzDebugMap* rz_debug_native_map_alloc (RzDebug *dbg, ut64 addr, int size, bool thp) {
#if __APPLE__
	(void)thp;
	return xnu_map_alloc (dbg, addr, size);
#elif __WINDOWS__
	(void)thp;
	return w32_map_alloc (dbg, addr, size);
#elif __linux__
	return linux_map_alloc (dbg, addr, size, thp);
#else
	// malloc not implemented for this platform
	return NULL;
#endif
}

static int rz_debug_native_map_dealloc (RzDebug *dbg, ut64 addr, int size) {
#if __APPLE__
	return xnu_map_dealloc (dbg, addr, size);
#elif __WINDOWS__
	return w32_map_dealloc (dbg, addr, size);
#elif __linux__
	return linux_map_dealloc (dbg, addr, size);
#else
    // mdealloc not implemented for this platform
	return false;
#endif
}

#if !__WINDOWS__ && !__APPLE__
static void _map_free(RzDebugMap *map) {
	if (!map) {
		return;
	}
	free (map->name);
	free (map->file);
	free (map);
}
#endif

static RzList *rz_debug_native_map_get (RzDebug *dbg) {
	RzList *list = NULL;
#if __KFBSD__
	int ign;
	char unkstr[128];
#endif
#if __APPLE__
	list = xnu_dbg_maps (dbg, 0);
#elif __WINDOWS__
	list = rz_w32_dbg_maps (dbg);
#else
#if __sun
	char path[1024];
	/* TODO: On solaris parse /proc/%d/map */
	snprintf (path, sizeof(path) - 1, "pmap %d >&2", ps.tid);
	system (path);
#else
	RzDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024], name[1024];
	char region[100], region2[100], perms[5];
	FILE *fd;
	if (dbg->pid == -1) {
		//eprintf ("rz_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}
	/* prepend 0x prefix */
	region[0] = region2[0] = '0';
	region[1] = region2[1] = 'x';

#if __OpenBSD__
	/* OpenBSD has no procfs, so no idea trying. */
	return bsd_native_sysctl_map (dbg);
#endif

#if __KFBSD__
	list = bsd_native_sysctl_map (dbg);
	if (list) {
		return list;
	}
	snprintf (path, sizeof (path), "/proc/%d/map", dbg->pid);
#else
	snprintf (path, sizeof (path), "/proc/%d/maps", dbg->pid);
#endif
	fd = rz_sandbox_fopen (path, "r");
	if (!fd) {
		perror (sdb_fmt ("Cannot open '%s'", path));
		return NULL;
	}

	list = rz_list_new ();
	if (!list) {
		fclose (fd);
		return NULL;
	}
	list->free = (RzListFree)_map_free;
	while (!feof (fd)) {
		size_t line_len;
		bool map_is_shared = false;
		ut64 map_start, map_end;

		if (!fgets (line, sizeof (line), fd)) {
			break;
		}
		/* kill the newline if we got one */
		line_len = strlen (line);
		if (line[line_len - 1] == '\n') {
			line[line_len - 1] = '\0';
			line_len--;
		}
		/* maps files should not have empty lines */
		if (line_len == 0) {
			break;
		}
#if __KFBSD__
		// 0x8070000 0x8072000 2 0 0xc1fde948 rw- 1 0 0x2180 COW NC vnode /usr/bin/gcc
		if (sscanf (line, "%s %s %d %d 0x%s %3s %d %d",
				&region[2], &region2[2], &ign, &ign,
				unkstr, perms, &ign, &ign) != 8) {
			eprintf ("%s: Unable to parse \"%s\"\n", __func__, path);
			rz_list_free (list);
			return NULL;
		}

		/* snag the file name */
		pos_c = strchr (line, '/');
		if (pos_c) {
			strncpy (name, pos_c, sizeof (name) - 1);
		} else {
			name[0] = '\0';
		}
#else
		ut64 offset = 0;;
		// 7fc8124c4000-7fc81278d000 r--p 00000000 fc:00 17043921 /usr/lib/locale/locale-archive
		i = sscanf (line, "%s %s %08"PFMT64x" %*s %*s %[^\n]", &region[2], perms, &offset, name);
		if (i == 3) {
			name[0] = '\0';
		} else if (i != 4) {
			eprintf ("%s: Unable to parse \"%s\"\n", __func__, path);
			eprintf ("%s: problematic line: %s\n", __func__, line);
			rz_list_free (list);
			return NULL;
		}

		/* split the region in two */
		pos_c = strchr (&region[2], '-');
		if (!pos_c) { // should this be an error?
			continue;
		}
		strncpy (&region2[2], pos_c + 1, sizeof (region2) - 2 - 1);
#endif // __KFBSD__
		if (!*name) {
			snprintf (name, sizeof (name), "unk%d", unk++);
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

		map_start = rz_num_get (NULL, region);
		map_end = rz_num_get (NULL, region2);
		if (map_start == map_end || map_end == 0) {
			eprintf ("%s: ignoring invalid map size: %s - %s\n", __func__, region, region2);
			continue;
		}
		map = rz_debug_map_new (name, map_start, map_end, perm, 0);
		if (!map) {
			break;
		}
#if __linux__
		map->offset = offset;
		map->shared = map_is_shared;
#endif
		map->file = strdup (name);
		rz_list_append (list, map);
	}
	fclose (fd);
#endif // __sun
#endif // __APPLE__
	return list;
}

static RzList *rz_debug_native_modules_get (RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
#if __APPLE__
	list = xnu_dbg_maps (dbg, 1);
	if (list && !rz_list_empty (list)) {
		return list;
	}
#elif  __WINDOWS__
	list = rz_w32_dbg_modules (dbg);
	if (list && !rz_list_empty (list)) {
		return list;
	}
#endif
	if (!(list = rz_debug_native_map_get (dbg))) {
		return NULL;
	}
	if (!(last = rz_list_newf ((RzListFree)rz_debug_map_free))) {
		rz_list_free (list);
		return NULL;
	}
	rz_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = strdup (map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp (lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			rz_list_delete (list, iter);
		} else {
			rz_list_append (last, map);
			free (lastname);
			lastname = strdup (file);
		}
	}
	list->free = NULL;
	free (lastname);
	rz_list_free (list);
	return last;
}

static bool rz_debug_native_kill(RzDebug *dbg, int pid, int tid, int sig) {
	bool ret = false;
	if (pid == 0) {
		pid = dbg->pid;
	}
#if __WINDOWS__
	ret = w32_kill (dbg, pid, tid, sig);
#else
#if 0
	if (thread) {
// XXX this is linux>2.5 specific..ugly
		if (dbg->tid>0 && (ret = tgkill (dbg->pid, dbg->tid, sig))) {
			if (ret != -1)
				ret = true;
		}
	} else {
#endif
	if (sig == SIGKILL && dbg->threads) {
		rz_list_free (dbg->threads);
		dbg->threads = NULL;
	}
	if ((rz_sandbox_kill (pid, sig) != -1)) {
		ret = true;
	}
	if (errno == 1) {
		ret = -true; // EPERM
	}
#if 0
//	}
#endif
#endif
	return ret;
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native;
static int rz_debug_native_init (RzDebug *dbg) {
	dbg->h->desc = rz_debug_desc_plugin_native;
#if __WINDOWS__
	return w32_init (dbg);
#else
	return true;
#endif
}

#if __i386__ || __x86_64__
static void sync_drx_regs (RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		eprintf ("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

	// sync drx regs
#define R dbg->reg
	regs[0] = rz_reg_getv (R, "dr0");
	regs[1] = rz_reg_getv (R, "dr1");
	regs[2] = rz_reg_getv (R, "dr2");
	regs[3] = rz_reg_getv (R, "dr3");
/*
	RESERVED
	regs[4] = rz_reg_getv (R, "dr4");
	regs[5] = rz_reg_getv (R, "dr5");
*/
	regs[6] = rz_reg_getv (R, "dr6");
	regs[7] = rz_reg_getv (R, "dr7");
}
#endif

#if __i386__ || __x86_64__
static void set_drx_regs (RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS){
		eprintf ("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

#define R dbg->reg
 	rz_reg_setv (R, "dr0", regs[0]);
	rz_reg_setv (R, "dr1", regs[1]);
	rz_reg_setv (R, "dr2", regs[2]);
	rz_reg_setv (R, "dr3", regs[3]);
	rz_reg_setv (R, "dr6", regs[6]);
	rz_reg_setv (R, "dr7", regs[7]);
}
#endif

static int rz_debug_native_drx (RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
#if __i386__ || __x86_64__
	int retval = false;
	drxt regs[NUM_DRX_REGISTERS] = {0};
	// sync drx regs
	sync_drx_regs (dbg, regs, NUM_DRX_REGISTERS);

	switch (api_type) {
	case DRX_API_LIST:
		drx_list (regs);
		retval = false;
		break;
	case DRX_API_GET_BP:
		/* get the index of the breakpoint at addr */
		retval = drx_get_at (regs, addr);
		break;
	case DRX_API_REMOVE_BP:
		/* remove hardware breakpoint */
		drx_set (regs, n, addr, -1, 0, 0);
		retval = true;
		break;
	case DRX_API_SET_BP:
		/* set hardware breakpoint */
		drx_set (regs, n, addr, sz, rwx, g);
		retval = true;
		break;
	default:
		/* this should not happen, someone misused the API */
		eprintf ("drx: Unsupported api type in rz_debug_native_drx\n");
		retval = false;
	}

	set_drx_regs (dbg, regs, NUM_DRX_REGISTERS);

	return retval;
#else
	eprintf ("drx: Unsupported platform\n");
#endif
	return false;
}


#if __linux__

#if __arm__ || __arm64__ || __aarch64__
#include <sys/prctl.h>
#include <sys/uio.h>

#define NT_ARM_VFP	0x400		/* ARM VFP/NEON registers */
#define NT_ARM_TLS	0x401		/* ARM TLS register */
#define NT_ARM_HW_BREAK	0x402		/* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH	0x403		/* ARM hardware watchpoint registers */
#define NT_ARM_SYSTEM_CALL	0x404	/* ARM system call number */

#ifndef PTRACE_GETHBPREGS
#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30
#endif

#if __arm__

static bool ll_arm32_hwbp_set(pid_t pid, ut64 addr, int size, int wp, int type) {
	const unsigned byte_mask = (1 << size) - 1;
	//const unsigned type = 2; // Write.
	const unsigned enable = 1;
	const unsigned control = byte_mask << 5 | type << 3 | enable;
	(void)ptrace (PTRACE_SETHBPREGS, pid, -1, (void*)(size_t)addr);
	return ptrace (PTRACE_SETHBPREGS, pid, -2, &control) != -1;
}

static bool arm32_hwbp_add (RzDebug *dbg, RzBreakpoint* bp, RzBreakpointItem *b) {
	return ll_arm32_hwbp_set (dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

static bool arm32_hwbp_del (RzDebug *dbg, RzBreakpoint *bp, RzBreakpointItem *b) {
	return false; // TODO: hwbp.del not yetimplemented
}
#endif // PTRACE_GETHWBPREGS
#endif // __arm

#if (__arm64__ || __aarch64__) && defined(PTRACE_GETREGSET)
// type = 2 = write
//static volatile uint8_t var[96] __attribute__((__aligned__(32)));

static bool ll_arm64_hwbp_set(pid_t pid, ut64 _addr, int size, int wp, ut32 type) {
	const volatile uint8_t *addr = (void*)(size_t)_addr; //&var[32 + wp];
	const unsigned int offset = (uintptr_t)addr % 8;
	const ut32 byte_mask = ((1 << size) - 1) << offset;
	const ut32 enable = 1;
	const ut32 control = byte_mask << 5 | type << 3 | enable;

	struct user_hwdebug_state dreg_state = {0};
	struct iovec iov = {0};
	iov.iov_base = &dreg_state;
	iov.iov_len = sizeof (dreg_state);

	if (ptrace (PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
		// error reading regs
	}
	memcpy (&dreg_state, iov.iov_base, sizeof (dreg_state));
	// wp is not honored here i think... we can't have more than one wp for now..
	dreg_state.dbg_regs[0].addr = (uintptr_t)(addr - offset);
	dreg_state.dbg_regs[0].ctrl = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = rz_offsetof (struct user_hwdebug_state, dbg_regs) +
				sizeof (dreg_state.dbg_regs[0]);
	if (ptrace (PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
		return true;
	}

	if (errno == EIO) {
		eprintf ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s\n",
			strerror (errno));
	}

	eprintf ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s\n", strerror (errno));
	return false;
}

static bool ll_arm64_hwbp_del(pid_t pid, ut64 _addr, int size, int wp, ut32 type) {
	// const volatile uint8_t *addr = &var[32 + wp];
	// TODO: support multiple watchpoints and find
	struct user_hwdebug_state dreg_state = {0};
	struct iovec iov = {0};
	iov.iov_base = &dreg_state;
	// only delete 1 bp for now
	iov.iov_len = rz_offsetof (struct user_hwdebug_state, dbg_regs) +
				sizeof (dreg_state.dbg_regs[0]);
	if (ptrace (PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
		return true;
	}
	if (errno == EIO) {
		eprintf ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s\n",
			strerror (errno));
	}

	eprintf ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s\n", strerror (errno));
	return false;
}

static bool arm64_hwbp_add (RzDebug *dbg, RzBreakpoint* bp, RzBreakpointItem *b) {
	return ll_arm64_hwbp_set (dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

static bool arm64_hwbp_del (RzDebug *dbg, RzBreakpoint *bp, RzBreakpointItem *b) {
	return ll_arm64_hwbp_del (dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

#endif //  __arm64__
#endif // __linux__

/*
 * set or unset breakpoints...
 *
 * we only handle the case for hardware breakpoints here. otherwise,
 * we let the caller handle the work.
 */
static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	RzDebug *dbg = bp->user;
	if (b && b->hw) {
#if __i386__ || __x86_64__
		return set
			? drx_add (dbg, bp, b)
			: drx_del (dbg, bp, b);
#elif (__arm64__ || __aarch64__) && __linux__
		return set
			? arm64_hwbp_add (dbg, bp, b)
			: arm64_hwbp_del (dbg, bp, b);
#elif __arm__ && __linux__
		return set
			? arm32_hwbp_add (dbg, bp, b)
			: arm32_hwbp_del (dbg, bp, b);
#endif
	}
	return false;
}

#if __APPLE__

static int getMaxFiles(void) {
	struct rlimit limit;
	if (getrlimit (RLIMIT_NOFILE, &limit) != 0) {
		return 1024;
	}
	return limit.rlim_cur;
}

static RzList *xnu_desc_list (int pid) {
#if TARGET_OS_IPHONE || __POWERPC__
	return NULL;
#else
#define xwrz_testwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
	RzDebugDesc *desc;
	RzList *ret = rz_list_new ();
	struct vnode_fdinfowithpath vi;
	int i, nb, type = 0;
	int maxfd = getMaxFiles();

	for (i=0 ; i<maxfd; i++) {
		nb = proc_pidfdinfo (pid, i, PROC_PIDFDVNODEPATHINFO, &vi, sizeof (vi));
		if (nb<1) {
			continue;
		}
		if (nb < sizeof (vi)) {
			perror ("too few bytes");
			break;
		}
		//printf ("FD %d RWX %x ", i, vi.pfi.fi_openflags);
		//printf ("PATH %s\n", vi.pvip.vip_path);
		desc = rz_debug_desc_new (i,
				vi.pvip.vip_path,
				xwrz_testwx(vi.pfi.fi_openflags),
				type, 0);
		rz_list_append (ret, desc);
	}
	return ret;
#endif
}
#endif

static RzList *rz_debug_desc_native_list (int pid) {
#if __APPLE__
	return xnu_desc_list (pid);
#elif __WINDOWS__
	return w32_desc_list (pid);
#elif __KFBSD__
	return bsd_desc_list (pid);
#elif __linux__
	return linux_desc_list (pid);
#else
#warning list filedescriptors not supported for this platform
	return NULL;
#endif
}

static int rz_debug_native_map_protect (RzDebug *dbg, ut64 addr, int size, int perms) {
#if __WINDOWS__
	return w32_map_protect (dbg, addr, size, perms);
#elif __APPLE__
	return xnu_map_protect (dbg, addr, size, perms);
#elif __linux__
	RzBuffer *buf = NULL;
	char code[1024];
	int num;

	num = rz_syscall_get_num (dbg->analysis->syscall, "mprotect");
	snprintf (code, sizeof (code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%p,%d,%d);\n"
		":int3\n"
		"}\n", num, (void*)addr, size, io_perms_to_prot (perms));

	rz_egg_reset (dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load (dbg->egg, code, 0);
	if (!rz_egg_compile (dbg->egg)) {
		eprintf ("Cannot compile.\n");
		return false;
	}
	if (!rz_egg_assemble (dbg->egg)) {
		eprintf ("rz_egg_assemble: invalid assembly\n");
		return false;
	}
	buf = rz_egg_get_bin (dbg->egg);
	if (buf) {
		rz_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data (buf, &tmpsz);
		rz_debug_execute (dbg, tmp, tmpsz, 1);
		rz_reg_arena_pop (dbg->reg);
		return true;
	}

	return false;
#else
	// mprotect not implemented for this platform
	return false;
#endif
}

static int rz_debug_desc_native_open (const char *path) {
	return 0;
}

#if 0
static int rz_debug_setup_ownership (int fd, RzDebug *dbg) {
	RzDebugInfo *info = rz_debug_info (dbg, NULL);

	if (!info) {
		eprintf ("Error while getting debug info.\n");
		return -1;
	}
	fchown (fd, info->uid, info->gid);
	rz_debug_info_free (info);
  	return 0;
}
#endif

static bool rz_debug_gcore (RzDebug *dbg, RzBuffer *dest) {
#if __APPLE__
	return xnu_generate_corefile (dbg, dest);
#elif __linux__ && (__x86_64__ || __i386__ || __arm__ || __arm64__)
#  if __ANDROID__
	return false;
#  else
	return linux_generate_corefile (dbg, dest);
#  endif
#else
	return false;
#endif
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
	.open = rz_debug_desc_native_open,
	.list = rz_debug_desc_native_list,
};

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
#if __i386__
	.bits = RZ_SYS_BITS_32,
	.arch = "x86",
	.canstep = 1,
#elif __x86_64__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1, // XXX it's 1 on some platforms...
#elif __aarch64__ || __arm64__
	.bits = RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "arm",
	.canstep = 1,
#elif __arm__
	.bits = RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "arm",
	.canstep = 0,
#elif __mips__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "mips",
	.canstep = 0,
#elif __powerpc__
# if __powerpc64__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
# else
	.bits = RZ_SYS_BITS_32,
#endif
	.arch = "ppc",
	.canstep = 1,
#else
	.bits = 0,
	.arch = 0,
	.canstep = 0,
#ifdef _MSC_VER
#pragma message("Unsupported architecture")
#else
#warning Unsupported architecture
#endif
#endif
	.init = &rz_debug_native_init,
	.step = &rz_debug_native_step,
	.cont = &rz_debug_native_continue,
	.stop = &rz_debug_native_stop,
	.contsc = &rz_debug_native_continue_syscall,
	.attach = &rz_debug_native_attach,
	.detach = &rz_debug_native_detach,
// TODO: add native select for other platforms?
#if __WINDOWS__ || __linux__
	.select = &rz_debug_native_select,
#endif
	.pids = &rz_debug_native_pids,
	.tids = &rz_debug_native_tids,
	.threads = &rz_debug_native_threads,
	.wait = &rz_debug_native_wait,
	.kill = &rz_debug_native_kill,
	.frames = &rz_debug_native_frames, // rename to backtrace ?
	.reg_profile = rz_debug_native_reg_profile,
	.reg_read = rz_debug_native_reg_read,
	.info = rz_debug_native_info,
	.reg_write = (void *)&rz_debug_native_reg_write,
	.map_alloc = rz_debug_native_map_alloc,
	.map_dealloc = rz_debug_native_map_dealloc,
	.map_get = rz_debug_native_map_get,
	.modules_get = rz_debug_native_modules_get,
	.map_protect = rz_debug_native_map_protect,
	.breakpoint = rz_debug_native_bp,
	.drx = rz_debug_native_drx,
	.gcore = rz_debug_gcore,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_native,
	.version = RZ_VERSION
};
#endif // RZ_PLUGIN_INCORE

//#endif
#else // DEBUGGER
RzDebugPlugin rz_debug_plugin_native = {
	NULL // .name = "native",
};

#endif // DEBUGGER
