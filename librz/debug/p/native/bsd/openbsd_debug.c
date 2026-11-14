// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <signal.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <kvm.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <kvm.h>
#include <limits.h>
#include "bsd_debug.h"
#include <rz_util/rz_log.h>
#include <sys/proc.h>

int bsd_handle_signals(RzDebug *dbg) {
	return -1;
}

int bsd_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int r = -1;
	switch (type) {
	case RZ_REG_TYPE_GPR:
		r = ptrace(PT_SETREGS, dbg->pid,
			(caddr_t)buf, sizeof(struct reg));
		break;
	case RZ_REG_TYPE_DRX:
		break;
	case RZ_REG_TYPE_FPU:
		r = ptrace(PT_SETFPREGS, dbg->pid, (caddr_t)buf, sizeof(struct fpreg));
		break;
	}

	return (r == 0 ? true : false);
}

bool bsd_generate_corefile(RzDebug *dbg, char *path, RzBuffer *dest) {
	return false;
}

RzDebugInfo *bsd_info(RzDebug *dbg, const char *arg) {
	struct kinfo_proc *kp;
	char err[_POSIX2_LINE_MAX];
	int rc;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, err);
	if (!kd) {
		free(rdi);
		return NULL;
	}

	kp = kvm_getprocs(kd, KERN_PROC_PID, dbg->pid, sizeof(*kp), &rc);
	if (kp) {
		rdi->pid = dbg->pid;
		rdi->tid = dbg->tid;
		rdi->uid = kp->p_uid;
		rdi->gid = kp->p__pgid;
		rdi->exe = rz_str_dup(kp->p_comm);

		switch (kp->p_stat) {
		case SDEAD:
			rdi->status = RZ_DBG_PROC_DEAD;
			break;
		case SSTOP:
			rdi->status = RZ_DBG_PROC_STOP;
			break;
		case SSLEEP:
			rdi->status = RZ_DBG_PROC_SLEEP;
			break;
		default:
			rdi->status = RZ_DBG_PROC_RUN;
			break;
		}
	}

	kvm_close(kd);

	return rdi;
}

static RzDebugProcessState openbsd_process_state(int stat) {
	switch (stat) {
	case SIDL:
	case SRUN:
	case SONPROC:
		return RZ_DBG_PROC_RUN;
	case SSLEEP:
		return RZ_DBG_PROC_SLEEP;
	case SSTOP:
		return RZ_DBG_PROC_STOP;
	case SDEAD:
		return RZ_DBG_PROC_DEAD;
	default:
		return RZ_DBG_PROC_UNKNOWN;
	}
}

RzList *bsd_pid_list(RzDebug *dbg, int pid, RzList *list) {
	char errbuf[_POSIX2_LINE_MAX];
	struct kinfo_proc *kp;
	int cnt = 0;
	int i;

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		return NULL;
	}

	kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &cnt);
	if (!kp) {
		kvm_close(kd);
		return NULL;
	}

	for (i = 0; i < cnt; i++) {
		struct kinfo_proc *entry = kp + i;
		if (pid && entry->p_pid != pid && entry->p_ppid != pid) {
			continue;
		}
		RzDebugProcess *proc = rz_debug_process_new(entry->p_comm, entry->p_pid, entry->p_uid, openbsd_process_state(entry->p_stat));
		if (!proc) {
			continue;
		}
		proc->ppid = entry->p_ppid;
		if (!rz_list_append(list, proc)) {
			rz_debug_process_free(proc);
		}
	}

	kvm_close(kd);
	return list;
}
RzList *bsd_native_sysctl_map(RzDebug *dbg) {
	int mib[3];
	size_t len;
	struct kinfo_vmentry entry;
	u_long old_end = 0;
	RzList *list = NULL;
	RzDebugMap *map;
	u_long map_start = 0;
	u_long map_end = 0;
	ut64 offset = 0;
	int perm = 0;

	len = sizeof(entry);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_VMMAP;
	mib[2] = dbg->pid;
	entry.kve_start = 0;

	if (sysctl(mib, 3, &entry, &len, NULL, 0) == -1) {
		RZ_LOG_ERROR("Could not get memory map: %s\n", strerror(errno));
		return NULL;
	}

	list = rz_debug_map_list_new();
	if (!list)
		return NULL;

	while (sysctl(mib, 3, &entry, &len, NULL, 0) != -1) {
		if (old_end == entry.kve_end) {
			/* No more entries */
			break;
		}
		/* path to vm obj is not included in kinfo_vmentry.
		 * see usr.sbin/procmap for namei-cache lookup.
		 */
		map_start = entry.kve_start;
		map_end = entry.kve_end;

		if (entry.kve_protection & KVE_PROT_READ) {
			perm |= RZ_PERM_R;
		}
		if (entry.kve_protection & KVE_PROT_WRITE) {
			perm |= RZ_PERM_W;
		}
		if (entry.kve_protection & KVE_PROT_EXEC) {
			perm |= RZ_PERM_X;
		}

		map = rz_debug_map_new("", map_start, map_end,
			perm, 0);
		if (!map) {
			break;
		}
		map->offset = entry.kve_offset;
		rz_list_append(list, map);

		entry.kve_start = entry.kve_start + 1;
		old_end = entry.kve_end;
	}

	return list;
}

RzList *bsd_desc_list(int pid) {
	return NULL;
}

static RzDebugThreadState openbsd_thread_state(int stat) {
	switch (stat) {
	case SIDL:
	case SRUN:
	case SONPROC:
		return RZ_DBG_THREAD_RUN;
	case SSLEEP:
		return RZ_DBG_THREAD_SLEEP;
	case SSTOP:
		return RZ_DBG_THREAD_STOP;
	case SDEAD:
		return RZ_DBG_THREAD_DEAD;
	default:
		return RZ_DBG_THREAD_UNKNOWN;
	}
}

static RzList *openbsd_thread_list(RzDebug *dbg, int pid, RzList *list) {
	int mib[6] = { CTL_KERN, KERN_PROC, KERN_PROC_PID | KERN_PROC_SHOW_THREADS, pid, sizeof(struct kinfo_proc), 0 };
	struct kinfo_proc *kp;
	size_t len = 0;
	size_t i, max;

	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		rz_list_free(list);
		return NULL;
	}

	len += sizeof(*kp) + len / 10;
	kp = malloc(len);
	if (!kp) {
		rz_list_free(list);
		return NULL;
	}
	mib[5] = len / sizeof(*kp);
	if (sysctl(mib, 6, kp, &len, NULL, 0) == -1) {
		free(kp);
		rz_list_free(list);
		return NULL;
	}

	max = len / sizeof(*kp);
	for (i = 0; i < max; i++) {
		if (kp[i].p_tid == -1) {
			continue;
		}
		RzDebugThread *th = rz_debug_thread_new(kp[i].p_tid, pid, openbsd_thread_state(kp[i].p_stat), 0);
		if (th && !rz_list_append(list, th)) {
			rz_debug_thread_free(th);
		}
	}

	free(kp);
	return list;
}

RzList *bsd_thread_list(RzDebug *dbg, int pid, RzList *list) {
	RzList *thread_list = openbsd_thread_list(dbg, pid, list);
	return thread_list;
}