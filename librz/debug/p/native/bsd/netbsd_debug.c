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
	siginfo_t siginfo;
	struct ptrace_siginfo sinfo = { 0 };
	if (ptrace(PT_GET_SIGINFO, dbg->pid, (char *)&sinfo, sizeof(sinfo)) == -1) {
		if (errno == ESRCH) {
			dbg->reason.type = RZ_DEBUG_REASON_DEAD;
			return 0;
		}
		rz_sys_perror("ptrace PTRACE_GET_SIGINFO");
		return -1;
	}

	siginfo = sinfo.psi_siginfo;
	dbg->reason.type = RZ_DEBUG_REASON_SIGNAL;
	dbg->reason.signum = siginfo.si_signo;

	switch (dbg->reason.signum) {
	case SIGABRT:
		dbg->reason.type = RZ_DEBUG_REASON_ABORT;
		break;
	case SIGSEGV:
		dbg->reason.type = RZ_DEBUG_REASON_SEGFAULT;
		break;
	case SIGTRAP:
		if (siginfo.si_code == TRAP_BRKPT) {
			dbg->reason.type = RZ_DEBUG_REASON_BREAKPOINT;
		}
		break;
	}

	return 0;
}

int bsd_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int r = -1;
	switch (type) {
	case RZ_REG_TYPE_GPR:
		r = ptrace(PT_SETREGS, dbg->pid,
			(caddr_t)buf, sizeof(struct reg));
		break;
	case RZ_REG_TYPE_DRX:
		r = ptrace(PT_SETDBREGS, dbg->pid, (caddr_t)buf, sizeof(struct dbreg));
		break;
	case RZ_REG_TYPE_FPU:
		r = ptrace(PT_SETFPREGS, dbg->pid, (caddr_t)buf, sizeof(struct fpreg));
		break;
	}

	return (r == 0 ? true : false);
}

bool bsd_generate_corefile(RzDebug *dbg, char *path, RzBuffer *dest) {
	return ptrace(PT_DUMPCORE, dbg->pid, path, strlen(path)) != -1;
}

RzDebugInfo *bsd_info(RzDebug *dbg, const char *arg) {
	struct kinfo_proc2 *kp;
	char err[_POSIX2_LINE_MAX];
	int np;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, err);
	if (!kd) {
		free(rdi);
		return NULL;
	}

	kp = kvm_getproc2(kd, KERN_PROC_PID, dbg->pid, sizeof(*kp), &np);
	if (kp) {
		rdi->pid = dbg->pid;
		rdi->tid = dbg->tid;
		rdi->uid = kp->p_uid;
		rdi->gid = kp->p__pgid;
		rdi->exe = rz_str_dup(kp->p_comm);

		rdi->status = RZ_DBG_PROC_STOP;

		switch (kp->p_stat) {
		case SDEAD:
			rdi->status = RZ_DBG_PROC_DEAD;
			break;
		case SSTOP:
			rdi->status = RZ_DBG_PROC_STOP;
			break;
		case SZOMB:
			rdi->status = RZ_DBG_PROC_ZOMBIE;
			break;
		case SACTIVE:
		case SIDL:
		case SDYING:
			rdi->status = RZ_DBG_PROC_RUN;
			break;
		default:
			rdi->status = RZ_DBG_PROC_SLEEP;
		}
	}

	kvm_close(kd);

	return rdi;
}

RzList /*<RzDebugProcess *>*/ *bsd_pid_list(RzDebug *dbg, int pid, RzList *list) {
#define KVM_OPEN_FLAG KVM_NO_FILES
#define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getproc2(kd, opt, arg, sizeof(struct kinfo_proc2), cntptr)
#define KP_COMM(x) (x)->p_comm
#define KP_PPID(x) (x)->p_ppid
#define KP_PID(x)  (x)->p_pid
#define KP_UID(x)  (x)->p_uid
#define KP_GID(x)  (x)->p_gid
#define KINFO_PROC kinfo_proc2

	char errbuf[_POSIX2_LINE_MAX];
	struct KINFO_PROC *kp, *entry;
	int cnt = 0;
	int i;

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_OPEN_FLAG, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		return NULL;
	}

	kp = KVM_GETPROCS(kd, KERN_PROC_ALL, 0, &cnt);
	if (!kp) {
		kvm_close(kd);
		return NULL;
	}

	list->free = (RzListFree)&rz_debug_process_free;
	for (i = 0; i < cnt; i++) {
		entry = kp + i;
		// Unless pid 0 is requested, only add the requested pid and its child processes
		if (0 == pid || KP_PID(entry) == pid || KP_PPID(entry) == pid) {
			RzDebugProcess *p = rz_debug_process_new(KP_COMM(entry), KP_PID(entry), KP_UID(entry), RZ_DBG_PROC_STOP);
			if (p) {
				p->ppid = KP_PPID(entry);
				p->gid = KP_GID(entry);
				rz_list_append(list, p);
			}
		}
	}

	kvm_close(kd);
	return list;
}

RzList *bsd_native_sysctl_map(RzDebug *dbg) {
	return NULL;
}

RzList *bsd_desc_list(int pid) {
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
			type = st.st_mode & S_IFIFO ? 'P' : st.st_mode & S_IFSOCK ? 'S'
				: st.st_mode & S_IFCHR                            ? 'C'
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

static RzDebugThreadState get_netbsd_thread_state(int stat) {
	switch (stat) {
	case LSIDL:
	case LSRUN:
	case LSONPROC:
		return RZ_DBG_THREAD_RUN;
	case LSSLEEP:
		return RZ_DBG_THREAD_SLEEP;
	case LSSTOP:
	case LSSUSPENDED:
		return RZ_DBG_THREAD_STOP;
	case LSZOMB:
		return RZ_DBG_THREAD_ZOMBIE;
#ifdef LSDEAD
	case LSDEAD:
		return RZ_DBG_THREAD_DEAD;
#endif
	default:
		return RZ_DBG_THREAD_UNKNOWN;
	}
}

static RzList /*<RzDebugThread *>*/ *netbsd_thread_list(RzDebug *dbg, int pid, RzList *list) {
	int mib[5] = { CTL_KERN, KERN_LWP, pid, sizeof(struct kinfo_lwp), 0 };
	struct kinfo_lwp *kl;
	size_t len = 0;
	size_t max, i;

	if (sysctl(mib, 5, NULL, &len, NULL, 0) == -1) {
		rz_list_free(list);
		return NULL;
	}

	len += sizeof(*kl) + len / 10;
	kl = malloc(len);
	if (!kl) {
		rz_list_free(list);
		return NULL;
	}

	mib[4] = len / sizeof(struct kinfo_lwp);

	if (sysctl(mib, 5, kl, &len, NULL, 0) == -1) {
		free(kl);
		rz_list_free(list);
		return NULL;
	}

	list->free = (RzListFree)&rz_debug_thread_free;
	max = len / sizeof(*kl);
	for (i = 0; i < max; i++) {
		RzDebugThread *th = rz_debug_thread_new(kl[i].l_lid, pid,
			get_netbsd_thread_state(kl[i].l_stat), 0);
		if (th) {
			rz_list_append(list, th);
		}
	}

	free(kl);
	return list;
}

RzList /*<RzDebugThread *>*/ *bsd_thread_list(RzDebug *dbg, int pid, RzList *list) {
	return netbsd_thread_list(dbg, pid, list);
}