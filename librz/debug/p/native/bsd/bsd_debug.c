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
#if __KFBSD__ || __DragonFly__
#include <sys/user.h>
#include <libutil.h>
#elif __OpenBSD__ || __NetBSD__
#include <sys/proc.h>
#endif

#if __KFBSD__
static void addr_to_string(struct sockaddr_storage *ss, char *buffer, int buflen) {
	char buffer2[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

	if (buflen > 0)
		switch (ss->ss_family) {
		case AF_LOCAL:
			sun = (struct sockaddr_un *)ss;
			strncpy(buffer, (sun && *sun->sun_path) ? sun->sun_path : "-", buflen - 1);
			break;
		case AF_INET:
			sin = (struct sockaddr_in *)ss;
			snprintf(buffer, buflen, "%s:%d", inet_ntoa(sin->sin_addr),
				ntohs(sin->sin_port));
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ss;
			if (inet_ntop(AF_INET6, &sin6->sin6_addr, buffer2,
				    sizeof(buffer2)) != NULL) {
				snprintf(buffer, buflen, "%s.%d", buffer2,
					ntohs(sin6->sin6_port));
			} else {
				strcpy(buffer, "-");
			}
			break;
		default:
			*buffer = 0;
			break;
		}
}
#endif

int bsd_handle_signals(RzDebug *dbg) {
#if __KFBSD__ || __NetBSD__
	siginfo_t siginfo;
#if __KFBSD__
	// Trying to figure out a bit by the signal
	struct ptrace_lwpinfo linfo = { 0 };
	int ret = ptrace(PT_LWPINFO, dbg->pid, (char *)&linfo, sizeof(linfo));
	if (ret == -1) {
		if (errno == ESRCH) {
			dbg->reason.type = RZ_DEBUG_REASON_DEAD;
			return 0;
		}
		rz_sys_perror("ptrace PTRACE_LWPINFO");
		return -1;
	}

	// Not stopped by the signal
	if (linfo.pl_event == PL_EVENT_NONE) {
		dbg->reason.type = RZ_DEBUG_REASON_BREAKPOINT;
		return 0;
	}

	siginfo = linfo.pl_siginfo;
#else
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
#endif
	dbg->reason.type = RZ_DEBUG_REASON_SIGNAL;
	dbg->reason.signum = siginfo.si_signo;

	switch (dbg->reason.signum) {
	case SIGABRT:
		dbg->reason.type = RZ_DEBUG_REASON_ABORT;
		break;
	case SIGSEGV:
		dbg->reason.type = RZ_DEBUG_REASON_SEGFAULT;
		break;
#if __NetBSD__
	case SIGTRAP:
		if (siginfo.si_code == TRAP_BRKPT) {
			dbg->reason.type = RZ_DEBUG_REASON_BREAKPOINT;
		}
		break;
#endif
	}

	return 0;
#else
	return -1;
#endif
}

int bsd_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int r = -1;
	switch (type) {
	case RZ_REG_TYPE_GPR:
		r = ptrace(PT_SETREGS, dbg->pid,
			(caddr_t)buf, sizeof(struct reg));
		break;
	case RZ_REG_TYPE_DRX:
#if __KFBSD__ || __NetBSD__
		r = ptrace(PT_SETDBREGS, dbg->pid, (caddr_t)buf, sizeof(struct dbreg));
#endif
		break;
	case RZ_REG_TYPE_FPU:
		r = ptrace(PT_SETFPREGS, dbg->pid, (caddr_t)buf, sizeof(struct fpreg));
		break;
	}

	return (r == 0 ? true : false);
}

bool bsd_generate_corefile(RzDebug *dbg, char *path, RzBuffer *dest) {
#if defined(__NetBSD__)
	return ptrace(PT_DUMPCORE, dbg->pid, path, strlen(path)) != -1;
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1302000
	struct ptrace_coredump pc = { .pc_fd = dest->fd, .pc_flags = PC_ALL, .pc_limit = 0 };
	return ptrace(PT_COREDUMP, dbg->pid, (void *)&pc, sizeof(pc)) != -1;
#else
	return false;
#endif
}
RzDebugInfo *bsd_info(RzDebug *dbg, const char *arg) {
#if __KFBSD__
	struct kinfo_proc *kp;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	if (!(kp = kinfo_getproc(dbg->pid))) {
		free(rdi);
		return NULL;
	}

	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = kp->ki_uid;
	rdi->gid = kp->ki_pgid;
	rdi->exe = strdup(kp->ki_comm);

	switch (kp->ki_stat) {
	case SSLEEP:
		rdi->status = RZ_DBG_PROC_SLEEP;
		break;
	case SSTOP:
		rdi->status = RZ_DBG_PROC_STOP;
		break;
	case SZOMB:
		rdi->status = RZ_DBG_PROC_ZOMBIE;
		break;
	case SRUN:
	case SIDL:
	case SLOCK:
	case SWAIT:
		rdi->status = RZ_DBG_PROC_RUN;
		break;
	default:
		rdi->status = RZ_DBG_PROC_DEAD;
	}

	free(kp);

	return rdi;
#elif __OpenBSD__
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
		rdi->exe = strdup(kp->p_comm);

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
#elif __NetBSD__
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
		rdi->exe = strdup(kp->p_comm);

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
#endif
}

RzList *bsd_pid_list(RzDebug *dbg, int pid, RzList *list) {
#if __KFBSD__
#ifdef __NetBSD__
#define KVM_OPEN_FLAG KVM_NO_FILES
#define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getproc2(kd, opt, arg, sizeof(struct kinfo_proc2), cntptr)
#define KP_COMM(x) (x)->p_comm
#define KP_PID(x)  (x)->p_pid
#define KP_PPID(x) (x)->p_ppid
#define KP_UID(x)  (x)->p_uid
#define KINFO_PROC kinfo_proc2
#elif defined(__OpenBSD__)
#define KVM_OPEN_FLAG KVM_NO_FILES
#define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getprocs(kd, opt, arg, sizeof(struct kinfo_proc), cntptr)
#define KP_COMM(x) (x)->p_comm
#define KP_PID(x)  (x)->p_pid
#define KP_PPID(x) (x)->p_ppid
#define KP_UID(x)  (x)->p_uid
#define KINFO_PROC kinfo_proc
#elif __DragonFly__
#define KVM_OPEN_FLAG O_RDONLY
#define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getprocs(kd, opt, arg, cntptr)
#define KP_COMM(x) (x)->kp_comm
#define KP_PID(x)  (x)->kp_pid
#define KP_PPID(x) (x)->kp_ppid
#define KP_UID(x)  (x)->kp_uid
#define KINFO_PROC kinfo_proc
#else
#define KVM_OPEN_FLAG O_RDONLY
#define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getprocs(kd, opt, arg, cntptr)
#define KP_COMM(x) (x)->ki_comm
#define KP_PID(x)  (x)->ki_pid
#define KP_PPID(x) (x)->ki_ppid
#define KP_UID(x)  (x)->ki_uid
#define KINFO_PROC kinfo_proc
#endif
	char errbuf[_POSIX2_LINE_MAX];
	struct KINFO_PROC *kp, *entry;
	int cnt = 0;
	int i;

#if __FreeBSD__
	kvm_t *kd = kvm_openfiles(NULL, "/dev/null", NULL, KVM_OPEN_FLAG, errbuf);
#else
	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_OPEN_FLAG, errbuf);
#endif
	if (!kd) {
		eprintf("kvm_openfiles failed: %s\n", errbuf);
		return NULL;
	}

	kp = KVM_GETPROCS(kd, KERN_PROC_PROC, 0, &cnt);
	for (i = 0; i < cnt; i++) {
		entry = kp + i;
		// Unless pid 0 is requested, only add the requested pid and it's child processes
		if (0 == pid || KP_PID(entry) == pid || KP_PPID(entry) == pid) {
			RzDebugPid *p = rz_debug_pid_new(KP_COMM(entry), KP_PID(entry), KP_UID(entry), 's', 0);
			if (p) {
				p->ppid = KP_PPID(entry);
				rz_list_append(list, p);
			}
		}
	}

	kvm_close(kd);
#endif
	return list;
}

RzList *bsd_native_sysctl_map(RzDebug *dbg) {
#if __KFBSD__
	int mib[4];
	size_t len;
	char *buf, *bp, *eb;
	struct kinfo_vmentry *kve;
	RzList *list = NULL;
	RzDebugMap *map;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_VMMAP;
	mib[3] = dbg->pid;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0)
		return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		free(buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	list = rz_debug_map_list_new();
	if (!list) {
		free(buf);
		return NULL;
	}
	while (bp < eb) {
		kve = (struct kinfo_vmentry *)(uintptr_t)bp;
		map = rz_debug_map_new(kve->kve_path, kve->kve_start,
			kve->kve_end, kve->kve_protection, 0);
		if (!map)
			break;
		rz_list_append(list, map);
		bp += kve->kve_structsize;
	}
	free(buf);
	return list;
#elif __OpenBSD__
	int mib[3];
	size_t len;
	struct kinfo_vmentry entry;
	u_long old_end = 0;
	RzList *list = NULL;
	RzDebugMap *map;

	len = sizeof(entry);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_VMMAP;
	mib[2] = dbg->pid;
	entry.kve_start = 0;

	if (sysctl(mib, 3, &entry, &len, NULL, 0) == -1) {
		eprintf("Could not get memory map: %s\n", strerror(errno));
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
		map = rz_debug_map_new("", entry.kve_start, entry.kve_end,
			entry.kve_protection, 0);
		if (!map)
			break;
		rz_list_append(list, map);

		entry.kve_start = entry.kve_start + 1;
		old_end = entry.kve_end;
	}

	return list;
#else
	return NULL;
#endif
}

RzList *bsd_desc_list(int pid) {
#if __KFBSD__
	RzList *ret = NULL;
	int perm, type, mib[4];
	size_t len;
	char *buf, *bp, *eb, *str, path[1024];
	RzDebugDesc *desc;
	struct kinfo_file *kve;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_FILEDESC;
	mib[3] = pid;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0)
		return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		free(buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	ret = rz_list_new();
	if (!ret) {
		free(buf);
		return NULL;
	}
	ret->free = (RzListFree)rz_debug_desc_free;
	while (bp < eb) {
		kve = (struct kinfo_file *)(uintptr_t)bp;
		bp += kve->kf_structsize;
		if (kve->kf_fd < 0)
			continue; // Skip root and cwd. We need it ??
		str = kve->kf_path;
		switch (kve->kf_type) {
		case KF_TYPE_VNODE: type = 'v'; break;
		case KF_TYPE_SOCKET:
			type = 's';
#if __FreeBSD_version < 1200031
			if (kve->kf_sock_domain == AF_LOCAL) {
				struct sockaddr_un *sun =
					(struct sockaddr_un *)&kve->kf_sa_local;
				if (sun->sun_path[0] != 0)
					addr_to_string(&kve->kf_sa_local, path, sizeof(path));
				else
					addr_to_string(&kve->kf_sa_peer, path, sizeof(path));
			} else {
				addr_to_string(&kve->kf_sa_local, path, sizeof(path));
				strcat(path, " ");
				addr_to_string(&kve->kf_sa_peer, path + strlen(path),
					sizeof(path));
			}
#else
			if (kve->kf_sock_domain == AF_LOCAL) {
				struct sockaddr_un *sun =
					(struct sockaddr_un *)&kve->kf_un.kf_sock.kf_sa_local;
				if (sun->sun_path[0] != 0)
					addr_to_string(&kve->kf_un.kf_sock.kf_sa_local, path, sizeof(path));
				else
					addr_to_string(&kve->kf_un.kf_sock.kf_sa_peer, path, sizeof(path));
			} else {
				addr_to_string(&kve->kf_un.kf_sock.kf_sa_local, path, sizeof(path));
				strcat(path, " ");
				addr_to_string(&kve->kf_un.kf_sock.kf_sa_peer, path + strlen(path),
					sizeof(path));
			}
#endif
			str = path;
			break;
		case KF_TYPE_PIPE: type = 'p'; break;
		case KF_TYPE_FIFO: type = 'f'; break;
		case KF_TYPE_KQUEUE: type = 'k'; break;
#if __FreeBSD_version < 1300130
		// removed in https://reviews.freebsd.org/D27302
		case KF_TYPE_CRYPTO: type = 'c'; break;
#endif
		case KF_TYPE_MQUEUE: type = 'm'; break;
		case KF_TYPE_SHM: type = 'h'; break;
		case KF_TYPE_PTS: type = 't'; break;
		case KF_TYPE_SEM: type = 'e'; break;
		case KF_TYPE_NONE:
		case KF_TYPE_UNKNOWN:
		default: type = '-'; break;
		}
		perm = (kve->kf_flags & KF_FLAG_READ) ? RZ_PERM_R : 0;
		perm |= (kve->kf_flags & KF_FLAG_WRITE) ? RZ_PERM_W : 0;
		desc = rz_debug_desc_new(kve->kf_fd, str, perm, type, kve->kf_offset);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}

	free(buf);
	return ret;
#elif __NetBSD__
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
#else
	return NULL;
#endif
}

#if __KFBSD__
static int get_rz_status(int stat) {
	switch (stat) {
	case SRUN:
	case SIDL:
	case SLOCK:
	case SWAIT:
		return RZ_DBG_PROC_RUN;
	case SSTOP:
		return RZ_DBG_PROC_STOP;
	case SZOMB:
		return RZ_DBG_PROC_ZOMBIE;
	case SSLEEP:
		return RZ_DBG_PROC_SLEEP;
	default:
		return RZ_DBG_PROC_DEAD;
	}
}
#endif

RzList *bsd_thread_list(RzDebug *dbg, int pid, RzList *list) {
#if __KFBSD__
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID | KERN_PROC_INC_THREAD, pid };
	struct kinfo_proc *kp;
	size_t len = 0;
	size_t max;
	int i = 0;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) == -1) {
		rz_list_free(list);
		return NULL;
	}

	len += sizeof(*kp) + len / 10;
	kp = malloc(len);
	if (sysctl(mib, 4, kp, &len, NULL, 0) == -1) {
		free(kp);
		rz_list_free(list);
		return NULL;
	}

	max = len / sizeof(*kp);
	for (i = 0; i < max; i++) {
		RzDebugPid *pid_info;
		int pid_stat;

		pid_stat = get_rz_status(kp[i].ki_stat);
		pid_info = rz_debug_pid_new(kp[i].ki_comm, kp[i].ki_tid,
			kp[i].ki_uid, pid_stat, (ut64)kp[i].ki_wchan);
		rz_list_append(list, pid_info);
	}

	free(kp);
	return list;
#else
	eprintf("bsd_thread_list unsupported on this platform\n");
	rz_list_free(list);
	return NULL;
#endif
}
