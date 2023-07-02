// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "debugger.h"

#include <limits.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "linux_ptrace.h"

#define LINUX_PROC_STATUS_TH_UID   "Uid:"
#define LINUX_PROC_STATUS_TH_PPID  "PPid:"
#define LINUX_PROC_STATUS_TH_TGID  "Tgid:"
#define LINUX_PROC_STATUS_TH_GID   "Gid:"
#define LINUX_PROC_STATUS_TH_STATE "State:"

static int native_linux_file_type(const char *path) {
	struct stat info = { 0 };
	if (stat(path, &info) < 0) {
		return 0;
	}
	if (info.st_mode & S_IFIFO) {
		return 'P';
	} else if (info.st_mode & S_IFCHR) {
		return 'C';
#ifdef S_IFSOCK
	} else if (info.st_mode & S_IFSOCK) {
		return 'S';
#endif
	}
	return '-';
}

static int native_linux_file_perm(const char *path) {
	struct stat info = { 0 };
	if (lstat(path, &info) < 0) {
		return 0;
	}
	int perm = 0;
	if (info.st_mode & S_IRUSR) {
		perm |= RZ_PERM_R;
	}
	if (info.st_mode & S_IWUSR) {
		perm |= RZ_PERM_W;
	}
	return perm;
}

static char *native_linux_process_cmd_line(int pid) {
	if (pid <= 0) {
		return NULL;
	}
	char path[PATH_MAX] = { 0 };
	rz_strf(path, "/proc/%d/cmdline", pid);
	char *cmdline = rz_file_slurp(path, NULL);
	rz_str_trim(cmdline);
	if (RZ_STR_ISEMPTY(cmdline)) {
		free(cmdline);
		return NULL;
	}
	return cmdline;
}

static char *native_linux_process_kernel_stack(int pid) {
	if (pid <= 0) {
		return NULL;
	}
	char path[PATH_MAX] = { 0 };
	rz_strf(path, "/proc/%d/stack", pid);
	return rz_file_slurp(path, NULL);
}

static char *native_linux_process_command_name(int pid) {
	if (pid <= 0) {
		return NULL;
	}
	char path[PATH_MAX] = { 0 };
	rz_strf(path, "/proc/%d/comm", pid);
	char *comm = rz_file_slurp(path, NULL);
	rz_str_trim(comm);
	if (RZ_STR_ISEMPTY(comm)) {
		free(comm);
		return rz_str_newf("thread_%d", pid);
	}
	return comm;
}

static ut32 linux_parse_map_permissions(const char *cur, const char *end) {
	ut32 perm = 0;
	while (cur < end) {
		switch (*cur) {
		case 'r':
			perm |= RZ_PERM_R;
			break;
		case 'w':
			perm |= RZ_PERM_W;
			break;
		case 'x':
			perm |= RZ_PERM_X;
			break;
		case 's':
			perm |= RZ_PERM_SHAR;
			break;
		default:
			break;
		}
		cur++;
	}
	return perm;
}

static RzList /*<RzDebugMap *>*/ *native_linux_process_maps(int pid) {
	if (pid <= 0) {
		return NULL;
	}
	char path[PATH_MAX] = { 0 };
	RzList *debug_maps = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!debug_maps) {
		RZ_LOG_ERROR("debug: failed to allocate process %d map list\n", pid);
		return NULL;
	}

	rz_strf(path, "/proc/%d/maps", pid);
	char *maps = rz_file_slurp(path, NULL);
	if (RZ_STR_ISEMPTY(maps)) {
		free(maps);
		return debug_maps;
	}

	char *cur = maps;
	char *end = maps + strlen(maps);
	while (cur < end) {
		char *endline = strchr(cur, '\n');
		if (!endline) {
			endline = end;
		}

		char *vend = strchr(cur, '-');
		if (!vend || vend > endline) {
			RZ_LOG_ERROR("debug: failed to parse map at %s\n", path);
			break;
		}
		*vend = 0;
		ut64 map_begin = strtoull(cur, NULL, 16);

		cur = vend + 1;
		vend = strchr(cur, ' ');
		if (!vend || vend > endline) {
			RZ_LOG_ERROR("debug: failed to parse map at %s\n", path);
			break;
		}
		*vend = 0;
		ut64 map_end = strtoull(cur, NULL, 16);

		cur = vend + 1;
		vend = strchr(cur, ' ');
		if (!vend || vend > endline) {
			RZ_LOG_ERROR("debug: failed to parse map at %s\n", path);
			break;
		}
		ut32 perms = linux_parse_map_permissions(cur, vend);

		cur = vend + 1;
		vend = strchr(cur, ' ');
		if (!vend || vend > endline) {
			RZ_LOG_ERROR("debug: failed to parse map at %s\n", path);
			break;
		}
		*vend = 0;
		ut64 map_offset = strtoull(cur, NULL, 16);

		cur = strchr(vend + 7, ' '); // skip major:minor inode
		if (!cur || cur > endline) {
			RZ_LOG_ERROR("debug: failed to parse map at %s\n", path);
			break;
		}
		char *name = end > cur ? rz_str_ndup(cur, endline - cur) : NULL;
		rz_str_trim(name);

		RzDebugMap *map = rz_debug_map_new(name, map_begin, map_end, perms, 0);
		free(name);
		if (!map) {
			RZ_LOG_ERROR("debug: failed to parse map at %s\n", path);
			break;
		}
		map->offset = map_offset;
		map->shared = perms & RZ_PERM_SHAR;
		map->file = strdup(path);

		if (!rz_list_append(debug_maps, map)) {
			RZ_LOG_ERROR("debug: failed append RzDebugMap for %s.\n", path);
			rz_debug_map_free(map);
			break;
		}

		cur = endline + 1;
	}

	free(maps);
	return debug_maps;
}

static RZ_OWN char *native_linux_process_read_link(int pid, const char *entry) {
	if (pid <= 0) {
		return NULL;
	}
	// always zero the buffer, because readlink might not add terminator.
	char sympath[PATH_MAX] = { 0 };
	char realpath[PATH_MAX] = { 0 };

	rz_strf(sympath, "/proc/%d/%s", pid, entry);
	if (readlink(sympath, realpath, sizeof(realpath)) < 0) {
		return NULL;
	}
	// always ensure the string is zero terminated.
	realpath[sizeof(realpath) - 1] = 0;
	return strdup(realpath);
}

static RzList /*<RzDebugDesc *>*/ *native_linux_process_file_descriptors(int pid) {
	if (pid <= 0) {
		return NULL;
	}

	RzList *list = NULL;
	RzListIter *it = NULL;
	const char *entry = NULL;
	char path[PATH_MAX] = { 0 };

	rz_strf(path, "/proc/%d/fd/", pid);
	RzList *dirlist = rz_sys_dir(path);
	if (!dirlist) {
		RZ_LOG_ERROR("debug: failed to open %s\n", path);
		return NULL;
	}

	list = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!list) {
		RZ_LOG_ERROR("debug: failed to allocate process file descriptors list\n");
		goto fail;
	}

	rz_list_foreach (dirlist, it, entry) {
		if (*entry == '.') {
			continue;
		}
		rz_strf(path, "/proc/%d/fd/%s", pid, entry);

		// always zero the buffer, because readlink might not add terminator.
		char symfile[PATH_MAX] = { 0 };
		if (readlink(path, symfile, sizeof(symfile)) < 0) {
			RZ_LOG_WARN("debug: failed read symbolic link '%s'.\n", path);
			continue;
		}
		// always ensure the string is zero terminated.
		symfile[sizeof(symfile) - 1] = 0;

		int type = native_linux_file_type(symfile);
		int perm = native_linux_file_perm(symfile);
		int fd = atoi(entry);
		RzDebugDesc *desc = rz_debug_desc_new(fd, symfile, perm, type, 0);
		if (!desc || !rz_list_append(list, desc)) {
			RZ_LOG_ERROR("debug: failed append RzDebugDesc for %s.\n", path);
			rz_debug_desc_free(desc);
			goto fail;
		}
	}
	rz_list_free(dirlist);
	return list;

fail:
	rz_list_free(dirlist);
	rz_list_free(list);
	return NULL;
}

static RzDebugPidState process_status_parse_state(const char *status) {
	// From https://man7.org/linux/man-pages/man5/proc.5.html
	char *found = strstr(status, LINUX_PROC_STATUS_TH_STATE);
	if (!found) {
		return RZ_DBG_PROC_SLEEP;
	}

	found += strlen(LINUX_PROC_STATUS_TH_STATE);
	for (; IS_WHITESPACE(*found) && *found != '\n'; found++)
		;

	switch (*found) {
	case 'R': // R (running)
		return RZ_DBG_PROC_RUN;
	case 'D': // D (disk sleep)
	case 'S': // S (sleeping)
		return RZ_DBG_PROC_SLEEP;
	case 'T': // T (stopped)
	case 't': // t (tracing stop)
		return RZ_DBG_PROC_STOP;
	case 'Z': // Z (zombie)
		return RZ_DBG_PROC_ZOMBIE;
	case 'X': // X (dead)
		return RZ_DBG_PROC_DEAD;
	default:
		return RZ_DBG_PROC_SLEEP;
	}
}

static int process_status_parse_num(const char *status, const char *kw, size_t kw_len) {
	// From https://man7.org/linux/man-pages/man5/proc.5.html
	char *found = strstr(status, kw);
	if (!found) {
		return -1;
	}

	found += kw_len;
	for (; IS_WHITESPACE(*found) && *found != '\n'; found++)
		;

	return atoi(found);
}

#define process_status_parse_id(s, k) \
	process_status_parse_num(s, k, strlen(k))

static RzDebugPid *native_linux_process_status_parse(int pid, int ppid) {
	if (pid <= 0) {
		// never read negative pids and never read pid 0.
		return NULL;
	}

	// This returns the RzDebugPid only if the tgid matches the pid.
	char path[PATH_MAX] = { 0 };
	rz_strf(path, "/proc/%d/status", pid);
	char *status = rz_file_slurp(path, NULL);
	if (!status) {
		return NULL;
	}

	if (ppid) {
		// only if ppid is not 0
		int tgid = process_status_parse_id(status, LINUX_PROC_STATUS_TH_TGID); // thread group id (i.e., process id).
		if (tgid != ppid) {
			// This process is not part of the same thread group.
			free(status);
			return NULL;
		}
	}

	RzDebugPid *thread = RZ_NEW0(RzDebugPid);
	if (!thread) {
		RZ_LOG_ERROR("debug: failed to allocate RzDebugPid\n");
		free(status);
		return NULL;
	}

	thread->status = process_status_parse_state(status);
	thread->ppid = process_status_parse_id(status, LINUX_PROC_STATUS_TH_PPID); // pid of parent process.
	thread->uid = process_status_parse_id(status, LINUX_PROC_STATUS_TH_UID); // filesystem UID
	thread->gid = process_status_parse_id(status, LINUX_PROC_STATUS_TH_GID); // filesystem GID
	thread->pid = pid;
	thread->path = native_linux_process_cmd_line(pid);
	if (RZ_STR_ISEMPTY(thread->path)) {
		free(thread->path);
		thread->path = native_linux_process_command_name(pid);
	}
	thread->runnable = true;
	free(status);
	return thread;
}

static bool native_linux_setup_ptrace(RzDebug *dbg, int pid) {
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
	while (rz_debug_ptrace(dbg, PTRACE_SETOPTIONS, pid, 0, (rz_ptrace_data_t)(size_t)traceflags) < 0) {
		void *bed = rz_cons_sleep_begin();
		usleep(1000);
		rz_cons_sleep_end(bed);
	}
	return true;
}

static bool native_linux_process_kill_thread(int tid, int signo) {
	return syscall(__NR_tkill, tid, signo) >= 0;
}

static bool native_linux_process_stop_thread(RzDebug *dbg, int tid) {
	int status = 0;
	siginfo_t siginfo = { 0 };
	rz_ptrace_data_t pdata = (rz_ptrace_data_t)(intptr_t)&siginfo;

	// Return if the thread is already stopped
	if (rz_debug_ptrace(dbg, PTRACE_GETSIGINFO, tid, NULL, pdata) >= 0) {
		return true;
	}

	if (native_linux_process_kill_thread(tid, SIGSTOP)) {
		int ret = waitpid(tid, &status, 0);
		if (ret < 0) {
			RZ_LOG_ERROR("debug: failed to wait for thread id %d\n", tid);
		}
		return ret == tid;
	}
	return false;
}

static bool native_linux_process_continue_thread(RzDebug *dbg, int pid, int sig) {
	if (pid < 1 || sig < 0 || pid == getpid()) {
		return false;
	}
	rz_ptrace_data_t pdata = (rz_ptrace_data_t)(size_t)sig;
	return rz_debug_ptrace(dbg, PTRACE_CONT, pid, NULL, pdata) >= 0;
}

static bool native_linux_process_attach_to_pid(RzDebug *dbg, int pid) {
	if (pid < 0) {
		return false;
	}

	siginfo_t sig = { 0 };
	rz_ptrace_data_t pdata = (rz_ptrace_data_t)(intptr_t)&sig;

	// Safely check if the PID has already been attached to avoid printing errors.
	// Attaching to a process that has already been started with PTRACE_TRACEME.
	// sets errno to "Operation not permitted" which may be misleading.
	// GETSIGINFO can be called multiple times and would fail without attachment.
	if (rz_debug_ptrace(dbg, PTRACE_GETSIGINFO, pid, NULL, pdata) < 0) {
		if (rz_debug_ptrace(dbg, PTRACE_ATTACH, pid, NULL, NULL) < 0) {
			RZ_LOG_ERROR("debug: failed to attach to pid %d\n", pid);
			return false;
		}

		// Make sure SIGSTOP is delivered and wait for it since we can't affect the pid
		// until it hits SIGSTOP.
		if (!native_linux_process_stop_thread(dbg, pid)) {
			RZ_LOG_ERROR("debug: failed to stop pid %d\n", pid);
			return false;
		}
	}

	if (!native_linux_setup_ptrace(dbg, pid)) {
		RZ_LOG_ERROR("debug: failed to setup ptrace for pid %d\n", pid);
		return false;
	}
	return true;
}

static ut64 native_linux_process_get_pc(RzDebug *dbg, int pid) {
	if (pid < 1 || pid == getpid()) {
		return 0;
	}
	int current_tid = dbg->tid;

	// Switch to the currently inspected thread to get it's program counter
	if (current_tid != pid) {
		native_linux_process_attach_to_pid(dbg, pid);
		dbg->tid = pid; // TODO: remove any assignment to dbg
	}

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	ut64 pc = rz_debug_reg_get(dbg, "PC");
	if (pc == UT64_MAX) {
		pc = 0;
	}

	if (current_tid != pid) {
		// Return to the original thread
		native_linux_process_attach_to_pid(dbg, current_tid);
		dbg->tid = current_tid; // TODO: remove any assignment to dbg
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	}
	return pc;
}

/**
 * \brief Reads all threads linked to a specific PID
 *
 * Sometimes kernels are configured to show the associated PIDs to a parent PID
 * and the path /proc/pid/task/ is available; we use this to read the sym-linked
 * /proc/pid/status file.
 */
static bool native_linux_process_threads_from_task(RzDebug *dbg, int pid, RzList *threads) {
	if (pid <= 0) {
		// forbid requesting negative and especially pid 0
		return false;
	}

	char path[PATH_MAX] = { 0 };
	RzListIter *it = NULL;
	const char *entry = NULL;

	rz_strf(path, "/proc/%d/task", pid);
	RzList *dirlist = rz_file_is_directory(path) ? rz_sys_dir(path) : NULL;
	if (!dirlist) {
		return false;
	}

	rz_debug_map_sync(dbg);
	rz_list_foreach (dirlist, it, entry) {
		if (*entry == '.') {
			continue;
		}
		int process_id = atoi(entry);

		RzDebugPid *thread = native_linux_process_status_parse(process_id, pid);
		if (!thread) {
			continue;
		}

		thread->pc = native_linux_process_get_pc(dbg, process_id);
		if (!rz_list_append(threads, thread)) {
			RZ_LOG_ERROR("debug: failed append RzDebugPid for pid %d.\n", process_id);
			rz_debug_pid_free(thread);
			break;
		}
	}

	rz_list_free(dirlist);
	return true;
}

static bool is_pid_name(const char *name) {
	size_t length = strlen(name);
	for (size_t i = 0; i < length; ++i) {
		if (!IS_DIGIT(name[i])) {
			return false;
		}
	}
	return true;
}

/**
 * \brief      Finds all threads linked to a specific PID
 *
 * Sometimes kernels are configured to not show the associated PIDs to a parent PID
 * and the path /proc/pid/task/ is not available; to overcome this limitation we
 * need to check all the PIDs in /proc and parse their /proc/pid/status file.
 */
static bool native_linux_process_threads_from_proc(RzDebug *dbg, int pid, RzList *threads) {
	if (pid < 0) {
		// forbid requesting negative but allow pid 0
		return false;
	}
	RzListIter *it = NULL;
	const char *entry = NULL;

	RzList *dirlist = rz_sys_dir("/proc");
	if (!dirlist) {
		RZ_LOG_ERROR("debug: failed to read /proc folder\n");
		return false;
	}

	rz_debug_map_sync(dbg);
	rz_list_foreach (dirlist, it, entry) {
		if (*entry == '.' || !is_pid_name(entry)) {
			continue;
		}
		int process_id = atoi(entry);

		RzDebugPid *thread = native_linux_process_status_parse(process_id, pid);
		if (!thread) {
			continue;
		}

		if (!rz_list_append(threads, thread)) {
			RZ_LOG_ERROR("debug: failed append RzDebugPid for pid %d.\n", process_id);
			rz_debug_pid_free(thread);
			break;
		}
	}

	rz_list_free(dirlist);
	return true;
}

RzList /*<RzDebugPid *>*/ *native_linux_process_threads(RzDebug *dbg, int pid) {
	if (pid < 0) {
		return NULL;
	}

	RzList *threads = rz_list_newf((RzListFree)rz_debug_pid_free);
	if (!threads) {
		RZ_LOG_ERROR("debug: failed to allocate process threads list\n");
		return NULL;
	}

	if (!native_linux_process_threads_from_task(dbg, pid, threads) &&
		!native_linux_process_threads_from_proc(dbg, pid, threads)) {
		RZ_LOG_ERROR("debug: failed to get process threads list\n");
		rz_list_free(threads);
		return NULL;
	}

	return threads;
}

static void native_linux_process_detach_all(RzDebug *dbg) {
	// TODO: remove any assignment to dbg
	int pid = dbg->main_pid;
	RzDebugPid *thread;
	RzListIter *it;
	rz_list_foreach (dbg->threads, it, thread) {
		if (thread->pid == pid) {
			// ignore main thread.
			continue;
		}
		native_linux_process_detach(dbg, thread->pid);
	}

	// detach main thread.
	native_linux_process_detach(dbg, pid);
}

static bool native_linux_process_attach_to_new_pid(RzDebug *dbg, int pid) {
	native_linux_process_detach_all(dbg);
	rz_list_free(dbg->threads);
	dbg->threads = NULL; // TODO: remove any assignment to dbg

	if (!native_linux_process_detach(dbg, pid)) {
		return false;
	}

	// Call select to syncrhonize the thread's data.
	dbg->pid = pid; // TODO: remove any assignment to dbg
	dbg->tid = pid; // TODO: remove any assignment to dbg
	rz_debug_select(dbg, pid, pid);

	return true;
}

static const RzDebugPid *native_linux_get_thread_by_pid(const RzList *threads, int pid) {
	const RzDebugPid *th;
	RzListIter *it;
	rz_list_foreach (threads, it, th) {
		if (th->pid == pid) {
			return th;
		}
	}
	return NULL;
}

static RzDebugDescPlugin native_linux_desc = {
	.open = NULL,
	.close = NULL,
	.read = NULL,
	.write = NULL,
	.seek = NULL,
	.dup = NULL,
	.list = native_linux_process_file_descriptors,
};

bool native_linux_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = native_linux_desc; // TODO: remove any assignment to dbg
	return true;
}

RzDebugInfo *native_linux_process_info(RzDebug *dbg, const char *arg) {
	RzDebugInfo *info = RZ_NEW0(RzDebugInfo);
	if (!info) {
		RZ_LOG_ERROR("debug: failed to allocate RzDebugInfo\n");
		return NULL;
	}

	RzList *threads = NULL;
	if (dbg->threads) {
		threads = rz_list_clone(dbg->threads);
	} else {
		threads = native_linux_process_threads(dbg, dbg->pid);
	}

	const RzDebugPid *th = native_linux_get_thread_by_pid(threads, dbg->pid);
	info->pid = dbg->pid;
	info->tid = dbg->tid;
	info->uid = th ? th->uid : -1;
	info->gid = th ? th->gid : -1;
	info->status = th ? th->status : RZ_DBG_PROC_STOP;
	info->cwd = native_linux_process_read_link(info->pid, "cwd");
	info->exe = native_linux_process_read_link(info->pid, "exe");
	info->cmdline = native_linux_process_cmd_line(info->pid);
	info->kernel_stack = native_linux_process_kernel_stack(info->pid);
	rz_list_free(threads);

	return info;
}

int native_linux_process_attach(RzDebug *dbg, int pid) {
	if (pid == getpid()) {
		RZ_LOG_ERROR("debug: it is forbidden to self attach.\n");
		return -1;
	} else if (pid <= 0) {
		return -1;
	}
	if (!dbg->threads) {
		dbg->threads = native_linux_process_threads(dbg, dbg->pid);
		dbg->main_pid = pid; // TODO: remove any assignment to dbg
	} else {
		if (!native_linux_get_thread_by_pid(dbg->threads, pid)) {
			native_linux_process_attach_to_pid(dbg, pid);
		}
	}
	return pid;
}

int native_linux_process_detach(RzDebug *dbg, int pid) {
	if (pid == getpid()) {
		RZ_LOG_ERROR("debug: it is forbidden to self detach.\n");
		return -1;
	} else if (pid <= 0) {
		return -1;
	}
	if (rz_debug_ptrace(dbg, PTRACE_DETACH, pid, NULL, NULL) < 0) {
		RZ_LOG_ERROR("debug: failed to detach pid %d\n", pid);
		return -1;
	}
	return pid;
}

int native_linux_process_select(RzDebug *dbg, int pid, int tid) {
	if (pid == getpid()) {
		RZ_LOG_ERROR("debug: it is forbidden to self select.\n");
		return -1;
	} else if (pid <= 0) {
		return -1;
	}
	if (dbg->pid != -1 && dbg->pid != pid) {
		return native_linux_process_attach_to_new_pid(dbg, pid);
	}
	return native_linux_process_attach(dbg, tid);
}

RzList /*<RzDebugPid *>*/ *native_linux_process_list(RzDebug *dbg, int ppid) {
	RzList *pids = rz_list_newf((RzListFree)rz_debug_pid_free);
	if (!pids || !native_linux_process_threads_from_proc(dbg, ppid, pids)) {
		RZ_LOG_ERROR("debug: failed to create process id list\n");
		rz_list_free(pids);
		return NULL;
	}

	return pids;
}

int native_linux_process_stop(RzDebug *dbg) {
	bool ret = true;
	int self_pid = getpid();
	RzDebugPid *thread;
	RzListIter *it;
	rz_list_foreach (dbg->threads, it, thread) {
		if (!thread->pid ||
			thread->pid == self_pid ||
			thread->pid == dbg->reason.tid) {
			continue;
		}
		if (!native_linux_process_stop_thread(dbg, thread->pid)) {
			ret = false;
		}
	}
	return ret;
}

bool native_linux_process_single_step(RzDebug *dbg) {
	int pid = dbg->tid;
	if (pid == getpid()) {
		RZ_LOG_ERROR("debug: it is forbidden to self step.\n");
		return false;
	} else if (pid <= 0) {
		return false;
	}
	return rz_debug_ptrace(dbg, PTRACE_SINGLESTEP, pid, 0, 0) >= 0;
}

/* Callback to trigger SIGINT signal */
static void interrupt_process_on_ctrl_c(RzDebug *dbg) {
	rz_debug_kill(dbg, dbg->pid, dbg->tid, SIGINT);
	rz_cons_break_pop();
}

int native_linux_process_continue(RzDebug *dbg, int pid, int tid, int sig) {
	if (pid == getpid()) {
		RZ_LOG_ERROR("debug: it is forbidden to self continue.\n");
		return -1;
	} else if (pid <= 0) {
		return -1;
	}
	int contsig = sig != -1 ? sig : dbg->reason.signum;

	/* SIGINT handler for attached processes: dbg.consbreak (disabled by default) */
	if (dbg->consbreak) {
		rz_cons_break_push((RzConsBreak)interrupt_process_on_ctrl_c, dbg);
	}

	if (dbg->continue_all_threads) {
		RzDebugPid *thread;
		RzListIter *it;
		rz_list_foreach (dbg->threads, it, thread) {
			if (!native_linux_process_continue_thread(dbg, thread->pid, 0)) {
				RZ_LOG_ERROR("debug: thread id %d is already running or is dead.\n", thread->pid);
			}
		}
	} else if (!native_linux_process_continue_thread(dbg, tid, contsig)) {
		RZ_LOG_ERROR("debug: pid %d is already running or is dead.\n", tid);
		return -1;
	}
	return tid;
}

RzDebugReasonType native_linux_process_wait(RzDebug *dbg, int pid) {
	if (pid == getpid()) {
		RZ_LOG_ERROR("debug: it is forbidden to self wait.\n");
		return RZ_DEBUG_REASON_ERROR;
	} else if (pid <= 0) {
		return RZ_DEBUG_REASON_ERROR;
	}
	RzDebugReasonType reason = 0; // linux_dbg_wait(dbg, dbg->tid);
	dbg->reason.type = reason; // TODO: remove any assignment to dbg
	return reason;
}

RzList /*<RzDebugMap *>*/ *native_linux_process_list_maps(RzDebug *dbg) {
	return native_linux_process_maps(dbg->pid);
}
