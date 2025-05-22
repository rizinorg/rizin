// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#if !defined(__HAIKU__) && !defined(__sun)
#include <sys/ptrace.h>
#endif
#include <sys/wait.h>
#include <signal.h>

#include <sys/mman.h>
#include "linux/linux_debug.h"
#include "procfs.h"

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

#define PROC_NAME_SZ   1024
#define PROC_REGION_SZ 100
// PROC_REGION_SZ - 2 (used for `0x`). Due to how RZ_STR_DEF works this can't be
// computed.
#define PROC_REGION_LEFT_SZ 98
#define PROC_PERM_SZ        5
#define PROC_UNKSTR_SZ      128

#if WAIT_ON_ALL_CHILDREN
static int rz_debug_handle_signals(RzDebug *dbg) {
	eprintf("Warning: signal handling is not supported on this platform\n");
	return 0;
}
#endif

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
	return linux_reg_profile(dbg);
}

static bool rz_debug_native_step(RzDebug *dbg) {
	return linux_step(dbg);
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	return linux_attach(dbg, pid);
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return rz_debug_ptrace(dbg, PTRACE_DETACH, pid, NULL, (rz_ptrace_data_t)(size_t)0);
}

static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	return linux_select(dbg, pid, tid);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	linux_set_options(dbg, pid);
	return rz_debug_ptrace(dbg, PTRACE_SYSCALL, pid, 0, 0);
}

static void interrupt_process(RzDebug *dbg) {
	rz_debug_kill(dbg, dbg->pid, dbg->tid, SIGINT);
	rz_cons_break_pop();
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return linux_stop_threads(dbg, dbg->reason.tid);
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	int contsig = dbg->reason.signum;
	int ret = -1;

	if (sig != -1) {
		contsig = sig;
	}
	/* SIGINT handler for attached processes: dbg.consbreak (disabled by default) */
	if (dbg->consbreak) {
		rz_cons_break_push((RzConsBreak)interrupt_process, dbg);
	}

	if (dbg->continue_all_threads && dbg->n_threads && dbg->threads) {
		RzDebugPid *th;
		RzListIter *it;
		rz_list_foreach (dbg->threads, it, th) {
			ret = rz_debug_ptrace(dbg, PTRACE_CONT, th->pid, 0, 0);
			if (ret) {
				eprintf("Error: (%d) is running or dead.\n", th->pid);
			}
		}
	} else {
		ret = rz_debug_ptrace(dbg, PTRACE_CONT, tid, NULL, (rz_ptrace_data_t)(size_t)contsig);
		if (ret) {
			rz_sys_perror("PTRACE_CONT");
		}
	}
	// return ret >= 0 ? tid : false;
	return tid;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return linux_info(dbg, arg);
}

#ifdef WAIT_ON_ALL_CHILDREN
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		eprintf("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}
	int status = -1;
	// XXX: this is blocking, ^C will be ignored
	int ret = waitpid(-1, &status, WAITPID_FLAGS);
	if (ret == -1) {
		rz_sys_perror("waitpid");
		return RZ_DEBUG_REASON_ERROR;
	}

	// eprintf ("rz_debug_native_wait: status=%d (0x%x) (return=%d)\n", status, status, ret);

	if (ret != pid) {
		reason = RZ_DEBUG_REASON_NEW_PID;
		eprintf("switching to pid %d\n", ret);
		rz_debug_select(dbg, ret, ret);
	}

	// TODO: switch status and handle reasons here
	// FIXME: Remove linux handling from this function?
#if defined(PT_GETEVENTMSG)
	reason = linux_ptrace_event(dbg, pid, status, true);
#endif

	/* propagate errors */
	if (reason == RZ_DEBUG_REASON_ERROR) {
		return reason;
	}

	/* we don't know what to do yet, let's try harder to figure it out. */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		if (WIFEXITED(status)) {
			eprintf("child exited with status %d\n", WEXITSTATUS(status));
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (WIFSIGNALED(status)) {
			eprintf("child received signal %d\n", WTERMSIG(status));
			reason = RZ_DEBUG_REASON_SIGNAL;
		} else if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) != SIGTRAP &&
				WSTOPSIG(status) != SIGSTOP) {
				eprintf("Child stopped with signal %d\n", WSTOPSIG(status));
			}

			/* the ptrace documentation says GETSIGINFO is only necessary for
			 * differentiating the various stops.
			 *
			 * this might modify dbg->reason.signum
			 */
			if (rz_debug_handle_signals(dbg) != 0) {
				return RZ_DEBUG_REASON_ERROR;
			}
			reason = dbg->reason.type;
#ifdef WIFCONTINUED
		} else if (WIFCONTINUED(status)) {
			eprintf("child continued...\n");
			reason = RZ_DEBUG_REASON_NONE;
#endif
		} else if (status == 1) {
			/* XXX(jjd): does this actually happen? */
			eprintf("debugger is dead with status 1!\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (status == 0) {
			/* XXX(jjd): does this actually happen? */
			eprintf("debugger is dead with status 0\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			if (ret != pid) {
				reason = RZ_DEBUG_REASON_NEW_PID;
			} else {
				/* ugh. still don't know :-/ */
				eprintf("returning from wait without knowing why...\n");
			}
		}
	}

	/* if we still don't know what to do, we have a problem... */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		eprintf("%s: no idea what happened...\n", __func__);
		reason = RZ_DEBUG_REASON_ERROR;
	}
	dbg->reason.tid = pid;
	dbg->reason.type = reason;
	return reason;
}
#else
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	if (pid == -1) {
		eprintf("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = linux_dbg_wait(dbg, dbg->tid);
	dbg->reason.type = reason;
	return reason;
}
#endif

#undef MAXPID
#define MAXPID 99999

static RzList /*<RzDebugPid *>*/ *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	return linux_pid_list(pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		eprintf("No list?\n");
		return NULL;
	}
	return linux_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return get_linux_tls_val(dbg, tid);
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	return linux_reg_read(dbg, type, buf, size);
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
		return false;
	} else if (type == RZ_REG_TYPE_GPR) {
		return linux_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_FPU) {
		return linux_reg_write(dbg, type, buf, size);
	} // else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
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
		eprintf("size not a power of huge pages size\n");
		return false;
	}
	// In always mode, is more into mmap syscall level
	// even though the address might not have the 'hg'
	// vmflags
	if (sys_thp_mode() != 1) {
		eprintf("transparent huge page mode is not in madvise mode\n");
		return false;
	}

	int num = rz_syscall_get_num(dbg->analysis->syscall, "madvise");

	snprintf(code, sizeof(code),
		"sc_madvise@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_madvise(0x%08" PFMT64x ",%d, %d);break;\n"
		"}\n",
		num, addr, size, MADV_HUGEPAGE);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		eprintf("Cannot compile.\n");
		goto err_linux_map_thp;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		eprintf("rz_egg_assemble: invalid assembly\n");
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

static RzDebugMap *linux_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
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
	num = rz_syscall_get_num(dbg->analysis->syscall, sc_name);
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
		eprintf("Cannot compile.\n");
		goto err_linux_map_alloc;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		eprintf("rz_egg_assemble: invalid assembly\n");
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
					// Not overly dramatic
					eprintf("map promotion to huge page failed\n");
				}
			}
			rz_debug_map_sync(dbg);
			map = rz_debug_map_get(dbg, map_addr);
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
	int num = rz_syscall_get_num(dbg->analysis->syscall, "munmap");

	snprintf(code, sizeof(code),
		"sc_munmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_munmap(0x%08" PFMT64x ",%d);break;\n"
		"}\n",
		num, addr, size);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		eprintf("Cannot compile.\n");
		goto err_linux_map_dealloc;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		eprintf("rz_egg_assemble: invalid assembly\n");
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

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	return linux_map_alloc(dbg, addr, size, thp);
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	return linux_map_dealloc(dbg, addr, size);
}

static void _map_free(RzDebugMap *map) {
	if (!map) {
		return;
	}
	free(map->name);
	free(map->file);
	free(map);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
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
		perror(errmsg);
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
			eprintf("%s: Unable to parse \"%s\"\n", __func__, path);
			eprintf("%s: problematic line: %s\n", __func__, line);
			rz_list_free(list);
			return NULL;
		}

		/* split the region in two */
		pos_c = strchr(&region[2], '-');
		if (!pos_c) { // should this be an error?
			continue;
		}
		strncpy(&region2[2], pos_c + 1, sizeof(region2) - 2 - 1);

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
			eprintf("%s: ignoring invalid map size: %s - %s\n", __func__, region, region2);
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

static RzList /*<RzDebugMap *>*/ *rz_debug_native_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	if (!(list = rz_debug_native_map_get(dbg))) {
		return NULL;
	}
	if (!(last = rz_list_newf((RzListFree)rz_debug_map_free))) {
		rz_list_free(list);
		return NULL;
	}
	rz_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = rz_str_dup(map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp(lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			rz_list_delete(list, iter);
		} else {
			rz_list_append(last, map);
			free(lastname);
			lastname = rz_str_dup(file);
		}
	}
	list->free = NULL;
	free(lastname);
	rz_list_free(list);
	return last;
}

static bool rz_debug_native_kill(RzDebug *dbg, int pid, int tid, int sig) {
	bool ret = false;
	if (pid == 0) {
		pid = dbg->pid;
	}
	if (sig == SIGKILL && dbg->threads) {
		rz_list_free(dbg->threads);
		dbg->threads = NULL;
	}
	if ((rz_sys_kill(pid, sig) != -1)) {
		ret = true;
	}
	if (errno == 1) {
		ret = -true; // EPERM
	}
	return ret;
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native;
static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
}

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
	eprintf("drx: Unsupported platform\n");
	return -1;
}

#include <sys/prctl.h>
#include <sys/uio.h>

#define NT_ARM_VFP         0x400 /* ARM VFP/NEON registers */
#define NT_ARM_TLS         0x401 /* ARM TLS register */
#define NT_ARM_HW_BREAK    0x402 /* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH    0x403 /* ARM hardware watchpoint registers */
#define NT_ARM_SYSTEM_CALL 0x404 /* ARM system call number */

#ifndef PTRACE_GETHBPREGS
#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30
#endif

#if PTRACE_GETREGSET
// type = 2 = write
// static volatile uint8_t var[96] __attribute__((__aligned__(32)));

static bool ll_arm64_hwbp_set(pid_t pid, ut64 _addr, int size, int wp, ut32 type) {
	const volatile uint8_t *addr = (void *)(size_t)_addr; //&var[32 + wp];
	const unsigned int offset = (uintptr_t)addr % 8;
	const ut32 byte_mask = ((1 << size) - 1) << offset;
	const ut32 enable = 1;
	const ut32 control = byte_mask << 5 | type << 3 | enable;

	struct user_hwdebug_state dreg_state = { 0 };
	struct iovec iov = { 0 };
	iov.iov_base = &dreg_state;
	iov.iov_len = sizeof(dreg_state);

	if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
		// error reading regs
	}
	memcpy(&dreg_state, iov.iov_base, sizeof(dreg_state));
	// wp is not honored here i think... we can't have more than one wp for now..
	dreg_state.dbg_regs[0].addr = (uintptr_t)(addr - offset);
	dreg_state.dbg_regs[0].ctrl = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = rz_offsetof(struct user_hwdebug_state, dbg_regs) +
		sizeof(dreg_state.dbg_regs[0]);
	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
		return true;
	}

	if (errno == EIO) {
		eprintf("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s\n",
			strerror(errno));
	}

	eprintf("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s\n", strerror(errno));
	return false;
}

static bool ll_arm64_hwbp_del(pid_t pid, ut64 _addr, int size, int wp, ut32 type) {
	// const volatile uint8_t *addr = &var[32 + wp];
	// TODO: support multiple watchpoints and find
	struct user_hwdebug_state dreg_state = { 0 };
	struct iovec iov = { 0 };
	iov.iov_base = &dreg_state;
	// only delete 1 bp for now
	iov.iov_len = rz_offsetof(struct user_hwdebug_state, dbg_regs) +
		sizeof(dreg_state.dbg_regs[0]);
	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
		return true;
	}
	if (errno == EIO) {
		eprintf("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s\n",
			strerror(errno));
	}

	eprintf("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s\n", strerror(errno));
	return false;
}

static bool arm64_hwbp_add(RzDebug *dbg, RzBreakpoint *bp, RzBreakpointItem *b) {
	return ll_arm64_hwbp_set(dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

static bool arm64_hwbp_del(RzDebug *dbg, RzBreakpoint *bp, RzBreakpointItem *b) {
	return ll_arm64_hwbp_del(dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

#endif

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
#if PTRACE_GETREGSET
	if (b && b->hw) {
		return set
			? arm64_hwbp_add((RzDebug *)bp->user, bp, b)
			: arm64_hwbp_del((RzDebug *)bp->user, bp, b);
	}
#endif
	return false;
}

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return linux_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	RzBuffer *buf = NULL;
	char code[1024];
	int num;

	num = rz_syscall_get_num(dbg->analysis->syscall, "mprotect");
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
		eprintf("Cannot compile.\n");
		return false;
	}
	if (!rz_egg_assemble(dbg->egg)) {
		eprintf("rz_egg_assemble: invalid assembly\n");
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

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	return false;
}