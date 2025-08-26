#include <rz_util/rz_log.h>
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>

#include "procfs.h"
#include "linux/linux_debug.h"

#define PROC_NAME_SZ   1024
#define PROC_REGION_SZ 100
// PROC_REGION_SZ - 2 (used for `0x`). Due to how RZ_STR_DEF works this can't be
// computed.
#define PROC_REGION_LEFT_SZ 98
#define PROC_PERM_SZ        5
#define PROC_UNKSTR_SZ      128

static bool rz_debug_native_step(RzDebug *dbg) {
	return linux_step(dbg);
}

static void interrupt_process(RzDebug *dbg) {
	rz_debug_kill(dbg, dbg->pid, dbg->tid, SIGINT);
	rz_cons_break_pop();
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
				RZ_LOG_ERROR("(%d) is running or dead.\n", th->pid);
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

static int rz_debug_native_stop(RzDebug *dbg) {
	return linux_stop_threads(dbg, dbg->reason.tid);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	linux_set_options(dbg, pid);
	return rz_debug_ptrace(dbg, PTRACE_SYSCALL, pid, 0, 0);
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

static RzList /*<RzDebugPid *>*/ *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		RZ_LOG_ERROR("Cannot create list");
		return NULL;
	}
	return linux_pid_list(pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	// RzList *list = rz_list_new();
	// if (!list) {
	// 	RZ_LOG_ERROR("Cannot create list");
	// 	return NULL;
	// }
	// return linux_thread_list(dbg, pid, list);
	RZ_LOG_ERROR("Unsupport right now");
	return NULL;
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	if (pid == -1) {
		RZ_LOG_ERROR("rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = linux_dbg_wait(dbg, dbg->tid);
	dbg->reason.type = reason;
	return reason;
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
		return true;
	}
	if (errno == EPERM) {
		RZ_LOG_ERROR("Permission denied for pid %d for signal %d\n", pid, sig);
		return false;
	}
	return ret;
}

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
	if (dbg->reg) {
		dbg->reg->big_endian = true;
	}
#include "reg/linux-s390x.h"
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	return linux_reg_read(dbg, type, buf, size);
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return linux_info(dbg, arg);
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
		return linux_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_GPR) {
		return linux_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_FPU) {
		return linux_reg_write(dbg, type, buf, size);
	} // else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}

// rz_egg does not support this architecture
static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	RZ_LOG_ERROR("This feature is not supported for this platform");
	return NULL;
}

// rz_egg does not support this architecture
static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	RZ_LOG_ERROR("This feature is not supported for this platform");
	return false;
}

// rz_egg does not support this architecture
static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	RZ_LOG_ERROR("This feature is not supported for this platform");
	return false;
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
			map->file = rz_str_dup(map->name);
			file = map->file;
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

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return linux_desc_list(pid);
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	if (b && b->hw) {
		return set
			? drx_add((RzDebug *)bp->user, bp, b)
			: drx_del((RzDebug *)bp->user, bp, b);
	}
	return false;
}

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
	RZ_LOG_ERROR("DRX Unsupported for this platform");
	return -1;
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	RZ_LOG_ERROR("Not supported for this platform");
	return false;
}

// struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
// 	.open = rz_debug_desc_native_open,
// 	.list = rz_debug_desc_native_list,
// };

// static bool rz_debug_native_init(RzDebug *dbg, void **user) {
// 	dbg->cur->desc = rz_debug_desc_plugin_native;
// 	return true;
// }

// static void rz_debug_native_fini(RzDebug *dbg, void *user) {
// 	if (!user) {
// 		return;
// 	}
// 	free(user);
// }

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native;
static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return get_linux_tls_val(dbg, tid);
}