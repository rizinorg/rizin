// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2018 defragger <rlaemmert@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include <libgdbr.h>
#include <gdbclient/commands.h>

typedef struct {
	libgdbr_t desc;
} RzIOGdb;

#define UNKNOWN     (-1)
#define UNSUPPORTED 0
#define SUPPORTED   1

static RzIOGdb **origriogdb = NULL;
static libgdbr_t *desc = NULL;
static ut8 *reg_buf = NULL;
static int buf_size = 0;
static int support_sw_bp = UNKNOWN;
static int support_hw_bp = UNKNOWN;

static int rz_debug_gdb_attach(RzDebug *dbg, int pid);
static void check_connection(RzDebug *dbg) {
	if (!desc) {
		rz_debug_gdb_attach(dbg, -1);
	}
}

static int rz_debug_gdb_step(RzDebug *dbg) {
	check_connection(dbg);
	if (!desc) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}
	gdbr_step(desc, dbg->tid);
	return true;
}

static RzList *rz_debug_gdb_threads(RzDebug *dbg, int pid) {
	RzList *list;
	if ((list = gdbr_threads_list(desc, pid))) {
		list->free = (RzListFree)&rz_debug_pid_free;
	}
	return list;
}

static RzList *rz_debug_gdb_pids(RzDebug *dbg, int pid) {
	RzList *list;
	if ((list = gdbr_pids_list(desc, pid))) {
		list->free = (RzListFree)&rz_debug_pid_free;
	}
	return list;
}

static int rz_debug_gdb_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	int copy_size;
	int buflen = 0;
	check_connection(dbg);
	if (!desc) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}
	gdbr_read_registers(desc);
	if (!desc || !desc->data) {
		return -1;
	}
	// read the len of the current area
	free(rz_reg_get_bytes(dbg->reg, type, &buflen));
	if (size < desc->data_len) {
		eprintf("rz_debug_gdb_reg_read: small buffer %d vs %d\n",
			(int)size, (int)desc->data_len);
		//	return -1;
	}
	copy_size = RZ_MIN(desc->data_len, size);
	buflen = RZ_MAX(desc->data_len, buflen);
	if (reg_buf) {
		// if (buf_size < copy_size) { //desc->data_len) {
		if (buflen > buf_size) { //copy_size) {
			ut8 *new_buf = realloc(reg_buf, buflen);
			if (!new_buf) {
				return -1;
			}
			reg_buf = new_buf;
			buf_size = buflen;
		}
	} else {
		reg_buf = calloc(buflen, 1);
		if (!reg_buf) {
			return -1;
		}
		buf_size = buflen;
	}
	memset((void *)(volatile void *)buf, 0, size);
	memcpy((void *)(volatile void *)buf, desc->data, RZ_MIN(copy_size, size));
	memset((void *)(volatile void *)reg_buf, 0, buflen);
	memcpy((void *)(volatile void *)reg_buf, desc->data, copy_size);
#if 0
	int i;
	//for(i=0;i<168;i++) {
	for(i=0;i<copy_size;i++) {
		if (!(i%16)) printf ("\n0x%08x  ", i);
		printf ("%02x ", buf[i]); //(ut8)desc->data[i]);
	}
	printf("\n");
#endif
	return desc->data_len;
}

static RzList *rz_debug_gdb_map_get(RzDebug *dbg) { //TODO
	check_connection(dbg);
	if (!desc || desc->pid <= 0) {
		return NULL;
	}
	RzList *retlist = NULL;
	if (desc->get_baddr) {
		desc->get_baddr = false;
		ut64 baddr;
		if ((baddr = gdbr_get_baddr(desc)) != UINT64_MAX) {
			if (!(retlist = rz_list_new())) {
				return NULL;
			}
			RzDebugMap *map;
			if (!(map = rz_debug_map_new("", baddr, baddr, RZ_PERM_RX, 0))) {
				rz_list_free(retlist);
				return NULL;
			}
			rz_list_append(retlist, map);
			return retlist;
		}
	}

	// Get file from GDB
	char path[128];
	ut8 *buf;
	int ret;
	// TODO don't hardcode buffer size, get from remote target
	// (I think gdb doesn't do that, it just keeps reading till EOF)
	// fstat info can get file size, but it doesn't work for /proc/pid/maps
	ut64 buflen = 16384;
	// If /proc/%d/maps is not valid for gdbserver, we return NULL, as of now
	snprintf(path, sizeof(path) - 1, "/proc/%d/maps", desc->pid);

#ifdef _MSC_VER
#define GDB_FILE_OPEN_MODE (_S_IREAD | _S_IWRITE)
#else
#define GDB_FILE_OPEN_MODE (S_IRUSR | S_IWUSR | S_IXUSR)
#endif

	if (gdbr_open_file(desc, path, O_RDONLY, GDB_FILE_OPEN_MODE) < 0) {
		return NULL;
	}
	if (!(buf = malloc(buflen))) {
		gdbr_close_file(desc);
		return NULL;
	}
	if ((ret = gdbr_read_file(desc, buf, buflen - 1)) <= 0) {
		gdbr_close_file(desc);
		free(buf);
		return NULL;
	}
	buf[ret] = '\0';

	// Get map list
	int unk = 0, perm, i;
	char *ptr, *pos_1;
	size_t line_len;
	char name[1024], region1[100], region2[100], perms[5];
	RzDebugMap *map = NULL;
	region1[0] = region2[0] = '0';
	region1[1] = region2[1] = 'x';
	if (!(ptr = strtok((char *)buf, "\n"))) {
		gdbr_close_file(desc);
		free(buf);
		return NULL;
	}
	if (!(retlist = rz_list_new())) {
		gdbr_close_file(desc);
		free(buf);
		return NULL;
	}
	while (ptr) {
		ut64 map_start, map_end, offset;
		bool map_is_shared = false;
		line_len = strlen(ptr);
		// maps files should not have empty lines
		if (line_len == 0) {
			break;
		}
		// We assume Linux target, for now, so -
		// 7ffff7dda000-7ffff7dfd000 r-xp 00000000 08:05 265428 /usr/lib/ld-2.25.so
		ret = sscanf(ptr, "%s %s %" PFMT64x " %*s %*s %[^\n]", &region1[2],
			perms, &offset, name);
		if (ret == 3) {
			name[0] = '\0';
		} else if (ret != 4) {
			eprintf("%s: Unable to parse \"%s\"\nContent:\n%s\n",
				__func__, path, buf);
			gdbr_close_file(desc);
			free(buf);
			rz_list_free(retlist);
			return NULL;
		}
		if (!(pos_1 = strchr(&region1[2], '-'))) {
			ptr = strtok(NULL, "\n");
			continue;
		}
		strncpy(&region2[2], pos_1 + 1, sizeof(region2) - 2 - 1);
		if (!*name) {
			snprintf(name, sizeof(name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; perms[i] && i < 5; i++) {
			switch (perms[i]) {
			case 'r': perm |= RZ_PERM_R; break;
			case 'w': perm |= RZ_PERM_W; break;
			case 'x': perm |= RZ_PERM_X; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}
		map_start = rz_num_get(NULL, region1);
		map_end = rz_num_get(NULL, region2);
		if (map_start == map_end || map_end == 0) {
			eprintf("%s: ignoring invalid map size: %s - %s\n",
				__func__, region1, region2);
			ptr = strtok(NULL, "\n");
			continue;
		}
		if (!(map = rz_debug_map_new(name, map_start, map_end, perm, 0))) {
			break;
		}
		map->offset = offset;
		map->shared = map_is_shared;
		map->file = strdup(name);
		rz_list_append(retlist, map);
		ptr = strtok(NULL, "\n");
	}
	gdbr_close_file(desc);
	free(buf);
	return retlist;
}

static RzList *rz_debug_gdb_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	if (!(list = rz_debug_gdb_map_get(dbg))) {
		return NULL;
	}
	if (!(last = rz_list_newf((RzListFree)rz_debug_map_free))) {
		rz_list_free(list);
		return NULL;
	}
	rz_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = strdup(map->name);
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
			lastname = strdup(file);
		}
	}
	list->free = NULL;
	free(lastname);
	rz_list_free(list);
	return last;
}

static int rz_debug_gdb_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	check_connection(dbg);
	if (!desc) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}
	if (!reg_buf) {
		// we cannot write registers before we once read them
		return -1;
	}
	int buflen = 0;
	int bits = dbg->analysis->bits;
	const char *pcname = rz_reg_get_name(dbg->analysis->reg, RZ_REG_NAME_PC);
	RzRegItem *reg = rz_reg_get(dbg->analysis->reg, pcname, 0);
	if (reg) {
		if (dbg->analysis->bits != reg->size) {
			bits = reg->size;
		}
	}
	free(rz_reg_get_bytes(dbg->reg, type, &buflen));
	// some implementations of the gdb protocol are acting weird.
	// so winedbg is not able to write registers through the <G> packet
	// and also it does not return the whole gdb register profile after
	// calling <g>
	// so this workaround resizes the small register profile buffer
	// to the whole set and fills the rest with 0
	if (buf_size < buflen) {
		ut8 *new_buf = realloc(reg_buf, buflen * sizeof(ut8));
		if (!new_buf) {
			return -1;
		}
		reg_buf = new_buf;
		memset(new_buf + buf_size, 0, buflen - buf_size);
	}

	RzRegItem *current = NULL;
	// We default to little endian if there's no way to get the configuration,
	// since this was the behaviour prior to the change.
	RzRegArena *arena = dbg->reg->regset[type].arena;
	for (;;) {
		current = rz_reg_next_diff(dbg->reg, type, reg_buf, buflen, current, bits);
		if (!current) {
			break;
		}
		gdbr_write_reg(desc, current->name, (char *)arena->bytes + (current->offset / 8), current->size / 8);
	}
	return true;
}

static int rz_debug_gdb_continue(RzDebug *dbg, int pid, int tid, int sig) {
	check_connection(dbg);
	if (!desc) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}
	gdbr_continue(desc, pid, -1, sig); // Continue all threads
	if (desc->stop_reason.is_valid && desc->stop_reason.thread.present) {
		//if (desc->tid != desc->stop_reason.thread.tid) {
		//	eprintf ("thread id (%d) in reason differs from current thread id (%d)\n", dbg->pid, dbg->tid);
		//}
		desc->tid = desc->stop_reason.thread.tid;
	}
	return desc->tid;
}

static RzDebugReasonType rz_debug_gdb_wait(RzDebug *dbg, int pid) {
	check_connection(dbg);
	if (!desc) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}
	if (!desc->stop_reason.is_valid) {
		if (gdbr_stop_reason(desc) < 0) {
			dbg->reason.type = RZ_DEBUG_REASON_UNKNOWN;
			return RZ_DEBUG_REASON_UNKNOWN;
		}
	}
	if (desc->stop_reason.thread.present) {
		dbg->reason.tid = desc->stop_reason.thread.tid;
		dbg->pid = desc->stop_reason.thread.pid;
		dbg->tid = desc->stop_reason.thread.tid;
		if (dbg->pid != desc->pid || dbg->tid != desc->tid) {
			//eprintf ("= attach %d %d\n", dbg->pid, dbg->tid);
			gdbr_select(desc, dbg->pid, dbg->tid);
		}
	}
	dbg->reason.signum = desc->stop_reason.signum;
	dbg->reason.type = desc->stop_reason.reason;
	return desc->stop_reason.reason;
}

static int rz_debug_gdb_attach(RzDebug *dbg, int pid) {
	RzIODesc *d = dbg->iob.io->desc;
	// TODO: the core must update the dbg.swstep config var when this var is changed
	dbg->swstep = false;
	//eprintf ("XWJSTEP TOFALSE\n");
	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp("gdb", d->plugin->name)) {
			RzIOGdb *g = d->data;
			origriogdb = (RzIOGdb **)&d->data; //TODO bit of a hack, please improve
			support_sw_bp = UNKNOWN;
			support_hw_bp = UNKNOWN;
			desc = &g->desc;
			int arch = rz_sys_arch_id(dbg->arch);
			int bits = dbg->analysis->bits;
			gdbr_set_architecture(desc, arch, bits);
		} else {
			eprintf("ERROR: Underlying IO descriptor is not a GDB one..\n");
		}
	}
	return true;
}

static int rz_debug_gdb_detach(RzDebug *dbg, int pid) {
	int ret = 0;

	if (pid <= 0 || !desc->stub_features.multiprocess) {
		gdbr_detach(desc);
	}
	ret = gdbr_detach_pid(desc, pid);

	if (dbg->pid == pid) {
		desc = NULL;
	}
	return ret;
}

static const char *rz_debug_gdb_reg_profile(RzDebug *dbg) {
	check_connection(dbg);
	int arch = rz_sys_arch_id(dbg->arch);
	int bits = dbg->analysis->bits;
	// XXX This happens when rizin set dbg.backend before opening io_gdb
	if (!desc) {
		return gdbr_get_reg_profile(arch, bits);
	}
	if (!desc->target.valid) {
		gdbr_set_architecture(desc, arch, bits);
	}
	if (desc->target.regprofile) {
		return strdup(desc->target.regprofile);
	}
	return NULL;
}

static int rz_debug_gdb_set_reg_profile(const char *str) {
	if (desc && str) {
		return gdbr_set_reg_profile(desc, str);
	}
	return false;
}

static int rz_debug_gdb_breakpoint(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	int ret = 0, bpsize;
	if (!b) {
		return false;
	}
	bpsize = b->size;
	// TODO handle conditions
	switch (b->perm) {
	case RZ_BP_PROT_EXEC: {
		if (set) {
			ret = b->hw ? gdbr_set_hwbp(desc, b->addr, "", bpsize) : gdbr_set_bp(desc, b->addr, "", bpsize);
		} else {
			ret = b->hw ? gdbr_remove_hwbp(desc, b->addr, bpsize) : gdbr_remove_bp(desc, b->addr, bpsize);
		}
		break;
	}
	// TODO handle size (area of watch in upper layer and then bpsize. For the moment watches are set on exact on byte
	case RZ_PERM_W: {
		if (set) {
			gdbr_set_hww(desc, b->addr, "", 1);
		} else {
			gdbr_remove_hww(desc, b->addr, 1);
		}
		break;
	}
	case RZ_PERM_R: {
		if (set) {
			gdbr_set_hwr(desc, b->addr, "", 1);
		} else {
			gdbr_remove_hwr(desc, b->addr, 1);
		}
		break;
	}
	case RZ_PERM_ACCESS: {
		if (set) {
			gdbr_set_hwa(desc, b->addr, "", 1);
		} else {
			gdbr_remove_hwa(desc, b->addr, 1);
		}
		break;
	}
	}
	return !ret;
}

static bool rz_debug_gdb_kill(RzDebug *dbg, int pid, int tid, int sig) {
	// TODO kill based on pid and signal
	if (sig != 0) {
		if (gdbr_kill(desc) < 0) {
			return false;
		}
	}
	return true;
}

static int rz_debug_gdb_select(RzDebug *dbg, int pid, int tid) {
	if (!desc || !*origriogdb) {
		desc = NULL; //TODO hacky fix, please improve. I would suggest using a **desc instead of a *desc, so it is automatically updated
		return false;
	}

	return gdbr_select(desc, pid, tid) >= 0;
}

static RzDebugInfo *rz_debug_gdb_info(RzDebug *dbg, const char *arg) {
	RzDebugInfo *rdi;
	if (!(rdi = RZ_NEW0(RzDebugInfo))) {
		return NULL;
	}
	RzList *th_list;
	bool list_alloc = false;
	if (dbg->threads) {
		th_list = dbg->threads;
	} else {
		th_list = rz_debug_gdb_threads(dbg, dbg->pid);
		list_alloc = true;
	}
	RzDebugPid *th;
	RzListIter *it;
	bool found = false;
	rz_list_foreach (th_list, it, th) {
		if (th->pid == dbg->pid) {
			found = true;
			break;
		}
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->exe = gdbr_exec_file_read(desc, dbg->pid);
	rdi->status = found ? th->status : RZ_DBG_PROC_STOP;
	rdi->uid = found ? th->uid : -1;
	rdi->gid = found ? th->gid : -1;
	if (gdbr_stop_reason(desc) >= 0) {
		eprintf("signal: %d\n", desc->stop_reason.signum);
		rdi->signum = desc->stop_reason.signum;
	}
	if (list_alloc) {
		rz_list_free(th_list);
	}
	return rdi;
}

#include "native/bt.c"

static RzList *rz_debug_gdb_frames(RzDebug *dbg, ut64 at) {
	return rz_debug_native_frames(dbg, at);
}

RzDebugPlugin rz_debug_plugin_gdb = {
	.name = "gdb",
	/* TODO: Add support for more architectures here */
	.license = "LGPL3",
	.arch = "x86,arm,sh,mips,avr,lm32,v850,ba2",
	.bits = RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.step = rz_debug_gdb_step,
	.cont = rz_debug_gdb_continue,
	.attach = &rz_debug_gdb_attach,
	.detach = &rz_debug_gdb_detach,
	.threads = &rz_debug_gdb_threads,
	.pids = &rz_debug_gdb_pids,
	.canstep = 1,
	.wait = &rz_debug_gdb_wait,
	.map_get = rz_debug_gdb_map_get,
	.modules_get = rz_debug_gdb_modules_get,
	.breakpoint = &rz_debug_gdb_breakpoint,
	.reg_read = &rz_debug_gdb_reg_read,
	.reg_write = &rz_debug_gdb_reg_write,
	.reg_profile = (void *)rz_debug_gdb_reg_profile,
	.set_reg_profile = &rz_debug_gdb_set_reg_profile,
	.kill = &rz_debug_gdb_kill,
	.info = &rz_debug_gdb_info,
	.select = &rz_debug_gdb_select,
	.frames = &rz_debug_gdb_frames,
	//.bp_write = &rz_debug_gdb_bp_write,
	//.bp_read = &rz_debug_gdb_bp_read,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_gdb,
	.version = RZ_VERSION
};
#endif
