// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_debug.h>

static int __io_step(RzDebug *dbg) {
	free(dbg->iob.system(dbg->iob.io, "ds"));
	return true;
}

static int __io_step_over(RzDebug *dbg) {
	free(dbg->iob.system(dbg->iob.io, "dso"));
	return true;
}

static RzList /*<RzDebugMap *>*/ *__io_maps(RzDebug *dbg) {
	RzList *list = rz_list_new();
	char *str = dbg->iob.system(dbg->iob.io, "dm");
	if (!str) {
		rz_list_free(list);
		return NULL;
	}
	char *ostr = str;
	ut64 map_start, map_end;
	char perm[32];
	char name[512];
	for (;;) {
		char *nl = strchr(str, '\n');
		if (nl) {
			*nl = 0;
			*name = 0;
			*perm = 0;
			map_start = map_end = 0LL;
			if (!strncmp(str, "sys ", 4)) {
				char *sp = strchr(str + 4, ' ');
				if (sp) {
					str = sp + 1;
				} else {
					str += 4;
				}
			}
			char *_s_ = strstr(str, " s ");
			if (_s_) {
				memmove(_s_, _s_ + 2, strlen(_s_));
			}
			_s_ = strstr(str, " ? ");
			if (_s_) {
				memmove(_s_, _s_ + 2, strlen(_s_));
			}
			sscanf(str, "0x%" PFMT64x " - 0x%" PFMT64x " %s %s",
				&map_start, &map_end, perm, name);
			if (map_end != 0LL) {
				RzDebugMap *map = rz_debug_map_new(name, map_start, map_end, rz_str_rwx(perm), 0);
				rz_list_append(list, map);
			}
			str = nl + 1;
		} else {
			break;
		}
	}
	free(ostr);
	rz_cons_reset();
	return list;
}

static RzDebugReasonType __io_wait(RzDebug *dbg, int pid) {
	/* do nothing */
	return RZ_DEBUG_REASON_NONE;
}

static int __io_attach(RzDebug *dbg, int pid) {
	return true;
}

// "drp" register profile
static char *__io_reg_profile(RzDebug *dbg) {
	rz_cons_push();
	char *drp = dbg->iob.system(dbg->iob.io, "drp");
	if (drp) {
		return drp;
	}
	char *buf = rz_cons_get_buffer_dup();
	if (RZ_STR_ISNOTEMPTY(buf)) {
		rz_cons_pop();
		return buf;
	}
	free(buf);
	rz_cons_pop();
	return rz_analysis_get_reg_profile(dbg->analysis);
}

// "dr8" read register state
static int __reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	char *dr8 = dbg->iob.system(dbg->iob.io, "dr8");
	if (!dr8) {
		char *fb = rz_cons_get_buffer_dup();
		if (RZ_STR_ISEMPTY(fb)) {
			free(fb);
			eprintf("debug.io: Failed to get dr8 from io\n");
			return -1;
		}
		dr8 = fb;
		rz_cons_reset();
	}
	ut8 *bregs = calloc(1, strlen(dr8));
	if (!bregs) {
		free(dr8);
		return -1;
	}
	rz_str_trim((char *)bregs);
	int sz = rz_hex_str2bin(dr8, bregs);
	if (sz > 0) {
		memcpy(buf, bregs, RZ_MIN(size, sz));
		free(bregs);
		free(dr8);
		return size;
	} else {
		// eprintf ("SIZE %d (%s)\n", sz, regs);
	}
	free(bregs);
	free(dr8);
	return -1;
}

// "dc" continue execution
static int __io_continue(RzDebug *dbg, int pid, int tid, int sig) {
	dbg->iob.system(dbg->iob.io, "dc");
	rz_cons_flush();
	return true;
}

// "dk" send kill signal
static bool __io_kill(RzDebug *dbg, int pid, int tid, int sig) {
	const char *cmd = sdb_fmt("dk %d", sig);
	dbg->iob.system(dbg->iob.io, cmd);
	rz_cons_flush();
	return true;
}

RzDebugPlugin rz_debug_plugin_io = {
	.name = "io",
	.license = "MIT",
	.arch = "any", // TODO: exception!
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.step = __io_step,
	.map_get = __io_maps,
	.attach = &__io_attach,
	.wait = &__io_wait,
	.reg_read = __reg_read,
	.cont = __io_continue,
	.kill = __io_kill,
	.reg_profile = __io_reg_profile,
	.step_over = __io_step_over,
	.canstep = 1,
#if 0
	.init = __esil_init,
	.contsc = __esil_continue_syscall,
	.detach = &__esil_detach,
	.stop = __esil_stop,
	.breakpoint = &__esil_breakpoint,
#endif
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_io,
	.version = RZ_VERSION
};
#endif
