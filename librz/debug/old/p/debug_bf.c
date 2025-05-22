// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#undef RZ_API
#define RZ_API static inline
#include "bfvm.c"

typedef struct {
	int desc;
	ut8 *buf;
	ut32 size;
	BfvmCPU *bfvm;
} RzIOBdescbg;

static bool brainfuck_is_valid_io(RzDebug *dbg) {
	if (!dbg->iob.io) {
		return false;
	}
	RzIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name) {
		if (!strcmp("bfdbg", d->plugin->name)) {
			return true;
		}
	}
	eprintf("error: the iodesc data is not brainfuck friendly\n");
	return false;
}

static bool brainfuck_step_over(RzDebug *dbg) {
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	int op, oop = 0;
	for (;;) {
		op = bfvm_op(o->bfvm);
		if (oop != 0 && op != oop) {
			break;
		}
		if (bfvm_in_trap(o->bfvm)) {
			break;
		}
		bfvm_step(o->bfvm, 0);
		oop = op;
	}
	return true;
}

static bool brainfuck_step(RzDebug *dbg) {
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_step(o->bfvm, 0);
	return true;
}

static void reg_set(RzReg *reg, const char *name, ut32 value) {
	RzRegItem *item = rz_reg_get(reg, name, -1);
	rz_reg_set_value(reg, item, value);
}

static ut32 reg_get(RzReg *reg, const char *name) {
	RzRegItem *item = rz_reg_get(reg, name, -1);
	return rz_reg_get_value(reg, item);
}

static bool brainfuck_sync_registers(RzDebug *dbg, RzReg *reg, bool to_debugger) {
	rz_return_val_if_fail(dbg && reg, false);
	if (!brainfuck_is_valid_io(dbg) || !dbg->iob.io->desc->data) {
		return false;
	}

	RzIOBdescbg *o = dbg->iob.io->desc->data;

	if (to_debugger) {
		o->bfvm->eip = reg_get(reg, "pc");
		o->bfvm->ptr = reg_get(reg, "ptr");
		o->bfvm->esp = reg_get(reg, "esp");
		o->bfvm->screen = reg_get(reg, "scr");
		o->bfvm->screen_idx = reg_get(reg, "scri");
		o->bfvm->input = reg_get(reg, "inp");
		o->bfvm->input_idx = reg_get(reg, "inpi");
		o->bfvm->base = reg_get(reg, "mem");
		o->bfvm->ptr = reg_get(reg, "memi");
	} else {
		reg_set(reg, "pc", o->bfvm->eip);
		reg_set(reg, "ptr", o->bfvm->ptr);
		reg_set(reg, "esp", o->bfvm->esp);
		reg_set(reg, "scr", o->bfvm->screen);
		reg_set(reg, "scri", o->bfvm->screen_idx);
		reg_set(reg, "inp", o->bfvm->input);
		reg_set(reg, "inpi", o->bfvm->input_idx);
		reg_set(reg, "mem", o->bfvm->base);
		reg_set(reg, "memi", o->bfvm->ptr);
	}
	return true;
}

static int brainfuck_continue(RzDebug *dbg, int pid, int tid, int sig) {
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_cont(o->bfvm, UT64_MAX);
	return true;
}

static int brainfuck_continue_syscall(RzDebug *dbg, int pid, int num) {
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_contsc(o->bfvm);
	return true;
}

static RzDebugReasonType brainfuck_wait(RzDebug *dbg, int pid) {
	/* do nothing */
	return RZ_DEBUG_REASON_NONE;
}

static int brainfuck_attach(RzDebug *dbg, int pid) {
	if (!brainfuck_is_valid_io(dbg)) {
		return false;
	}
	return true;
}

static int brainfuck_detach(RzDebug *dbg, int pid) {
	// reset vm?
	return true;
}

static char *brainfuck_reg_profile(RzDebug *dbg) {
	return rz_str_dup(
		"=PC	pc\n"
		"=SP	esp\n"
		"=BP	ptr\n"
		"=A0	mem\n"
		"gpr	pc	.32	0	0\n"
		"gpr	ptr	.32	4	0\n"
		"gpr	esp	.32	8	0\n"
		"gpr	scr	.32	12	0\n"
		"gpr	scri	.32	16	0\n"
		"gpr	inp	.32	20	0\n"
		"gpr	inpi	.32	24	0\n"
		"gpr	mem	.32	28	0\n"
		"gpr	memi	.32	32	0\n");
}

static int brainfuck_breakpoint(struct rz_bp_t *bp, RzBreakpointItem *b, bool set) {
	// rz_io_system (dbg->iob.io, "db");
	return false;
}

static bool brainfuck_kill(RzDebug *dbg, int pid, int tid, int sig) {
	if (!brainfuck_is_valid_io(dbg)) {
		return false;
	}
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	if (o) {
		bfvm_reset(o->bfvm);
	}
	return true;
}

static RzList /*<RzDebugMap *>*/ *brainfuck_map_get(RzDebug *dbg) {
	if (!brainfuck_is_valid_io(dbg)) {
		return false;
	}
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	BfvmCPU *c = o->bfvm;
	RzList *list = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!list) {
		return NULL;
	}
	rz_list_append(list, rz_debug_map_new("code", 0, 4096, 6, 0));
	rz_list_append(list, rz_debug_map_new("memory", c->base, c->base + c->size, 6, 0));
	rz_list_append(list, rz_debug_map_new("screen", c->screen, c->screen + c->screen_size, 6, 0));
	rz_list_append(list, rz_debug_map_new("input", c->input, c->input + c->input_size, 6, 0));
	return list;
}

static int brainfuck_stop(RzDebug *dbg) {
	if (!brainfuck_is_valid_io(dbg)) {
		return false;
	}
	RzIOBdescbg *o = dbg->iob.io->desc->data;
	BfvmCPU *c = o->bfvm;
	c->breaked = true;
	return true;
}

RzDebugPlugin rz_debug_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.license = "LGPL3",
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.step = brainfuck_step,
	.step_over = brainfuck_step_over,
	.cont = brainfuck_continue,
	.contsc = brainfuck_continue_syscall,
	.attach = &brainfuck_attach,
	.detach = &brainfuck_detach,
	.wait = &brainfuck_wait,
	.stop = brainfuck_stop,
	.kill = brainfuck_kill,
	.breakpoint = &brainfuck_breakpoint,
	.sync_registers = &brainfuck_sync_registers,
	.reg_profile = brainfuck_reg_profile,
	.map_get = brainfuck_map_get,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_bf,
	.version = RZ_VERSION
};
#endif
