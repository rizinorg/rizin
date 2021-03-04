// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/* definition */

//static RzList *backtrace_frames_x86_32(RzDebug *dbg, ut64 at);
//static RzList *backtrace_frames_x86_32_analysis(RzDebug *dbg, ut64 at);

/* implementation */
#include <rz_debug.h>

static RzList *backtrace_x86_32(RzDebug *dbg, ut64 at) {
	RzRegItem *ri;
	RzReg *reg = dbg->reg;
	ut32 i, _esp, esp, ebp2;
	RzList *list = rz_list_new();
	RzIOBind *bio = &dbg->iob;
	ut8 buf[4];

	list->free = free;
	ri = (at == UT64_MAX) ? rz_reg_get(reg, "ebp", RZ_REG_TYPE_GPR) : NULL;
	_esp = (ut32)((ri) ? rz_reg_get_value(reg, ri) : at);
	// TODO: implement [stack] map uptrace method too
	esp = _esp;
	for (i = 0; i < dbg->btdepth; i++) {
		bio->read_at(bio->io, esp, (void *)&ebp2, 4);
		if (ebp2 == UT32_MAX)
			break;
		*buf = '\0';
		bio->read_at(bio->io, (ebp2 - 5) - (ebp2 - 5) % 4, (void *)&buf, 4);

		// TODO: arch_is_call() here and this fun will be portable
		if (buf[(ebp2 - 5) % 4] == 0xe8) {
			RzDebugFrame *frame = RZ_NEW0(RzDebugFrame);
			frame->addr = ebp2;
			frame->size = esp - _esp;
			rz_list_append(list, frame);
		}
		esp += 4;
	}
	return list;
}

/* TODO: Can I use this as in a coroutine? */
static RzList *backtrace_x86_32_analysis(RzDebug *dbg, ut64 at) {
	RzRegItem *ri;
	RzReg *reg = dbg->reg;
	ut32 i, _esp, esp, eip, ebp2;
	RzList *list;
	RzIOBind *bio = &dbg->iob;
	RzAnalysisFunction *fcn;
	RzDebugFrame *frame;
	ut8 buf[4];

	// TODO : frame->size by using esil to emulate first instructions
	list = rz_list_new();
	list->free = free;

	ri = (at == UT64_MAX) ? rz_reg_get(reg, "ebp", RZ_REG_TYPE_GPR) : NULL;
	_esp = (ut32)((ri) ? rz_reg_get_value(reg, ri) : at);
	// TODO: implement [stack] map uptrace method too
	esp = _esp;

	eip = rz_reg_get_value(reg, rz_reg_get(reg, "eip", RZ_REG_TYPE_GPR));
	fcn = rz_analysis_get_fcn_in(dbg->analysis, eip, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (fcn != NULL) {
		frame = RZ_NEW0(RzDebugFrame);
		frame->addr = eip;
		frame->size = 0;
		rz_list_append(list, frame);
	}

	for (i = 1; i < dbg->btdepth; i++) {
		bio->read_at(bio->io, esp, (void *)&ebp2, 4);
		if (ebp2 == UT32_MAX)
			break;
		*buf = '\0';
		bio->read_at(bio->io, (ebp2 - 5) - (ebp2 - 5) % 4, (void *)&buf, 4);

		// TODO: arch_is_call() here and this fun will be portable
		if (buf[(ebp2 - 5) % 4] == 0xe8) {
			frame = RZ_NEW0(RzDebugFrame);
			frame->addr = ebp2;
			frame->size = esp - _esp;
			frame->sp = _esp;
			frame->bp = _esp + frame->size;
			rz_list_append(list, frame);
		}
		esp += 4;
	}
	return list;
}
