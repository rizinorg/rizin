// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

static ut64 read_ptr(RzDebug *dbg, ut64 at) {
	ut8 buf[8];
	if (!dbg->iob.read_at(dbg->iob.io, at, buf, dbg->bits)) {
		return UT64_MAX;
	}
	return rz_read_ble(buf, dbg->analysis->big_endian, dbg->bits * 8);
}

static RzList /*<RzDebugFrame *>*/ *backtrace_generic(RZ_BORROW RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, NULL);
	const size_t pointer_size = dbg->bits;
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	ut64 lr = rz_reg_getv_by_role_or_name(dbg->reg, "LR");
	ut64 sp = rz_reg_getv_by_role_or_name(dbg->reg, "SP");
	ut64 bp = rz_reg_getv_by_role_or_name(dbg->reg, "BP");
	ut64 pc = rz_reg_getv_by_role_or_name(dbg->reg, "PC");
	RzDebugFrame *frame = RZ_NEW0(RzDebugFrame);
	if (!frame) {
		return ret;
	}
	frame->addr = pc;
	frame->bp = bp;
	frame->sp = sp;
	frame->size = bp - sp;
	sp = bp;
	bp = read_ptr(dbg, sp);
	sp += pointer_size;
	if (!lr || lr == UT64_MAX) {
		pc = read_ptr(dbg, sp);
		sp += pointer_size;
	} else {
		pc = lr;
	}
	rz_list_push(ret, frame);

	do {
		frame = RZ_NEW0(RzDebugFrame);
		if (!frame) {
			return ret;
		}
		frame->bp = bp;
		frame->sp = sp;
		frame->size = bp ? bp - sp : 0;
		frame->addr = pc;
		sp = bp;
		if (sp) {
			bp = read_ptr(dbg, sp);
			sp += pointer_size;
			pc = read_ptr(dbg, sp);
			sp += pointer_size;
		}
		rz_list_push(ret, frame);
	} while (sp && pc && pc != UT64_MAX);

	return ret;
}
