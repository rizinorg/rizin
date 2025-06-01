// SPDX-FileCopyrightText: 2010-2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2017 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>

RZ_IPI void rz_bp_item_insert(RzBreakpoint *bp, RzBreakpointItem *b);

static void rz_bp_watch_add_hw(RzBreakpoint *bp, RzBreakpointItem *b) {
	if (bp->breakpoint) {
		bp->breakpoint(bp, b, true);
	}
}

RZ_API RZ_BORROW RzBreakpointItem *rz_bp_watch_add(RZ_NONNULL RzBreakpoint *bp, ut64 addr, int size, int hw, int perm) {
	rz_return_val_if_fail(bp, NULL);
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (rz_bp_get_in(bp, addr, perm)) {
		RZ_LOG_ERROR("Breakpoint already set at this address.\n");
		return NULL;
	}
	RzBreakpointItem *b = RZ_NEW0(RzBreakpointItem);
	if (!b) {
		return NULL;
	}
	b->addr = addr;
	b->size = size;
	b->enabled = true;
	b->perm = perm;
	b->hw = hw;
	if (hw) {
		rz_bp_watch_add_hw(bp, b);
	} else {
		RZ_LOG_ERROR("[TODO]: Software watchpoint is not implemented yet (use ESIL)\n");
		/* TODO */
	}
	rz_bp_item_insert(bp, b);
	return b;
}

RZ_API void rz_bp_watch_del(void) {
}
