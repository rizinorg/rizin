// SPDX-FileCopyrightText: 2010-2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2017 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>

static void rz_bp_watch_add_hw(RzBreakpoint *bp, RzBreakpointItem *b) {
	if (bp->breakpoint) {
		bp->breakpoint(bp, b, true);
	}
}

RZ_API RzBreakpointItem *rz_bp_watch_add(RzBreakpoint *bp, ut64 addr, int size, int hw, int perm) {
	RzBreakpointItem *b;
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (rz_bp_get_in(bp, addr, perm)) {
		eprintf("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = rz_bp_item_new(bp);
	b->addr = addr + bp->delta;
	b->size = size;
	b->enabled = true;
	b->perm = perm;
	b->hw = hw;
	if (hw) {
		rz_bp_watch_add_hw(bp, b);
	} else {
		eprintf("[TODO]: Software watchpoint is not implemented yet (use ESIL)\n");
		/* TODO */
	}
	bp->nbps++;
	rz_list_append(bp->bps, b);
	return b;
}

RZ_API void rz_bp_watch_del(void) {
}
