/* radare - LGPL - Copyright 2010-2017 pancake<nopcode.org>, rkx1209 */

#include <rz_bp.h>

static void rz_bp_watch_add_hw(RBreakpoint *bp, RBreakpointItem *b) {
	if (bp->breakpoint) {
		bp->breakpoint (bp, b, true);
	}
}

RZ_API RBreakpointItem* rz_bp_watch_add(RBreakpoint *bp, ut64 addr, int size, int hw, int perm) {
	RBreakpointItem *b;
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (rz_bp_get_in (bp, addr, perm)) {
		eprintf ("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = rz_bp_item_new (bp);
	b->addr = addr + bp->delta;
	b->size = size;
	b->enabled = true;
	b->perm = perm;
	b->hw = hw;
	if (hw) {
		rz_bp_watch_add_hw (bp, b);
	} else {
		eprintf ("[TODO]: Software watchpoint is not implemented yet (use ESIL)\n");
		/* TODO */
	}
	bp->nbps++;
	rz_list_append (bp->bps, b);
	return b;
}

RZ_API void rz_bp_watch_del(void) {
}
