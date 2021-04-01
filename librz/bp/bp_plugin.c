// SPDX-FileCopyrightText: 2009-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>

RZ_API int rz_bp_plugin_del(RzBreakpoint *bp, const char *name) {
	RzListIter *iter;
	RzBreakpointPlugin *h;
	if (name && *name) {
		rz_list_foreach (bp->plugins, iter, h) {
			if (!strcmp(h->name, name)) {
				if (bp->cur == h) {
					bp->cur = NULL;
				}
				rz_list_delete(bp->plugins, iter);
				bp->nbps--;
				return true;
			}
		}
	}
	return false;
}

RZ_API int rz_bp_plugin_add(RzBreakpoint *bp, RzBreakpointPlugin *foo) {
	RzListIter *iter;
	RzBreakpointPlugin *h;
	if (!bp) {
		eprintf("Cannot add plugin because dbg->bp is null and/or plugin is null\n");
		return false;
	}
	/* avoid dupped plugins */
	rz_list_foreach (bp->bps, iter, h) {
		if (!strcmp(h->name, foo->name)) {
			return false;
		}
	}
	bp->nbps++;
	rz_list_append(bp->plugins, foo);
	return true;
}

RZ_API int rz_bp_use(RzBreakpoint *bp, const char *name, int bits) {
	RzListIter *iter;
	bp->bits = bits;
	RzBreakpointPlugin *h;
	rz_list_foreach (bp->plugins, iter, h) {
		if (!strcmp(h->name, name)) {
			bp->cur = h;
			return true;
		}
	}
	return false;
}

// TODO: deprecate
RZ_API void rz_bp_plugin_list(RzBreakpoint *bp) {
	RzListIter *iter;
	RzBreakpointPlugin *b;
	rz_list_foreach (bp->plugins, iter, b) {
		bp->cb_printf("bp %c %s\n",
			(bp->cur && !strcmp(bp->cur->name, b->name)) ? '*' : '-',
			b->name);
	}
}
