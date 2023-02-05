// SPDX-FileCopyrightText: 2009-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <rz_lib.h>

RZ_API int rz_bp_plugin_del_byname(RzBreakpoint *bp, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bp && name, false);

	RzListIter *iter;
	RzBreakpointPlugin *h;
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
	return false;
}

RZ_API bool rz_bp_plugin_add(RzBreakpoint *bp, RZ_BORROW RZ_NONNULL RzBreakpointPlugin *plugin) {
	rz_return_val_if_fail(bp && plugin, false);
	RZ_PLUGIN_CHECK_AND_ADD(bp->plugins, plugin, RzBreakpointPlugin);
	return true;
}

RZ_API bool rz_bp_plugin_del(RzBreakpoint *bp, RZ_BORROW RZ_NONNULL RzBreakpointPlugin *plugin) {
	rz_return_val_if_fail(bp && plugin, false);
	bool res = rz_list_delete_data(bp->plugins, plugin);
	if (res) {
		bp->nbps--;
		if (bp->cur == plugin) {
			bp->cur = NULL;
		}
	}
	return res;
}

/**
 * Switch to the registered breakpoint plugin called \p name
 */
RZ_API int rz_bp_use(RZ_NONNULL RzBreakpoint *bp, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bp && name, false);
	RzListIter *iter;
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
