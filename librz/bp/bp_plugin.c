// SPDX-FileCopyrightText: 2009-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <rz_lib.h>
#include <rz_util/ht_sp.h>
#include <rz_util/rz_iterator.h>

RZ_API int rz_bp_plugin_del_byname(RzBreakpoint *bp, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bp && name, false);

	bool found = false;
	RzBreakpointPlugin *bp_plugin = ht_sp_find(bp->plugins, name, &found);
	if (!found) {
		return false;
	}
	if (bp_plugin == bp->cur) {
		bp->cur = NULL;
	}
	ht_sp_delete(bp->plugins, name);
	bp->nbps--;
	return true;
}

RZ_API bool rz_bp_plugin_add(RzBreakpoint *bp, RZ_BORROW RZ_NONNULL RzBreakpointPlugin *plugin) {
	rz_return_val_if_fail(bp && plugin, false);
	ht_sp_insert(bp->plugins, plugin->name, plugin);
	return true;
}

RZ_API bool rz_bp_plugin_del(RzBreakpoint *bp, RZ_BORROW RZ_NONNULL RzBreakpointPlugin *plugin) {
	rz_return_val_if_fail(bp && plugin, false);
	bool res = ht_sp_delete(bp->plugins, plugin->name);
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
	RzIterator *iter = ht_sp_as_iter(bp->plugins);
	RzBreakpointPlugin *h;
	rz_iterator_foreach(iter, h) {
		if (!strcmp(h->name, name)) {
			bp->cur = h;
			return true;
		}
	}
	rz_iterator_free(iter);
	return false;
}

// TODO: deprecate
RZ_API void rz_bp_plugin_list(RzBreakpoint *bp) {
	RzIterator *iter = ht_sp_as_iter(bp->plugins);
	RzBreakpointPlugin *b;
	rz_iterator_foreach(iter, b) {
		bp->cb_printf("bp %c %s\n",
			(bp->cur && !strcmp(bp->cur->name, b->name)) ? '*' : '-',
			b->name);
	}
	rz_iterator_free(iter);
}
