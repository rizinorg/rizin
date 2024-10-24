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
	if (!ht_sp_insert(bp->plugins, plugin->name, plugin)) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
	}
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
	RzBreakpointPlugin **val;
	rz_iterator_foreach(iter, val) {
		RzBreakpointPlugin *h = *val;
		if (!strcmp(h->name, name)) {
			bp->cur = h;
			rz_iterator_free(iter);
			return true;
		}
	}
	rz_iterator_free(iter);
	return false;
}

RZ_DEPRECATE RZ_API void rz_bp_plugin_print(RZ_NONNULL RzBreakpoint *bp) {
	rz_return_if_fail(bp);
	RzIterator *iter = ht_sp_as_iter(bp->plugins);
	RzList *plugin_list = rz_list_new_from_iterator(iter);
	if (!plugin_list) {
		rz_iterator_free(iter);
		return;
	}
	rz_list_sort(plugin_list, (RzListComparator)rz_breakpoint_plugin_cmp, NULL);
	RzListIter *it;
	RzBreakpointPlugin *b;
	rz_list_foreach (plugin_list, it, b) {
		bp->cb_printf("bp %c %s\n",
			(bp->cur && !strcmp(bp->cur->name, b->name)) ? '*' : '-',
			b->name);
	}
	rz_list_free(plugin_list);
	rz_iterator_free(iter);
}
