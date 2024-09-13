// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include "rz_bp_plugins.h"

RZ_LIB_VERSION(rz_bp);

static struct rz_bp_plugin_t *bp_static_plugins[] = { RZ_BP_STATIC_PLUGINS };

static void rz_bp_item_free(RzBreakpointItem *b) {
	free(b->name);
	free(b->bbytes);
	free(b->obytes);
	free(b->module_name);
	free(b->data);
	free(b->cond);
	free(b->expr);
	free(b);
}

/**
 * Construct a new RzBreakpoint instance
 * \param ctx global context in which the instance will operate (giving mappings, etc)
 */
RZ_API RzBreakpoint *rz_bp_new(RZ_BORROW RZ_NONNULL RzBreakpointContext *ctx) {
	int i;
	RzBreakpoint *bp = RZ_NEW0(RzBreakpoint);
	if (!bp) {
		return NULL;
	}
	bp->ctx = *ctx;
	bp->bps_idx_count = 16;
	bp->bps_idx = RZ_NEWS0(RzBreakpointItem *, bp->bps_idx_count);
	bp->stepcont = RZ_BP_CONT_NORMAL;
	bp->traces = rz_bp_traptrace_new();
	bp->cb_printf = (PrintfCallback)printf;
	bp->bps = rz_list_newf((RzListFree)rz_bp_item_free);
	bp->plugins = rz_list_new();
	bp->nhwbps = 0;
	for (i = 0; i < RZ_ARRAY_SIZE(bp_static_plugins); i++) {
		rz_bp_plugin_add(bp, bp_static_plugins[i]);
	}
	memset(&bp->iob, 0, sizeof(bp->iob));
	return bp;
}

RZ_API RzBreakpoint *rz_bp_free(RzBreakpoint *bp) {
	rz_list_free(bp->bps);
	rz_list_free(bp->plugins);
	rz_list_free(bp->traces);
	free(bp->bps_idx);
	free(bp);
	return NULL;
}

/**
 * Get the bytes to place at \p addr in order to set a sw breakpoint there
 * \p return the length of bytes or 0 on failure
 */
RZ_API int rz_bp_get_bytes(RZ_NONNULL RzBreakpoint *bp, ut64 addr, RZ_NONNULL ut8 *buf, int len) {
	rz_return_val_if_fail(bp && buf, 0);
	int endian = bp->endian;
	int bits = bp->ctx.bits_at ? bp->ctx.bits_at(addr, bp->ctx.user) : 0;
	struct rz_bp_arch_t *b;
	if (!bp->cur) {
		return 0;
	}
	// find matching size breakpoint
repeat:
	for (int i = 0; i < bp->cur->nbps; i++) {
		b = &bp->cur->bps[i];
		if (bp->cur->bps[i].bits) {
			if (!bits || bits != bp->cur->bps[i].bits) {
				continue;
			}
		}
		if (bp->cur->bps[i].length == len && bp->cur->bps[i].endian == endian) {
			memcpy(buf, b->bytes, b->length);
			return b->length;
		}
	}
	if (len != 4) {
		len = 4;
		goto repeat;
	}
	/* if not found try to pad with the first one */
	b = &bp->cur->bps[0];
	if (len % b->length) {
		RZ_LOG_ERROR("No matching bpsize\n");
		return 0;
	}
	for (int i = 0; i < len; i++) {
		memcpy(buf + i, b->bytes, b->length);
	}
	return b->length;
}

/**
 * \brief Get the breakpoint at exactly \p addr
 */
RZ_API RZ_BORROW RzBreakpointItem *rz_bp_get_at(RZ_NONNULL RzBreakpoint *bp, ut64 addr) {
	rz_return_val_if_fail(bp, NULL);
	RzListIter *iter;
	RzBreakpointItem *b;
	rz_list_foreach (bp->bps, iter, b) {
		if (b->addr == addr) {
			return b;
		}
	}
	return NULL;
}

/**
 * \brief Get the breakpoint b that fulfills `b->addr + b-> size == addr`
 * After hitting a (usually software) breakpoint, the program counter will be directly after it.
 * This way we can trace back the breakpoint matching this program counter.
 */
RZ_API RZ_BORROW RzBreakpointItem *rz_bp_get_ending_at(RZ_NONNULL RzBreakpoint *bp, ut64 addr) {
	rz_return_val_if_fail(bp, NULL);
	RzListIter *iter;
	RzBreakpointItem *b;
	rz_list_foreach (bp->bps, iter, b) {
		if (!b->hw && b->addr + b->size == addr) {
			return b;
		}
	}
	return NULL;
}

static inline bool inRange(RzBreakpointItem *b, ut64 addr) {
	return (addr >= b->addr && addr < (b->addr + b->size));
}

static inline bool matchProt(RzBreakpointItem *b, int perm) {
	return (!perm || (perm && b->perm));
}

RZ_API RzBreakpointItem *rz_bp_get_in(RzBreakpoint *bp, ut64 addr, int perm) {
	RzBreakpointItem *b;
	RzListIter *iter;
	rz_list_foreach (bp->bps, iter, b) {
		// eprintf ("---ataddr--- 0x%08"PFMT64x" %d %d %x\n", b->addr, b->size, b->recoil, b->perm);
		// Check addr within range and provided perm matches (or null)
		if (inRange(b, addr) && matchProt(b, perm)) {
			return b;
		}
	}
	return NULL;
}

RZ_API RzBreakpointItem *rz_bp_enable(RzBreakpoint *bp, ut64 addr, int set, int count) {
	RzBreakpointItem *b = rz_bp_get_in(bp, addr, 0);
	if (b) {
		b->enabled = set;
		b->togglehits = count;
		return b;
	}
	return NULL;
}

RZ_API bool rz_bp_enable_all(RzBreakpoint *bp, int set) {
	RzListIter *iter;
	RzBreakpointItem *b;
	rz_list_foreach (bp->bps, iter, b) {
		b->enabled = set;
	}
	return true;
}

RZ_API int rz_bp_stepy_continuation(RzBreakpoint *bp) {
	// TODO: implement
	return bp->stepcont;
}

static void unlinkBreakpoint(RzBreakpoint *bp, RzBreakpointItem *b) {
	int i;
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (bp->bps_idx[i] == b) {
			bp->bps_idx[i] = NULL;
		}
	}
	rz_list_delete_data(bp->bps, b);
}

/**
 * Put an allocated RzBreakpointItem into the RzBreakpoint's list and give it an index
 */
RZ_IPI void rz_bp_item_insert(RzBreakpoint *bp, RzBreakpointItem *b) {
	int i;
	/* find empty slot */
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (!bp->bps_idx[i]) {
			break;
		}
	}
	if (i == bp->bps_idx_count) {
		/* allocate new slot */
		bp->bps_idx_count += 16; // allocate space for 16 more bps
		RzBreakpointItem **newbps = realloc(bp->bps_idx, bp->bps_idx_count * sizeof(RzBreakpointItem *));
		if (newbps) {
			bp->bps_idx = newbps;
			for (int j = i; j < bp->bps_idx_count; j++) {
				bp->bps_idx[j] = NULL;
			}
		} else {
			bp->bps_idx_count -= 16; // allocate space for 16 more bps
			i = 0; // avoid oob below
		}
	}
	/* empty slot */
	bp->bps_idx[i] = b;
	bp->nbps++;
	rz_list_append(bp->bps, b);
}

/* TODO: detect overlapping of breakpoints */
static RzBreakpointItem *rz_bp_add(RzBreakpoint *bp, const ut8 *obytes, ut64 addr, int size, int hw, int perm) {
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
	if (bp->baddr > addr) {
		RZ_LOG_ERROR("base addr should not be larger than the breakpoint address.\n");
	}
	if (bp->bpinmaps && !rz_bp_is_valid(bp, b)) {
		RZ_LOG_WARN("Breakpoint won't be placed since it's not in a valid map.\n"
			    "You can bypass this check by setting dbg.bpinmaps to false.\n");
	}
	b->delta = addr - bp->baddr;
	b->size = size;
	b->enabled = true;
	b->perm = perm;
	b->hw = hw;
	// NOTE: for hw breakpoints there are no bytes to save/restore
	if (!hw) {
		b->bbytes = calloc(size + 16, 1);
		if (!b->bbytes) {
			goto err;
		}
		if (obytes) {
			b->obytes = malloc(size);
			if (!b->obytes) {
				goto err;
			}
			memcpy(b->obytes, obytes, size);
		} else {
			b->obytes = NULL;
		}
		int ret = rz_bp_get_bytes(bp, b->addr, b->bbytes, size);
		if (ret != size) {
			RZ_LOG_ERROR("Cannot get breakpoint bytes. Incorrect architecture/bits selected for software breakpoints?\n");
			goto err;
		}
	}
	rz_bp_item_insert(bp, b);
	return b;
err:
	rz_bp_item_free(b);
	return NULL;
}

RZ_API int rz_bp_add_fault(RzBreakpoint *bp, ut64 addr, int size, int perm) {
	// TODO
	return false;
}

/**
 * \brief Add a software breakpoint
 * \p size preferred size of the breakpoint, or 0 to determine automatically
 */
RZ_API RZ_BORROW RzBreakpointItem *rz_bp_add_sw(RZ_NONNULL RzBreakpoint *bp, ut64 addr, int size, int perm) {
	rz_return_val_if_fail(bp, NULL);
	RzBreakpointItem *item;
	ut8 *bytes;
	if (size < 1) {
		size = rz_bp_size_at(bp, addr);
	}
	if (!(bytes = calloc(1, size))) {
		return NULL;
	}
	memset(bytes, 0, size);
	if (bp->iob.read_at) {
		bp->iob.read_at(bp->iob.io, addr, bytes, size);
	}
	item = rz_bp_add(bp, bytes, addr, size, RZ_BP_TYPE_SW, perm);
	free(bytes);
	return item;
}

RZ_API RzBreakpointItem *rz_bp_add_hw(RzBreakpoint *bp, ut64 addr, int size, int perm) {
	return rz_bp_add(bp, NULL, addr, size, RZ_BP_TYPE_HW, perm);
}

RZ_API bool rz_bp_del_all(RzBreakpoint *bp) {
	int i;
	if (!rz_list_empty(bp->bps)) {
		rz_list_purge(bp->bps);
		for (i = 0; i < bp->bps_idx_count; i++) {
			bp->bps_idx[i] = NULL;
		}
		return true;
	}
	return false;
}

RZ_API bool rz_bp_del(RzBreakpoint *bp, ut64 addr) {
	RzListIter *iter;
	RzBreakpointItem *b;
	/* No _safe loop necessary because we return immediately after the delete. */
	rz_list_foreach (bp->bps, iter, b) {
		if (b->addr == addr) {
			unlinkBreakpoint(bp, b);
			// rz_list_delete (bp->bps, iter);
			return true;
		}
	}
	return false;
}

RZ_API int rz_bp_set_trace(RzBreakpoint *bp, ut64 addr, int set) {
	RzBreakpointItem *b = rz_bp_get_in(bp, addr, 0);
	if (b) {
		b->trace = set;
		return true;
	}
	return false;
}

RZ_API int rz_bp_set_trace_all(RzBreakpoint *bp, int set) {
	RzListIter *iter;
	RzBreakpointItem *b;
	rz_list_foreach (bp->bps, iter, b) {
		b->trace = set;
	}
	return true;
}

RZ_API RzBreakpointItem *rz_bp_get_index(RzBreakpoint *bp, int idx) {
	if (idx >= 0 && idx < bp->bps_idx_count) {
		return bp->bps_idx[idx];
	}
	return NULL;
}

RZ_API int rz_bp_get_index_at(RzBreakpoint *bp, ut64 addr) {
	int i;
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (bp->bps_idx[i] && bp->bps_idx[i]->addr == addr) {
			return i;
		}
	}
	return -1;
}

RZ_API int rz_bp_del_index(RzBreakpoint *bp, int idx) {
	if (idx >= 0 && idx < bp->bps_idx_count) {
		rz_list_delete_data(bp->bps, bp->bps_idx[idx]);
		bp->bps_idx[idx] = 0;
		return true;
	}
	return false;
}

/**
 * \brief Predict the software breakpoint size to use for the given arch-bitness
 * \param bits bitness or 0 if unspecified
 */
RZ_API int rz_bp_size(RZ_NONNULL RzBreakpoint *bp, int bits) {
	rz_return_val_if_fail(bp, 0);
	RzBreakpointArch *bpa;
	int i, bpsize = 8;
	if (!bp || !bp->cur) {
		return 0;
	}
	for (i = 0; bp->cur->bps[i].bytes; i++) {
		bpa = &bp->cur->bps[i];
		if (bpa->bits && bpa->bits != bits) {
			continue;
		}
		if (bpa->length < bpsize) {
			bpsize = bpa->length;
		}
	}
	return bpsize;
}

/**
 * \brief Predict the software breakpoint size to use when placing a breakpoint at \p addr
 */
RZ_API int rz_bp_size_at(RZ_NONNULL RzBreakpoint *bp, ut64 addr) {
	rz_return_val_if_fail(bp, 0);
	int bits = bp->ctx.bits_at ? bp->ctx.bits_at(addr, bp->ctx.user) : 0;
	return rz_bp_size(bp, bits);
}

// Check if the breakpoint is in a valid map
RZ_API bool rz_bp_is_valid(RzBreakpoint *bp, RzBreakpointItem *b) {
	if (!bp->bpinmaps) {
		return true;
	}
	if (!bp->ctx.is_mapped) {
		return false;
	}
	return bp->ctx.is_mapped(b->addr, b->perm, bp->ctx.user);
}

/**
 * \brief set the condition for a RzBreakpointItem
 *
 * \param item brekapoint item to set value for
 * \param cond value of cond to be set; if NULL is passed, then the cond value of \p item will be set to NULL
 * \return bool true if succesful; false otherwise; if false returned, then \p item will not have been modified
 */
RZ_API bool rz_bp_item_set_cond(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *cond) {
	rz_return_val_if_fail(item, false);

	char *tmp_cond = NULL;
	if (cond) {
		tmp_cond = rz_str_dup(cond);
		if (!tmp_cond) {
			return false;
		}
	}
	free(item->cond);
	item->cond = tmp_cond;
	return true;
}

/**
 * \brief set the data for a RzBreakpointItem
 *
 * \param item brekapoint item to set value for
 * \param data value of data to be set; if NULL is passed, then the data value of \p item will be set to NULL
 * \return bool true if succesful; false otherwise; if false returned, then \p item will not have been modified
 */
RZ_API bool rz_bp_item_set_data(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *data) {
	rz_return_val_if_fail(item, false);

	char *tmp_data = NULL;
	if (data) {
		tmp_data = rz_str_dup(data);
		if (!tmp_data) {
			return false;
		}
	}
	free(item->data);
	item->data = tmp_data;
	return true;
}

/**
 * \brief set the expr for a RzBreakpointItem
 *
 * \param item brekapoint item to set value for
 * \param expr value of expr to be set; if NULL is passed, then the expr value of \p item will be set to NULL
 * \return bool true if succesful; false otherwise; if false returned, then \p item will not have been modified
 */
RZ_API bool rz_bp_item_set_expr(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *expr) {
	rz_return_val_if_fail(item, false);

	char *tmp_expr = NULL;
	if (expr) {
		tmp_expr = rz_str_dup(expr);
		if (!tmp_expr) {
			return false;
		}
	}
	free(item->expr);
	item->expr = tmp_expr;
	return true;
}

/**
 * \brief set the name for a RzBreakpointItem
 *
 * \param item brekapoint item to set value for
 * \param name value of name to be set; if NULL is passed, then the name value of \p item will be set to NULL
 * \return bool true if succesful; false otherwise; if false returned, then \p item will not have been modified
 */
RZ_API bool rz_bp_item_set_name(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *name) {
	rz_return_val_if_fail(item, false);

	char *tmp_name = NULL;
	if (name) {
		tmp_name = rz_str_dup(name);
		if (!tmp_name) {
			return false;
		}
	}
	free(item->name);
	item->name = tmp_name;
	return true;
}
