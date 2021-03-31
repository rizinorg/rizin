// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <config.h>

RZ_LIB_VERSION(rz_bp);

static struct rz_bp_plugin_t *bp_static_plugins[] = { RZ_BP_STATIC_PLUGINS };

static void rz_bp_item_free(RzBreakpointItem *b) {
	free(b->name);
	free(b->bbytes);
	free(b->obytes);
	free(b->module_name);
	free(b->data);
	free(b->cond);
	free(b);
}

RZ_API RzBreakpoint *rz_bp_new(void) {
	int i;
	RzBreakpointPlugin *static_plugin;
	RzBreakpoint *bp = RZ_NEW0(RzBreakpoint);
	if (!bp) {
		return NULL;
	}
	bp->bps_idx_count = 16;
	bp->bps_idx = RZ_NEWS0(RzBreakpointItem *, bp->bps_idx_count);
	bp->stepcont = RZ_BP_CONT_NORMAL;
	bp->traces = rz_bp_traptrace_new();
	bp->cb_printf = (PrintfCallback)printf;
	bp->bps = rz_list_newf((RzListFree)rz_bp_item_free);
	bp->plugins = rz_list_newf((RzListFree)free);
	bp->nhwbps = 0;
	for (i = 0; bp_static_plugins[i]; i++) {
		static_plugin = RZ_NEW(RzBreakpointPlugin);
		memcpy(static_plugin, bp_static_plugins[i],
			sizeof(RzBreakpointPlugin));
		rz_bp_plugin_add(bp, static_plugin);
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

RZ_API int rz_bp_get_bytes(RzBreakpoint *bp, ut8 *buf, int len, int endian, int idx) {
	int i;
	struct rz_bp_arch_t *b;
	if (bp->cur) {
		// find matching size breakpoint
	repeat:
		for (i = 0; i < bp->cur->nbps; i++) {
			b = &bp->cur->bps[i];
			if (bp->cur->bps[i].bits) {
				if (bp->bits != bp->cur->bps[i].bits) {
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
			eprintf("No matching bpsize\n");
			return 0;
		}
		for (i = 0; i < len; i++) {
			memcpy(buf + i, b->bytes, b->length);
		}
		return b->length;
	}
	return 0;
}

RZ_API RzBreakpointItem *rz_bp_get_at(RzBreakpoint *bp, ut64 addr) {
	RzListIter *iter;
	RzBreakpointItem *b;
	rz_list_foreach (bp->bps, iter, b) {
		if (b->addr == addr) {
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

RZ_API int rz_bp_enable_all(RzBreakpoint *bp, int set) {
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

/* TODO: detect overlapping of breakpoints */
static RzBreakpointItem *rz_bp_add(RzBreakpoint *bp, const ut8 *obytes, ut64 addr, int size, int hw, int perm) {
	int ret;
	RzBreakpointItem *b;
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (rz_bp_get_in(bp, addr, perm)) {
		eprintf("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = rz_bp_item_new(bp);
	if (!b) {
		return NULL;
	}
	b->addr = addr + bp->delta;
	if (bp->baddr > addr) {
		eprintf("base addr should not be larger than the breakpoint address.\n");
	}
	if (bp->bpinmaps && !rz_bp_is_valid(bp, b)) {
		eprintf("WARNING: Breakpoint won't be placed since it's not in a valid map.\n"
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
			return NULL;
		}
		if (obytes) {
			b->obytes = malloc(size);
			if (!b->obytes) {
				free(b->bbytes);
				return NULL;
			}
			memcpy(b->obytes, obytes, size);
		} else {
			b->obytes = NULL;
		}
		ret = rz_bp_get_bytes(bp, b->bbytes, size, bp->endian, 0);
		if (ret != size) {
			eprintf("Cannot get breakpoint bytes. No architecture selected?\n");
		}
	}
	bp->nbps++;
	rz_list_append(bp->bps, b);
	return b;
}

RZ_API int rz_bp_add_fault(RzBreakpoint *bp, ut64 addr, int size, int perm) {
	// TODO
	return false;
}

RZ_API RzBreakpointItem *rz_bp_add_sw(RzBreakpoint *bp, ut64 addr, int size, int perm) {
	RzBreakpointItem *item;
	ut8 *bytes;
	if (size < 1) {
		size = 1;
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

RZ_API int rz_bp_del_all(RzBreakpoint *bp) {
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

RZ_API int rz_bp_del(RzBreakpoint *bp, ut64 addr) {
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

// TODO: deprecate
RZ_API int rz_bp_list(RzBreakpoint *bp, int rad) {
	int n = 0;
	RzBreakpointItem *b;
	RzListIter *iter;
	PJ *pj = NULL;
	if (rad == 'j') {
		pj = pj_new();
		if (!pj) {
			return 0;
		}
		pj_a(pj);
	}
	//eprintf ("Breakpoint list:\n");
	rz_list_foreach (bp->bps, iter, b) {
		if (pj) {
			pj_o(pj);
			pj_kN(pj, "addr", b->addr);
			pj_ki(pj, "size", b->size);
			pj_ks(pj, "perm", rz_str_rwx_i(b->perm & 7)); /* filter out R_BP_PROT_ACCESS */
			pj_kb(pj, "hw", b->hw);
			pj_kb(pj, "trace", b->trace);
			pj_kb(pj, "enabled", b->enabled);
			pj_kb(pj, "valid", rz_bp_is_valid(bp, b));
			pj_ks(pj, "data", rz_str_get(b->data));
			pj_ks(pj, "cond", rz_str_get(b->cond));
			pj_end(pj);
		} else if (rad) {
			if (b->module_name) {
				bp->cb_printf("dbm %s %" PFMT64d "\n", b->module_name, b->module_delta);
			} else {
				bp->cb_printf("db 0x%08" PFMT64x "\n", b->addr);
			}
		} else {
			bp->cb_printf("0x%08" PFMT64x " - 0x%08" PFMT64x
				      " %d %c%c%c %s %s %s %s cmd=\"%s\" cond=\"%s\" "
				      "name=\"%s\" module=\"%s\"\n",
				b->addr, b->addr + b->size, b->size,
				((b->perm & RZ_BP_PROT_READ) | (b->perm & RZ_BP_PROT_ACCESS)) ? 'r' : '-',
				((b->perm & RZ_BP_PROT_WRITE) | (b->perm & RZ_BP_PROT_ACCESS)) ? 'w' : '-',
				(b->perm & RZ_BP_PROT_EXEC) ? 'x' : '-',
				b->hw ? "hw" : "sw",
				b->trace ? "trace" : "break",
				b->enabled ? "enabled" : "disabled",
				rz_bp_is_valid(bp, b) ? "valid" : "invalid",
				rz_str_get(b->data),
				rz_str_get(b->cond),
				rz_str_get(b->name),
				rz_str_get(b->module_name));
		}
		n++;
	}
	if (pj) {
		pj_end(pj);
		bp->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
	return n;
}

RZ_API RzBreakpointItem *rz_bp_item_new(RzBreakpoint *bp) {
	int i, j;
	/* find empty slot */
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (!bp->bps_idx[i]) {
			goto return_slot;
		}
	}
	/* allocate new slot */
	bp->bps_idx_count += 16; // allocate space for 16 more bps
	RzBreakpointItem **newbps = realloc(bp->bps_idx, bp->bps_idx_count * sizeof(RzBreakpointItem *));
	if (newbps) {
		bp->bps_idx = newbps;
	} else {
		bp->bps_idx_count -= 16; // allocate space for 16 more bps
	}
	for (j = i; j < bp->bps_idx_count; j++) {
		bp->bps_idx[j] = NULL;
	}
return_slot:
	/* empty slot */
	return (bp->bps_idx[i] = RZ_NEW0(RzBreakpointItem));
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

RZ_API int rz_bp_size(RzBreakpoint *bp) {
	RzBreakpointArch *bpa;
	int i, bpsize = 8;
	if (!bp || !bp->cur) {
		return 0;
	}
	for (i = 0; bp->cur->bps[i].bytes; i++) {
		bpa = &bp->cur->bps[i];
		if (bpa->bits && bpa->bits != bp->bits) {
			continue;
		}
		if (bpa->length < bpsize) {
			bpsize = bpa->length;
		}
	}
	return bpsize;
}

// Check if the breakpoint is in a valid map
RZ_API bool rz_bp_is_valid(RzBreakpoint *bp, RzBreakpointItem *b) {
	if (!bp->bpinmaps) {
		return true;
	}

	return bp->corebind.isMapped(bp->corebind.core, b->addr, b->perm);
}
