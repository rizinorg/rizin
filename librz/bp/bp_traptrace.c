// SPDX-FileCopyrightText: 2010 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// TODO: use rz_range here??
#include <rz_bp.h>
#include <rz_list.h>

RZ_API void rz_bp_traptrace_free(void *ptr) {
	RzBreakpointTrace *trace = ptr;
	free(trace->buffer);
	free(trace->traps);
	free(trace->bits);
	free(trace);
}

RZ_API RzList *rz_bp_traptrace_new(void) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	list->free = &rz_bp_traptrace_free;
	return list;
}

RZ_API void rz_bp_traptrace_enable(RzBreakpoint *bp, int enable) {
	RzListIter *iter;
	RzBreakpointTrace *trace;
	rz_list_foreach (bp->traces, iter, trace) {
		ut8 *buf = (enable) ? trace->traps : trace->buffer;
		bp->iob.write_at(bp->iob.io, trace->addr, buf, trace->length);
	}
}

RZ_API void rz_bp_traptrace_reset(RzBreakpoint *bp, int hard) {
	RzListIter *iter;
	RzBreakpointTrace *trace;
	rz_list_foreach (bp->traces, iter, trace) {
		if (hard) {
			rz_bp_traptrace_free(trace);
			// XXX: This segfaults
			//rz_list_delete (bp->traces, rz_list_iter_cur (iter));
		} else {
			memset(trace->bits, 0x00, trace->bitlen);
		}
	}
	if (hard) {
		// XXX: traces not freed correctly (memleak)
		bp->traces = rz_list_new();
		bp->traces->free = rz_bp_traptrace_free;
	}
}

// FIX: efficiency
RZ_API ut64 rz_bp_traptrace_next(RzBreakpoint *bp, ut64 addr) {
	int i, delta;
	RzListIter *iter;
	RzBreakpointTrace *trace;
	rz_list_foreach (bp->traces, iter, trace) {
		if (addr >= trace->addr && addr <= trace->addr_end) {
			delta = (int)(addr - trace->addr);
			for (i = delta; i < trace->length; i++) {
				if (RZ_BIT_CHK(trace->bits, i)) {
					return addr + i;
				}
			}
		}
	}
	return 0LL;
}

RZ_API int rz_bp_traptrace_add(RzBreakpoint *bp, ut64 from, ut64 to) {
	RzBreakpointTrace *trace;
	ut8 *buf, *trap, *bits;
	ut64 len;
	int bitlen;
	/* cannot map addr 0 */
	if (from == 0LL) {
		return false;
	}
	if (from > to) {
		return false;
	}
	len = to - from;
	if (len >= ST32_MAX) {
		return false;
	}
	buf = (ut8 *)malloc((int)len);
	if (!buf) {
		return false;
	}
	trap = (ut8 *)malloc((int)len + 4);
	if (!trap) {
		free(buf);
		return false;
	}
	bitlen = (len >> 4) + 1;
	bits = malloc(bitlen);
	if (!bits) {
		free(buf);
		free(trap);
		return false;
	}
	// TODO: check return value
	bp->iob.read_at(bp->iob.io, from, buf, len);
	memset(bits, 0x00, bitlen);
	rz_bp_get_bytes(bp, trap, len, bp->endian, 0);

	trace = RZ_NEW(RzBreakpointTrace);
	if (!trace) {
		free(buf);
		free(trap);
		free(bits);
		return false;
	}
	trace->addr = from;
	trace->addr_end = to;
	trace->bits = bits;
	trace->traps = trap;
	trace->buffer = buf;
	trace->length = len;
	if (!rz_list_append(bp->traces, trace)) {
		free(buf);
		free(trap);
		free(trace);
		return false;
	}
	// read a memory, overwrite it as breakpointing area
	// every time it is hitted, instruction is restored
	return true;
}

RZ_API int rz_bp_traptrace_free_at(RzBreakpoint *bp, ut64 from) {
	int ret = false;
	RzListIter *iter, *iter_tmp;
	RzBreakpointTrace *trace;
	rz_list_foreach_safe (bp->traces, iter, iter_tmp, trace) {
		if (from >= trace->addr && from <= trace->addr_end) {
			bp->iob.write_at(bp->iob.io, trace->addr,
				trace->buffer, trace->length);
			rz_bp_traptrace_free(trace);
			rz_list_delete(bp->traces, iter);
			ret = true;
		}
	}
	return ret;
}

RZ_API void rz_bp_traptrace_list(RzBreakpoint *bp) {
	int i;
	RzListIter *iter;
	RzBreakpointTrace *trace;
	rz_list_foreach (bp->traces, iter, trace) {
		for (i = 0; i < trace->bitlen; i++) {
			if (RZ_BIT_CHK(trace->bits, i)) {
				eprintf("  - 0x%08" PFMT64x "\n", trace->addr + (i << 4));
			}
		}
	}
}

RZ_API int rz_bp_traptrace_at(RzBreakpoint *bp, ut64 from, int len) {
	int delta;
	RzListIter *iter;
	RzBreakpointTrace *trace;
	rz_list_foreach (bp->traces, iter, trace) {
		// TODO: do we really need len?
		if (from >= trace->addr && from + len <= trace->addr_end) {
			delta = (int)(from - trace->addr);
			if (RZ_BIT_CHK(trace->bits, delta)) {
				if (trace->traps[delta] == 0x00) {
					return false; // already traced..debugger should stop
				}
			}
			RZ_BIT_SET(trace->bits, delta);
			return true;
		}
	}
	return false;
}
