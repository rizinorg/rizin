// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"
#include <rz_core.h>

#define mid_down_refline(a, r) ((r)->from > (r)->to && (a) < (r)->from && (a) > (r)->to)
#define mid_up_refline(a, r)   ((r)->from < (r)->to && (a) > (r)->from && (a) < (r)->to)
#define mid_refline(a, r)      (mid_down_refline(a, r) || mid_up_refline(a, r))
#define in_refline(a, r)       (mid_refline(a, r) || (a) == (r)->from || (a) == (r)->to)

typedef struct {
	ut64 addr;
	RzAnalysisRefline *ref;
} ReflineEnd;

static int cmp_refline_end(const void *lhs, const void *rhs) {
	const ReflineEnd *a = lhs;
	const ReflineEnd *b = rhs;
	if (a->addr != b->addr) {
		return a->addr < b->addr ? -1 : 1;
	}
	// At a shared endpoint, the newer line has always taken the inner column.
	return (b->ref->index > a->ref->index) - (b->ref->index < a->ref->index);
}

static int cmp_by_ref_lvl(const RzAnalysisRefline *a, const RzAnalysisRefline *b, void *user) {
	return (a->level < b->level) - (a->level > b->level);
}

typedef struct {
	RzPVector /*<RzAnalysisRefline *>*/ *refs;
	ut64 start;
	ut64 size;
	size_t max;
	bool linesout;
} ReflineRange;

static bool add_refline(ReflineRange *range, ut64 from, ut64 to) {
	if (rz_pvector_len(range->refs) >= range->max ||
		(!range->linesout && (to < range->start || to - range->start >= range->size))) {
		return true;
	}
	RzAnalysisRefline *ref = RZ_NEW0(RzAnalysisRefline);
	if (!ref) {
		return false;
	}
	ref->from = from;
	ref->to = to;
	ref->level = -1;
	ref->direction = to > from ? 1 : -1;
	if (!rz_pvector_push(range->refs, ref)) {
		free(ref);
		return false;
	}
	return true;
}

RZ_API void rz_analysis_reflines_free(RzAnalysisRefline *rl) {
	free(rl);
}

static ut64 refline_meta_size(RzAnalysis *analysis, ut64 addr) {
	RzPVector *metas = rz_meta_get_all_at(analysis, addr);
	ut64 size = 0;
	if (metas) {
		void **it;
		rz_pvector_foreach (metas, it) {
			RzIntervalNode *node = *it;
			RzAnalysisMetaItem *meta = node->data;
			if (meta->type == RZ_META_TYPE_DATA || meta->type == RZ_META_TYPE_STRING ||
				meta->type == RZ_META_TYPE_HIDE || meta->type == RZ_META_TYPE_FORMAT ||
				meta->type == RZ_META_TYPE_MAGIC) {
				size = rz_meta_node_size(node);
				break;
			}
		}
		rz_pvector_free(metas);
	}
	return size;
}

static bool refline_add_op(ReflineRange *range, const RzAnalysisOp *op, bool linescall) {
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_CALL:
		if (!linescall) {
			break;
		}
		// fallthrough
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_JMP:
		if (op->jump != UT64_MAX && !add_refline(range, op->addr, op->jump)) {
			return false;
		}
		if (!op->delay && op->fail != UT64_MAX && op->fail != op->addr + op->size) {
			return add_refline(range, op->addr, op->fail);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_SWITCH:
		if (op->switch_op) {
			RzListIter *it;
			RzAnalysisCaseOp *c;
			rz_list_foreach (op->switch_op->cases, it, c) {
				if (rz_pvector_len(range->refs) >= range->max) {
					break;
				}
				if (!add_refline(range, op->switch_op->addr, c->jump)) {
					return false;
				}
			}
		}
		break;
	default:
		break;
	}
	return true;
}

static bool refline_levels(RzPVector /*<RzAnalysisRefline *>*/ *refs, ut64 start, ut64 size, bool linesout) {
	// The range of a counted listing is known only after its last row.
	size_t count = 0;
	void **entries = rz_pvector_data(refs);
	for (size_t i = 0; i < rz_pvector_len(refs); i++) {
		RzAnalysisRefline *ref = entries[i];
		if (!linesout && (ref->to < start || ref->to - start >= size)) {
			free(ref);
			continue;
		}
		ref->index = count;
		entries[count++] = ref;
	}
	while (rz_pvector_len(refs) > count) {
		rz_pvector_pop(refs);
	}
	if (!count) {
		return true;
	}
	ReflineEnd *ends = calloc(count, 2 * sizeof(*ends));
	ut8 *levels = RZ_NEWS0(ut8, count + 1);
	if (!ends || !levels) {
		free(ends);
		free(levels);
		return false;
	}
	for (size_t i = 0; i < count; i++) {
		RzAnalysisRefline *ref = entries[i];
		ends[2 * i] = (ReflineEnd){ ref->from, ref };
		ends[2 * i + 1] = (ReflineEnd){ ref->to, ref };
	}
	qsort(ends, 2 * count, sizeof(*ends), cmp_refline_end);
	size_t min = 0;
	for (size_t i = 0; i < 2 * count; i++) {
		RzAnalysisRefline *ref = ends[i].ref;
		if (ref->level == -1) {
			ref->level = min + 1;
			levels[min] = 1;
			while (levels[++min]) {
			}
		} else {
			size_t level = ref->level - 1;
			levels[level] = 0;
			min = RZ_MIN(min, level);
		}
	}
	free(levels);
	free(ends);
	return true;
}

static bool scan_refline_rows(RzAnalysis *analysis, ReflineRange *range, ut64 limit, int nlines, bool linescall, RzAnalysisReflineDecode decode, void *user, bool counted, ut64 *scanned) {
	ut64 off = 0;
	while (off < limit && nlines && !rz_interrupt_is_breaked(analysis->intr)) {
		if (nlines > 0) {
			nlines--;
		}
		ut64 addr = range->start + off;
		ut64 step = refline_meta_size(analysis, addr);
		if (!step) {
			bool executable = range->refs && analysis->iob.is_valid_offset(analysis->iob.io, addr, RZ_PERM_X);
			if (counted || executable) {
				RzAnalysisOp op = { 0 };
				int decoded = decode(user, addr, &op);
				bool ok = decoded <= 0 || !executable || refline_add_op(range, &op, linescall);
				rz_analysis_op_fini(&op);
				if (!ok) {
					return false;
				}
				if (decoded <= 0) {
					break;
				}
				step = decoded;
			} else {
				step = 4;
			}
		}
		off += RZ_MIN(step, limit - off);
		if (off > UT64_MAX - range->start || (range->refs && rz_pvector_len(range->refs) >= range->max)) {
			break;
		}
	}
	*scanned = off;
	return true;
}

static RzPVector /*<RzAnalysisRefline *>*/ *collect_reflines(RzAnalysis *analysis, ut64 start, ut64 limit, int nlines, bool linesout, bool linescall, RzAnalysisReflineDecode decode, void *user, bool counted) {
	RzPVector *refs = rz_pvector_new(free);
	if (!refs) {
		return NULL;
	}
	ReflineRange range = {
		.start = start,
		.size = limit,
		.max = analysis->maxreflines > 0 ? (size_t)analysis->maxreflines : SIZE_MAX,
		.linesout = linesout,
	};
	ut64 scanned = 0;
	bool ok = true;
	rz_interrupt_break_push(analysis->intr, NULL, NULL);
	if (counted && !linesout && analysis->maxreflines > 0) {
		// Resolve forward targets before spending the limited number of visible lines.
		ok = scan_refline_rows(analysis, &range, limit, nlines, linescall, decode, user, true, &range.size);
		limit = range.size;
	}
	range.refs = refs;
	ok = ok && scan_refline_rows(analysis, &range, limit, nlines, linescall, decode, user, counted, &scanned);
	rz_interrupt_break_pop(analysis->intr);
	ut64 size = counted && analysis->maxreflines <= 0 ? scanned : range.size;
	if (!ok || !refline_levels(refs, start, size, linesout)) {
		rz_pvector_free(refs);
		return NULL;
	}
	return refs;
}

typedef struct {
	RzAnalysis *analysis;
	ut64 start;
	const ut8 *buf;
	ut64 len;
} ReflineBuffer;

static int refline_buffer_op(void *user, ut64 addr, RzAnalysisOp *op) {
	ReflineBuffer *input = user;
	ut64 off = addr - input->start;
	rz_analysis_op(input->analysis, op, addr, input->buf + off,
		RZ_MIN(input->len - off, ST32_MAX), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
	return RZ_MAX(op->size, 1);
}

/**
 * \brief Collect jump, conditional branch and optional call lines in the supplied byte range.
 * \param nlines Maximum number of rows to scan, or -1 for the whole buffer.
 */
RZ_API RZ_OWN RzPVector /*<RzAnalysisRefline *>*/ *rz_analysis_reflines_get(RZ_NONNULL RzAnalysis *analysis, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len, int nlines, int linesout, int linescall) {
	rz_return_val_if_fail(analysis && buf, NULL);
	ReflineBuffer input = { analysis, addr, buf, len };
	return collect_reflines(analysis, addr, len, nlines, linesout, linescall, refline_buffer_op, &input, false);
}

/**
 * \brief Collect reference lines across \p nlines display rows, including metadata.
 * \param decode Supplies an instruction and its display size at each code address.
 * \param user Context passed to \p decode.
 */
RZ_API RZ_OWN RzPVector /*<RzAnalysisRefline *>*/ *rz_analysis_reflines_get_count(RZ_NONNULL RzAnalysis *analysis, ut64 addr, int nlines, bool linesout, bool linescall, RZ_NONNULL RzAnalysisReflineDecode decode, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(analysis && decode && nlines >= 0, NULL);
	return collect_reflines(analysis, addr, UT64_MAX, nlines, linesout, linescall, decode, user, true);
}

/**
 * Given a RzAnalysisRefline vector, this function check whether any refline's destination address falls inside
 * the range [ \p addr .. \p addr + \p len ].
 *
 * \param a RzAnalysis instance (currently not used).
 * \param reflines Vector of reflines.
 * \param addr Range start address.
 * \param len Range size.
 * \return true in case any refline's "to" address is in range, false otherwise.
 */
RZ_API bool rz_analysis_reflines_middle(RZ_NONNULL RzAnalysis *a, RZ_NONNULL const RzPVector /*<RzAnalysisRefline *>*/ *reflines, ut64 addr, int len) {
	rz_return_val_if_fail(a && reflines, false);

	void **iter;
	rz_pvector_foreach (reflines, iter) {
		RzAnalysisRefline *ref = *iter;
		if (RZ_BETWEEN_EXCL(ref->to, addr, addr + len)) {
			return true;
		}
	}
	return false;
}

static const char *get_corner_char(RzAnalysisRefline *ref, ut64 addr, bool is_middle_before) {
	if (ref->from == ref->to) {
		return "@";
	}
	if (addr == ref->to) {
		if (is_middle_before) {
			return (ref->from > ref->to) ? " " : "|";
		}
		return (ref->from > ref->to) ? "." : "`";
	}
	if (addr == ref->from) {
		if (is_middle_before) {
			return (ref->from > ref->to) ? "|" : " ";
		}
		return (ref->from > ref->to) ? "`" : ",";
	}
	return "";
}

static void add_spaces(RzBuffer *b, int level, int pos, bool wide) {
	if (pos != -1) {
		if (wide) {
			pos *= 2;
			level *= 2;
		}
		if (pos > level + 1) {
			char *pad = rz_str_pad(' ', pos - level - 1);
			rz_buf_append_string(b, pad);
			free(pad);
		}
	}
}

static void fill_level(RzBuffer *b, int pos, char ch, RzAnalysisRefline *r, bool wide) {
	int sz = r->level;
	if (wide) {
		sz *= 2;
	}
	char *pad = rz_str_pad(ch, sz - 1);
	if (pos == -1) {
		rz_buf_append_string(b, pad);
	} else {
		int pdlen = strlen(pad);
		if (pdlen > 0) {
			rz_buf_write_at(b, pos, (const ut8 *)pad, pdlen);
		}
	}
	free(pad);
}

static inline bool refline_kept(RzAnalysisRefline *ref, bool middle_after, ut64 addr) {
	if (middle_after) {
		if (ref->direction < 0) {
			if (ref->from == addr) {
				return false;
			}
		} else {
			if (ref->to == addr) {
				return false;
			}
		}
	}
	return true;
}

// TODO: move into another file
// TODO: this is TOO SLOW. do not iterate over all reflines
RZ_API RzAnalysisRefStr *rz_analysis_reflines_str(void *_core, ut64 addr, int opts) {
	RzCore *core = _core;
	RzAnalysis *analysis = core->analysis;
	RzBuffer *b;
	RzBuffer *c;
	RzListIter *iter;
	void **refline_iter;
	RzAnalysisRefline *ref;
	int l;
	bool wide = opts & RZ_ANALYSIS_REFLINE_TYPE_WIDE;
	int dir = 0, pos = -1, max_level = -1;
	bool middle_before = opts & RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_BEFORE;
	bool middle_after = opts & RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_AFTER;
	char *str = NULL;
	char *col_str = NULL;

	rz_return_val_if_fail(core->cons && analysis && analysis->reflines, NULL);

	/*
	 * Reflines whose level does not fit into the visible columns are not
	 * rendered at all: their vertical bars and corner characters always land
	 * outside of the visible (rightmost "lineswidth") columns, but the
	 * horizontal fills drawn for their corners are still written into the
	 * visible area, erasing the reflines that are actually visible. This
	 * results in stray full-width horizontal runs (the corner itself is
	 * truncated away), in visible vertical bars disappearing under those runs
	 * and in dangling bars on the "CODE XREF" comment lines that do not line
	 * up with the instruction below them (see issue #3568). Thus such
	 * reflines are skipped completely.
	 */
	int lw = analysis->lineswidth;
	int max_visible_level = wide ? (lw - 1) / 2 : lw;

	RzList *lvls = rz_list_new();
	if (!lvls) {
		return NULL;
	}
	rz_pvector_foreach (analysis->reflines, refline_iter) {
		ref = *refline_iter;
		if (core->cons && rz_interrupt_is_breaked(core->cons->intr)) {
			rz_list_free(lvls);
			return NULL;
		}
		if (lw > 0 && ref->level > max_visible_level) {
			continue;
		}
		if (in_refline(addr, ref) && refline_kept(ref, middle_after, addr)) {
			rz_list_add_sorted(lvls, (void *)ref, (RzListComparator)cmp_by_ref_lvl, NULL);
		}
	}
	b = rz_buf_new_with_bytes(NULL, 0);
	c = rz_buf_new_with_bytes(NULL, 0);
	rz_buf_append_string(c, " ");
	rz_buf_append_string(b, " ");
	rz_list_foreach (lvls, iter, ref) {
		if (core->cons && rz_interrupt_is_breaked(core->cons->intr)) {
			rz_list_free(lvls);
			rz_buf_free(b);
			rz_buf_free(c);
			return NULL;
		}
		if ((ref->from == addr || ref->to == addr) && !middle_after) {
			const char *corner = get_corner_char(ref, addr, middle_before);
			const char ch = ref->from == addr ? '=' : '-';
			const char ch_col = ref->from >= ref->to ? 't' : 'd';
			const char *col = (ref->from >= ref->to) ? "t" : "d";
			if (!pos) {
				int ch_pos = max_level + 1 - ref->level;
				if (wide) {
					ch_pos = ch_pos * 2 - 1;
				}
				rz_buf_write_at(b, ch_pos, (ut8 *)corner, 1);
				rz_buf_write_at(c, ch_pos, (ut8 *)col, 1);
				fill_level(b, ch_pos + 1, ch, ref, wide);
				fill_level(c, ch_pos + 1, ch_col, ref, wide);
			} else {
				add_spaces(b, ref->level, pos, wide);
				add_spaces(c, ref->level, pos, wide);
				rz_buf_append_string(b, corner);
				rz_buf_append_string(c, col);
				if (!middle_before) {
					fill_level(b, -1, ch, ref, wide);
					fill_level(c, -1, ch_col, ref, wide);
				}
			}
			if (!middle_before) {
				dir = ref->to == addr ? 1 : 2;
			}
			pos = middle_before ? ref->level : 0;
		} else {
			if (!pos) {
				continue;
			}
			add_spaces(b, ref->level, pos, wide);
			add_spaces(c, ref->level, pos, wide);
			if (ref->from >= ref->to) {
				rz_buf_append_string(b, ":");
				rz_buf_append_string(c, "t");
			} else {
				rz_buf_append_string(b, "|");
				rz_buf_append_string(c, "d");
			}
			pos = ref->level;
		}
		if (max_level == -1) {
			max_level = ref->level;
		}
	}
	add_spaces(c, 0, pos, wide);
	add_spaces(b, 0, pos, wide);
	str = rz_buf_to_string(b);
	col_str = rz_buf_to_string(c);
	rz_buf_free(b);
	rz_buf_free(c);
	b = NULL;
	c = NULL;
	if (!str || !col_str) {
		rz_list_free(lvls);
		// rz_buf_free_to_string already free b and if that is the case
		// b will be NULL and rz_buf_free will return but if there was
		// an error we free b here so in other words is safe
		rz_buf_free(b);
		rz_buf_free(c);
		return NULL;
	}
	if (core->analysis->lineswidth > 0) {
		int lw = core->analysis->lineswidth;
		l = strlen(str);
		if (l > lw) {
			rz_str_cpy(str, str + l - lw);
			rz_str_cpy(col_str, col_str + l - lw);
		} else {
			char pfx[128];
			lw -= l;
			memset(pfx, ' ', sizeof(pfx));
			if (lw >= sizeof(pfx)) {
				lw = sizeof(pfx) - 1;
			}
			if (lw > 0) {
				pfx[lw] = 0;
				str = rz_str_prepend(str, pfx);
				col_str = rz_str_prepend(col_str, pfx);
			}
		}
	}
	const char prev_col = col_str[strlen(col_str) - 1];
	const char *arr_col = prev_col == 't' ? "tt " : "dd ";
	str = rz_str_append(str, (dir == 1) ? "-> " : (dir == 2) ? "=< "
								 : "   ");
	col_str = rz_str_append(col_str, arr_col);

	rz_list_free(lvls);
	RzAnalysisRefStr *out = RZ_NEW0(RzAnalysisRefStr);
	out->str = str;
	out->cols = col_str;
	return out;
}

RZ_API void rz_analysis_reflines_str_free(RzAnalysisRefStr *refstr) {
	free(refstr->str);
	free(refstr->cols);
	free(refstr);
}
