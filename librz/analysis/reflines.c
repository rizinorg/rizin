// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>
#include <rz_cons.h>

#define mid_down_refline(a, r) ((r)->from > (r)->to && (a) < (r)->from && (a) > (r)->to)
#define mid_up_refline(a, r)   ((r)->from < (r)->to && (a) > (r)->from && (a) < (r)->to)
#define mid_refline(a, r)      (mid_down_refline(a, r) || mid_up_refline(a, r))
#define in_refline(a, r)       (mid_refline(a, r) || (a) == (r)->from || (a) == (r)->to)

typedef struct refline_end {
	int val;
	bool is_from;
	RzAnalysisRefline *r;
} ReflineEnd;

static int cmp_asc(const struct refline_end *a, const struct refline_end *b) {
	return (a->val > b->val) - (a->val < b->val);
}

static int cmp_by_ref_lvl(const RzAnalysisRefline *a, const RzAnalysisRefline *b) {
	return (a->level < b->level) - (a->level > b->level);
}

static ReflineEnd *refline_end_new(ut64 val, bool is_from, RzAnalysisRefline *ref) {
	ReflineEnd *re = RZ_NEW0(struct refline_end);
	if (!re) {
		return NULL;
	}
	re->val = val;
	re->is_from = is_from;
	re->r = ref;
	return re;
}

static bool add_refline(RzList *list, RzList *sten, ut64 addr, ut64 to, int *idx) {
	ReflineEnd *re1, *re2;
	RzAnalysisRefline *item = RZ_NEW0(RzAnalysisRefline);
	if (!item) {
		return false;
	}
	item->from = addr;
	item->to = to;
	item->index = *idx;
	item->level = -1;
	item->direction = (to > addr) ? 1 : -1;
	*idx += 1;
	rz_list_append(list, item);

	re1 = refline_end_new(item->from, true, item);
	if (!re1) {
		free(item);
		return false;
	}
	rz_list_add_sorted(sten, re1, (RzListComparator)cmp_asc);

	re2 = refline_end_new(item->to, false, item);
	if (!re2) {
		free(re1);
		free(item);
		return false;
	}
	rz_list_add_sorted(sten, re2, (RzListComparator)cmp_asc);
	return true;
}

RZ_API void rz_analysis_reflines_free(RzAnalysisRefline *rl) {
	free(rl);
}

/* returns a list of RzAnalysisRefline for the code present in the buffer buf, of
 * length len. A RzAnalysisRefline exists from address A to address B if a jmp,
 * conditional jmp or call instruction exists at address A and it targets
 * address B.
 *
 * nlines - max number of lines of code to consider
 * linesout - true if you want to display lines that go outside of the scope [addr;addr+len)
 * linescall - true if you want to display call lines */
RZ_API RzList *rz_analysis_reflines_get(RzAnalysis *analysis, ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall) {
	RzList *list, *sten;
	RzListIter *iter;
	RzAnalysisOp op;
	struct refline_end *el;
	const ut8 *ptr = buf;
	const ut8 *end = buf + len;
	ut8 *free_levels;
	int sz = 0, count = 0;
	ut64 opc = addr;

	memset(&op, 0, sizeof(op));
	/*
	 * 1) find all reflines
	 * 2) sort "from"s and "to"s in a list
	 * 3) traverse the list to find the minimum available level for each refline
	 *      * create a sorted list with available levels.
	 *      * when we encounter a previously unseen "from" or "to" of a
	 *        refline, we occupy the lowest level available for it.
	 *      * when we encounter the "from" or "to" of an already seen
	 *        refline, we free that level.
	 */

	list = rz_list_newf(free);
	if (!list) {
		return NULL;
	}
	sten = rz_list_newf((RzListFree)free);
	if (!sten) {
		goto list_err;
	}
	rz_cons_break_push(NULL, NULL);
	/* analyze code block */
	while (ptr < end && !rz_cons_is_breaked()) {
		if (nlines != -1) {
			if (!nlines) {
				break;
			}
			nlines--;
		}
		if (analysis->maxreflines && count > analysis->maxreflines) {
			break;
		}
		addr += sz;
		{
			RzPVector *metas = rz_meta_get_all_at(analysis, addr);
			if (metas) {
				void **it;
				ut64 skip = 0;
				rz_pvector_foreach (metas, it) {
					RzIntervalNode *node = *it;
					RzAnalysisMetaItem *meta = node->data;
					switch (meta->type) {
					case RZ_META_TYPE_DATA:
					case RZ_META_TYPE_STRING:
					case RZ_META_TYPE_HIDE:
					case RZ_META_TYPE_FORMAT:
					case RZ_META_TYPE_MAGIC:
						skip = rz_meta_node_size(node);
						goto do_skip;
					default:
						break;
					}
				}
			do_skip:
				rz_pvector_free(metas);
				if (skip) {
					ptr += skip;
					addr += skip;
					goto __next;
				}
			}
		}
		if (!analysis->iob.is_valid_offset(analysis->iob.io, addr, RZ_PERM_X)) {
			const int size = 4;
			ptr += size;
			addr += size;
			goto __next;
		}

		// This can segfault if opcode length and buffer check fails
		rz_analysis_op_fini(&op);
		rz_analysis_op(analysis, &op, addr, ptr, (int)(end - ptr), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
		sz = op.size;
		if (sz <= 0) {
			sz = 1;
			goto __next;
		}

		/* store data */
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_CALL:
			if (!linescall) {
				break;
			}
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_JMP:
			if ((!linesout && (op.jump > opc + len || op.jump < opc)) || !op.jump) {
				break;
			}
			if (!add_refline(list, sten, addr, op.jump, &count)) {
				rz_analysis_op_fini(&op);
				goto sten_err;
			}
			// add false branch in case its set and its not a call, useful for bf, maybe others
			if (!op.delay && op.fail != UT64_MAX && op.fail != addr + op.size) {
				if (!add_refline(list, sten, addr, op.fail, &count)) {
					rz_analysis_op_fini(&op);
					goto sten_err;
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_SWITCH: {
			RzAnalysisCaseOp *caseop;
			RzListIter *iter;

			// add caseops
			if (!op.switch_op) {
				break;
			}
			rz_list_foreach (op.switch_op->cases, iter, caseop) {
				if (!linesout && (op.jump > opc + len || op.jump < opc)) {
					goto __next;
				}
				if (!add_refline(list, sten, op.switch_op->addr, caseop->jump, &count)) {
					rz_analysis_op_fini(&op);
					goto sten_err;
				}
			}
			break;
		}
		}
	__next:
		ptr += sz;
	}
	rz_analysis_op_fini(&op);
	rz_cons_break_pop();

	free_levels = RZ_NEWS0(ut8, rz_list_length(list) + 1);
	if (!free_levels) {
		goto sten_err;
	}
	int min = 0;

	rz_list_foreach (sten, iter, el) {
		if ((el->is_from && el->r->level == -1) || (!el->is_from && el->r->level == -1)) {
			el->r->level = min + 1;
			free_levels[min] = 1;
			if (min < 0) {
				min = 0;
			}
			while (free_levels[++min] == 1) {
				;
			}
		} else {
			free_levels[el->r->level - 1] = 0;
			if (min > el->r->level - 1) {
				min = el->r->level - 1;
			}
		}
	}

	/* XXX: the algorithm can be improved. We can calculate the set of
	 * reflines used in each interval of addresses and store them.
	 * Considering rz_analysis_reflines_str is always called with increasing
	 * addresses, we can just traverse linearly the list of intervals to
	 * know which reflines need to be drawn for each address. In this way,
	 * we don't need to traverse again and again the reflines for each call
	 * to rz_analysis_reflines_str, but we can reuse the data already
	 * calculated. Those data will be quickly available because the
	 * intervals will be sorted and the addresses to consider are always
	 * increasing. */
	free(free_levels);
	rz_list_free(sten);
	return list;

sten_err:
list_err:
	rz_list_free(sten);
	rz_list_free(list);
	return NULL;
}

RZ_API int rz_analysis_reflines_middle(RzAnalysis *a, RzList * /*<RzAnalysisRefline>*/ list, ut64 addr, int len) {
	if (a && list) {
		RzAnalysisRefline *ref;
		RzListIter *iter;
		rz_list_foreach (list, iter, ref) {
			if ((ref->to > addr) && (ref->to < addr + len)) {
				return true;
			}
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
			const char *pd = rz_str_pad(' ', pos - level - 1);
			rz_buf_append_string(b, pd);
		}
	}
}

static void fill_level(RzBuffer *b, int pos, char ch, RzAnalysisRefline *r, bool wide) {
	int sz = r->level;
	if (wide) {
		sz *= 2;
	}
	const char *pd = rz_str_pad(ch, sz - 1);
	if (pos == -1) {
		rz_buf_append_string(b, pd);
	} else {
		int pdlen = strlen(pd);
		if (pdlen > 0) {
			rz_buf_write_at(b, pos, (const ut8 *)pd, pdlen);
		}
	}
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
	RzCons *cons = core->cons;
	RzAnalysis *analysis = core->analysis;
	RzBuffer *b;
	RzBuffer *c;
	RzListIter *iter;
	RzAnalysisRefline *ref;
	int l;
	bool wide = opts & RZ_ANALYSIS_REFLINE_TYPE_WIDE;
	int dir = 0, pos = -1, max_level = -1;
	bool middle_before = opts & RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_BEFORE;
	bool middle_after = opts & RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_AFTER;
	char *str = NULL;
	char *col_str = NULL;

	rz_return_val_if_fail(cons && analysis && analysis->reflines, NULL);

	RzList *lvls = rz_list_new();
	if (!lvls) {
		return NULL;
	}
	rz_list_foreach (analysis->reflines, iter, ref) {
		if (core->cons && core->cons->context->breaked) {
			rz_list_free(lvls);
			return NULL;
		}
		if (in_refline(addr, ref) && refline_kept(ref, middle_after, addr)) {
			rz_list_add_sorted(lvls, (void *)ref, (RzListComparator)cmp_by_ref_lvl);
		}
	}
	b = rz_buf_new();
	c = rz_buf_new();
	rz_buf_append_string(c, " ");
	rz_buf_append_string(b, " ");
	rz_list_foreach (lvls, iter, ref) {
		if (core->cons && core->cons->context->breaked) {
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
		//rz_buf_free_to_string already free b and if that is the case
		//b will be NULL and rz_buf_free will return but if there was
		//an error we free b here so in other words is safe
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
