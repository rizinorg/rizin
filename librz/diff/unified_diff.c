// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>

#define Color_RANGE    Color_BBLUE
#define Color_INSERT   Color_BGREEN
#define Color_DELETE   Color_BRED
#define Color_BGINSERT "\x1b[48;5;22m"
#define Color_BGDELETE "\x1b[48;5;52m"

#define FAST_MOD2(x, y)      ((x) & (y - 1))
#define FAST_MOD64(x)        FAST_MOD2(x, 64)
#define DIFF_COLOR(prefix)   (prefix == '+' ? Color_INSERT : (prefix == '-' ? Color_DELETE : ""))
#define DIFF_BGCOLOR(prefix) (prefix == '+' ? Color_BGINSERT : (prefix == '-' ? Color_BGDELETE : ""))

static inline ut32 count_newlines(RzDiff *diff, const void *array, st32 beg, st32 end) {
	RzDiffMethodElemAt elem_at = diff->methods.elem_at;
	RzDiffMethodStringify stringify = diff->methods.stringify;
	int len = 0;
	ut32 count = 0;
	const char *p;
	const void *elem;
	RzStrBuf tmp;

	for (st32 i = beg; i < end; ++i) {
		rz_strbuf_init(&tmp);
		elem = elem_at(array, i);
		stringify(elem, &tmp);
		len = rz_strbuf_length(&tmp);
		p = rz_strbuf_get(&tmp);
		if (len > 0 && p[len - 1] == '\n') {
			count++;
		}
		rz_strbuf_fini(&tmp);
	}
	return count;
}

static inline void diff_unified_append_ranges(RzList *opcodes, RzStrBuf *sb, bool color) {
	const char *color_beg = color ? Color_RANGE : "";
	const char *color_end = color ? Color_RESET : "";

	RzDiffOp *first = rz_list_first(opcodes);
	RzDiffOp *last = rz_list_last(opcodes);
	st32 a_len = last->a_end - first->a_beg;
	st32 b_len = last->b_end - first->b_beg;

	rz_strbuf_appendf(sb, "%s@@ -%d,%d +%d,%d @@%s\n", color_beg, first->a_beg + 1, a_len, first->b_beg + 1, b_len, color_end);
}

static inline void diff_unified_json_ranges(RzList *opcodes, PJ *pj) {
	RzDiffOp *first = rz_list_first(opcodes);
	RzDiffOp *last = rz_list_last(opcodes);
	st32 a_len = last->a_end - first->a_beg;
	st32 b_len = last->b_end - first->b_beg;

	pj_ka(pj, "from");
	pj_N(pj, first->a_beg + 1);
	pj_N(pj, a_len);
	pj_end(pj);

	pj_ka(pj, "to");
	pj_N(pj, first->b_beg + 1);
	pj_N(pj, b_len);
	pj_end(pj);
}

static inline void diff_unified_append_data(RzDiff *diff, const void *array, st32 beg, st32 end, RzStrBuf *sb, char prefix, bool color) {
	RzDiffMethodElemAt elem_at = diff->methods.elem_at;
	RzDiffMethodStringify stringify = diff->methods.stringify;
	int len = 0;
	ut32 count = 0;
	const char *p;
	const void *elem;
	RzStrBuf tmp;
	bool newline = false;
	bool is_bytes = DIFF_IS_BYTES_METHOD(diff->methods);

	if (beg < 0) {
		beg = 0;
	}

	const char *bcol = color ? DIFF_COLOR(prefix) : "";
	const char *ecol = color ? (Color_RESET) : "";

	rz_strbuf_appendf(sb, "%s%c", bcol, prefix);
	for (st32 i = beg; i < end; ++i) {
		if (newline || (is_bytes && count > 0 && !FAST_MOD64(count))) {
			rz_strbuf_appendf(sb, "%s\n%s%c", ecol, bcol, prefix);
			newline = false;
		}
		rz_strbuf_init(&tmp);
		elem = elem_at(array, i);
		stringify(elem, &tmp);
		len = rz_strbuf_length(&tmp);
		p = rz_strbuf_get(&tmp);
		count += len;
		if (len > 0 && p[len - 1] == '\n') {
			len--;
			newline = true;
		}
		rz_strbuf_append_n(sb, p, len);
		rz_strbuf_fini(&tmp);
	}
	rz_strbuf_appendf(sb, "%s\n", ecol);
}

// Assumes that color is true, diffing lines, op->type is RZ_DIFF_OP_REPLACE
// and that the number of inserted lines is equal to the number of deleted
// lines.
static inline void diff_unified_lines_hl(RzDiff *diff, RzDiffOp *op, RzStrBuf *sb, char del_prefix, char ins_prefix) {
	RzDiffMethodElemAt elem_at = diff->methods.elem_at;
	RzDiffMethodStringify stringify = diff->methods.stringify;
	int len = 0;
	const char *p;
	const void *elem;
	RzStrBuf tmp, tmp2;
	const char *ecol = Color_RESET;
	const char *ebgcol = Color_RESET_BG;

	const void *a_array = diff->a;
	st32 a_beg = op->a_beg;
	if (a_beg < 0) {
		a_beg = 0;
	}
	st32 a_end = op->a_end;

	const void *b_array = diff->b;
	st32 b_beg = op->b_beg;
	if (b_beg < 0) {
		b_beg = 0;
	}
	st32 b_end = op->b_end;

	ut32 num_nl = count_newlines(diff, a_array, a_beg, a_end);
	// + 1 just in case there's no nl at end
	ut32 num_bounds = num_nl + 1;
	st32 *char_bounds = malloc(sizeof(st32) * 2 * num_bounds);
	if (!char_bounds) {
		return;
	}
	for (ut32 i = 0; i < num_bounds; i++) {
		char_bounds[i * 2] = char_bounds[i * 2 + 1] = -1;
	}

	// Fill char_bounds array
	ut32 bounds_idx = 0;
	ut32 count = 0;
	ut32 count_b = 0;
	bool newline = false;
	st32 i = a_beg;
	st32 j = b_beg;
	for (; i < a_end; ++i) {
		if (newline) {
			bounds_idx++;
			newline = false;
		}
		rz_strbuf_init(&tmp);
		elem = elem_at(a_array, i);
		stringify(elem, &tmp);
		len = rz_strbuf_length(&tmp);
		p = rz_strbuf_get(&tmp);
		count += len;
		if (len > 0 && p[len - 1] == '\n') {
			len--;
			newline = true;
		}

		int len_b = 0;
		const void *elem_b;
		const char *p_b;

		for (; j < b_end; ++j) {
			rz_strbuf_init(&tmp2);
			elem_b = elem_at(b_array, j);
			stringify(elem_b, &tmp2);
			len_b = rz_strbuf_length(&tmp2);
			p_b = rz_strbuf_get(&tmp2);
			count_b += len_b;
			if (len_b > 0 && p_b[len_b - 1] == '\n') {
				len_b--;
			}

			if (len && len_b && (p[0] == p_b[0] || p[len - 1] == p_b[len_b - 1])) {
				// Get left bound.
				st32 left = 0;
				for (; left < R_MIN(len, len_b) && p[left] == p_b[left]; left++)
					;
				char_bounds[bounds_idx * 2] = left;
				// Get right bound (offset). "- left" chops off
				// the left portion that has already matched.
				st32 right = 0;
				for (; right < R_MIN(len, len_b) - left && p[len - 1 - right] == p_b[len_b - 1 - right];
					right++)
					;
				char_bounds[bounds_idx * 2 + 1] = right;
			}

			rz_strbuf_fini(&tmp2);
			++j;
			break;
		}
		rz_strbuf_fini(&tmp);
	}

	// Show deleted lines
	char prefix = del_prefix;
	const char *bcol = DIFF_COLOR(prefix);
	const char *bbgcol = DIFF_BGCOLOR(prefix);
	count = 0;
	newline = false;
	bounds_idx = 0;

	rz_strbuf_appendf(sb, "%s%c", bcol, prefix);
	for (st32 i = a_beg; i < a_end; ++i) {
		if (newline) {
			rz_strbuf_appendf(sb, "%s\n%s%c", ecol, bcol, prefix);
			newline = false;
			bounds_idx++;
		}
		rz_strbuf_init(&tmp);
		elem = elem_at(a_array, i);
		stringify(elem, &tmp);
		len = rz_strbuf_length(&tmp);
		p = rz_strbuf_get(&tmp);
		count += len;
		if (len > 0 && p[len - 1] == '\n') {
			len--;
			newline = true;
		}
		st32 left = char_bounds[bounds_idx * 2];
		st32 right = char_bounds[bounds_idx * 2 + 1];
		if (left < 0 || right < 0 || len - right < left) {
			rz_strbuf_append_n(sb, p, len);
		} else {
			rz_strbuf_append_n(sb, p, left);
			rz_strbuf_append(sb, bbgcol);
			rz_strbuf_append_n(sb, p + left, len - right - left);
			rz_strbuf_append(sb, ebgcol);
			rz_strbuf_append_n(sb, p + len - right, right);
		}
		rz_strbuf_fini(&tmp);
	}
	rz_strbuf_appendf(sb, "%s\n", ecol);

	// Show inserted lines
	prefix = ins_prefix;
	bcol = DIFF_COLOR(prefix);
	bbgcol = DIFF_BGCOLOR(prefix);
	count = 0;
	newline = false;
	bounds_idx = 0;

	rz_strbuf_appendf(sb, "%s%c", bcol, prefix);
	for (st32 i = b_beg; i < b_end; ++i) {
		if (newline) {
			rz_strbuf_appendf(sb, "%s\n%s%c", ecol, bcol, prefix);
			newline = false;
			bounds_idx++;
		}
		rz_strbuf_init(&tmp);
		elem = elem_at(b_array, i);
		stringify(elem, &tmp);
		len = rz_strbuf_length(&tmp);
		p = rz_strbuf_get(&tmp);
		count += len;
		if (len > 0 && p[len - 1] == '\n') {
			len--;
			newline = true;
		}
		st32 left = char_bounds[bounds_idx * 2];
		st32 right = char_bounds[bounds_idx * 2 + 1];
		if (left < 0 || right < 0 || len - right < left) {
			rz_strbuf_append_n(sb, p, len);
		} else {
			rz_strbuf_append_n(sb, p, left);
			rz_strbuf_append(sb, bbgcol);
			rz_strbuf_append_n(sb, p + left, len - right - left);
			rz_strbuf_append(sb, ebgcol);
			rz_strbuf_append_n(sb, p + len - right, right);
		}
		rz_strbuf_fini(&tmp);
	}
	rz_strbuf_appendf(sb, "%s\n", ecol);
	free(char_bounds);
}

static inline void diff_unified_json_data(RzDiff *diff, const void *array, st32 beg, st32 end, PJ *pj, const char *op) {
	RzDiffMethodElemAt elem_at = diff->methods.elem_at;
	RzDiffMethodStringify stringify = diff->methods.stringify;
	int len = 0;
	ut32 count = 0;
	const char *p;
	const void *elem;
	RzStrBuf tmp;
	bool newline = false;
	bool is_bytes = DIFF_IS_BYTES_METHOD(diff->methods);

	if (beg < 0) {
		beg = 0;
	}

	pj_o(pj);
	pj_ks(pj, "op", op);
	rz_strbuf_init(&tmp);
	for (st32 i = beg; i < end; ++i) {
		if (newline || (is_bytes && count > 0 && !FAST_MOD64(count))) {
			pj_ks(pj, "value", rz_strbuf_get(&tmp));
			pj_end(pj);

			rz_strbuf_fini(&tmp);
			rz_strbuf_init(&tmp);

			pj_o(pj);
			pj_ks(pj, "op", op);
			newline = false;
		}
		elem = elem_at(array, i);
		stringify(elem, &tmp);
		len = rz_strbuf_length(&tmp);
		p = rz_strbuf_get(&tmp);
		count += len;
		if (len > 0 && p[len - 1] == '\n') {
			newline = true;
		}
	}
	pj_ks(pj, "value", rz_strbuf_get(&tmp));
	pj_end(pj);
	rz_strbuf_fini(&tmp);
}

/**
 * \brief Produces a diff output with A and B inputs presented immediately adjacent to each other.
 *
 * Produces a diff output with A and B inputs presented immediately adjacent to each other.
 * It begins with range information and is immediately followed with the line additions,
 * line deletions, and any number of the contextual lines.
 * */
RZ_API RZ_OWN char *rz_diff_unified_text(RZ_NONNULL RzDiff *diff, RZ_NULLABLE const char *from, RZ_NULLABLE const char *to, bool show_time, bool color) {
	rz_return_val_if_fail(diff && diff->methods.elem_at && diff->methods.stringify, NULL);
	RzStrBuf *sb = NULL;
	RzList *groups = NULL;
	RzList *opcodes = NULL;
	RzDiffOp *op = NULL;
	RzListIter *itg = NULL;
	RzListIter *ito = NULL;

	if (!from) {
		from = "/original";
	}
	if (!to) {
		to = "/modified";
	}
	sb = rz_strbuf_new("");
	if (!sb) {
		RZ_LOG_ERROR("rz_diff_unified: cannot allocate sb\n");
		goto rz_diff_unified_text_fail;
	}

	if (show_time) {
		char *time = rz_time_date_now_to_string();
		rz_strbuf_appendf(sb, "--- %s %s\n+++ %s %s\n", from, (time ? time : ""), to, (time ? time : ""));
		free(time);
	} else {
		rz_strbuf_appendf(sb, "--- %s\n+++ %s\n", from, to);
	}

	groups = rz_diff_opcodes_grouped_new(diff, RZ_DIFF_DEFAULT_N_GROUPS);
	if (!groups) {
		goto rz_diff_unified_text_fail;
	}

	rz_list_foreach (groups, itg, opcodes) {
		if (rz_list_length(opcodes) < 1) {
			continue;
		}
		diff_unified_append_ranges(opcodes, sb, color);
		rz_list_foreach (opcodes, ito, op) {
			if (op->type == RZ_DIFF_OP_EQUAL) {
				diff_unified_append_data(diff, diff->a, op->a_beg, op->a_end, sb, ' ', color);
				continue;
			}
			if (op->type == RZ_DIFF_OP_DELETE) {
				diff_unified_append_data(diff, diff->a, op->a_beg, op->a_end, sb, '-', color);
			} else if (op->type == RZ_DIFF_OP_INSERT) {
				diff_unified_append_data(diff, diff->b, op->b_beg, op->b_end, sb, '+', color);
			} else if (op->type == RZ_DIFF_OP_REPLACE) {
				if (!color || !DIFF_IS_LINES_METHOD(diff->methods) ||
					count_newlines(diff, diff->a, op->a_beg, op->a_end) !=
						count_newlines(diff, diff->b, op->b_beg, op->b_end)) {
					diff_unified_append_data(diff, diff->a, op->a_beg, op->a_end, sb, '-', color);
					diff_unified_append_data(diff, diff->b, op->b_beg, op->b_end, sb, '+', color);
				} else {
					diff_unified_lines_hl(diff, op, sb, '-', '+');
				}
			}
		}
	}

	rz_list_free(groups);
	return rz_strbuf_drain(sb);

rz_diff_unified_text_fail:
	rz_strbuf_free(sb);
	rz_list_free(groups);
	return NULL;
}

/**
 * \brief Produces a diff output to convert A in B in a JSON format.
 *
 * Produces a diff output with A and B inputs and contains the operations required
 * to convert A in B and the values to remove, insert or keep.
 * */
RZ_API RZ_OWN PJ *rz_diff_unified_json(RZ_NONNULL RzDiff *diff, RZ_NULLABLE const char *from, RZ_NULLABLE const char *to, bool show_time) {
	rz_return_val_if_fail(diff && diff->methods.elem_at && diff->methods.stringify, NULL);
	PJ *pj = NULL;
	RzList *groups = NULL;
	RzList *opcodes = NULL;
	RzDiffOp *op = NULL;
	RzListIter *itg = NULL;
	RzListIter *ito = NULL;

	if (!from) {
		from = "/original";
	}
	if (!to) {
		to = "/modified";
	}

	pj = pj_new();
	if (!pj) {
		RZ_LOG_ERROR("rz_diff_unified: failed to allocate json\n");
		goto rz_diff_unified_json_fail;
	}
	pj_o(pj);

	if (show_time) {
		char *time = rz_time_date_now_to_string();
		if (!time) {
			RZ_LOG_ERROR("rz_diff_unified: failed to allocate timestamp\n");
			goto rz_diff_unified_json_fail;
		}
		pj_ks(pj, "timestamp", time);
		free(time);
	}

	pj_ks(pj, "from", from);
	pj_ks(pj, "to", to);

	groups = rz_diff_opcodes_grouped_new(diff, RZ_DIFF_DEFAULT_N_GROUPS);
	if (!groups) {
		goto rz_diff_unified_json_fail;
	}

	pj_ka(pj, "diff");
	rz_list_foreach (groups, itg, opcodes) {
		if (rz_list_length(opcodes) < 1) {
			continue;
		}
		pj_o(pj);
		diff_unified_json_ranges(opcodes, pj);
		pj_ka(pj, "ops");
		rz_list_foreach (opcodes, ito, op) {
			if (op->type == RZ_DIFF_OP_EQUAL) {
				diff_unified_json_data(diff, diff->a, op->a_beg, op->a_end, pj, "equal");
				continue;
			}
			if (op->type == RZ_DIFF_OP_DELETE || op->type == RZ_DIFF_OP_REPLACE) {
				diff_unified_json_data(diff, diff->a, op->a_beg, op->a_end, pj, "delete");
			}
			if (op->type == RZ_DIFF_OP_INSERT || op->type == RZ_DIFF_OP_REPLACE) {
				diff_unified_json_data(diff, diff->b, op->b_beg, op->b_end, pj, "insert");
			}
		}
		pj_end(pj);
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);

	rz_list_free(groups);
	return pj;

rz_diff_unified_json_fail:
	pj_free(pj);
	rz_list_free(groups);
	return NULL;
}
