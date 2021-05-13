// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>

#define Color_RANGE  Color_BBLUE
#define Color_INSERT Color_BGREEN
#define Color_DELETE Color_BRED

#define FAST_MOD2(x, y)    ((x) & (y - 1))
#define FAST_MOD64(x)      FAST_MOD2(x, 64)
#define DIFF_COLOR(prefix) (prefix == '+' ? Color_INSERT : (prefix == '-' ? Color_DELETE : ""))

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

	rz_strbuf_appendf(sb, "%s%c", color ? DIFF_COLOR(prefix) : "", prefix);
	for (st32 i = beg; i < end; ++i) {
		if (newline || (is_bytes && count > 0 && !FAST_MOD64(count))) {
			rz_strbuf_appendf(sb, "\n%c", prefix);
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
	rz_strbuf_appendf(sb, "%s\n", color ? (Color_RESET) : "");
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
		char *time = rz_time_to_string(rz_time_now());
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
			if (op->type == RZ_DIFF_OP_DELETE || op->type == RZ_DIFF_OP_REPLACE) {
				diff_unified_append_data(diff, diff->a, op->a_beg, op->a_end, sb, '-', color);
			}
			if (op->type == RZ_DIFF_OP_INSERT || op->type == RZ_DIFF_OP_REPLACE) {
				diff_unified_append_data(diff, diff->b, op->b_beg, op->b_end, sb, '+', color);
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
		char *time = rz_time_to_string(rz_time_now());
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
