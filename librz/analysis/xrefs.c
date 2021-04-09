// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 defragger <rlaemmert@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_cons.h>

#if 0
DICT
====

refs 10->20 C 16->10 J 20->10 C

	xrefs 20->[10 C] 10 -> [16 J, 20 C]

	10 : call 20 16 : jmp 10 20 : call 10
#endif

// XXX: is it possible to have multiple type for the same (from, to) pair?
//      if it is, things need to be adjusted

static RzAnalysisXRef *rz_analysis_xref_new(ut64 from, ut64 to, ut64 type) {
	RzAnalysisXRef *xref = RZ_NEW(RzAnalysisXRef);
	if (xref) {
		xref->from = from;
		xref->to = to;
		xref->type = (type == -1) ? RZ_ANALYSIS_REF_TYPE_CODE : type;
	}
	return xref;
}

static void rz_analysis_xref_free(RzAnalysisXRef *xref) {
	free(xref);
}

RZ_API RzList *rz_analysis_xref_list_new() {
	return rz_list_newf((RzListFree)free);
}

static void xrefs_l1_free_kv(HtUPKv *kv) {
	ht_up_free(kv->value);
}

static void xrefs_l2_free_kv(HtUPKv *kv) {
	rz_analysis_xref_free(kv->value);
}

static bool set_xref(HtUP *l1, RzAnalysisXRef *xref, bool from2to) {
	ut64 key1 = from2to ? xref->from : xref->to;
	HtUP *l2 = ht_up_find(l1, key1, NULL);
	if (!l2) {
		// RzAnalysis::ht_xrefs_to is responsible for releasing of pointers.
		HtUPKvFreeFunc cb = from2to ? NULL : xrefs_l2_free_kv;
		l2 = ht_up_new(NULL, cb, NULL);
		if (!l2) {
			return false;
		}
		if (!ht_up_insert(l1, key1, l2)) {
			return false;
		}
	}
	ut64 key2 = from2to ? xref->to : xref->from;
	return ht_up_update(l2, key2, xref);
}

// Set a cross reference from FROM to TO.
RZ_API bool rz_analysis_xrefs_set(RzAnalysis *analysis, ut64 from, ut64 to, RzAnalysisXRefType type) {
	if (!analysis || from == to) {
		return false;
	}
	if (analysis->iob.is_valid_offset) {
		if (!analysis->iob.is_valid_offset(analysis->iob.io, from, 0)) {
			return false;
		}
		if (!analysis->iob.is_valid_offset(analysis->iob.io, to, 0)) {
			return false;
		}
	}
	RzAnalysisXRef *xref = rz_analysis_xref_new(from, to, type);
	if (!xref) {
		return false;
	}
	if (!set_xref(analysis->ht_xrefs_from, xref, true)) {
		// Pointer isn't added to <ht_xrefs_from> so we have to release it
		rz_analysis_xref_free(xref);
		return false;
	}
	if (!set_xref(analysis->ht_xrefs_to, xref, false)) {
		// Delete the entry in <ht_xrefs_from>
		rz_analysis_xrefs_deln(analysis, from, to, type);
		// Pointer isn't added to <ht_xrefs_to> so we have to release it
		rz_analysis_xref_free(xref);
		return false;
	}
	return true;
}

RZ_API bool rz_analysis_xrefs_deln(RzAnalysis *analysis, ut64 from, ut64 to, RzAnalysisXRefType type) {
	if (!analysis) {
		return false;
	}
	HtUP *ht1 = ht_up_find(analysis->ht_xrefs_from, from, NULL);
	if (ht1) {
		ht_up_delete(ht1, to);
	}
	HtUP *ht2 = ht_up_find(analysis->ht_xrefs_to, to, NULL);
	if (ht2) {
		ht_up_delete(ht2, from);
	}
	return true;
}

RZ_API bool rz_analysis_xref_del(RzAnalysis *analysis, ut64 from, ut64 to) {
	bool res = false;
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_REF_TYPE_NULL);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_REF_TYPE_CODE);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_REF_TYPE_CALL);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_REF_TYPE_DATA);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_REF_TYPE_STRING);
	return res;
}

typedef struct xrefs_foreach_ctx {
	RzAnalysisXRefCb cb;
	void *user;
	bool stop;
} xrefs_foreach_ctx_t;

static bool l2_item_cb(xrefs_foreach_ctx_t *ctx, RZ_UNUSED ut64 addr, RzAnalysisXRef *xref) {
	ctx->stop = !ctx->cb(xref, ctx->user);
	return !ctx->stop;
}

static bool l1_item_cb(xrefs_foreach_ctx_t *ctx, RZ_UNUSED ut64 addr, HtUP *l2) {
	ht_up_foreach(l2, (HtUPForeachCallback)l2_item_cb, ctx);
	return !ctx->stop;
}

RZ_API void rz_analysis_xrefs_foreach(RzAnalysis *analysis, RzAnalysisXRefCb cb, void *user) {
	rz_return_if_fail(analysis && cb);
	xrefs_foreach_ctx_t ctx = {
		.cb = cb,
		.user = user,
		.stop = false
	};
	ht_up_foreach(analysis->ht_xrefs_from, (HtUPForeachCallback)l1_item_cb, &ctx);
}

void l1_item_foreach(HtUP *l1, ut64 addr, RzAnalysisXRefCb cb, void *user) {
	xrefs_foreach_ctx_t ctx = {
		.cb = cb,
		.user = user,
		.stop = false
	};
	HtUP *l2 = ht_up_find(l1, addr, NULL);
	if (l2) {
		ht_up_foreach(l2, (HtUPForeachCallback)l2_item_cb, &ctx);
	}
}

RZ_API void rz_analysis_xrefs_to_foreach(RzAnalysis *analysis, ut64 addr, RzAnalysisXRefCb cb, void *user) {
	rz_return_if_fail(analysis && cb);
	l1_item_foreach(analysis->ht_xrefs_to, addr, cb, user);
}

RZ_API void rz_analysis_xrefs_from_foreach(RzAnalysis *analysis, ut64 addr, RzAnalysisXRefCb cb, void *user) {
	rz_return_if_fail(analysis && cb);
	l1_item_foreach(analysis->ht_xrefs_from, addr, cb, user);
}

static int xref_cmp(const RzAnalysisXRef *a, const RzAnalysisXRef *b) {
	if (a->from < b->from) {
		return -1;
	}
	if (a->from > b->from) {
		return 1;
	}
	if (a->to < b->to) {
		return -1;
	}
	if (a->to > b->to) {
		return 1;
	}
	return 0;
}

static void xrefs_list_sort(RzList *list) {
	rz_list_sort(list, (RzListComparator)xref_cmp);
}

static bool xrefs_list_append(RzAnalysisXRef *xref, void *user) {
	RzList *list = (RzList *)user;
	RzAnalysisXRef *cloned = rz_analysis_xref_new(xref->from, xref->to, xref->type);
	if (cloned) {
		rz_list_append(list, cloned);
		return true;
	}
	return false;
}

static RzList *xrefs_list_addr(HtUP *l1, ut64 addr) {
	RzList *list = rz_analysis_xref_list_new();
	if (!list) {
		return NULL;
	}
	l1_item_foreach(l1, addr, xrefs_list_append, list);
	xrefs_list_sort(list);
	if (rz_list_empty(list)) {
		rz_list_free(list);
		list = NULL;
	}
	return list;
}

RZ_API RzList *rz_analysis_xrefs_get_to(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	return xrefs_list_addr(analysis->ht_xrefs_to, addr);
}

RZ_API RzList *rz_analysis_xrefs_get_from(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	return xrefs_list_addr(analysis->ht_xrefs_from, addr);
}

RZ_API void rz_analysis_xrefs_list(RzAnalysis *analysis, int rad) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	PJ *pj = NULL;
	RzList *list = rz_analysis_xref_list_new();
	if (!list) {
		return;
	}
	rz_analysis_xrefs_foreach(analysis, xrefs_list_append, list);
	xrefs_list_sort(list);
	if (rad == 'j') {
		pj = analysis->coreb.pjWithEncoding(analysis->coreb.core);
		if (!pj) {
			return;
		}
		pj_a(pj);
	}
	rz_list_foreach (list, iter, xref) {
		int t = xref->type ? xref->type : ' ';
		switch (rad) {
		case '*':
			analysis->cb_printf("ax%c 0x%" PFMT64x " 0x%" PFMT64x "\n", t, xref->to, xref->from);
			break;
		case '\0': {
			char *name = analysis->coreb.getNameDelta(analysis->coreb.core, xref->from);
			if (name) {
				rz_str_replace_ch(name, ' ', 0, true);
				analysis->cb_printf("%40s", name);
				free(name);
			} else {
				analysis->cb_printf("%40s", "?");
			}
			analysis->cb_printf(" 0x%" PFMT64x " -> %9s -> 0x%" PFMT64x, xref->from, rz_analysis_xrefs_type_tostring(t), xref->to);
			name = analysis->coreb.getNameDelta(analysis->coreb.core, xref->to);
			if (name) {
				rz_str_replace_ch(name, ' ', 0, true);
				analysis->cb_printf(" %s\n", name);
				free(name);
			} else {
				analysis->cb_printf("\n");
			}
		} break;
		case 'q':
			analysis->cb_printf("0x%08" PFMT64x " -> 0x%08" PFMT64x "  %s\n", xref->from, xref->to, rz_analysis_xrefs_type_tostring(t));
			break;
		case 'j': {
			pj_o(pj);
			char *name = analysis->coreb.getNameDelta(analysis->coreb.core, xref->from);
			if (name) {
				rz_str_replace_ch(name, ' ', 0, true);
				pj_ks(pj, "name", name);
				free(name);
			}
			pj_kn(pj, "from", xref->from);
			pj_kn(pj, "to", xref->to);
			pj_ks(pj, "type", rz_analysis_xrefs_type_tostring(t));
			name = analysis->coreb.getNameDelta(analysis->coreb.core, xref->to);
			if (name) {
				rz_str_replace_ch(name, ' ', 0, true);
				pj_ks(pj, "refname", name);
				free(name);
			}
			pj_end(pj);
		} break;
		default:
			break;
		}
	}
	if (rad == 'j') {
		pj_end(pj);
		analysis->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
	rz_list_free(list);
}

RZ_API const char *rz_analysis_xrefs_type_tostring(RzAnalysisXRefType type) {
	switch (type) {
	case RZ_ANALYSIS_REF_TYPE_CODE:
		return "CODE";
	case RZ_ANALYSIS_REF_TYPE_CALL:
		return "CALL";
	case RZ_ANALYSIS_REF_TYPE_DATA:
		return "DATA";
	case RZ_ANALYSIS_REF_TYPE_STRING:
		return "STRING";
	case RZ_ANALYSIS_REF_TYPE_NULL:
	default:
		return "UNKNOWN";
	}
}

RZ_API RzAnalysisXRefType rz_analysis_xrefs_type(char ch) {
	switch (ch) {
	case RZ_ANALYSIS_REF_TYPE_CODE:
	case RZ_ANALYSIS_REF_TYPE_CALL:
	case RZ_ANALYSIS_REF_TYPE_DATA:
	case RZ_ANALYSIS_REF_TYPE_STRING:
	case RZ_ANALYSIS_REF_TYPE_NULL:
		return (RzAnalysisXRefType)ch;
	default:
		return RZ_ANALYSIS_REF_TYPE_NULL;
	}
}

RZ_API bool rz_analysis_xrefs_init(RzAnalysis *analysis) {
	ht_up_free(analysis->ht_xrefs_from);
	analysis->ht_xrefs_from = NULL;
	ht_up_free(analysis->ht_xrefs_to);
	analysis->ht_xrefs_to = NULL;

	HtUP *tmp = ht_up_new(NULL, xrefs_l1_free_kv, NULL);
	if (!tmp) {
		return false;
	}
	analysis->ht_xrefs_from = tmp;

	tmp = ht_up_new(NULL, xrefs_l1_free_kv, NULL);
	if (!tmp) {
		ht_up_free(analysis->ht_xrefs_from);
		analysis->ht_xrefs_from = NULL;
		return false;
	}
	analysis->ht_xrefs_to = tmp;
	return true;
}

static bool count_cb(void *user, const ut64 k, const void *v) {
	(*(ut64 *)user) += ((HtUP *)v)->count;
	return true;
}

RZ_API ut64 rz_analysis_xrefs_count(RzAnalysis *analysis) {
	ut64 ret = 0;
	ht_up_foreach(analysis->ht_xrefs_to, count_cb, &ret);
	return ret;
}

static void fcn_bb_op_xrefs_foreach(RzAnalysisFunction *fcn, RzAnalysisXRefCb cb, void *user, HtUP *l1) {
	RzListIter *iter;
	RzAnalysisBlock *bb;
	rz_list_foreach (fcn->bbs, iter, bb) {
		for (int i = 0; i < bb->ninstr; i++) {
			ut64 addr = bb->addr + rz_analysis_block_get_op_offset(bb, i);
			l1_item_foreach(l1, addr, cb, user);
		}
	}
}

RZ_API void rz_analysis_function_xrefs_from_foreach(RzAnalysisFunction *fcn, RzAnalysisXRefCb cb, void *user) {
	fcn_bb_op_xrefs_foreach(fcn, cb, user, fcn->analysis->ht_xrefs_from);
}

RZ_API void rz_analysis_function_xrefs_to_foreach(RzAnalysisFunction *fcn, RzAnalysisXRefCb cb, void *user) {
	fcn_bb_op_xrefs_foreach(fcn, cb, user, fcn->analysis->ht_xrefs_from);
}

static RzList *fcn_xrefs_list(RzAnalysisFunction *fcn, HtUP *l1) {
	RzList *list = rz_analysis_xref_list_new();
	if (!list) {
		return NULL;
	}
	fcn_bb_op_xrefs_foreach(fcn, xrefs_list_append, list, l1);
	xrefs_list_sort(list);
	return list;
}

RZ_API RzList *rz_analysis_function_get_xrefs_from(RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, NULL);
	return fcn_xrefs_list(fcn, fcn->analysis->ht_xrefs_from);
}

RZ_API RzList *rz_analysis_function_get_xrefs_to(RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, NULL);
	return fcn_xrefs_list(fcn, fcn->analysis->ht_xrefs_to);
}

RZ_API const char *rz_analysis_ref_type_tostring(RzAnalysisXRefType t) {
	switch (t) {
	case RZ_ANALYSIS_REF_TYPE_NULL:
		return "null";
	case RZ_ANALYSIS_REF_TYPE_CODE:
		return "code";
	case RZ_ANALYSIS_REF_TYPE_CALL:
		return "call";
	case RZ_ANALYSIS_REF_TYPE_DATA:
		return "data";
	case RZ_ANALYSIS_REF_TYPE_STRING:
		return "string";
	}
	return "unknown";
}
