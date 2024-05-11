// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 defragger <rlaemmert@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_cons.h>

/*
DICT
====

refs 10->20 C 16->10 J 20->10 C

xrefs 20->[10 C] 10 -> [16 J, 20 C]

10 : call 20 16 : jmp 10 20 : call 10
*/
// TODO: is it possible to have multiple type for the same (from, to) pair?
//       if it is, things need to be adjusted

static RzAnalysisXRef *rz_analysis_xref_new(ut64 from, ut64 to, ut64 type) {
	RzAnalysisXRef *xref = RZ_NEW(RzAnalysisXRef);
	if (xref) {
		xref->from = from;
		xref->to = to;
		xref->type = (type == -1) ? RZ_ANALYSIS_XREF_TYPE_CODE : type;
	}
	return xref;
}

static void rz_analysis_xref_free(RzAnalysisXRef *xref) {
	free(xref);
}

RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_xref_list_new() {
	return rz_list_newf((RzListFree)free);
}

static bool appendRef(void *u, const ut64 k, const void *v) {
	RzList *list = (RzList *)u;
	RzAnalysisXRef *xref = (RzAnalysisXRef *)v;
	RzAnalysisXRef *cloned = rz_analysis_xref_new(xref->from, xref->to, xref->type);
	if (cloned) {
		rz_list_append(list, cloned);
		return true;
	}
	return false;
}

static bool mylistrefs_cb(void *list, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach(ht, appendRef, list);
	return true;
}

static int ref_cmp(const RzAnalysisXRef *a, const RzAnalysisXRef *b, void *user) {
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

static void sortxrefs(RzList /*<RzAnalysisXRef *>*/ *list) {
	rz_list_sort(list, (RzListComparator)ref_cmp, NULL);
}

static void listxrefs(HtUP *m, ut64 addr, RzList /*<RzAnalysisXRef *>*/ *list) {
	if (addr == UT64_MAX) {
		ht_up_foreach(m, mylistrefs_cb, list);
	} else {
		HtUP *d = ht_up_find(m, addr, NULL);
		if (d) {
			ht_up_foreach(d, appendRef, list);
		}
	}
}

static bool set_xref(HtUP *m, RzAnalysisXRef *xref, bool from2to) {
	ut64 key1 = from2to ? xref->from : xref->to;
	HtUP *ht = ht_up_find(m, key1, NULL);
	if (!ht) {
		// RzAnalysis::ht_xrefs_to is responsible for releasing of pointers.
		HtUPFreeValue cb = from2to ? NULL : (HtUPFreeValue)rz_analysis_xref_free;
		ht = ht_up_new(NULL, cb);
		if (!ht) {
			return false;
		}
		if (!ht_up_insert(m, key1, ht, NULL)) {
			return false;
		}
	}
	ut64 key2 = from2to ? xref->to : xref->from;
	return ht_up_update(ht, key2, xref, NULL);
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
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_XREF_TYPE_NULL);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_XREF_TYPE_CODE);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_XREF_TYPE_CALL);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_XREF_TYPE_DATA);
	res |= rz_analysis_xrefs_deln(analysis, from, to, RZ_ANALYSIS_XREF_TYPE_STRING);
	return res;
}

RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_xrefs_get_to(RzAnalysis *analysis, ut64 addr) {
	RzList *list = rz_analysis_xref_list_new();
	if (!list) {
		return NULL;
	}
	listxrefs(analysis->ht_xrefs_to, addr, list);
	sortxrefs(list);
	if (rz_list_empty(list)) {
		rz_list_free(list);
		list = NULL;
	}
	return list;
}

RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_xrefs_get_from(RzAnalysis *analysis, ut64 addr) {
	RzList *list = rz_analysis_xref_list_new();
	if (!list) {
		return NULL;
	}
	listxrefs(analysis->ht_xrefs_from, addr, list);
	sortxrefs(list);
	if (rz_list_empty(list)) {
		rz_list_free(list);
		list = NULL;
	}
	return list;
}

/**
 * \brief Get list of all xrefs.
 * \param analysis RzAnalysis instance
 * \return RzList <RzAnalysisXRef *>
 */
RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_xrefs_list(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *list = rz_analysis_xref_list_new();
	if (list) {
		listxrefs(analysis->ht_xrefs_from, UT64_MAX, list);
		sortxrefs(list);
	}
	return list;
}

RZ_API const char *rz_analysis_xrefs_type_tostring(RzAnalysisXRefType type) {
	switch (type) {
	case RZ_ANALYSIS_XREF_TYPE_CODE:
		return "CODE";
	case RZ_ANALYSIS_XREF_TYPE_CALL:
		return "CALL";
	case RZ_ANALYSIS_XREF_TYPE_DATA:
		return "DATA";
	case RZ_ANALYSIS_XREF_TYPE_STRING:
		return "STRING";
	case RZ_ANALYSIS_XREF_TYPE_NULL:
	default:
		return "UNKNOWN";
	}
}

RZ_API RzAnalysisXRefType rz_analysis_xrefs_type(char ch) {
	switch (ch) {
	case RZ_ANALYSIS_XREF_TYPE_CODE:
	case RZ_ANALYSIS_XREF_TYPE_CALL:
	case RZ_ANALYSIS_XREF_TYPE_DATA:
	case RZ_ANALYSIS_XREF_TYPE_STRING:
	case RZ_ANALYSIS_XREF_TYPE_NULL:
		return (RzAnalysisXRefType)ch;
	default:
		return RZ_ANALYSIS_XREF_TYPE_NULL;
	}
}

RZ_API bool rz_analysis_xrefs_init(RzAnalysis *analysis) {
	ht_up_free(analysis->ht_xrefs_from);
	analysis->ht_xrefs_from = NULL;
	ht_up_free(analysis->ht_xrefs_to);
	analysis->ht_xrefs_to = NULL;

	HtUP *tmp = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	if (!tmp) {
		return false;
	}
	analysis->ht_xrefs_from = tmp;

	tmp = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
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

static RZ_OWN RzList /*<RzAnalysisXRef *>*/ *fcn_get_refs(const RzAnalysisFunction *fcn, HtUP *ht) {
	void **it;
	RzAnalysisBlock *bb;
	RzList *list = rz_analysis_xref_list_new();
	if (!list) {
		return NULL;
	}
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		for (size_t i = 0; i < bb->ninstr; i++) {
			ut64 at = bb->addr + rz_analysis_block_get_op_offset(bb, i);
			listxrefs(ht, at, list);
		}
	}
	sortxrefs(list);
	return list;
}

RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_function_get_xrefs_from(const RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, NULL);
	return fcn_get_refs(fcn, fcn->analysis->ht_xrefs_from);
}

RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_function_get_xrefs_to(const RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, NULL);
	return fcn_get_refs(fcn, fcn->analysis->ht_xrefs_to);
}

RZ_API const char *rz_analysis_ref_type_tostring(RzAnalysisXRefType t) {
	switch (t) {
	case RZ_ANALYSIS_XREF_TYPE_NULL:
		return "null";
	case RZ_ANALYSIS_XREF_TYPE_CODE:
		return "code";
	case RZ_ANALYSIS_XREF_TYPE_CALL:
		return "call";
	case RZ_ANALYSIS_XREF_TYPE_DATA:
		return "data";
	case RZ_ANALYSIS_XREF_TYPE_STRING:
		return "string";
	}
	return "unknown";
}
