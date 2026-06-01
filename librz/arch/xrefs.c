// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 defragger <rlaemmert@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"
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
		if (!ht_up_insert(m, key1, ht)) {
			return false;
		}
	}
	ut64 key2 = from2to ? xref->to : xref->from;
	return ht_up_update(ht, key2, xref);
}

static bool set_xref_by_type(HtUP *type_ht, RzAnalysisXRef *xref, bool from2to) {
	ut64 type_key = (ut64)xref->type;
	HtUP *addr_ht = ht_up_find(type_ht, type_key, NULL);
	if (!addr_ht) {
		addr_ht = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
		if (!addr_ht) {
			return false;
		}
		if (!ht_up_insert(type_ht, type_key, addr_ht)) {
			ht_up_free(addr_ht);
			return false;
		}
	}
	ut64 key1 = from2to ? xref->from : xref->to;
	HtUP *inner = ht_up_find(addr_ht, key1, NULL);
	if (!inner) {
		inner = ht_up_new(NULL, NULL);
		if (!inner) {
			return false;
		}
		if (!ht_up_insert(addr_ht, key1, inner)) {
			ht_up_free(inner);
			return false;
		}
	}
	ut64 key2 = from2to ? xref->to : xref->from;
	return ht_up_update(inner, key2, xref);
}

static void del_xref_by_type(HtUP *type_ht, ut64 from, ut64 to,
	RzAnalysisXRefType type, bool from2to) {
	HtUP *addr_ht = ht_up_find(type_ht, (ut64)type, NULL);
	if (!addr_ht) {
		return;
	}
	ut64 key1 = from2to ? from : to;
	HtUP *inner = ht_up_find(addr_ht, key1, NULL);
	if (!inner) {
		return;
	}
	ut64 key2 = from2to ? to : from;
	ht_up_delete(inner, key2);
}

/**
 * \brief Set a cross reference from \p from to \p to.
 *
 * If a xref for the same (from, to) pair already exists with a different type,
 * the old xref is replaced with the new one. Type indices are updated accordingly.
 *
 * \param analysis RzAnalysis instance.
 * \param from Source address.
 * \param to Target address.
 * \param type Xref type.
 * \return true if the xref was set successfully, false otherwise.
 */
RZ_API bool rz_analysis_xrefs_set(RzAnalysis *analysis, ut64 from, ut64 to, RzAnalysisXRefType type) {
	rz_return_val_if_fail(analysis && analysis->ht_xrefs_to_by_type && analysis->ht_xrefs_from_by_type, false);
	if (from == to) {
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
	// Clean up old type index entries if a different-typed xref existed before.
	if (analysis->ht_xrefs_to_by_type) {
		HtUP *ht = ht_up_find(analysis->ht_xrefs_to, to, NULL);
		if (ht) {
			RzAnalysisXRef *old = ht_up_find(ht, from, NULL);
			if (old && old->type != type) {
				del_xref_by_type(analysis->ht_xrefs_from_by_type, from, to, old->type, true);
				del_xref_by_type(analysis->ht_xrefs_to_by_type, from, to, old->type, false);
			}
		}
	}
	if (!set_xref(analysis->ht_xrefs_from, xref, true)) {
		rz_analysis_xref_free(xref);
		return false;
	}
	if (!set_xref(analysis->ht_xrefs_to, xref, false)) {
		rz_analysis_xrefs_deln(analysis, from, to, type);
		rz_analysis_xref_free(xref);
		return false;
	}
	if (analysis->ht_xrefs_from_by_type &&
		!set_xref_by_type(analysis->ht_xrefs_from_by_type, xref, true)) {
		rz_analysis_xrefs_deln(analysis, from, to, type);
		return false;
	}
	if (analysis->ht_xrefs_to_by_type &&
		!set_xref_by_type(analysis->ht_xrefs_to_by_type, xref, false)) {
		if (analysis->ht_xrefs_from_by_type) {
			del_xref_by_type(analysis->ht_xrefs_from_by_type, from, to, type, true);
		}
		rz_analysis_xrefs_deln(analysis, from, to, type);
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
	if (analysis->ht_xrefs_from_by_type) {
		del_xref_by_type(analysis->ht_xrefs_from_by_type, from, to, type, true);
	}
	if (analysis->ht_xrefs_to_by_type) {
		del_xref_by_type(analysis->ht_xrefs_to_by_type, from, to, type, false);
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
	ht_up_free(analysis->ht_xrefs_from_by_type);
	analysis->ht_xrefs_from_by_type = NULL;
	ht_up_free(analysis->ht_xrefs_to_by_type);
	analysis->ht_xrefs_to_by_type = NULL;

	HtUP *tmp;
	tmp = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	if (!tmp) {
		goto err;
	}
	analysis->ht_xrefs_from = tmp;

	tmp = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	if (!tmp) {
		goto err_free_from;
	}
	analysis->ht_xrefs_to = tmp;

	tmp = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	if (!tmp) {
		goto err_free_to;
	}
	analysis->ht_xrefs_from_by_type = tmp;

	tmp = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	if (!tmp) {
		goto err_free_from_by_type;
	}
	analysis->ht_xrefs_to_by_type = tmp;
	return true;

err_free_from_by_type:
	ht_up_free(analysis->ht_xrefs_from_by_type);
	analysis->ht_xrefs_from_by_type = NULL;
err_free_to:
	ht_up_free(analysis->ht_xrefs_to);
	analysis->ht_xrefs_to = NULL;
err_free_from:
	ht_up_free(analysis->ht_xrefs_from);
	analysis->ht_xrefs_from = NULL;
err:
	return false;
}

static bool count_cb(void *user, const ut64 k, const void *v) {
	(*(ut64 *)user) += ht_up_size((HtUP *)v);
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

typedef struct {
	RzIterator *outer; ///< iterates addr_ht, yields HtUP **
	RzIterator *inner; ///< iterates current inner HtUP, yields RzAnalysisXRef **
} XrefTypeAllState;

static void *xref_type_all_next(RzIterator *it) {
	XrefTypeAllState *st = it->u;
	if (st->inner) {
		void *next = rz_iterator_next(st->inner);
		if (next) {
			return next;
		}
		rz_iterator_free(st->inner);
		st->inner = NULL;
	}
	while (true) {
		void *outer_val = rz_iterator_next(st->outer);
		if (!outer_val) {
			return NULL;
		}
		HtUP *inner_ht = *(HtUP **)outer_val;
		if (!inner_ht || !ht_up_size(inner_ht)) {
			continue;
		}
		st->inner = ht_up_as_iter(inner_ht);
		if (!st->inner) {
			continue;
		}
		void *next = rz_iterator_next(st->inner);
		if (next) {
			return next;
		}
		rz_iterator_free(st->inner);
		st->inner = NULL;
	}
}

static void xref_type_all_free_state(XrefTypeAllState *st) {
	if (!st) {
		return;
	}
	rz_iterator_free(st->inner);
	rz_iterator_free(st->outer);
	free(st);
}

/**
 * \brief Get all xrefs of a given type.
 *
 * Uses the type-indexed storage for efficient O(k) access where k is
 * the number of xrefs of the requested type, instead of scanning all xrefs.
 * Returns an RzIterator yielding RzAnalysisXRef ** pointers.
 *
 * \param analysis RzAnalysis instance.
 * \param type The xref type to filter by.
 * \return RzIterator yielding RzAnalysisXRef **, or NULL if none found.
 */
RZ_API RZ_OWN RzIterator *rz_analysis_xrefs_get_all_of_type(
	RzAnalysis *analysis, RzAnalysisXRefType type) {
	rz_return_val_if_fail(analysis, NULL);
	if (!analysis->ht_xrefs_from_by_type) {
		return NULL;
	}
	HtUP *addr_ht = ht_up_find(analysis->ht_xrefs_from_by_type, (ut64)type, NULL);
	if (!addr_ht || !ht_up_size(addr_ht)) {
		return NULL;
	}
	XrefTypeAllState *st = RZ_NEW(XrefTypeAllState);
	if (!st) {
		return NULL;
	}
	st->inner = NULL;
	st->outer = ht_up_as_iter(addr_ht);
	if (!st->outer) {
		free(st);
		return NULL;
	}
	RzIterator *it = rz_iterator_new(
		xref_type_all_next, NULL,
		(rz_iterator_free_cb)xref_type_all_free_state, st);
	if (!it) {
		return NULL;
	}
	return it;
}

/**
 * \brief Get xrefs pointing TO a given address, filtered by type.
 *
 * Returns an RzIterator yielding RzAnalysisXRef ** pointers.
 *
 * \param analysis RzAnalysis instance.
 * \param addr The target address.
 * \param type The xref type to filter by.
 * \return RzIterator yielding RzAnalysisXRef **, or NULL if none found.
 */
RZ_API RZ_OWN RzIterator *rz_analysis_xrefs_get_to_type(
	RzAnalysis *analysis, ut64 addr, RzAnalysisXRefType type) {
	rz_return_val_if_fail(analysis, NULL);
	if (!analysis->ht_xrefs_to_by_type) {
		return NULL;
	}
	HtUP *addr_ht = ht_up_find(analysis->ht_xrefs_to_by_type, (ut64)type, NULL);
	if (!addr_ht) {
		return NULL;
	}
	HtUP *inner = ht_up_find(addr_ht, addr, NULL);
	if (!inner) {
		return NULL;
	}
	return ht_up_as_iter(inner);
}

/**
 * \brief Get xrefs FROM a given address, filtered by type.
 *
 * Returns an RzIterator yielding RzAnalysisXRef ** pointers.
 *
 * \param analysis RzAnalysis instance.
 * \param addr The source address.
 * \param type The xref type to filter by.
 * \return RzIterator yielding RzAnalysisXRef **, or NULL if none found.
 */
RZ_API RZ_OWN RzIterator *rz_analysis_xrefs_get_from_type(
	RzAnalysis *analysis, ut64 addr, RzAnalysisXRefType type) {
	rz_return_val_if_fail(analysis, NULL);
	if (!analysis->ht_xrefs_from_by_type) {
		return NULL;
	}
	HtUP *addr_ht = ht_up_find(analysis->ht_xrefs_from_by_type, (ut64)type, NULL);
	if (!addr_ht) {
		return NULL;
	}
	HtUP *inner = ht_up_find(addr_ht, addr, NULL);
	if (!inner) {
		return NULL;
	}
	return ht_up_as_iter(inner);
}

static bool count_type_cb(void *user, const ut64 k, const void *v) {
	(*(ut64 *)user) += ht_up_size((HtUP *)v);
	return true;
}

/**
 * \brief Count xrefs of a given type.
 * \param analysis RzAnalysis instance.
 * \param type The xref type to count.
 * \return Number of xrefs of the given type.
 */
RZ_API ut64 rz_analysis_xrefs_count_type(RzAnalysis *analysis, RzAnalysisXRefType type) {
	rz_return_val_if_fail(analysis, 0);
	if (!analysis->ht_xrefs_to_by_type) {
		return 0;
	}
	HtUP *addr_ht = ht_up_find(analysis->ht_xrefs_to_by_type, (ut64)type, NULL);
	if (!addr_ht) {
		return 0;
	}
	ut64 ret = 0;
	ht_up_foreach(addr_ht, count_type_cb, &ret);
	return ret;
}

typedef struct {
	HtUP *ht; ///< outer hashtable to look up keys in
	RzIterator *keys; ///< iterates over outer ht keys
	RzIterator *inner; ///< iterates over current inner ht
	ut64 range_from;
	ut64 range_to;
} XrefRangeState;

static void *xref_range_next(RzIterator *it) {
	XrefRangeState *st = it->u;
	if (st->inner) {
		void *next = rz_iterator_next(st->inner);
		if (next) {
			return next;
		}
		rz_iterator_free(st->inner);
		st->inner = NULL;
	}
	while (true) {
		void *keyp = rz_iterator_next(st->keys);
		if (!keyp) {
			return NULL;
		}
		ut64 key = *(const ut64 *)keyp;
		if (key < st->range_from || key > st->range_to) {
			continue;
		}
		HtUP *inner_ht = ht_up_find(st->ht, key, NULL);
		if (!inner_ht || !ht_up_size(inner_ht)) {
			continue;
		}
		st->inner = ht_up_as_iter(inner_ht);
		if (!st->inner) {
			continue;
		}
		void *next = rz_iterator_next(st->inner);
		if (next) {
			return next;
		}
		rz_iterator_free(st->inner);
		st->inner = NULL;
	}
}

static void xref_range_free_state(XrefRangeState *st) {
	if (!st) {
		return;
	}
	rz_iterator_free(st->inner);
	rz_iterator_free(st->keys);
	free(st);
}

/**
 * \brief Get xrefs pointing TO addresses in a given range.
 *
 * Returns an RzIterator yielding RzAnalysisXRef ** pointers.
 * Xrefs where the target address falls within [addr_from, addr_to] are included.
 *
 * \param analysis RzAnalysis instance.
 * \param addr_from Start of the address range (inclusive).
 * \param addr_to End of the address range (inclusive).
 * \return RzIterator yielding RzAnalysisXRef **, or NULL if none found.
 */
RZ_API RZ_OWN RzIterator *rz_analysis_xrefs_get_to_range(
	RzAnalysis *analysis, ut64 addr_from, ut64 addr_to) {
	rz_return_val_if_fail(analysis, NULL);
	if (!analysis->ht_xrefs_to) {
		return NULL;
	}
	XrefRangeState *st = RZ_NEW(XrefRangeState);
	if (!st) {
		return NULL;
	}
	st->ht = analysis->ht_xrefs_to;
	st->inner = NULL;
	st->range_from = addr_from;
	st->range_to = addr_to;
	st->keys = ht_up_as_iter_keys(analysis->ht_xrefs_to);
	if (!st->keys) {
		free(st);
		return NULL;
	}
	RzIterator *it = rz_iterator_new(
		xref_range_next, NULL,
		(rz_iterator_free_cb)xref_range_free_state, st);
	if (!it) {
		return NULL;
	}
	return it;
}

/**
 * \brief Get xrefs FROM addresses in a given range.
 *
 * Returns an RzIterator yielding RzAnalysisXRef ** pointers.
 * Xrefs where the source address falls within [addr_from, addr_to] are included.
 *
 * \param analysis RzAnalysis instance.
 * \param addr_from Start of the address range (inclusive).
 * \param addr_to End of the address range (inclusive).
 * \return RzIterator yielding RzAnalysisXRef **, or NULL if none found.
 */
RZ_API RZ_OWN RzIterator *rz_analysis_xrefs_get_from_range(
	RzAnalysis *analysis, ut64 addr_from, ut64 addr_to) {
	rz_return_val_if_fail(analysis, NULL);
	if (!analysis->ht_xrefs_from) {
		return NULL;
	}
	XrefRangeState *st = RZ_NEW(XrefRangeState);
	if (!st) {
		return NULL;
	}
	st->ht = analysis->ht_xrefs_from;
	st->inner = NULL;
	st->range_from = addr_from;
	st->range_to = addr_to;
	st->keys = ht_up_as_iter_keys(analysis->ht_xrefs_from);
	if (!st->keys) {
		free(st);
		return NULL;
	}
	RzIterator *it = rz_iterator_new(
		xref_range_next, NULL,
		(rz_iterator_free_cb)xref_range_free_state, st);
	if (!it) {
		return NULL;
	}
	return it;
}
