// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

static bool purity_checked(HtUP *ht, RzAnalysisFunction *fcn) {
	bool checked;
	ht_up_find(ht, fcn->addr, &checked);
	return checked;
}

/*
 * Checks whether a given function is pure and sets its 'is_pure' field.
 * This function marks fcn 'not pure' if fcn, or any function called by fcn, accesses data
 * from outside, even if it only READS it.
 * Probably worth changing it in the future, so that it marks fcn 'impure' only when it
 * (or any function called by fcn) MODIFIES external data.
 */
static void check_purity(HtUP *ht, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzAnalysisXRef *xref;
	ht_up_insert(ht, fcn->addr, NULL);
	fcn->is_pure = true;
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL || xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			RzAnalysisFunction *called_fcn = rz_analysis_get_fcn_in(fcn->analysis, xref->to, 0);
			if (!called_fcn) {
				continue;
			}
			if (!purity_checked(ht, called_fcn)) {
				check_purity(ht, called_fcn);
			}
			if (!called_fcn->is_pure) {
				fcn->is_pure = false;
				break;
			}
		}
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			fcn->is_pure = false;
			break;
		}
	}
	rz_list_free(xrefs);
}

/**
 * \brief Returns if the function pure - accesses any external resources or not
 */
RZ_API bool rz_analysis_function_purity(RzAnalysisFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new(NULL, NULL);
		if (ht) {
			check_purity(ht, fcn);
			ht_up_free(ht);
		}
	}
	return fcn->is_pure;
}
