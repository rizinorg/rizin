// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <string.h>
#include <sdb.h>

// TODO:
// 1. Change the analysis serialization/deserialization code
// 2. Add to projects migration/tests

RZ_API bool rz_analysis_type_link_exists(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	bool found = false;
	return ht_up_find(analysis->type_links, addr, &found) && !found;
}

RZ_API RZ_BORROW RzType *rz_analysis_type_link_at(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	bool found = false;
	RzType *result = ht_up_find(analysis->type_links, addr, &found);
	if (!found || !result) {
		return NULL;
	}
	return result;
}

RZ_API bool rz_analysis_type_set_link(RzAnalysis *analysis, RZ_BORROW RzType *type, ut64 addr) {
	rz_return_val_if_fail(analysis && type, false);
	ht_up_insert(analysis->type_links, addr, type);
	return true;
}

RZ_API bool rz_analysis_type_unlink(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, false);
	ht_up_delete(analysis->type_links, addr);
	return true;
}

RZ_API bool rz_analysis_type_unlink_all(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, false);
	ht_up_free(analysis->type_links);
	analysis->type_links = ht_up_new0();
	if (!analysis->type_links) {
		return false;
	}
	return true;
}

static bool type_collect_cb(void *user, ut64 k, const void *v) {
	rz_return_val_if_fail(user && v, false);
	RzList *l = user;
	rz_list_append(l, (RzType *)v);
	return true;
}

RZ_API RZ_OWN RzList /* RzType */ *rz_analysis_type_links(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *types = rz_list_new();
	ht_up_foreach(analysis->type_links, type_collect_cb, types);
	return types;
}
