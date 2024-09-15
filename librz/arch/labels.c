// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

HEAPTYPE(ut64);

RZ_API ut64 rz_analysis_function_get_label(RzAnalysisFunction *fcn, const char *name) {
	rz_return_val_if_fail(fcn, UT64_MAX);
	ut64 *addr = ht_sp_find(fcn->label_addrs, name, NULL);
	return addr ? *addr : UT64_MAX;
}

RZ_API const char *rz_analysis_function_get_label_at(RzAnalysisFunction *fcn, ut64 addr) {
	rz_return_val_if_fail(fcn, NULL);
	return ht_up_find(fcn->labels, addr, NULL);
}

RZ_API bool rz_analysis_function_set_label(RzAnalysisFunction *fcn, const char *name, ut64 addr) {
	rz_return_val_if_fail(fcn && name, false);
	if (ht_sp_find(fcn->label_addrs, name, NULL)) {
		return false;
	}
	char *n = rz_str_dup(name);
	if (!ht_up_insert(fcn->labels, addr, n)) {
		free(n);
		return false;
	}
	ht_sp_insert(fcn->label_addrs, name, ut64_new(addr));
	return true;
}

RZ_API bool rz_analysis_function_delete_label(RzAnalysisFunction *fcn, const char *name) {
	rz_return_val_if_fail(fcn && name, false);
	ut64 *addr = ht_sp_find(fcn->label_addrs, name, NULL);
	if (!addr) {
		return false;
	}
	ht_up_delete(fcn->labels, *addr);
	ht_sp_delete(fcn->label_addrs, name);
	return true;
}

RZ_API bool rz_analysis_function_delete_label_at(RzAnalysisFunction *fcn, ut64 addr) {
	rz_return_val_if_fail(fcn, false);
	char *name = ht_up_find(fcn->labels, addr, NULL);
	if (!name) {
		return false;
	}
	ht_sp_delete(fcn->label_addrs, name);
	ht_up_delete(fcn->labels, addr);
	return true;
}
