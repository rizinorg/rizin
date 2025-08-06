// SPDX-FileCopyrightText: 2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_util.h>

/**
 * \file no_rtti.c
 * This file does the analysis which does not require RTTI information.
 *
 * Virtual Table Detection :
 *
 * Generally with RTTI, enough information is available and hence we can easily pair
 * virtual table(s) with corresponding class(es).
 * Without RTTI, we use references to vtable base addresses to figure out corresponding classes.
 * The constructors have data xrefs to virtual table base addresses. Hence for each virtual table,
 * we can find the constructor(s) that use it.
 */

static void get_method_class_map(RzCore *core, RZ_OUT HtSS *method_class_map) {
	RzAnalysis *analysis = core->analysis;
	RzPVector *classes = rz_analysis_class_get_all(analysis, false);

	char *name = NULL;

	void **iter;
	rz_pvector_foreach (classes, iter) {
		SdbKv *kv = *iter;
		const char *class_name = sdbkv_key(kv);

		RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
		RzAnalysisMethod *meth;
		rz_vector_foreach (methods, meth) {
			ut64 addr = meth->addr;
			RzAnalysisFunction *function = rz_analysis_get_fcn_in(analysis, addr, RZ_ANALYSIS_FCN_TYPE_ROOT);
			if (!function) {
				function = rz_analysis_get_fcn_in(analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
			}
			if (!function) {
				continue;
			}
			bool found = false;
			ht_ss_find(method_class_map, function->name, &found);
			if (found) {
				continue;
			}
			ht_ss_insert(method_class_map, function->name, (char *)class_name);
		}
		rz_vector_free(methods);
		if (name != NULL) {
			break;
		}
	}
	rz_pvector_free(classes);
}

static const char *class_name_from_method(HtSS *method_class_map, RzAnalysisFunction *method) {
	bool found = false;
	const char *class_name = ht_ss_find(method_class_map, method->name, &found);
	if (!found) {
		return NULL;
	}
	return class_name;
}

static RzAnalysisMethod get_class_method(RzAnalysis *analysis, RVTableMethodInfo *vmethod, const char *class_name) {
	RzAnalysisMethod method = { 0 };
	if (!rz_analysis_class_method_exists_by_addr(analysis, class_name, vmethod->addr)) {
		method.addr = vmethod->addr;
		method.vtable_offset = vmethod->vtable_offset;
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, vmethod->addr);
		method.name = fcn ? rz_str_dup(fcn->name) : rz_str_newf("virtual_%" PFMT64d, method.vtable_offset);
		// Temporarily set as attr name
		method.real_name = fcn ? rz_str_dup(fcn->name) : rz_str_newf("virtual_%" PFMT64d, method.vtable_offset);
		method.method_type = RZ_ANALYSIS_CLASS_METHOD_VIRTUAL;
	} else {
		RzAnalysisMethod exist_meth = { 0 };
		if (rz_analysis_class_method_get_by_addr(analysis, class_name, vmethod->addr, &exist_meth) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
			method.addr = vmethod->addr;
			method.name = rz_str_dup(exist_meth.name);
			method.real_name = rz_str_dup(exist_meth.real_name);
			method.vtable_offset = vmethod->vtable_offset;
			method.method_type = RZ_ANALYSIS_CLASS_METHOD_VIRTUAL;
			rz_analysis_class_method_fini(&exist_meth);
		} else {
			rz_warn_if_reached();
		}
	}
	return method;
}

/**
 * \param context Vtble context object
 * \param vtables List of virtual tables
 * \brief Runs non-rtti required analysis on binaries
 */
RZ_API void rz_analysis_no_rtti_analysis(RVTableContext *context, RzList /*<RVTableInfo *>*/ *vtables) {
	RzAnalysis *analysis = context->analysis;
	RzCore *core = analysis->core;

	HtSS *method_class_map = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	get_method_class_map(core, method_class_map);

	RzListIter *it;
	RVTableInfo *vtable_info;
	rz_list_foreach (vtables, it, vtable_info) {
		RzList *xref_list = rz_analysis_xrefs_get_to(analysis, vtable_info->saddr);
		if (!xref_list) {
			continue;
		}
		RzListIter *itt;
		RzAnalysisXRef *xref;
		rz_list_foreach (xref_list, itt, xref) {
			RzAnalysisFunction *func = rz_analysis_get_fcn_in(analysis, xref->from, 0);
			if (!func) {
				continue;
			}
			const char *class_name = class_name_from_method(method_class_map, func);
			if (!class_name) {
				continue;
			}
			RzAnalysisVTable vtable = { 0 };
			vtable.addr = vtable_info->saddr;
			RVTableMethodInfo *vmethod;
			rz_vector_foreach (&vtable_info->methods, vmethod) {
				RzAnalysisMethod method = get_class_method(analysis, vmethod, class_name);
				rz_analysis_class_method_set(analysis, class_name, &method);
				rz_analysis_class_method_fini(&method);
			}
			rz_analysis_class_vtable_set(analysis, class_name, &vtable);
			rz_analysis_class_vtable_fini(&vtable);
		}
	}

	ht_ss_free(method_class_map);
}