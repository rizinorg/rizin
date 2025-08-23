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
 * \param analysis Rizin analysis object
 * \param vtable_info Information about current virtual table
 * \param addr_vect Vector of addresses to calculate xrefs to. For first call, this should have a single address pointing to vtable saadr
 * \param method_class_map Map between methods and their class
 * \param depth Recursion depth, for first call, it should be 0
 * \brief Recursively calculates xrefs to virtual tables. Stops analysis when the first class method (in a branch) is discovered which uses the vtable.
 */
static void xrefs_to_vtables_recursive(RzAnalysis *analysis, RVTableInfo *vtable_info, RzVector /*<ut64>*/ *addr_vect, HtSS *method_class_map, ut16 depth) {
	// Limiting the depth because class virtual table analysis is generally done in first few depths.
	// This prevents redundant recursive analysis of vtables containing debug functions / non-virtual method vtables
	if (rz_vector_len(addr_vect) == 0 || depth == 5) {
		return;
	}
	RzVector *new_addr_vect = rz_vector_new(sizeof(ut64), NULL, NULL);
	ut64 *it;

	bool found = false;
	rz_vector_foreach (addr_vect, it) {
		ut64 addr = *it;
		RzList *xref_list = rz_analysis_xrefs_get_to(analysis, addr);
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
			rz_vector_push(new_addr_vect, &func->addr);
			const char *class_name = class_name_from_method(method_class_map, func);
			if (!class_name) {
				continue;
			}
			found = true;
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
		rz_list_free(xref_list);
	}
	if (!found) {
		xrefs_to_vtables_recursive(analysis, vtable_info, new_addr_vect, method_class_map, depth + 1);
	}
	rz_vector_free(new_addr_vect);
}

/**
 * \brief Runs non-rtti required analysis on binaries : connecting vtables to classes using recursive data xrefs
 * \param context Vtble context object
 * \param vtables List of virtual tables
 */
RZ_API void rz_analysis_no_rtti_analysis(RZ_NONNULL RVTableContext *context, RZ_NONNULL RzList /*<RVTableInfo *>*/ *vtables) {
	RzAnalysis *analysis = context->analysis;
	RzCore *core = analysis->core;

	HtSS *method_class_map = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	get_method_class_map(core, method_class_map);

	RzListIter *it;
	RVTableInfo *vtable_info;
	rz_list_foreach (vtables, it, vtable_info) {
		RzVector *addr_vect = rz_vector_new(sizeof(ut64), NULL, NULL);
		rz_vector_push(addr_vect, &vtable_info->saddr);
		xrefs_to_vtables_recursive(analysis, vtable_info, addr_vect, method_class_map, 0);
		rz_vector_free(addr_vect);
	}
	ht_ss_free(method_class_map);
}