// SPDX-FileCopyrightText: 2021-2023 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <string.h>

static RZ_OWN RzList /*<RzTypePathTuple *>*/ *var_global_type_paths(RzAnalysis *analysis, RzAnalysisVarGlobal *gv, ut64 addr, unsigned int depth) {
	rz_return_val_if_fail(gv, false);

	// Calculate the possible offset as a difference between base address of the global variable
	// and the given address to check against
	st64 offset = (st64)(addr - gv->addr);
	if (offset < 0) {
		return NULL;
	}
	const char *tname = rz_type_identifier(gv->type);
	if (!tname) {
		return NULL;
	}
	RzList *tlist = rz_type_path_by_offset(analysis->typedb, gv->type, offset, depth);
	if (!tlist) {
		return NULL;
	}
	RzListIter *iter;
	RzTypePath *path;
	RzList *matches = rz_list_new();
	rz_list_foreach (tlist, iter, path) {
		if (!path->path) {
			rz_type_path_free(path);
			continue;
		}
		char *s = rz_str_newf("%s%s", tname, path->path);
		if (!s) {
			rz_type_path_free(path);
			continue;
		}
		free(path->path);
		path->path = s;
		RzTypePathTuple *tpl = RZ_NEW(RzTypePathTuple);
		if (!tpl) {
			rz_type_path_free(path);
			continue;
		}
		tpl->path = path;
		tpl->root = rz_type_clone(gv->type);
		rz_list_append(matches, tpl);
	}
	return matches;
}

/**
 * \brief Returns the list of all type paths for globals that belong to some address
 *
 * \param analysis RzAnalysis instance
 * \param addr The address to check against possible matches
 */
RZ_API RZ_OWN RzList /*<RzTypePathTuple *>*/ *rz_analysis_type_paths_by_address(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	// Search among globals
	RzAnalysisVarGlobal *gv = rz_analysis_var_global_get_byaddr_in(analysis, addr);
	if (!gv) {
		return NULL;
	}
	// TODO: Make the depth search configurable
	return var_global_type_paths(analysis, gv, addr, 8);
}
