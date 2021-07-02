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

/**
 * \brief Checks if the RzType linked to the given address
 *
 * \param analysis RzAnalysis instance
 * \param addr The address to check the link at
 */
RZ_API bool rz_analysis_type_link_exists(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	bool found = false;
	return ht_up_find(analysis->type_links, addr, &found) && !found;
}

/**
 * \brief Returns the RzType linked to the given address
 *
 * \param analysis RzAnalysis instance
 * \param addr The address to check the link at
 */
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

/**
 * \brief Links the given RzType to the address
 *
 * \param analysis RzAnalysis instance
 * \param type RzType to link
 * \param addr The address to add the type link
 */
RZ_API bool rz_analysis_type_set_link(RzAnalysis *analysis, RZ_BORROW RzType *type, ut64 addr) {
	rz_return_val_if_fail(analysis && type, false);
	ht_up_insert(analysis->type_links, addr, type);
	return true;
}

/**
 * \brief Removes the type link given the address
 *
 * \param analysis RzAnalysis instance
 * \param addr The address to remove the type link from
 */
RZ_API bool rz_analysis_type_unlink(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, false);
	ht_up_delete(analysis->type_links, addr);
	return true;
}

/**
 * \brief Removes all type links
 *
 * \param analysis RzAnalysis instance
 */
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

/**
 * \brief Returns the list of all linked types
 *
 * \param analysis RzAnalysis instance
 */
RZ_API RZ_OWN RzList /* RzType */ *rz_analysis_type_links(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *types = rz_list_new();
	ht_up_foreach(analysis->type_links, type_collect_cb, types);
	return types;
}

struct TListMeta {
	RzTypeDB *typedb;
	RzList *l;
	ut64 addr;
	ut64 offset;
};

// TODO: Also resolve pointers and arrays
static bool type_paths_collect_by_offset_cb(void *user, ut64 k, const void *v) {
	rz_return_val_if_fail(user && v, false);
	struct TListMeta *tl = (struct TListMeta *)user;
	RzType *t = (RzType *)v;
	// Handle only identifiers here
	if (t->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (!t->identifier.name) {
		return false;
	}
	// Get the base type
	RzBaseType *btype = rz_type_db_get_base_type(tl->typedb, t->identifier.name);
	if (!btype) {
		return false;
	}
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT || btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		RzList *list = rz_type_path_by_offset(tl->typedb, btype, tl->offset);
		if (list) {
			rz_list_join(tl->l, list);
		}
	}
	return true;
}

/**
 * \brief Returns the list of all structured types that are linked and have members matching the offset
 *
 * \param analysis RzAnalysis instance
 * \param offset The offset of the member to match against
 */
RZ_API RZ_OWN RzList /* RzTypePath */ *rz_analysis_type_links_by_offset(RzAnalysis *analysis, ut64 offset) {
	rz_return_val_if_fail(analysis, NULL);
	if (offset == UT64_MAX) {
		return NULL;
	}
	RzList *typepaths = rz_list_new();
	struct TListMeta tl = {
		.typedb = analysis->typedb,
		.l = typepaths,
		.addr = 0,
		.offset = offset
	};
	ht_up_foreach(analysis->type_links, type_paths_collect_by_offset_cb, &tl);
	return typepaths;
}

// TODO: Also resolve pointers and arrays
static bool type_paths_collect_by_address_cb(void *user, ut64 k, const void *v) {
	rz_return_val_if_fail(user && v, false);
	struct TListMeta *tl = (struct TListMeta *)user;
	// If the possible offset doesn't make sense - we skip it
	if (tl->addr < k) {
		return false;
	}

	RzType *t = (RzType *)v;
	// Handle only identifiers here
	if (t->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (!t->identifier.name) {
		return false;
	}
	// Get the base type
	RzBaseType *btype = rz_type_db_get_base_type(tl->typedb, t->identifier.name);
	if (!btype) {
		return false;
	}
	// Calculate the possible offset as a difference between base address of the type link
	// and the given address to check against
	st64 offset = (st64)(tl->addr - k);
	if (offset < 0) {
		return false;
	}
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT || btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		RzList *list = rz_type_path_by_offset(tl->typedb, btype, offset);
		if (list) {
			rz_list_join(tl->l, list);
		}
	}
	return true;
}

/**
 * \brief Returns the list of all type paths that are linked to some address and have suitable offset
 *
 * \param analysis RzAnalysis instance
 * \param addr The address to check against possible matches
 */
RZ_API RZ_OWN RzList /* RzTypePath */ *rz_analysis_type_paths_by_address(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	RzList *typepaths = rz_list_new();
	struct TListMeta tl = {
		.typedb = analysis->typedb,
		.l = typepaths,
		.addr = addr,
		.offset = 0
	};
	ht_up_foreach(analysis->type_links, type_paths_collect_by_address_cb, &tl);
	return typepaths;
}
