// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_project.h>
#include <rz_util/pj.h>

/**
 * \file
 * About Project Migrations:
 * The project format is versioned, which means that a project saved with a certain version
 * will always follow the exact same format.
 * The current version is defined as `RZ_PROJECT_VERSION` and is completely independent of
 * Rizin release versions. Do not confuse them!
 * When any change in Rizin happens that changes the project format, this version must be raised
 * and a migration must be implemented, which converts a given project from the previous version
 * to the current and will be executed when loading an old project with new Rizin.
 * These migrations always bring a project from version x to version x+1 and they may be executed
 * sequentially if multiple versions are skipped. For example loading a project with version 1 in
 * Rizin with version 3 will execute (1->2), then (2->3) and finally load the project just like
 * any regular project of version 3.
 *
 * After introducing format changes in Rizin, do the following:
 *  * Raise RZ_PROJECT_VERSION by exactly 1.
 *  * Implement a function like `bool rz_project_migrate_migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res)`
 *    which edits prj in-place and converts it from the previous to the current version.
 *  * Append this function to the `migrations` array below.
 *  * Implement tests in `test/unit/test_project_migrate.c` that cover all changes (see the documentation there).
 */

// --
// Migration 1 -> 2
//
// Changes from 788fdb3d8ef98f50d61cdee72e0b57c74c814022:
//   Information which addresses are marked as noreturn was previosly saved in "/core/analysis/types" as records like:
//     addr.1337.noreturn=true
//   Now it is available in "/core/analysis/noreturn" while actual type-related info stays in "/core/analysis/types".

typedef struct {
	RzList /*<char *>*/ *moved_keys; ///< deferred for deletion from the old sdb
	Sdb *noreturn_db;
} V1V2TypesCtx;

bool v1_v2_types_foreach_cb(void *user, const char *k, const char *v) {
	if (!rz_str_startswith(k, "addr.") || !rz_str_endswith(k, ".noreturn")) {
		return true;
	}
	V1V2TypesCtx *ctx = user;
	sdb_set(ctx->noreturn_db, k, v, 0);
	rz_list_push(ctx->moved_keys, strdup(k));
	return true;
}

RZ_API bool rz_project_migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *types_db;
	RZ_SERIALIZE_SUB(analysis_db, types_db, res, "types", return false;);
	V1V2TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.noreturn_db = sdb_ns(analysis_db, "noreturn", true)
	};
	if (!ctx.moved_keys || !ctx.noreturn_db) {
		return false;
	}
	sdb_foreach(types_db, v1_v2_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(types_db, s, 0);
	}
	rz_list_free(ctx.moved_keys);
	return true;
}

// --
// Migration 2 -> 3
//
// Changes from 788fdb3d8ef98f50d61cdee72e0b57c74c814022:
//  Types database "analysis/types" was converted into two
//  separate SDBs - types and callables
//  Thus all "func.*" keys from "/core/analysis/types" should be moved to
//  "/core/analysis/callables"
//	Type links information is also separated now from
//	"/core/analysis/types" to "/core/analysis/typelinks"

typedef struct {
	RzList /*<char *>*/ *moved_keys; ///< deferred for deletion from the old sdb
	Sdb *callables_db;
	Sdb *typelinks_db;
} V2V3TypesCtx;

bool v2_v3_types_foreach_cb(void *user, const char *k, const char *v) {
	V2V3TypesCtx *ctx = user;
	if (rz_str_startswith(k, "func.") || !strcmp(v, "func")) {
		sdb_set(ctx->callables_db, k, v, 0);
		rz_list_push(ctx->moved_keys, strdup(k));
	} else if (rz_str_startswith(k, "link.")) {
		// Old addresses were stored as hexadecimal numbers without `0x` part
		// New addresses have them
		char *tl_key = rz_str_newf("0x%s", k + strlen("link."));
		sdb_set(ctx->typelinks_db, tl_key, v, 0);
		free(tl_key);
		rz_list_push(ctx->moved_keys, strdup(k));
	}
	return true;
}

RZ_API bool rz_project_migrate_v2_v3(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *types_db;
	RZ_SERIALIZE_SUB(analysis_db, types_db, res, "types", return false;);
	V2V3TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.callables_db = sdb_ns(analysis_db, "callables", true),
		.typelinks_db = sdb_ns(analysis_db, "typelinks", true)
	};
	if (!ctx.moved_keys || !ctx.callables_db || !ctx.typelinks_db) {
		return false;
	}
	sdb_foreach(types_db, v2_v3_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(types_db, s, 0);
	}
	rz_list_free(ctx.moved_keys);
	return true;
}

// --
// Migration 3 -> 4
//
// Changes from 8d54707ccf8b3492b999dfa42057da0847acb952:
//	Added new global variables in "/core/analysis/vars"

#if 0
typedef struct {
	RzList /*<char *>*/ *moved_keys; ///< deferred for deletion from the old sdb
	Sdb *global_vars_db;
} V3V4TypesCtx;

bool v3_v4_types_foreach_cb(void *user, const char *k, const char *v) {
	V3V4TypesCtx *ctx = user;
	if (rz_str_startswith(k, "0x")) {
		char name[32];
		PJ *j = pj_new();
		pj_o(j);
		pj_ks(j, "name", rz_strf(name, "gvar_%s", k));
		pj_ks(j, "type", v);
		pj_ks(j, "addr", k);
		// We don't have constraints for typelink here.
		pj_end(j);
		sdb_set(ctx->global_vars_db, k, pj_string(j), 0);
		pj_free(j);
		rz_list_push(ctx->moved_keys, strdup(k));
	}
	return true;
}
#endif

RZ_API bool rz_project_migrate_v3_v4(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	// Kill me in the future
	sdb_ns(analysis_db, "vars", true);
#if 0
	V3V4TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.global_vars_db = sdb_ns(analysis_db, "vars", true)
	};

	if (!ctx.moved_keys || !ctx.global_vars_db) {
		return false;
	}
	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", true);
	sdb_foreach(typelinks_db, v3_v4_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(typelinks_db, s, 0);
	}
	rz_list_free(ctx.moved_keys);
#endif
	return true;
}

// --
// Migration 4 -> 5
//
// Changes from a523314fa7c8fde0c2c0d116e82aa77f62991d37
//	Added new type called `unknown_t` in "/core/analysis/types"
//	It is used for all unknown types during the project loading and saving

RZ_API bool rz_project_migrate_v4_v5(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	Sdb *types_db;
	RZ_SERIALIZE_SUB(analysis_db, types_db, res, "types", return false;);
	// Common keys:
	// unknown_t=type
	// type.unknown_t.typeclass=Integral
	sdb_set(types_db, "unknown_t", "type", 0);
	sdb_set(types_db, "type.unknown_t.typeclass", "Integral", 0);
	// Now we read the bits value from "asm.bits=XX" in "/core/config"
	int bits = sdb_num_get(config_db, "asm.bits", 0);
	switch (bits) {
	case 16:
		// type.unknown_t=w
		// type.unknown_t.size=16
		sdb_set(types_db, "type.unknown_t", "w", 0);
		sdb_set(types_db, "type.unknown_t.size", "16", 0);
		break;
	case 64:
		// type.unknown_t=q
		// type.unknown_t.size=64
		sdb_set(types_db, "type.unknown_t", "q", 0);
		sdb_set(types_db, "type.unknown_t.size", "64", 0);
		break;
	case 32:
	default:
		// type.unknown_t=d
		// type.unknown_t.size=32
		sdb_set(types_db, "type.unknown_t", "d", 0);
		sdb_set(types_db, "type.unknown_t.size", "32", 0);
		break;
	}
	return true;
}

// --
// Migration 5 -> 6
//
// Changes from <commit-hash>
//	Added serialization functionality for debug (only for breakpoints as of now)
//	Used to save and load current RzDebug instance (only breakpoints) using serialization
//	New namespaces: /core/debug, /core/debug/breakpoints

RZ_API bool rz_project_migrate_v5_v6(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *debug_db = sdb_ns(core_db, "debug", true);
	sdb_ns(debug_db, "breakpoints", true);

	return true;
}

// --

static bool (*const migrations[])(RzProject *prj, RzSerializeResultInfo *res) = {
	rz_project_migrate_v1_v2,
	rz_project_migrate_v2_v3,
	rz_project_migrate_v3_v4,
	rz_project_migrate_v4_v5,
	rz_project_migrate_v5_v6
};

/// Migrate the given project to the current version in-place
RZ_API bool rz_project_migrate(RzProject *prj, unsigned long version, RzSerializeResultInfo *res) {
	RZ_STATIC_ASSERT(RZ_ARRAY_SIZE(migrations) + 1 == RZ_PROJECT_VERSION);
	while (version < RZ_PROJECT_VERSION) {
		bool succ = migrations[version - 1](prj, res);
		if (!succ) {
			rz_list_push(res, rz_str_newf("project migration from version %lu to %lu failed.", version, version + 1));
			return false;
		}
		rz_list_push(res, rz_str_newf("project migrated from version %lu to %lu.", version, version + 1));
		version++;
	}
	return true;
}
