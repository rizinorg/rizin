// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_project.h>

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
 *  * Implement a function like `static bool migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res)`
 *    which edits prj in-place and converts it from the previous to the current version.
 *  * Append this function to the `migrations` array below.
 *  * Implement tests in `test/unit/test_project_migrate.c` that cover all changes.
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

static bool migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res) {
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

static bool (*const migrations[])(RzProject *prj, RzSerializeResultInfo *res) = {
	migrate_v1_v2
};

/// Migrate the given project to the current version in-place
RZ_IPI bool rz_project_migrate(RzProject *prj, unsigned long version, RzSerializeResultInfo *res) {
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
