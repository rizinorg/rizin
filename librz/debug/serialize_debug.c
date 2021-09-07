// SPDX-FileCopyrightText: 2021 DMaroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_bp.h>
#include <rz_util/rz_serialize.h>

RZ_API void rz_serialize_debug_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzDebug *dbg) {
	rz_serialize_bp_save(sdb_ns(db, "breakpoints", true), dbg->bp);
}

RZ_API bool rz_serialize_debug_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzDebug *dbg, RZ_NULLABLE RzSerializeResultInfo *res) {
	bool ret = false;
#define SUB(ns, call) RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, goto heaven;)

	Sdb *subdb;
	SUB("breakpoints", rz_serialize_bp_load(subdb, dbg->bp, res));

	ret = true;
heaven:
	return ret;
}
