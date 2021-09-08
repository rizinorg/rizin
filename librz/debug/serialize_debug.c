// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_bp.h>
#include <rz_util/rz_serialize.h>

/**
 * \brief Serialize debug state (RzDebug) and save to a sdb
 * 
 * \param db sdb to save the state
 * \param dbg RzDebug instance to save
 */
RZ_API void rz_serialize_debug_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzDebug *dbg) {
	rz_return_if_fail(db && dbg);
	rz_serialize_bp_save(sdb_ns(db, "breakpoints", true), dbg->bp);
}

/**
 * \brief Load a serialized debug state to a RzDebug instance
 * 
 * \param db sdb storing the serialized debug state
 * \param dbg RzDebug instance to load the state into
 * \param res RzSerializeResultInfo to store info/errors/warnings
 * \return true if successful, false otherwise
 */
RZ_API bool rz_serialize_debug_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzDebug *dbg, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && dbg, false);
	bool ret = false;
#define SUB(ns, call) RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, goto heaven;)

	Sdb *subdb;
	SUB("breakpoints", rz_serialize_bp_load(subdb, dbg->bp, res));

	ret = true;
heaven:
	return ret;
}
