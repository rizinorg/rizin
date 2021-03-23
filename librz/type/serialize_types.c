// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_type.h>

RZ_API void rz_serialize_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzType *types) {
	sdb_copy(types->sdb_types, db);
}

RZ_API bool rz_serialize_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzType *types, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_reset(types->sdb_types);
	sdb_copy(db, types->sdb_types);
	return true;
}
