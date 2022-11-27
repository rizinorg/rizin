// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_analysis.h>
#include <sdb.h>

static bool typelinks_load_sdb(RzAnalysis *analysis, Sdb *sdb) {
	rz_return_val_if_fail(analysis && sdb, false);
	RzType *type;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, false);
	ls_foreach (l, iter, kv) {
		ut64 addr = rz_num_get(NULL, sdbkv_key(kv));
		if (addr > 0) {
			char *error_msg = NULL;
			type = rz_type_parse_string_single(analysis->typedb->parser, sdbkv_value(kv), &error_msg);
			if (type) {
				ht_up_insert(analysis->type_links, addr, type);
			}
			free(error_msg);
		}
	}
	ls_free(l);
	return true;
}

static void save_typelink(const RzAnalysis *analysis, Sdb *sdb, const RzType *type, ut64 addr) {
	rz_return_if_fail(analysis && sdb && type);
	/*
		Sdb:
		addr=type
	*/

	// addr=type
	char *key = rz_str_newf("0x%08" PFMT64x, addr);
	char *type_str = rz_type_as_string(analysis->typedb, type);
	sdb_set(sdb, key, type_str, 0);
}

struct analysis_sdb {
	const RzAnalysis *analysis;
	Sdb *sdb;
};

static bool export_typelink_cb(void *user, ut64 k, const void *v) {
	struct analysis_sdb *s = user;
	RzType *type = (RzType *)v;
	save_typelink(s->analysis, s->sdb, type, k);
	return true;
}

static bool typelinks_export_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL const RzAnalysis *analysis) {
	rz_return_val_if_fail(db && analysis, false);
	struct analysis_sdb tdb = { analysis, db };
	ht_up_foreach(analysis->type_links, export_typelink_cb, &tdb);
	return true;
}

/**
 * \brief Saves the type links into SDB
 *
 * \param db A SDB database object
 * \param analysis RzAnalysis instance
 */
RZ_API void rz_serialize_typelinks_save(RZ_NONNULL Sdb *db, RZ_NONNULL const RzAnalysis *analysis) {
	rz_return_if_fail(db && analysis);
	typelinks_export_sdb(db, analysis);
}

/**
 * \brief Loads the type links from SDB
 *
 * \param db A SDB database object
 * \param analysis RzAnalysis instance
 * \param res A structure where the result is stored
 */
RZ_API bool rz_serialize_typelinks_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && analysis, false);
	return typelinks_load_sdb(analysis, db);
}
