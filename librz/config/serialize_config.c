// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include "config_internal.h"

static bool config_serialize_to_sdb(const RzConfigEntry *entry, void *user) {
	Sdb *db = user;
	if (entry->is_variable) {
		char *value = rz_config_var_as_string(&entry->var);
		sdb_set(db, entry->var.name, value);
		free(value);
	} else {
		const RzConfigNode *node = &entry->node;
		sdb_set(db, node->name, node->value);
	}
	return true;
}

/*
 *
 * RzConfig isn't completely serialized, only the values.
 *
 * SDB Format:
 *
 * /
 *   <name>=<value>
 *   ...
 *
 */
RZ_API void rz_serialize_config_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config) {
	rz_config_iterate_over(config, config_serialize_to_sdb, db);
}

typedef struct deserialize_ctx_s {
	RzConfig *config;
	HtSP *exclude;
} DeserializeCtx;

static bool config_deserialize_from_sdb(void *user, const SdbKv *kv) {
	DeserializeCtx *ctx = user;
	const char *key = sdbkv_key(kv);
	if (ctx->exclude && ht_sp_find_kv(ctx->exclude, key, NULL)) {
		return true;
	}

	RzConfigEntry *entry = config_find_entry(ctx->config, key);
	if (!entry) {
		return true;
	}

	const char *value = sdbkv_value(kv);
	if (entry->is_variable) {
		rz_config_var_set_any(&entry->var, value);
	} else {
		rz_config_set(ctx->config, key, value);
	}
	return true;
}

/**
 * \param exclude NULL-terminated array of keys to not load from the sdb.
 */
RZ_API bool rz_serialize_config_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config, RZ_NULLABLE const char **exclude) {
	rz_return_val_if_fail(db && config, false);

	DeserializeCtx ctx = { config, NULL };
	if (exclude) {
		ctx.exclude = ht_sp_new(HT_STR_DUP, NULL, NULL);
		if (!ctx.exclude) {
			return false;
		}
		for (; *exclude; exclude++) {
			ht_sp_insert(ctx.exclude, *exclude, NULL);
		}
	}
	sdb_foreach(db, config_deserialize_from_sdb, &ctx);
	ht_sp_free(ctx.exclude);
	return true;
}
