// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include "config_internal.h"

static RzSetS *build_exclude_set(const char **strings) {
	if (!strings) {
		return NULL;
	}
	HtSP *r = rz_set_s_new(HT_STR_DUP);
	if (!r) {
		return NULL;
	}
	for (; *strings; strings++) {
		rz_set_s_add(r, *strings);
	}
	return r;
}

typedef struct serialze_ctx_t {
	Sdb *db;
	HtSP *exclude;
} SerializeCtx;

static bool config_serialize_to_sdb(const RzConfigEntry *entry, void *user) {
	SerializeCtx *ctx = user;
	if (entry->is_variable) {
		if (ctx->exclude && rz_set_s_contains(ctx->exclude, entry->var.name)) {
			return true;
		}
		char *value = rz_config_var_as_string(&entry->var);
		sdb_set(ctx->db, entry->var.name, value);
		free(value);
	} else {
		const RzConfigNode *node = &entry->node;
		if (ctx->exclude && rz_set_s_contains(ctx->exclude, node->name)) {
			return true;
		}
		sdb_set(ctx->db, node->name, node->value);
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
 * \param exclude NULL-terminated array of keys to not store in the sdb.
 */
RZ_API void rz_serialize_config_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config, RZ_NULLABLE const char **exclude) {
	rz_return_if_fail(db && config);
	SerializeCtx ctx = { .db = db, .exclude = build_exclude_set(exclude) };
	if (exclude && !ctx.exclude) {
		return;
	}
	rz_config_iterate_over(config, config_serialize_to_sdb, &ctx);
	rz_set_s_free(ctx.exclude);
}

typedef struct deserialize_ctx_t {
	RzConfig *config;
	RzSetS *exclude;
} DeserializeCtx;

static bool config_deserialize_from_sdb(void *user, const SdbKv *kv) {
	DeserializeCtx *ctx = user;
	const char *key = sdbkv_key(kv);
	if (ctx->exclude && rz_set_s_contains(ctx->exclude, key)) {
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

	DeserializeCtx ctx = { .config = config, .exclude = build_exclude_set(exclude) };
	if (exclude && !ctx.exclude) {
		return false;
	}
	sdb_foreach(db, config_deserialize_from_sdb, &ctx);
	rz_set_s_free(ctx.exclude);
	return true;
}
