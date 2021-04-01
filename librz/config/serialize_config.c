// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_config.h>

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
	RzListIter *iter;
	RzConfigNode *node;
	rz_list_foreach (config->nodes, iter, node) {
		sdb_set(db, node->name, node->value, 0);
	}
}

typedef struct load_config_ctx_t {
	RzConfig *config;
	HtPP *exclude;
} LoadConfigCtx;

static bool load_config_cb(void *user, const char *k, const char *v) {
	LoadConfigCtx *ctx = user;
	if (ctx->exclude && ht_pp_find_kv(ctx->exclude, k, NULL)) {
		return true;
	}
	RzConfigNode *node = rz_config_node_get(ctx->config, k);
	if (!node) {
		return 1;
	}
	rz_config_set(ctx->config, k, v);
	return 1;
}

/**
 * @param exclude NULL-terminated array of keys to not load from the sdb.
 */
RZ_API bool rz_serialize_config_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config,
	RZ_NULLABLE const char *const *exclude, RZ_NULLABLE RzSerializeResultInfo *res) {
	LoadConfigCtx ctx = { config, NULL };
	if (exclude) {
		ctx.exclude = ht_pp_new(NULL, NULL, NULL);
		if (!ctx.exclude) {
			return false;
		}
		for (; *exclude; exclude++) {
			ht_pp_insert(ctx.exclude, *exclude, NULL);
		}
	}
	sdb_foreach(db, load_config_cb, &ctx);
	ht_pp_free(ctx.exclude);
	return true;
}
