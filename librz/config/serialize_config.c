/* radare - LGPL - Copyright 2019 - thestr4ng3r */

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
		sdb_set (db, node->name, node->value, 0);
	}
}

static bool load_config_cb(void *user, const char *k, const char *v) {
	RzConfig *config = user;
	RzConfigNode *node = rz_config_node_get (config, k);
	if (!node) {
		return 1;
	}
	rz_config_set (config, k, v);
	return 1;
}

RZ_API bool rz_serialize_config_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_foreach (db, load_config_cb, config);
	return true;
}
