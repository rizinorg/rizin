// SPDX-FileCopyrightText: 2006-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_config.h"

RZ_API RZ_OWN RzConfigNode *rz_config_node_new(RZ_NONNULL const char *name, RZ_NONNULL const char *value) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name) && value, NULL);
	RzConfigNode *node = RZ_NEW0(RzConfigNode);
	if (!node) {
		return NULL;
	}
	node->name = rz_str_dup(name);
	node->value = rz_str_dup(value);
	node->flags = CN_RW | CN_STR;
	node->i_value = rz_num_get(NULL, value);
	node->options = rz_list_new();
	return node;
}

RZ_API RZ_OWN RzConfigNode *rz_config_node_clone(RzConfigNode *n) {
	rz_return_val_if_fail(n, NULL);
	RzConfigNode *cn = RZ_NEW0(RzConfigNode);
	if (!cn) {
		return NULL;
	}
	cn->name = rz_str_dup(n->name);
	cn->desc = n->desc ? rz_str_dup(n->desc) : NULL;
	cn->value = rz_str_dup(n->value ? n->value : "");
	cn->i_value = n->i_value;
	cn->flags = n->flags;
	cn->setter = n->setter;
	cn->options = rz_list_clone(n->options);
	return cn;
}

RZ_API void rz_config_node_free(RZ_NULLABLE void *n) {
	RzConfigNode *node = (RzConfigNode *)n;
	if (!node) {
		return;
	}
	free(node->name);
	free(node->desc);
	free(node->value);
	rz_list_free(node->options);
	free(node);
}

RZ_API RZ_BORROW RzConfigNode *rz_config_node_get(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);
	return ht_sp_find(cfg->ht, name, NULL);
}

RZ_API bool rz_config_set_getter(RzConfig *cfg, const char *key, RzConfigCallback cb) {
	rz_return_val_if_fail(cfg && key, false);
	RzConfigNode *node = rz_config_node_get(cfg, key);
	if (node) {
		node->getter = cb;
		return true;
	}
	return false;
}

RZ_API bool rz_config_set_setter(RzConfig *cfg, const char *key, RzConfigCallback cb) {
	RzConfigNode *node = rz_config_node_get(cfg, key);
	if (node) {
		node->setter = cb;
		return true;
	}
	return false;
}

/**
 * Returns the value of the config variable of \p name as a string
 */
RZ_API RZ_BORROW const char *rz_config_get(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		if (node->getter) {
			node->getter(cfg->user, node);
		}
		if (rz_config_node_is_bool(node)) {
			return rz_str_bool(rz_str_is_true(node->value));
		}
		return node->value;
	} else {
		RZ_LOG_DEBUG("rz_config_get: variable '%s' not found\n", name);
	}
	return NULL;
}

/**
 * Reads the value of the config variable of \p name only and only if
 * the variable is boolean, then tries to write back the inverted value.
 * Returns true in case of success.
 */
RZ_API bool rz_config_toggle(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (!node) {
		return false;
	}
	if (!rz_config_node_is_bool(node)) {
		RZ_LOG_DEBUG("(error: '%s' is not a boolean variable)\n", name);
		return false;
	}
	if (rz_config_node_is_ro(node)) {
		RZ_LOG_DEBUG("(error: '%s' config key is read only)\n", name);
		return false;
	}
	(void)rz_config_set_i(cfg, name, !node->i_value);
	return true;
}

/**
 * Reads the value of the config variable of \p name only and only if
 * the variable is integer.
 */
RZ_API ut64 rz_config_get_i(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), 0);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		if (node->getter) {
			node->getter(cfg->user, node);
		}
		if (node->i_value || !strcmp(node->value, "false")) {
			return node->i_value;
		}
		// TODO: Remove it once the switch to `rz_config_get_b()` is complete
		if (!strcmp(node->value, "true")) {
			return 1;
		}
		return (ut64)rz_num_math(cfg->num, node->value);
	}
	return (ut64)0LL;
}

/**
 * Reads the value of the config variable of \p name only and only if
 * the variable is boolean. Returns false in case of the failure.
 */
RZ_API bool rz_config_get_b(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (!node) {
		return false;
	}
	if (!rz_config_node_is_bool(node)) {
		RZ_LOG_DEBUG("(error: '%s' is not a boolean variable)\n", name);
		return false;
	}
	return rz_str_is_true(node->value);
}

RZ_API const char *rz_config_node_type(RzConfigNode *node) {
	rz_return_val_if_fail(node, "");

	if (rz_config_node_is_bool(node)) {
		return "bool";
	}
	if (rz_config_node_is_str(node)) {
		return "str";
	}
	if (rz_config_node_is_int(node)) {
		if (!strncmp(node->value, "0x", 2)) {
			return "addr";
		}
		return "int";
	}
	return "";
}

RZ_API RzConfigNode *rz_config_set_cb(RzConfig *cfg, const char *name, const char *value, RzConfigCallback cb) {
	RzConfigNode *node = rz_config_set(cfg, name, value);
	if (node && (node->setter = cb)) {
		if (!cb(cfg->user, node)) {
			return NULL;
		}
	}
	return node;
}

RZ_API RzConfigNode *rz_config_set_i_cb(RzConfig *cfg, const char *name, int ivalue, RzConfigCallback cb) {
	RzConfigNode *node = rz_config_set_i(cfg, name, ivalue);
	if (node && (node->setter = cb)) {
		if (!node->setter(cfg->user, node)) {
			return NULL;
		}
	}
	return node;
}

static bool __is_true_or_false(const char *s) {
	return s && (!rz_str_casecmp(s, "true") || !rz_str_casecmp(s, "false"));
}

/**
 * Writes the boolean \p value in the config variable of \p name only and only if
 * the variable is boolean.
 */
RZ_API RzConfigNode *rz_config_set_b(RzConfig *cfg, RZ_NONNULL const char *name, bool value) {
	rz_return_val_if_fail(cfg && cfg->ht, NULL);
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name), NULL);

	char *ov = NULL;
	ut64 oi = 0;
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		if (rz_config_node_is_ro(node)) {
			RZ_LOG_DEBUG("(error: '%s' config key is read only)\n", name);
			return node;
		}

		oi = node->i_value;
		if (node->value) {
			ov = rz_str_dup(node->value);
		}
		if (rz_config_node_is_bool(node)) {
			node->i_value = value ? 1 : 0;
			char *svalue = rz_str_dup(rz_str_bool(value));
			if (svalue) {
				free(node->value);
				node->value = svalue;
			}
		} else {
			RZ_LOG_ERROR("(error: '%s' is not a boolean variable)\n", name);
			free(ov);
			return NULL;
		}
	} else {
		if (!cfg->lock) {
			node = rz_config_node_new(name, rz_str_bool(value));
			if (!node) {
				node = NULL;
				goto beach;
			}
			node->flags = CN_RW | CN_BOOL;
			node->i_value = value ? 1 : 0;
			ht_sp_insert(cfg->ht, node->name, node);
			if (cfg->nodes) {
				rz_list_append(cfg->nodes, node);
			}
		} else {
			RZ_LOG_ERROR("(locked: no new keys can be created (%s))\n", name);
		}
	}

	if (node && node->setter) {
		if (!node->setter(cfg->user, node)) {
			if (oi != UT64_MAX) {
				node->i_value = oi;
			}
			free(node->value);
			node->value = rz_str_dup(ov ? ov : "");
		}
	}

beach:
	free(ov);
	return node;
}

/* TODO: reduce number of strdups here */
/**
 * Writes the string \p value in the config variable of \p name.
 */
RZ_API RzConfigNode *rz_config_set(RzConfig *cfg, RZ_NONNULL const char *name, const char *value) {
	rz_return_val_if_fail(cfg && cfg->ht, NULL);
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name), NULL);

	char *ov = NULL;
	ut64 oi;
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		if (rz_config_node_is_ro(node)) {
			eprintf("(error: '%s' config key is read only)\n", name);
			return node;
		}
		oi = node->i_value;
		if (node->value) {
			ov = rz_str_dup(node->value);
			if (!ov) {
				goto beach;
			}
		} else {
			free(node->value);
			node->value = rz_str_dup("");
		}
		if (rz_config_node_is_bool(node)) {
			bool b = rz_str_is_true(value);
			node->i_value = b ? 1 : 0;
			char *value = rz_str_dup(rz_str_bool(b));
			if (value) {
				free(node->value);
				node->value = value;
			}
		} else {
			if (!value) {
				free(node->value);
				node->value = rz_str_dup("");
				node->i_value = 0;
			} else {
				if (node->value == value) {
					goto beach;
				}
				free(node->value);
				node->value = rz_str_dup(value);
				if (IS_DIGIT(*value) || (value[0] == '-' && IS_DIGIT(value[1]))) {
					if (strchr(value, '/')) {
						node->i_value = rz_num_get(cfg->num, value);
					} else {
						node->i_value = rz_num_math(cfg->num, value);
					}
				} else {
					node->i_value = 0;
				}
				node->flags |= CN_INT;
			}
		}
	} else { // Create a new RzConfigNode
		oi = UT64_MAX;
		if (!cfg->lock) {
			node = rz_config_node_new(name, value);
			if (node) {
				if (__is_true_or_false(value)) {
					node->flags |= CN_BOOL;
					node->i_value = rz_str_is_true(value) ? 1 : 0;
				}
				ht_sp_insert(cfg->ht, node->name, node);
				rz_list_append(cfg->nodes, node);
			} else {
				eprintf("rz_config_set: unable to create a new RzConfigNode\n");
			}
		} else {
			eprintf("rz_config_set: variable '%s' not found\n", name);
		}
	}

	if (node && node->setter) {
		if (!node->setter(cfg->user, node)) {
			if (oi != UT64_MAX) {
				node->i_value = oi;
			}
			free(node->value);
			node->value = rz_str_dup(ov ? ov : "");
			free(ov);
			return NULL;
		}
	}
beach:
	free(ov);
	return node;
}

/**
 * \brief Appends the given node to the config \p cfg.
 *
 * \param cfg The configuration the node is appended.
 * \param node The node to append.
 * \return bool True if the node was successful added. False otherwise.
 */
RZ_API bool rz_config_add_node(RZ_BORROW RzConfig *cfg, RZ_OWN RzConfigNode *node) {
	rz_return_val_if_fail(cfg && node, false);
	if (cfg->lock) {
		RZ_LOG_WARN("Config locked. Plugin config node not copied.\n");
		rz_config_node_free(node);
		return false;
	}
	ht_sp_insert(cfg->ht, node->name, node);
	rz_list_append(cfg->nodes, node);
	return true;
}

/* rz_config_desc takes a RzConfig and a name,
 * rz_config_node_desc takes a RzConfigNode
 * Both set and return node->desc */
RZ_API const char *rz_config_desc(RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name), NULL);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	return rz_config_node_desc(node, desc);
}

RZ_API const char *rz_config_node_desc(RzConfigNode *node, RZ_NULLABLE const char *desc) {
	rz_return_val_if_fail(node, NULL);
	if (desc) {
		free(node->desc);
		node->desc = rz_str_dup(desc);
	}
	return node->desc;
}

RZ_API bool rz_config_rm(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name) && cfg, false);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		ht_sp_delete(cfg->ht, node->name);
		rz_list_delete_data(cfg->nodes, node);
		return true;
	}
	return false;
}

RZ_API void rz_config_node_value_format_i(char *buf, size_t buf_size, const ut64 i, RZ_NULLABLE RzConfigNode *node) {
	if (node && rz_config_node_is_bool(node)) {
		rz_str_ncpy(buf, rz_str_bool((int)i), buf_size);
		return;
	}
	if (i < 1024) {
		snprintf(buf, buf_size, "%" PFMT64d "", i);
	} else {
		snprintf(buf, buf_size, "0x%08" PFMT64x "", i);
	}
}

/**
 * Writes the integer \p value in the config variable of \p name only and only if
 * the variable is integer.
 */
RZ_API RzConfigNode *rz_config_set_i(RzConfig *cfg, RZ_NONNULL const char *name, const ut64 i) {
	char buf[128], *ov = NULL;
	rz_return_val_if_fail(cfg && name, NULL);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		if (rz_config_node_is_ro(node)) {
			node = NULL;
			goto beach;
		}
		if (node->value) {
			ov = rz_str_dup(node->value);
		}
		rz_config_node_value_format_i(buf, sizeof(buf), i, NULL);
		free(node->value);
		node->value = rz_str_dup(buf);
		if (!node->value) {
			node = NULL;
			goto beach;
		}
		node->i_value = i;
	} else {
		if (!cfg->lock) {
			rz_config_node_value_format_i(buf, sizeof(buf), i, NULL);
			node = rz_config_node_new(name, buf);
			if (!node) {
				node = NULL;
				goto beach;
			}
			node->flags = CN_RW | CN_INT;
			node->i_value = i;
			ht_sp_insert(cfg->ht, node->name, node);
			if (cfg->nodes) {
				rz_list_append(cfg->nodes, node);
			}
		} else {
			RZ_LOG_ERROR("(locked: no new keys can be created (%s))\n", name);
		}
	}

	if (node && node->setter) {
		ut64 oi = node->i_value;
		int ret = node->setter(cfg->user, node);
		if (!ret) {
			node->i_value = oi;
			free(node->value);
			node->value = rz_str_dup(ov ? ov : "");
		}
	}
beach:
	free(ov);
	return node;
}

static int cmp(RzConfigNode *a, RzConfigNode *b, void *user) {
	return strcmp(a->name, b->name);
}

RZ_API void rz_config_lock(RzConfig *cfg, int l) {
	rz_list_sort(cfg->nodes, (RzListComparator)cmp, NULL);
	cfg->lock = l;
}

RZ_API bool rz_config_readonly(RzConfig *cfg, const char *key) {
	RzConfigNode *n = rz_config_node_get(cfg, key);
	if (n) {
		n->flags |= CN_RO;
		return true;
	}
	return false;
}

RZ_API RzConfig *rz_config_new(void *user) {
	RzConfig *cfg = RZ_NEW0(RzConfig);
	if (!cfg) {
		return NULL;
	}
	cfg->ht = ht_sp_new(HT_STR_DUP, NULL, NULL);
	cfg->nodes = rz_list_newf((RzListFree)rz_config_node_free);
	if (!cfg->nodes) {
		RZ_FREE(cfg);
		return NULL;
	}
	cfg->user = user;
	cfg->num = NULL;
	cfg->lock = 0;
	return cfg;
}

RZ_API RzConfig *rz_config_clone(RzConfig *cfg) {
	RzListIter *iter;
	RzConfigNode *node;
	RzConfig *c = rz_config_new(cfg->user);
	if (!c) {
		return NULL;
	}
	rz_list_foreach (cfg->nodes, iter, node) {
		RzConfigNode *nn = rz_config_node_clone(node);
		ht_sp_insert(c->ht, node->name, nn);
		rz_list_append(c->nodes, nn);
	}
	c->lock = cfg->lock;
	return c;
}

RZ_API void rz_config_free(RzConfig *cfg) {
	if (cfg) {
		cfg->nodes->free = rz_config_node_free;
		rz_list_free(cfg->nodes);
		ht_sp_free(cfg->ht);
		free(cfg);
	}
}

RZ_API void rz_config_visual_hit_i(RzConfig *cfg, const char *name, int delta) {
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node && rz_config_node_is_int(node)) {
		(void)rz_config_set_i(cfg, name, rz_config_get_i(cfg, name) + delta);
	}
}

RZ_API void rz_config_bump(RzConfig *cfg, const char *key) {
	char *orig = rz_str_dup(rz_config_get(cfg, key));
	if (orig) {
		rz_config_set(cfg, key, orig);
		free(orig);
	}
}

RZ_API void rz_config_serialize(RZ_NONNULL RzConfig *config, RZ_NONNULL Sdb *db) {
	RzListIter *iter;
	RzConfigNode *node;
	rz_list_foreach (config->nodes, iter, node) {
		sdb_set(db, node->name, node->value);
	}
}

static bool load_config_cb(void *user, const SdbKv *kv) {
	RzConfig *config = user;
	RzConfigNode *node = rz_config_node_get(config, sdbkv_key(kv));
	if (node) {
		rz_config_set(config, sdbkv_key(kv), sdbkv_value(kv));
	}
	return true;
}

RZ_API bool rz_config_unserialize(RZ_NONNULL RzConfig *config, RZ_NONNULL Sdb *db, RZ_NULLABLE char **err) {
	sdb_foreach(db, load_config_cb, config);
	return true;
}

/**
 * \brief Sets the configuration variable and its value passed as argument
 *
 * \param cfg reference to RzConfig
 * \param str reference the configuration variable string (eg, 'asm.arch=x86')
 */
RZ_API bool rz_config_eval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(str, false);

	char *name = rz_str_trim_dup(str);
	char *value = strchr(name, '=');
	if (!value) {
		free(name);
		return false;
	}
	*value++ = 0;
	rz_config_set(cfg, name, value);
	free(name);
	return true;
}
