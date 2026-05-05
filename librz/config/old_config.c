// SPDX-FileCopyrightText: 2006-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "config_internal.h"

static bool config_node_init(RzConfigNode *node, RZ_NONNULL const char *name, RZ_NONNULL const char *value) {
	if (RZ_STR_ISEMPTY(name) || !value) {
		return false;
	}

	node->name = rz_str_dup(name);
	node->value = rz_str_dup(value);
	node->flags = CN_STR;
	node->i_value = rz_num_get(NULL, value);
	node->options = rz_list_new();

	return node->name && node->value && node->options;
}

RZ_IPI void rz_config_node_fini(RZ_NULLABLE RzConfigNode *node) {
	if (!node) {
		return;
	}
	free(node->name);
	free(node->desc);
	free(node->value);
	rz_list_free(node->options);
}

RZ_API RZ_BORROW RzConfigNode *rz_config_node_get(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry || entry->is_variable) {
		return NULL;
	}
	return &entry->node;
}

static const char *config_node_get(RzConfigNode *node) {
	if (rz_config_node_is_bool(node)) {
		return rz_str_bool(rz_str_is_true(node->value));
	}
	return node->value;
}

static ut64 config_node_get_i(RzConfigNode *node) {
	if (node->i_value || !strcmp(node->value, "false")) {
		return node->i_value;
	}
	// TODO: Remove it once the switch to `rz_config_get_b()` is complete
	if (!strcmp(node->value, "true")) {
		return 1;
	}
	return (ut64)rz_num_math(NULL, node->value);
}

static bool config_node_get_b(RzConfigNode *node) {
	if (!rz_config_node_is_bool(node)) {
		RZ_LOG_DEBUG("error: '%s' is not a boolean variable\n", node->name);
		return false;
	}
	return rz_str_is_true(node->value);
}

static bool config_node_toggle(RzConfigNode *node, void *user) {
	if (!rz_config_node_is_bool(node)) {
		RZ_LOG_DEBUG("error: '%s' is not a boolean variable\n", node->name);
		return false;
	} else if (rz_config_node_is_ro(node)) {
		RZ_LOG_DEBUG("error: '%s' config key is read only\n", node->name);
		return false;
	}
	(void)rz_config_node_set_integer(node, !node->i_value, user);
	return true;
}

/**
 * Returns the value of the config variable of \p name as a string
 */
RZ_API RZ_BORROW const char *rz_config_get(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_DEBUG("config: variable '%s' not found\n", name);
		return NULL;
	} else if (entry->is_variable) {
		return rz_config_var_get_string(&entry->var);
	}
	return config_node_get(&entry->node);
}

/**
 * Reads the value of the config variable of \p name only and only if
 * the variable is boolean, then tries to write back the inverted value.
 * Returns true in case of success.
 */
RZ_API bool rz_config_toggle(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		return false;
	} else if (entry->is_variable) {
		return rz_config_toggle_var_bool(&entry->var);
	}

	return config_node_toggle(&entry->node, cfg->user);
}

/**
 * Reads the value of the config variable of \p name only and only if
 * the variable is integer.
 */
RZ_API ut64 rz_config_get_i(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), 0);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_DEBUG("config: variable '%s' not found\n", name);
		return 0;
	} else if (entry->is_variable) {
		return rz_config_var_get_integer(&entry->var);
	}
	return config_node_get_i(&entry->node);
}

/**
 * Reads the value of the config variable of \p name only and only if
 * the variable is boolean. Returns false in case of the failure.
 */
RZ_API bool rz_config_get_b(RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_DEBUG("config: variable '%s' not found\n", name);
		return NULL;
	} else if (entry->is_variable) {
		return rz_config_var_get_integer(&entry->var);
	}
	return config_node_get_b(&entry->node);
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
		return "int";
	}
	return "";
}

RZ_API RZ_BORROW RzConfigNode *rz_config_set_cb(RZ_BORROW RzConfig *cfg, const char *name, const char *value, RzConfigCallback cb) {
	RzConfigNode *node = rz_config_set(cfg, name, value);
	if (node && (node->setter = cb)) {
		node->setter(cfg->user, node);
	}
	// it's not guaranteed that node is still pointing to the same object.
	// as this old config method will call the callback which may add new
	// config variables which will move or realloc the entry in the vector.
	return rz_config_node_get(cfg, name);
}

RZ_API RZ_BORROW RzConfigNode *rz_config_set_i_cb(RZ_BORROW RzConfig *cfg, const char *name, st64 ivalue, RzConfigCallback cb) {
	RzConfigNode *node = rz_config_set_i(cfg, name, ivalue);
	if (node && (node->setter = cb)) {
		node->setter(cfg->user, node);
	}
	// it's not guaranteed that node is still pointing to the same object.
	// as this old config method will call the callback which may add new
	// config variables which will move or realloc the entry in the vector.
	return rz_config_node_get(cfg, name);
}

static bool __is_true_or_false(const char *s) {
	return s && (!rz_str_casecmp(s, "true") || !rz_str_casecmp(s, "false"));
}

RZ_IPI bool rz_config_node_set_bool(RzConfigNode *node, bool value, void *user) {
	char *ov = NULL;
	ut64 oi = 0;
	if (rz_config_node_is_ro(node)) {
		RZ_LOG_ERROR("error: '%s' config key is read only\n", node->name);
		return false;
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
		RZ_LOG_ERROR("error: '%s' is not a boolean variable\n", node->name);
		free(ov);
		return false;
	}

	if (node && node->setter) {
		if (!node->setter(user, node)) {
			if (oi != UT64_MAX) {
				node->i_value = oi;
			}
			free(node->value);
			node->value = rz_str_dup(ov ? ov : "");
		}
	}

	free(ov);
	return true;
}

RZ_IPI bool rz_config_node_set_integer(RzConfigNode *node, ut64 i, void *user) {
	char buf[128], *ov = NULL;
	if (rz_config_node_is_ro(node)) {
		return false;
	}
	if (node->value) {
		ov = rz_str_dup(node->value);
	}
	rz_config_node_value_format_i(buf, sizeof(buf), i, NULL);
	free(node->value);
	node->value = rz_str_dup(buf);
	if (!node->value) {
		free(ov);
		return false;
	}
	node->i_value = i;

	if (node && node->setter) {
		ut64 oi = node->i_value;
		if (!node->setter(user, node)) {
			node->i_value = oi;
			free(node->value);
			node->value = rz_str_dup(ov ? ov : "");
			free(ov);
			return false;
		}
	}

	free(ov);
	return true;
}

RZ_IPI bool rz_config_node_set_string(RzConfigNode *node, const char *value, void *user) {
	char *ov = NULL;
	ut64 oi;
	if (rz_config_node_is_ro(node)) {
		RZ_LOG_ERROR("error: '%s' config key is read only\n", node->name);
		return false;
	}
	if (node->value == value) {
		return true;
	}
	oi = node->i_value;
	if (node->value) {
		ov = rz_str_dup(node->value);
		if (!ov) {
			free(ov);
			return false;
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
	} else if (rz_config_node_is_str(node)) {
		free(node->value);
		node->value = rz_str_dup(rz_str_get(value));
	} else {
		if (!value) {
			free(node->value);
			node->value = rz_str_dup("0");
			node->i_value = 0;
		} else {
			free(node->value);
			node->value = rz_str_dup(value);
			if (IS_DIGIT(*value) || (value[0] == '-' && IS_DIGIT(value[1]))) {
				if (strchr(value, '/')) {
					node->i_value = rz_num_get(NULL, value);
				} else {
					node->i_value = rz_num_math(NULL, value);
				}
			} else {
				node->i_value = 0;
			}
		}
	}

	if (node && node->setter) {
		if (!node->setter(user, node)) {
			if (oi != UT64_MAX) {
				node->i_value = oi;
			}
			free(node->value);
			node->value = rz_str_dup(ov ? ov : "");
			free(ov);
			return false;
		}
	}

	free(ov);
	return true;
}

/**
 * Writes the boolean \p value in the config variable of \p name only and only if
 * the variable is boolean.
 */
RZ_API RZ_BORROW RzConfigNode *rz_config_set_b(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, bool value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigNode *node = NULL;
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (entry) {
		if (entry->is_variable) {
			rz_config_var_set_bool(&entry->var, value);
			return NULL;
		}
		node = &entry->node;
	} else {
		RzConfigEntry new_entry = { 0 };
		if (!config_node_init(&new_entry.node, name, rz_str_bool(value))) {
			rz_config_node_fini(&new_entry.node);
			return NULL;
		}
		new_entry.node.flags = CN_BOOL;
		new_entry.node.i_value = value ? 1 : 0;
		config_add_entry(cfg, name, &new_entry, false);
		node = rz_config_node_get(cfg, name);
	}

	if (!rz_config_node_set_bool(node, value, cfg->user)) {
		return NULL;
	}
	return node;
}

/* TODO: reduce number of strdups here */
/**
 * Writes the string \p value in the config variable of \p name.
 */
RZ_API RZ_BORROW RzConfigNode *rz_config_set(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, const char *value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigNode *node = NULL;
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (entry) {
		if (entry->is_variable) {
			rz_config_var_set_any(&entry->var, value);
			return NULL;
		}
		node = &entry->node;
	} else {
		RzConfigEntry new_entry = { 0 };
		if (!config_node_init(&new_entry.node, name, value)) {
			rz_config_node_fini(&new_entry.node);
			return NULL;
		}
		if (__is_true_or_false(value)) {
			new_entry.node.flags = CN_BOOL;
			new_entry.node.i_value = rz_str_is_true(value) ? 1 : 0;
		}
		config_add_entry(cfg, name, &new_entry, false);
		node = rz_config_node_get(cfg, name);
	}

	if (!rz_config_node_set_string(node, value, cfg->user)) {
		return NULL;
	}
	return node;
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

RZ_API void rz_config_node_value_format_i(RZ_OUT char *buf, size_t buf_size, const ut64 i, RZ_NULLABLE RzConfigNode *node) {
	if (node && rz_config_node_is_bool(node)) {
		rz_str_ncpy(buf, rz_str_bool((int)i), buf_size);
		return;
	}
	if (i < 1024) {
		snprintf(buf, buf_size, "%" PFMT64d, i);
	} else {
		snprintf(buf, buf_size, "0x%08" PFMT64x, i);
	}
}

/**
 * Only exists for temporary compatibility with external plugins using the old RzConfig API.
 * It is a no-op now.
 */
RZ_DEPRECATE RZ_API void rz_config_lock(RZ_BORROW RzConfig *cfg, int l) {
	(void)cfg, (void)l;
}

/**
 * Writes the integer \p value in the config variable of \p name only and only if
 * the variable is integer.
 */
RZ_API RZ_BORROW RzConfigNode *rz_config_set_i(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, const ut64 i) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigNode *node = NULL;
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (entry) {
		if (entry->is_variable) {
			rz_config_var_set_integer(&entry->var, i);
			return NULL;
		}
		node = &entry->node;
	} else {
		char buf[128];
		RzConfigEntry new_entry = { 0 };
		rz_config_node_value_format_i(buf, sizeof(buf), i, NULL);

		if (!config_node_init(&new_entry.node, name, buf)) {
			rz_config_node_fini(&new_entry.node);
			return NULL;
		}
		new_entry.node.flags = CN_INT;
		new_entry.node.i_value = i;
		config_add_entry(cfg, name, &new_entry, false);
		node = rz_config_node_get(cfg, name);
	}

	if (!rz_config_node_set_integer(node, i, cfg->user)) {
		return NULL;
	}

	return node;
}

RZ_IPI bool rz_config_node_is_readonly(const RzConfigNode *n) {
	return n->flags & CN_RO;
}

RZ_IPI bool rz_config_node_set_readonly(RzConfigNode *n, bool read_only) {
	if (read_only) {
		n->flags |= CN_RO;
	} else {
		n->flags &= ~CN_RO;
	}
	return true;
}

RZ_API void rz_config_visual_hit_i(RzConfig *cfg, const char *name, int delta) {
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node && rz_config_node_is_int(node)) {
		(void)rz_config_set_i(cfg, name, rz_config_get_i(cfg, name) + delta);
	}
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

RZ_API ut32 rz_config_node_get_var_flags(RZ_NONNULL const RzConfigNode *node) {
	rz_return_val_if_fail(node, 0);
	ut32 flags = 0;

	if (!(node->flags & CN_RO)) {
		flags |= RZ_CONFIG_VAR_FLAG_WRITABLE;
	}
	if (node->flags & CN_BOOL) {
		flags |= RZ_CONFIG_VAR_TYPE_BOOL;
	}
	if (node->flags & CN_INT) {
		flags |= RZ_CONFIG_VAR_TYPE_INT;
	}
	if (node->flags & CN_STR) {
		flags |= RZ_CONFIG_VAR_TYPE_STR;
	}
	if (node->setter) {
		flags |= RZ_CONFIG_VAR_FLAG_BIND;
	}
	return flags;
}
