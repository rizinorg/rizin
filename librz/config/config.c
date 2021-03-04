// SPDX-FileCopyrightText: 2006-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_config.h"

RZ_API RzConfigNode *rz_config_node_new(const char *name, const char *value) {
	rz_return_val_if_fail(name && *name && value, NULL);
	RzConfigNode *node = RZ_NEW0(RzConfigNode);
	if (!node) {
		return NULL;
	}
	node->name = strdup(name);
	node->value = strdup(value ? value : "");
	node->flags = CN_RW | CN_STR;
	node->i_value = rz_num_get(NULL, value);
	node->options = rz_list_new();
	return node;
}

RZ_API RzConfigNode *rz_config_node_clone(RzConfigNode *n) {
	rz_return_val_if_fail(n, NULL);
	RzConfigNode *cn = RZ_NEW0(RzConfigNode);
	if (!cn) {
		return NULL;
	}
	cn->name = strdup(n->name);
	cn->desc = n->desc ? strdup(n->desc) : NULL;
	cn->value = strdup(n->value ? n->value : "");
	cn->i_value = n->i_value;
	cn->flags = n->flags;
	cn->setter = n->setter;
	cn->options = rz_list_clone(n->options);
	return cn;
}

RZ_API void rz_config_node_free(void *n) {
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

static void config_print_value_json(RzConfig *cfg, RzConfigNode *node) {
	rz_return_if_fail(cfg && node);
	const char *val = node->value;
	if (!val) {
		val = "0";
	}
	char *sval = rz_str_escape(val);
	if (rz_config_node_is_bool(node) || rz_config_node_is_int(node)) {
		if (!strncmp(val, "0x", 2)) {
			ut64 n = rz_num_get(NULL, val);
			cfg->cb_printf("%" PFMT64d, n);
		} else if (rz_str_isnumber(val) || (*val /* HACK */ && rz_str_is_bool(val))) {
			cfg->cb_printf("%s", val); // TODO: always use true/false for bool json str
		} else {
			cfg->cb_printf("\"%s\"", sval);
		}
	} else {
		cfg->cb_printf("\"%s\"", sval);
	}
	free(sval);
}

static void config_print_node(RzConfig *cfg, RzConfigNode *node, const char *pfx, const char *sfx, bool verbose, bool json) {
	rz_return_if_fail(cfg && node && pfx && sfx);
	char *option;
	bool isFirst;
	RzListIter *iter;
	char *es = NULL;

	if (json) {
		if (verbose) {
			cfg->cb_printf("{");
			cfg->cb_printf("\"name\":\"%s\",", node->name);
			cfg->cb_printf("\"value\":");
			config_print_value_json(cfg, node);
			cfg->cb_printf(",\"type\":\"%s\",", rz_config_node_type(node));
			es = rz_str_escape(node->desc);
			if (es) {
				cfg->cb_printf("\"desc\":\"%s\",", es);
				free(es);
			}
			cfg->cb_printf("\"ro\":%s", rz_str_bool(rz_config_node_is_ro(node)));
			if (!rz_list_empty(node->options)) {
				isFirst = true;
				cfg->cb_printf(",\"options\":[");
				rz_list_foreach (node->options, iter, option) {
					es = rz_str_escape(option);
					if (es) {
						if (isFirst) {
							isFirst = false;
						} else {
							cfg->cb_printf(",");
						}
						cfg->cb_printf("\"%s\"", es);
						free(es);
					}
				}
				cfg->cb_printf("]");
			}
			cfg->cb_printf("}");
		} else {
			cfg->cb_printf("\"%s\":", node->name);
			config_print_value_json(cfg, node);
		}
	} else {
		if (verbose) {
			cfg->cb_printf("%s%s = %s%s %s; %s", pfx,
				node->name, node->value, sfx,
				rz_config_node_is_ro(node) ? "(ro)" : "",
				node->desc);
			if (!rz_list_empty(node->options)) {
				isFirst = true;
				cfg->cb_printf(" [");
				rz_list_foreach (node->options, iter, option) {
					if (isFirst) {
						isFirst = false;
					} else {
						cfg->cb_printf(", ");
					}
					cfg->cb_printf("%s", option);
				}
				cfg->cb_printf("]");
			}
			cfg->cb_printf("\n");
		} else {
			cfg->cb_printf("%s%s = %s%s\n", pfx,
				node->name, node->value, sfx);
		}
	}
}

RZ_API void rz_config_list(RzConfig *cfg, const char *str, int rad) {
	rz_return_if_fail(cfg);
	RzConfigNode *node;
	RzListIter *iter;
	const char *sfx = "";
	const char *pfx = "";
	int len = 0;
	bool verbose = false;
	bool json = false;
	bool isFirst = false;

	if (RZ_STR_ISNOTEMPTY(str)) {
		str = rz_str_trim_head_ro(str);
		len = strlen(str);
		if (len > 0 && str[0] == 'j') {
			str++;
			len--;
			json = true;
			rad = 'J';
		}
		if (len > 0 && str[0] == ' ') {
			str++;
			len--;
		}
		if (strlen(str) == 0) {
			str = NULL;
			len = 0;
		}
	}

	switch (rad) {
	case 1:
		pfx = "\"e ";
		sfx = "\"";
	/* fallthrou */
	case 0:
		rz_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp(str, node->name, len)))) {
				config_print_node(cfg, node, pfx, sfx, verbose, json);
			}
		}
		break;
	case 2:
		rz_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp(str, node->name, len)))) {
				if (!str || !strncmp(str, node->name, len)) {
					cfg->cb_printf("%20s: %s\n", node->name,
						node->desc ? node->desc : "");
				}
			}
		}
		break;
	case 's':
		if (str && *str) {
			rz_list_foreach (cfg->nodes, iter, node) {
				char *space = strdup(node->name);
				char *dot = strchr(space, '.');
				if (dot) {
					*dot = 0;
				}
				if (!strcmp(str, space)) {
					cfg->cb_printf("%s\n", dot + 1);
				}
				free(space);
			}
		} else {
			char *oldSpace = NULL;
			rz_list_foreach (cfg->nodes, iter, node) {
				char *space = strdup(node->name);
				char *dot = strchr(space, '.');
				if (dot) {
					*dot = 0;
				}
				if (oldSpace) {
					if (!strcmp(space, oldSpace)) {
						free(space);
						continue;
					}
					free(oldSpace);
					oldSpace = space;
				} else {
					oldSpace = space;
				}
				cfg->cb_printf("%s\n", space);
			}
			free(oldSpace);
		}
		break;
	case 'v':
		verbose = true;
		rz_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp(str, node->name, len)))) {
				config_print_node(cfg, node, pfx, sfx, verbose, json);
			}
		}
		break;
	case 'q':
		rz_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp(str, node->name, len)))) {
				cfg->cb_printf("%s\n", node->name);
			}
		}
		break;
	case 'J':
		verbose = true;
	/* fallthrou */
	case 'j':
		isFirst = true;
		if (verbose) {
			cfg->cb_printf("[");
		} else {
			cfg->cb_printf("{");
		}
		rz_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp(str, node->name, len)))) {
				if (!str || !strncmp(str, node->name, len)) {
					if (isFirst) {
						isFirst = false;
					} else {
						cfg->cb_printf(",");
					}
					config_print_node(cfg, node, pfx, sfx, verbose, true);
				}
			}
		}
		if (verbose) {
			cfg->cb_printf("]\n");
		} else {
			cfg->cb_printf("}\n");
		}
		break;
	}
}

RZ_API RzConfigNode *rz_config_node_get(RzConfig *cfg, const char *name) {
	rz_return_val_if_fail(cfg && name, NULL);
	return ht_pp_find(cfg->ht, name, NULL);
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
RZ_API const char *rz_config_get(RzConfig *cfg, const char *name) {
	rz_return_val_if_fail(cfg && name, NULL);
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
RZ_API bool rz_config_toggle(RzConfig *cfg, const char *name) {
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
RZ_API ut64 rz_config_get_i(RzConfig *cfg, const char *name) {
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
RZ_API bool rz_config_get_b(RzConfig *cfg, const char *name) {
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
RZ_API RzConfigNode *rz_config_set_b(RzConfig *cfg, const char *name, bool value) {
	RzConfigNode *node = NULL;
	char *ov = NULL;
	ut64 oi = 0;

	rz_return_val_if_fail(cfg && cfg->ht, NULL);
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name), NULL);

	node = rz_config_node_get(cfg, name);
	if (node) {
		if (rz_config_node_is_ro(node)) {
			RZ_LOG_DEBUG("(error: '%s' config key is read only)\n", name);
			return node;
		}

		oi = node->i_value;
		if (node->value) {
			ov = strdup(node->value);
		}
		if (rz_config_node_is_bool(node)) {
			node->i_value = value ? 1 : 0;
			char *svalue = strdup(rz_str_bool(value));
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
			ht_pp_insert(cfg->ht, node->name, node);
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
			node->value = strdup(ov ? ov : "");
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
RZ_API RzConfigNode *rz_config_set(RzConfig *cfg, const char *name, const char *value) {
	RzConfigNode *node = NULL;
	char *ov = NULL;
	ut64 oi;

	rz_return_val_if_fail(cfg && cfg->ht, NULL);
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name), NULL);

	node = rz_config_node_get(cfg, name);
	if (node) {
		if (rz_config_node_is_ro(node)) {
			eprintf("(error: '%s' config key is read only)\n", name);
			return node;
		}
		oi = node->i_value;
		if (node->value) {
			ov = strdup(node->value);
			if (!ov) {
				goto beach;
			}
		} else {
			free(node->value);
			node->value = strdup("");
		}
		if (rz_config_node_is_bool(node)) {
			bool b = rz_str_is_true(value);
			node->i_value = b ? 1 : 0;
			char *value = strdup(rz_str_bool(b));
			if (value) {
				free(node->value);
				node->value = value;
			}
		} else {
			if (!value) {
				free(node->value);
				node->value = strdup("");
				node->i_value = 0;
			} else {
				if (node->value == value) {
					goto beach;
				}
				free(node->value);
				node->value = strdup(value);
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
				ht_pp_insert(cfg->ht, node->name, node);
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
			node->value = strdup(ov ? ov : "");
			free(ov);
			return NULL;
		}
	}
beach:
	free(ov);
	return node;
}

/* rz_config_desc takes a RzConfig and a name,
 * rz_config_node_desc takes a RzConfigNode
 * Both set and return node->desc */
RZ_API const char *rz_config_desc(RzConfig *cfg, const char *name, const char *desc) {
	RzConfigNode *node = rz_config_node_get(cfg, name);
	return rz_config_node_desc(node, desc);
}

RZ_API const char *rz_config_node_desc(RzConfigNode *node, const char *desc) {
	rz_return_val_if_fail(node, NULL);
	if (desc) {
		free(node->desc);
		node->desc = strdup(desc);
	}
	return node->desc;
}

RZ_API bool rz_config_rm(RzConfig *cfg, const char *name) {
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		ht_pp_delete(cfg->ht, node->name);
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
RZ_API RzConfigNode *rz_config_set_i(RzConfig *cfg, const char *name, const ut64 i) {
	char buf[128], *ov = NULL;
	rz_return_val_if_fail(cfg && name, NULL);
	RzConfigNode *node = rz_config_node_get(cfg, name);
	if (node) {
		if (rz_config_node_is_ro(node)) {
			node = NULL;
			goto beach;
		}
		if (node->value) {
			ov = strdup(node->value);
		}
		rz_config_node_value_format_i(buf, sizeof(buf), i, NULL);
		free(node->value);
		node->value = strdup(buf);
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
			ht_pp_insert(cfg->ht, node->name, node);
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
			node->value = strdup(ov ? ov : "");
		}
	}
beach:
	free(ov);
	return node;
}

static void __evalString(RzConfig *cfg, char *name) {
	if (!*name) {
		return;
	}
	char *eq = strchr(name, '=');
	if (eq) {
		*eq++ = 0;
		rz_str_trim(name);
		rz_str_trim(eq);
		if (*name) {
			(void)rz_config_set(cfg, name, eq);
		}
	} else {
		if (rz_str_endswith(name, ".")) {
			rz_config_list(cfg, name, 0);
		} else {
			const char *v = rz_config_get(cfg, name);
			if (v) {
				cfg->cb_printf("%s\n", v);
			} else {
				eprintf("Invalid config key %s\n", name);
			}
		}
	}
}

RZ_API bool rz_config_eval(RzConfig *cfg, const char *str, bool many) {
	rz_return_val_if_fail(cfg && str, false);

	char *s = rz_str_trim_dup(str);

	if (!*s || !strcmp(s, "help")) {
		rz_config_list(cfg, NULL, 0);
		free(s);
		return false;
	}

	if (*s == '-') {
		rz_config_rm(cfg, s + 1);
		free(s);
		return false;
	}
	if (many) {
		// space separated list of k=v k=v,..
		// if you want to use spaces go for base64 or e.
		RzList *list = rz_str_split_list(s, ",", 0);
		RzListIter *iter;
		char *name;
		rz_list_foreach (list, iter, name) {
			__evalString(cfg, name);
		}
		free(s);
		return true;
	}
	__evalString(cfg, s);
	free(s);
	return true;
}

static int cmp(RzConfigNode *a, RzConfigNode *b) {
	return strcmp(a->name, b->name);
}

RZ_API void rz_config_lock(RzConfig *cfg, int l) {
	rz_list_sort(cfg->nodes, (RzListComparator)cmp);
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
	cfg->ht = ht_pp_new0();
	cfg->nodes = rz_list_newf((RzListFree)rz_config_node_free);
	if (!cfg->nodes) {
		RZ_FREE(cfg);
		return NULL;
	}
	cfg->user = user;
	cfg->num = NULL;
	cfg->lock = 0;
	cfg->cb_printf = (void *)printf;
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
		ht_pp_insert(c->ht, node->name, nn);
		rz_list_append(c->nodes, nn);
	}
	c->lock = cfg->lock;
	c->cb_printf = cfg->cb_printf;
	return c;
}

RZ_API void rz_config_free(RzConfig *cfg) {
	if (cfg) {
		cfg->nodes->free = rz_config_node_free;
		rz_list_free(cfg->nodes);
		ht_pp_free(cfg->ht);
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
	char *orig = strdup(rz_config_get(cfg, key));
	if (orig) {
		rz_config_set(cfg, key, orig);
		free(orig);
	}
}

RZ_API void rz_config_serialize(RZ_NONNULL RzConfig *config, RZ_NONNULL Sdb *db) {
	RzListIter *iter;
	RzConfigNode *node;
	rz_list_foreach (config->nodes, iter, node) {
		sdb_set(db, node->name, node->value, 0);
	}
}

static bool load_config_cb(void *user, const char *k, const char *v) {
	RzConfig *config = user;
	RzConfigNode *node = rz_config_node_get(config, k);
	if (node) {
		rz_config_set(config, k, v);
	}
	return true;
}

RZ_API bool rz_config_unserialize(RZ_NONNULL RzConfig *config, RZ_NONNULL Sdb *db, RZ_NULLABLE char **err) {
	sdb_foreach(db, load_config_cb, config);
	return true;
}
