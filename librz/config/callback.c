/* radare - LGPL - Copyright 2006-2019 - pancake */

#include "rz_config.h"

static bool rz_config_setter_q(void *data) {
	RConfigNode *node = data;
	*(node->cb_ptr_q) = node->i_value;
	return true;
}

static bool rz_config_setter_i(void *data) {
	RConfigNode *node = data;
	*(node->cb_ptr_i) = node->i_value;
	return true;
}

static bool rz_config_setter_s(void *data) {
	RConfigNode *node = data;
	if (!node->value || !*node->value) {
		free (*node->cb_ptr_s);
		*node->cb_ptr_s = NULL;
	} else {
		*node->cb_ptr_s = rz_str_dup (*node->cb_ptr_s, node->value);
	}
	return true;
}

RZ_API bool rz_config_set_setter_q(RConfig *cfg, const char *name, ut64 *ptr) {
	RConfigNode *node = rz_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_q = ptr;
		node->setter = (void *) &rz_config_setter_q;
		return true;
	}
	return false;
}

RZ_API bool rz_config_set_setter_i(RConfig *cfg, const char *name, int *ptr) {
	RConfigNode *node = rz_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_i = ptr;
		node->setter = (void *) &rz_config_setter_i;
		return true;
	}
	return false;
}

RZ_API bool rz_config_set_setter_s(RConfig *cfg, const char *name, char * *ptr) {
	RConfigNode *node = rz_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_s = ptr;
		node->setter = (void *) &rz_config_setter_s;
		return true;
	}
	return false;
}
