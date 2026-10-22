// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry/rz_cfg.h>

struct rz_cfg_map_t {
	HtUP /* fcn_addr, RzGraph */ *map;
};

RZ_API RZ_OWN RzCFGMap *rz_cfg_map_new() {
	RzCFGMap *m = RZ_NEW0(RzCFGMap);
	if (!m) {
		return NULL;
	}
	HtUP *fcn_cfgs = ht_up_new(NULL, (HtUPFreeValue)rz_graph_free);
	if (!fcn_cfgs) {
		free(m);
		return NULL;
	}
	m->map = fcn_cfgs;
	return m;
}

RZ_API void rz_cfg_map_free(RZ_NULLABLE RZ_OWN RzCFGMap *map) {
	if (!map) {
		return;
	}
	ht_up_free(map->map);
	free(map);
}

RZ_API RZ_BORROW RzGraph *rz_cfg_map_get_cfg(RZ_NONNULL RZ_BORROW RzCFGMap *map, ut64 entry_point) {
	rz_return_val_if_fail(map, NULL);
	RzGraph *cfg = ht_up_find(map->map, entry_point, NULL);
	if (!cfg) {
		if (!(cfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, NULL, (RzGraphNodeDataFree)rz_cfg_node_free, NULL))) {
			rz_warn_if_reached();
			return NULL;
		}
		ht_up_insert(map->map, entry_point, cfg);
	}
	return cfg;
}

RZ_API RZ_OWN RzCFGNode *rz_cfg_node_new() {
	RzCFGNode *node = RZ_NEW0(RzCFGNode);
	if (!node) {
		return NULL;
	}
	rz_vector_init(&node->insn_offsets, sizeof(ut16), NULL, NULL);
	return node;
}

RZ_API void rz_cfg_node_free(RZ_NULLABLE RZ_OWN RzCFGNode *node) {
	rz_return_if_fail(node);
	if (!node) {
		return;
	}
	rz_vector_fini(&node->insn_offsets);
	free(node);
}
