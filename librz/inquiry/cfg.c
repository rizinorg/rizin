// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry/rz_cfg.h>

struct rz_icfg_t {
	RzVector /* ut64 */ proc_entries; ///< Sorted vector of all procedure entry points in the icfg.
	RzGraph /*<RzCFGNode *, RzCFGEdgeType>*/ *icfg;
};

struct rz_cfg_t {
	ut64 entry;
	RzIterator *cfg_nodes; ///< An iterator over the sub-graph in the iCFG belonging to the function.
};

RZ_API RZ_OWN RzICFG *rz_icfg_new() {
	RzICFG *m = RZ_NEW0(RzICFG);
	if (!m) {
		return NULL;
	}
	RzGraph *icfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, NULL, (RzGraphNodeDataFree)rz_icfg_node_free, NULL);
	if (!icfg) {
		free(m);
		return NULL;
	}
	m->icfg = icfg;
	return m;
}

RZ_API void rz_icfg_free(RZ_NULLABLE RZ_OWN RzICFG *map) {
	if (!map) {
		return;
	}
	rz_graph_free(map->icfg);
	free(map);
}

RZ_API bool rz_icfg_get_cfg(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 entry_point, RZ_OUT RzCFG *cfg_out) {
	rz_return_val_if_fail(icfg, false);
	// TODO
	rz_warn_if_reached();
	return false;
}

RZ_API RZ_OWN RzCFGNode *rz_icfg_node_new() {
	RzCFGNode *node = RZ_NEW0(RzCFGNode);
	if (!node) {
		return NULL;
	}
	rz_vector_init(&node->insn_offsets, sizeof(ut16), NULL, NULL);
	return node;
}

RZ_API void rz_icfg_node_free(RZ_NULLABLE RZ_OWN RzCFGNode *node) {
	rz_return_if_fail(node);
	if (!node) {
		return;
	}
	rz_vector_fini(&node->insn_offsets);
	free(node);
}

RZ_API void rz_cfg_fini(RZ_NULLABLE RZ_BORROW RzCFG *cfg) {
	if (!cfg) {
		return;
	}
	rz_iterator_fini(cfg->cfg_nodes);
}
