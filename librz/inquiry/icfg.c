// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry/rz_icfg.h>
#include "icfg_priv.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_vector.h"

RZ_IPI char *rz_icfg_node_str(const RzICFGNode *node) {
	RzStrBuf sb = { 0 };
	rz_strbuf_init(&sb);
	rz_strbuf_appendf(&sb, "0x%08" PFMT64x " m: (", node->addr);
	if (node->memberships_n == 1) {
		rz_strbuf_appendf(&sb, "0x%08" PFMT64x, node->proc_memberships.m);
	} else {
		RzIterator it;
		rz_set_u_as_iter(node->proc_memberships.set, &it);
		size_t i = 0;
		ut64 *m;
		rz_iterator_foreach(&it, m) {
			if (i > 0) {
				rz_strbuf_append(&sb, ",");
			}
			rz_strbuf_appendf(&sb, "0x%08" PFMT64x, *m);
			i++;
		}
		rz_iterator_fini(&it);
	}
	rz_strbuf_append(&sb, ")");
	char *s = rz_strbuf_drain_nofree(&sb);
	rz_strbuf_fini(&sb);
	return s;
}

static bool icfg_proc_memberships_contains(const RzICFGNode *node, ut64 proc_membership) {
	if (node->memberships_n > 1) {
		return rz_set_u_contains(node->proc_memberships.set, proc_membership);
	}
	return node->proc_memberships.m == proc_membership;
}

/**
 * \brief Adds a procedure entry point to the memberships of \p node.
 *
 * Memberships are kept inline in an array as long as there are at most RZ_ICFG_PROC_MEMBERSHIPS_DEFAULT of them.
 * Only if more are needed, a set is allocated and all members are moved into it.
 *
 * \return True if \p proc_membership was newly added, false if it was already a member or on allocation failure.
 */
static bool icfg_proc_memberships_add(RZ_NONNULL RzICFGNode *node, ut64 proc_membership) {
	if (icfg_proc_memberships_contains(node, proc_membership)) {
		return false;
	}
	if (node->memberships_n < 1) {
		node->proc_memberships.m = proc_membership;
		node->memberships_n++;
		return true;
	}
	if (node->memberships_n == 1) {
		RzSetU *set = rz_set_u_new();
		if (!set) {
			return false;
		}
		rz_set_u_add(set, node->proc_memberships.m);
		node->proc_memberships.set = set;
		node->memberships_n++;
		rz_set_u_add(set, proc_membership);
		return true;
	}
	rz_set_u_add(node->proc_memberships.set, proc_membership);
	node->memberships_n++;
	return true;
}

static bool icfg_proc_memberships_update(RZ_NONNULL RzICFGNode *dst, const RZ_NONNULL RzICFGNode *src) {
	rz_return_val_if_fail(src->memberships_n > 0, false);
	if (src->memberships_n == 1) {
		return icfg_proc_memberships_add(dst, src->proc_memberships.m);
	}
	RzIterator iter;
	if (!rz_set_u_as_iter(src->proc_memberships.set, &iter)) {
		rz_warn_if_reached();
		return false;
	}
	bool added = false;
	ut64 *val;
	rz_iterator_foreach(&iter, val) {
		added |= icfg_proc_memberships_add(dst, *val);
	}
	rz_iterator_fini(&iter);
	return added;
}

static void icfg_proc_memberships_fini(RzICFGNode *node) {
	if (node->memberships_n > 1) {
		rz_set_u_free(node->proc_memberships.set);
	}
	node->memberships_n = 0;
}

static void rz_icfg_node_free(RZ_NULLABLE RZ_OWN RzICFGNode *node) {
	rz_return_if_fail(node);
	if (!node) {
		return;
	}
	rz_vector_fini(&node->insn_offsets);
	icfg_proc_memberships_fini(node);
	free(node);
}

ut64 node_hash(RZ_NULLABLE const void *data) {
	if (!data) {
		rz_warn_if_reached();
		return 0;
	}
	const RzICFGNode *node = data;
	return node->addr;
}

RZ_API RZ_OWN RzICFG *rz_icfg_new() {
	RzICFG *m = RZ_NEW0(RzICFG);
	if (!m) {
		return NULL;
	}
	RzGraph *icfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, (RzGraphIdentifierHash)node_hash, (RzGraphNodeDataFree)rz_icfg_node_free, NULL);
	if (!icfg) {
		free(m);
		return NULL;
	}
	m->graph = icfg;
	rz_interval_tree_init(&m->itv_tree, NULL);
	rz_vector_init(&m->prepared_edges, sizeof(ICFGEdge), NULL, NULL);
	rz_vector_init(&m->proc_entries, sizeof(ut64), NULL, NULL);
	m->node_conflicts = rz_set_u_new();
	return m;
}

RZ_API void rz_icfg_free(RZ_NULLABLE RZ_OWN RzICFG *icfg) {
	if (!icfg) {
		return;
	}
	rz_interval_tree_fini(&icfg->itv_tree);
	rz_graph_free(icfg->graph);
	rz_vector_fini(&icfg->prepared_edges);
	rz_vector_fini(&icfg->proc_entries);
	rz_set_u_free(icfg->node_conflicts);
	free(icfg);
}

static RZ_OWN RzICFGNode *icfg_node_new(ut64 addr, size_t size, RZ_NONNULL const RzVector *insn_offsets) {
	rz_return_val_if_fail(insn_offsets, NULL);
	RzICFGNode *node = RZ_NEW0(RzICFGNode);
	if (!node) {
		return NULL;
	}
	node->addr = addr;
	node->size = size;
	rz_vector_clone_into(&node->insn_offsets, insn_offsets);
	return node;
}

static int uint_cmp(ut64 *a, ut64 *b, void *user) {
	return (*a > *b) - (*a < *b);
}

typedef struct {
	RzPVector /*<RzIntervalNode *>*/ *itv_node;
} CoveringNodes;

static int itv_node_cmp_asc(const RzIntervalNode *a, const RzIntervalNode *b, void *user) {
	return (a->start < b->start) - (a->start > b->start);
}

static bool itv_intersect_cb(RzIntervalNode *node, void *user) {
	RzPVector /*<RzIntervalNode *>*/ *overlaps = user;
	rz_pvector_insert_sorted(overlaps, node, (RzPVectorComparator)itv_node_cmp_asc, NULL);
	return true;
}

// Changes the size of an overlapping blocks.
// All overlapping blocks are guaranteed to share the same end address.
//
// Case 0 - Block X and Block Y are duplicates -> warn and fail.
// Duplicates must be handled before.
//
// +-  +-
// | X | Y
// +- +-
//
// Case 1 - Block X has a lower start address than Block Y -> Shorten Block Y.
//     +-             +-
//     |              | Y
// +-  | Y  ===>  +-  +-
// | X |          | X
// +- +-          +-
//
// Or
//     +-             +-
//     |              | Y
// +-  | Y  ===>  +-  +-
// | X +-         | X
// +-             +-
//
// NOTE: If you change this part, remember that the start address of every
// block must stay the same! Otherwise edges get invalidated.
static bool solve_intersection(RzICFG *icfg, RzIntervalNode *x_smaller, RzIntervalNode *y_bigger) {
	rz_return_val_if_fail(x_smaller->start > y_bigger->start, false);
	rz_return_val_if_fail(x_smaller->start <= y_bigger->end, false);

	RzGraphNode *graph_node_y = y_bigger->data;
	RzICFGNode *icfg_node_y = rz_graph_node_get_data_mut(graph_node_y);
	RzGraphNode *graph_node_x = x_smaller->data;
	RzICFGNode *icfg_node_x = rz_graph_node_get_data_mut(graph_node_x);

	// Resize in itv tree
	rz_interval_tree_resize(&icfg->itv_tree, y_bigger, y_bigger->start, x_smaller->start - 1);

	// resize icfg size
	icfg_node_y->size = x_smaller->start - y_bigger->start;

	// update insn_offsets
	ut16 last_off = icfg_node_y->size;
	ut16 insn_off;
	do {
		rz_vector_pop(&icfg_node_y->insn_offsets, &insn_off);
	} while (insn_off > last_off);
	rz_warn_if_fail(insn_off == last_off); // Debug check

	// update memberships (important if just added node is itv_x)
	icfg_proc_memberships_update(icfg_node_x, icfg_node_y);

	// add fallthru edge
	rz_icfg_prepare_edge(icfg, y_bigger->start, x_smaller->start, RZ_ICFG_EDGE_TYPE_FALLTHROUGH);
	return true;
}

static bool solve_overlaps(RzICFG *icfg, RzPVector /*<RzIntervalNode *>*/ *overlaps) {
	RzIntervalNode *itv_bigger; // The bigger block (starts at lower address).
	RzIntervalNode *itv_smaller; // The smaller block (starts at higher address).

	bool success = true;
	itv_bigger = rz_pvector_pop(overlaps);
	while (rz_pvector_len(overlaps)) {
		itv_smaller = rz_pvector_pop(overlaps);
		// Duplicates should have been removed before.
		rz_warn_if_fail(itv_smaller->start != itv_bigger->start);

		success &= solve_intersection(icfg, itv_smaller, itv_bigger);
		itv_bigger = itv_smaller;
	}
	return success;
}

static RzGraphNode *get_already_solved(RzPVector /*<RzIntervalNode *>*/ *overlaps, ut64 addr, ut64 size) {
	if (rz_pvector_len(overlaps) == 0) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (overlaps, it) {
		RzIntervalNode *in = *it;
		if (in->start == addr) {
			return in->data;
		}
	}
	return NULL;
}

RZ_API bool rz_icfg_add_node(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 addr, size_t size, RZ_NONNULL const RzVector /*<ut16>*/ *insn_offsets, ut64 proc_membership) {
	rz_return_val_if_fail(icfg && insn_offsets, false);

	RzICFGNode *icfg_node = NULL;
	RzGraphNode *graph_node = NULL;

	printf("Add node: 0x%lx\n", addr);
	// Search for any graph node intersection with the new one.
	RzPVector /*<RzIntervalNode *>*/ overlaps = { 0 };
	rz_pvector_init(&overlaps, NULL);

	rz_interval_tree_all_intersect(&icfg->itv_tree, addr, addr + size, false, itv_intersect_cb, &overlaps);
	bool new_node_overlaps = !rz_pvector_empty(&overlaps);

	graph_node = get_already_solved(&overlaps, addr, size);
	bool was_solved_before = graph_node != NULL;
	if (!graph_node) {
		// Create a new graph node.
		icfg_node = icfg_node_new(addr, size, insn_offsets);
		if (!icfg_node) {
			rz_warn_if_reached();
			goto error;
		}
		if (rz_graph_add_node(icfg->graph, icfg_node, &graph_node) != RZ_GRAPH_STATUS_OK) {
			rz_warn_if_reached();
			goto error;
		}
		// Add the new node to the overlaps vector.
		RzIntervalNode *itv_node = rz_interval_tree_insert(&icfg->itv_tree, addr, addr + size - 1, graph_node);
		rz_pvector_insert_sorted(&overlaps, itv_node, (RzPVectorComparator)itv_node_cmp_asc, NULL);
	} else {
		icfg_node = rz_graph_node_get_data_mut(graph_node);
	}
	if (!icfg_proc_memberships_add(icfg_node, proc_membership)) {
		rz_warn_if_reached();
	}

	if (new_node_overlaps && !was_solved_before && !solve_overlaps(icfg, &overlaps)) {
		rz_warn_if_reached();
	}
	if (icfg_node->memberships_n > 1) {
		rz_set_u_add(icfg->node_conflicts, (utptr)icfg_node);
	}

	if (rz_vector_find_sorted(&icfg->proc_entries, &proc_membership, (RzVectorComparator)uint_cmp, NULL) == SZT_MAX) {
		rz_vector_insert_sorted(&icfg->proc_entries, &proc_membership, (RzVectorComparator)uint_cmp, NULL);
	}
	rz_pvector_fini(&overlaps);
	return true;

error:
	rz_pvector_fini(&overlaps);
	return false;
}

/**
 * \brief Prepares an edge to be added to the ICFG.
 * The nodes for \p from and \p to don't have to exist.
 *
 * NOTE: After all edges were added, rz_icfg_apply() *must* be run to copy the edges to the graph.
 */
RZ_API bool rz_icfg_prepare_edge(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 from, ut64 to, RzICFGEdgeType type) {
	rz_return_val_if_fail(icfg, false);
	ICFGEdge edge = { .from = from, .to = to, .type = type };
	rz_vector_push(&icfg->prepared_edges, &edge);
	return true;
}

/**
 * \brief Applies all prepared edges to the iCFG.
 * This function will return the number of edges which miss a node.
 * Or SZT_MAX in case of error.
 *
 * \param icfg The iCFG to update.
 */
RZ_API size_t rz_icfg_apply(RZ_NONNULL RZ_BORROW RzICFG *icfg) {
	rz_return_val_if_fail(icfg, SZT_MAX);

	size_t existed = 0; // TODO: Remove after debug
	size_t missing_node = 0;
	ICFGEdge *edge;
	rz_vector_foreach (&icfg->prepared_edges, edge) {
		RzGraphStatus status = rz_graph_add_edge_by_id(icfg->graph, edge->from, edge->to, RZ_GRAPH_INT_AS_DATA(edge->type));
		switch (status) {
		case RZ_GRAPH_STATUS_OK:
			break;
		case RZ_GRAPH_STATUS_EXISTED:
			existed++;
			break;
		case RZ_GRAPH_STATUS_MISSING_NODE:
			RZ_LOG_DEBUG("missing node in edge: 0x%" PFMT64x " -> 0x%" PFMT64x " t: %" PFMT32d "n",
				edge->from, edge->to, edge->type);
			missing_node++;
			break;
		case RZ_GRAPH_STATUS_ERR:
		default:
			RZ_LOG_ERROR("icfg: Failed to add apply edge (0x%" PFMT64x ", 0x%" PFMT64x ", %" PFMT32d ") to iCFG.\n",
				edge->from,
				edge->to,
				edge->type);
			break;
		}
	}
	rz_vector_clear(&icfg->prepared_edges);
	(void)existed;
	return missing_node;
}

RZ_API bool rz_icfg_get_cfg(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 entry_point, RZ_OUT RzCFG *cfg_out) {
	rz_return_val_if_fail(icfg, false);
	// TODO
	rz_warn_if_reached();
	return false;
}

RZ_API void rz_cfg_fini(RZ_NULLABLE RZ_BORROW RzCFG *cfg) {
	if (!cfg) {
		return;
	}
	rz_iterator_fini(cfg->cfg_nodes);
}

static void bb_add_target(RzAnalysisBlock *abb, ut64 target) {
	if (abb->jump == UT64_MAX && abb->fail != target) {
		abb->jump = target;
	} else if (abb->fail == UT64_MAX && abb->jump != target) {
		abb->fail = target;
	} else if (abb->fail != target && abb->jump != target) {
		RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
			    "\t\tHas jump = 0x%" PFMT64x " fail = 0x%" PFMT64x ". Will miss = 0x%" PFMT64x "\n",
			abb->addr, abb->jump, abb->fail,
			target);
	}
}

typedef struct {
	size_t n_errors;
	RzAnalysis *analysis;
	RzAnalysisFunction *fcn;
} ConvertBundle;

bool handle_edge(const RzGraphEdge *e, RzGraphVisitor *vis) {
	ConvertBundle *bundle = vis->visitor_data;
	RzICFGEdgeType type = (utptr)rz_graph_edge_get_data(e);
	const RzGraphNode *from = rz_graph_edge_get_from(e);
	const RzGraphNode *to = rz_graph_edge_get_to(e);
	ut64 from_addr = rz_graph_node_get_id(from);
	ut64 to_addr = rz_graph_node_get_id(to);

	switch (type) {
	case RZ_ICFG_EDGE_TYPE_FALLTHROUGH:
		return true;
	case RZ_ICFG_EDGE_TYPE_JUMP:
		if (!rz_analysis_xrefs_set(bundle->analysis, from_addr, to_addr, RZ_ANALYSIS_XREF_TYPE_CODE)) {
			bundle->n_errors++;
			rz_warn_if_reached();
		}
		// The block is created when the node is discovered.
		// Because we do DFS the "from" block should have been added already,
		// when this outgoing edge is walked.
		RzAnalysisBlock *ablock = rz_analysis_get_block_at(bundle->analysis, from_addr);
		if (ablock) {
			bb_add_target(ablock, to_addr);
		} else {
			bundle->n_errors++;
			rz_warn_if_reached();
		}
		return true;
	case RZ_ICFG_EDGE_TYPE_CALL:
		// Don't follow call edges, just add them as xrefs.
		if (!rz_analysis_xrefs_set(bundle->analysis, from_addr, to_addr, RZ_ANALYSIS_XREF_TYPE_CALL)) {
			bundle->n_errors++;
			rz_warn_if_reached();
		}
		return false;
	case RZ_ICFG_EDGE_TYPE_RETURN:
		return false;
	}
	rz_warn_if_reached();
	return false;
}

void handle_node(RzGraphNode *n, RzGraphVisitor *vis) {
	ConvertBundle *bundle = vis->visitor_data;
	const RzICFGNode *cfg_node = rz_graph_node_get_data(n);
	RzAnalysisBlock *ablock = rz_analysis_get_block_at(bundle->analysis, cfg_node->addr);
	if (ablock) {
		// Already created.
		rz_analysis_function_add_block(bundle->fcn, ablock);
		return;
	}
	ablock = rz_analysis_create_block(bundle->analysis, cfg_node->addr, cfg_node->size);
	if (!ablock) {
		RZ_LOG_ERROR("Failed to create analysis block at 0x%" PFMT64x "\n", cfg_node->addr);
		bundle->n_errors++;
		return;
	}
	// TODO: analyze_ops should eventually not be used here since
	// it does its own analysis on stack variables.
	//
	// After we have https://github.com/rizinorg/rizin/issues/6386
	// we should manually apply our analysis info to it.
	rz_analysis_block_analyze_ops(ablock);
	rz_analysis_function_add_block(bundle->fcn, ablock);
}

RZ_API bool rz_icfg_copy_to_analysis(const RZ_NONNULL RzICFG *icfg, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzICFGFcnNameChooser chooser, void *chooser_priv) {
	rz_return_val_if_fail(icfg && analysis, false);
	size_t n_errors = 0;

	ut64 *addr_it;
	rz_vector_foreach (&icfg->proc_entries, addr_it) {
		ut64 addr = *addr_it;
		char *fcn_name = chooser ? chooser(addr, chooser_priv) : NULL;
		char name_alt[32] = { 0 };
		RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, fcn_name ? fcn_name : rz_strf(name_alt, "inquiry.0x%" PFMT64x, addr), addr, RZ_ANALYSIS_FCN_TYPE_FCN);
		if (!fcn) {
			// TODO: handle better than skipping everything
			// rz_analysis_create_function() already prints the more detailed reason if there is any
			RZ_LOG_ERROR("Could not apply analysis result as function @ 0x%" PFMT64x ": func == NULL\n", addr);
			continue;
		}
		RzGraphNode *fcn_entry = rz_graph_find_node(icfg->graph, addr);
		ConvertBundle bundle = { .analysis = analysis, .fcn = fcn };
		RzGraphVisitor visitor = { 0 };
		visitor.edge_selector = handle_edge;
		visitor.discover_node = handle_node;
		visitor.visitor_data = &bundle;
		// Walk subgraph of procedure, skipping any call edge.
		rz_graph_dfs_from_node(icfg->graph, fcn_entry, &visitor);
		n_errors += bundle.n_errors;
	}
	return n_errors == 0;
}
