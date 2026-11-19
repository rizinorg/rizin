// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry/rz_icfg.h>
#include "icfg_priv.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_set.h"
#include "rz_util/rz_strbuf.h"

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

static bool icfg_proc_memberships_update(RZ_NONNULL RzICFGNode *dst, RZ_NONNULL RzICFGNode *src) {
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
		added |= icfg_proc_memberships_add(dst, src->proc_memberships.m);
	}
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
	if (*a > *b) {
		return 1;
	} else if (*a < *b) {
		return -1;
	}
	return 0;
}

struct covering_node {
	RzIntervalNode *itv_node;
	size_t count;
};

static bool itv_intersect_cb(RzIntervalNode *node, void *user) {
	struct covering_node *pair = user;
	if (pair->count >= 1) {
		pair->count++;
		return false;
	}
	pair->itv_node = node;
	pair->count++;
	return true;
}

// Changes the size of an overlapping block with the new block.
// If the new block is exactly the same as the existing block,
// it returns the RzGraphNode of the existing block.
// Otherwise NULL.
//
// Case 0 - Block X exists, Block Y is a duplicate -> return Block X.
// +-  +-
// | X | Y
// +- +-
//
// Case I - Block X exists, Block Y is added -> Shorten existing Block X.
//     +-
//     |
// +-  | X
// |   |
// | Y +-
// |
// +-
//
// Case II - Block X exists, Block Y is added -> Shorten new Block Y.
//     +-
//     |
// +-  | Y
// | X |
// +- +-
//
//
// NOTE: If you change this part, remember that the start address of every
// block must stay the same! Otherwise edges get invalidated.
static RzGraphNode *handle_overlapping_icfg_blocks(
	RzICFG *icfg,
	ut64 addr,
	size_t *size,
	RZ_NONNULL const RzVector /*<ut16>*/ *insn_offsets,
	struct covering_node overlap,
	RzVector *fixed_insn_offsets,
	ut64 proc_membership,
	RZ_OUT RzICFGNode **use_memberships) {
	if (overlap.itv_node->start == addr && overlap.itv_node->end == addr + *size) {
		// Case 0:
		// The node already exists in the graph, covering the same dimensions.
		*use_memberships = NULL;
		return overlap.itv_node->data;
	}

	ICFGEdge split_block_edge = { .from = 0, .to = 0, .type = RZ_ICFG_EDGE_TYPE_FALLTHROUGH };

	RzGraphNode *ov_graph_node = overlap.itv_node->data;
	RzICFGNode *ov_icfg_node = rz_graph_node_get_data_mut(ov_graph_node);

	if (overlap.itv_node->start < addr) {
		// Case I:
		// Resize existing block and update start address of new block.
		ut64 resize_start = overlap.itv_node->start;
		ut64 resize_end = resize_start + addr - overlap.itv_node->start;
		size_t insn_off_to_remove = addr - overlap.itv_node->start + 1;
		split_block_edge.from = resize_start;
		split_block_edge.to = resize_end + 1;
		rz_interval_tree_resize(&icfg->itv_tree, overlap.itv_node, resize_start, resize_end);
		overlap.itv_node = NULL; // Pointer is invalid after resizing.

		// Update the insn_offset list of the existing graph node.
		ut16 insn_off;
		do {
			rz_vector_pop(&ov_icfg_node->insn_offsets, &insn_off);
		} while (insn_off > insn_off_to_remove);
		// Debug check
		rz_warn_if_fail(insn_off == insn_off_to_remove);
		*use_memberships = ov_icfg_node;
	} else {
		// Case II:
		// Reduce size of new block.
		if (icfg_proc_memberships_add(ov_icfg_node, proc_membership)) {
			rz_set_u_add(icfg->node_conflicts, (utptr)ov_icfg_node);
		}
		*size = overlap.itv_node->start - addr;
		split_block_edge.from = addr;
		split_block_edge.to = addr + *size;
		// Update the instruction offsets.
		ut16 *off;
		rz_vector_foreach (insn_offsets, off) {
			if (*off == *size) {
				break;
			}
			rz_vector_push(fixed_insn_offsets, off);
		}
		// Debug check
		rz_warn_if_fail(rz_vector_len(insn_offsets) > rz_vector_len(fixed_insn_offsets));
		*use_memberships = NULL;
	}
	rz_icfg_prepare_edge(icfg, split_block_edge.from, split_block_edge.to, RZ_ICFG_EDGE_TYPE_FALLTHROUGH);
	return NULL;
}

RZ_API bool rz_icfg_add_node(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 addr, size_t size, RZ_NONNULL const RzVector /*<ut16>*/ *insn_offsets, ut64 proc_membership) {
	rz_return_val_if_fail(icfg && insn_offsets, false);

	RzICFGNode *icfg_node = NULL;
	RzICFGNode *overlapping_icfg_node = NULL;
	RzGraphNode *graph_node = NULL;

	RzVector fixed_insn_offsets = { 0 };
	rz_vector_init(&fixed_insn_offsets, sizeof(ut16), NULL, NULL);

	printf("Add node: 0x%lx\n", addr);
	// Search for any graph node intersection with the new one.
	struct covering_node overlap = { 0 };
	rz_interval_tree_all_intersect(&icfg->itv_tree, addr, addr + size, false, itv_intersect_cb, &overlap);
	switch (overlap.count) {
	case 0:
		// Node is totally new.
		break;
	case 1:
		graph_node = handle_overlapping_icfg_blocks(icfg, addr, &size, insn_offsets, overlap, &fixed_insn_offsets, proc_membership, &overlapping_icfg_node);
		if (graph_node) {
			icfg_node = rz_graph_node_get_data_mut(graph_node);
		}
		break;
	default:
		// This should never happen, because we resolve intersections for every node we add.
		goto error;
	}

	if (!graph_node) {
		// Create a new graph node.
		icfg_node = icfg_node_new(addr, size, rz_vector_len(&fixed_insn_offsets) ? &fixed_insn_offsets : insn_offsets);
		if (!icfg_node) {
			goto error;
		}
		if (rz_graph_add_node(icfg->graph, icfg_node, &graph_node) != RZ_GRAPH_STATUS_OK) {
			goto error;
		}
		rz_interval_tree_insert(&icfg->itv_tree, addr, addr + size, graph_node);
	}

	if (!icfg_proc_memberships_add(icfg_node, proc_membership)) {
		rz_warn_if_reached();
	}
	if (overlapping_icfg_node) {
		icfg_proc_memberships_update(icfg_node, overlapping_icfg_node);
	}
	if (icfg_node->memberships_n > 1) {
		rz_set_u_add(icfg->node_conflicts, (utptr)icfg_node);
	}

	if (rz_vector_find_sorted(&icfg->proc_entries, &proc_membership, (RzVectorComparator)uint_cmp, NULL) == SZT_MAX) {
		rz_vector_insert_sorted(&icfg->proc_entries, &proc_membership, (RzVectorComparator)uint_cmp, NULL);
	}
	rz_vector_fini(&fixed_insn_offsets);
	return true;

error:
	rz_warn_if_reached();
	rz_vector_fini(&fixed_insn_offsets);
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
