// SPDX-FileCopyrightText: 2014-2020 pancake
// SPDX-FileCopyrightText: 2014-2020 ret2libc
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_util/rz_graph_drawable.h>
#include <rz_util/ht_pu.h>
#include <ctype.h>
#include <limits.h>
#include "core_private.h"

/*
 * TODO(agraph-refactor): Remaining legacy dependencies on old graph.c API/struct layout are annotated below.
 * - Replace list-based neighbor access with iterator-based APIs from rz_graph.h (graph_impl/graph_algorithm).
 * - Remove all direct RzGraphNode field access (out_nodes/in_nodes/all_neighbours/idx).
 * - Preserve edge ordering semantics (old edge->nth / add_edge_at) via edge->data (AGraphEdgeData) and sort when needed.
 */

static const char *mousemodes[] = {
	"canvas-y",
	"canvas-x",
	"node-y",
	"node-x",
	NULL
};

#define BORDER                  3
#define BORDER_WIDTH            2
#define BORDER_HEIGHT           3
#define MARGIN_TEXT_X           2
#define MARGIN_TEXT_Y           2
#define HORIZONTAL_NODE_SPACING 4
#define VERTICAL_NODE_SPACING   2
#define MIN_NODE_WIDTH          12
#define MIN_NODE_HEIGHT         BORDER_HEIGHT
#define TITLE_LEN               128
#define DEFAULT_SPEED           1
#define PAGEKEY_SPEED           (h / 2)
/* 15 */
#define MINIGRAPH_NODE_TEXT_CUR  "<@@@@@@>"
#define MINIGRAPH_NODE_MIN_WIDTH 12
#define MINIGRAPH_NODE_TITLE_LEN 4
#define MINIGRAPH_NODE_CENTER_X  3
#define MININODE_MIN_WIDTH       16

#define ZOOM_STEP    10
#define ZOOM_DEFAULT 100

#define BODY_OFFSETS  0x1
#define BODY_SUMMARY  0x2
#define BODY_COMMENTS 0x4

#define NORMALIZE_MOV(x) ((x) < 0 ? -1 : ((x) > 0 ? 1 : 0))

/* don't use macros for this */
#define get_anode(gn) ((gn) ? (RzANode *)(gn)->data : NULL)

struct len_pos_t {
	int len;
	int pos;
};

struct dist_t {
	const RzGraphNode *from;
	const RzGraphNode *to;
	int dist;
};

struct g_cb {
	RzAGraph *graph;
	RzANodeCallback node_cb;
	RAEdgeCallback edge_cb;
	void *data;
};

typedef struct ascii_edge_t {
	RzANode *from;
	RzANode *to;
	RzList /*<void *>*/ *x, *y; // void* is treated as a size_t
	int is_reversed;
} AEdge;

struct layer_t {
	int n_nodes;
	RzGraphNode **nodes;
	int position;
	int height;
	int width;
	int gap;
};

typedef struct agraph_context_t {
	int display_mode; ///< Integer indicating display mode: 0 = raw (no pseudo, no ESIL), 1 = pseudo-code enabled, 2 = ESIL.
	int scroll_position; ///< Integer representing the vertical scroll position of the Graph in "RZ_AGRAPH_MODE_MINI".
	int mouse_mode; ///< Integer identifying mouse mode: one of "canvas-y", "canvas-x", "node-y", "node-x", or NULL.
	bool graph_cursor; ///< Boolean indicating whether the graph cursor is active.
	bool follow_offset;
	int fs;
	RzCore *core;
	RzAGraph *g;
	RzAnalysisFunction **fcn;
} AGraphContext;

struct rz_agraph_location {
	int x;
	int y;
};

#define G(x, y)            rz_cons_canvas_gotoxy(g->can, x, y)
#define W(x)               rz_cons_canvas_write(g->can, x)
#define F(x, y, x2, y2, c) rz_cons_canvas_fill(g->can, x, y, x2, y2, c)

/**
 * Iterator state for a PVector whose ownership is transferred to the iterator.
 * Used by both node and edge iterators so we only need one set of callbacks.
 */
typedef struct {
	RzPVector *vec;
	ut64 idx;
} PVecOwnedIter;

static void *pvec_owned_iter_next(RzIterator *it) {
	PVecOwnedIter *s = it ? (PVecOwnedIter *)it->u : NULL;
	return s ? rz_pvector_at(s->vec, s->idx++) : NULL;
}

static void pvec_owned_iter_free(void *u) {
	PVecOwnedIter *s = (PVecOwnedIter *)u;
	if (s) {
		rz_pvector_free(s->vec);
		free(s);
	}
}

/** Wrap an owned PVector as an RzIterator; frees vec on iterator_free. */
static RzIterator *pvector_as_owned_iter(RzPVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	PVecOwnedIter *s = RZ_NEW0(PVecOwnedIter);
	if (!s) {
		rz_pvector_free(vec);
		return NULL;
	}
	s->vec = vec;
	RzIterator *it = rz_iterator_new(pvec_owned_iter_next, NULL, pvec_owned_iter_free, s);
	if (!it) {
		pvec_owned_iter_free(s);
		return NULL;
	}
	return it;
}

typedef struct rz_agraph_edge_data {
	int nth;
	int kind;
	ut64 creation_order;
	bool tmp_reversed_added;
} AGraphEdgeData;

static void rz_agraph_edge_data_free(void *data) {
	free(data);
}

enum {
	AGRAPH_EDGE_KIND_UNKNOWN = -1,
	AGRAPH_EDGE_KIND_TRUE = 0,
	AGRAPH_EDGE_KIND_FALSE = 1,
};

static AGraphEdgeData *agraph_edge_data_new(int nth, int kind, ut64 creation_order) {
	AGraphEdgeData *d = RZ_NEW0(AGraphEdgeData);
	if (d) {
		d->nth = nth;
		d->kind = kind;
		d->creation_order = creation_order;
		d->tmp_reversed_added = false;
	}
	return d;
}

static int get_edge_nth(const RzGraphEdge *e) {
	if (e && e->data) {
		return ((AGraphEdgeData *)e->data)->nth;
	}
	return -1;
}

static int get_edge_kind(const RzGraphEdge *e) {
	if (e && e->data) {
		return ((AGraphEdgeData *)e->data)->kind;
	}
	return AGRAPH_EDGE_KIND_UNKNOWN;
}

static ut64 get_edge_creation_order(const RzGraphEdge *e) {
	if (e && e->data) {
		return ((AGraphEdgeData *)e->data)->creation_order;
	}
	return UT64_MAX;
}

static void set_edge_tmp_reversed_added(RzGraphEdge *e, bool added) {
	if (e && e->data) {
		((AGraphEdgeData *)e->data)->tmp_reversed_added = added;
	}
}

static bool get_edge_tmp_reversed_added(const RzGraphEdge *e) {
	if (e && e->data) {
		return ((AGraphEdgeData *)e->data)->tmp_reversed_added;
	}
	return false;
}

/** Ensure edge has an AGraphEdgeData struct, allocating a default one if needed. */
static AGraphEdgeData *agraph_edge_data_ensure(RzGraphEdge *e) {
	if (!e->data) {
		e->data = agraph_edge_data_new(-1, AGRAPH_EDGE_KIND_UNKNOWN, UT64_MAX);
	}
	return (AGraphEdgeData *)e->data;
}

static void set_edge_kind(RzGraphEdge *e, int kind) {
	if (e) {
		AGraphEdgeData *d = agraph_edge_data_ensure(e);
		if (d) {
			d->kind = kind;
		}
	}
}

static RzGraphEdge *agraph_find_graph_edge(const RzAGraph *g, const RzGraphNode *from, const RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, NULL);
	return rz_graph_find_edge(g->graph, (RzGraphNode *)from, (RzGraphNode *)to);
}

static int agraph_out_degree(const RzAGraph *g, const RzGraphNode *node) {
	rz_return_val_if_fail(g && node, 0);
	return (int)rz_graph_out_degree(g->graph, node);
}

static int agraph_in_degree(const RzAGraph *g, const RzGraphNode *node) {
	rz_return_val_if_fail(g && node, 0);
	return (int)rz_graph_in_degree(g->graph, node);
}

static int agraph_out_edge_order_cmp(const void *_a, const void *_b, void *user) {
	const RzGraphEdge *ea = (const RzGraphEdge *)_a;
	const RzGraphEdge *eb = (const RzGraphEdge *)_b;
	const int a_nth = get_edge_nth(ea);
	const int b_nth = get_edge_nth(eb);
	const bool a_has_nth = a_nth >= 0;
	const bool b_has_nth = b_nth >= 0;

	// 1. compare manual specified nth
	if (a_has_nth != b_has_nth) {
		return a_has_nth ? -1 : 1;
	}

	if (a_has_nth && a_nth != b_nth) {
		return a_nth < b_nth ? -1 : 1;
	}

	// 2. compare with edge raw order (creation order)
	const ut64 a_order = get_edge_creation_order(ea);
	const ut64 b_order = get_edge_creation_order(eb);
	if (a_order != b_order) {
		return a_order < b_order ? -1 : 1;
	}

	// 3. final policy, compare with node creation order (_vec_id)
	if (ea->to->_vec_id != eb->to->_vec_id) {
		return ea->to->_vec_id < eb->to->_vec_id ? -1 : 1;
	}
	return 0;
}

static int agraph_in_edge_order_cmp(const void *_a, const void *_b, void *user) {
	const RzGraphEdge *ea = (const RzGraphEdge *)_a;
	const RzGraphEdge *eb = (const RzGraphEdge *)_b;
	const bool a_self = ea && ea->from == ea->to;
	const bool b_self = eb && eb->from == eb->to;

	// avoid self loop
	if (a_self != b_self) {
		return a_self ? 1 : -1;
	}
	const RzANode *afrom = get_anode(ea ? ea->from : NULL);
	const RzANode *bfrom = get_anode(eb ? eb->from : NULL);
	if (afrom && bfrom && afrom->is_dummy != bfrom->is_dummy) {
		return afrom->is_dummy ? 1 : -1;
	}
	const ut64 a_order = get_edge_creation_order(ea);
	const ut64 b_order = get_edge_creation_order(eb);
	if (a_order != b_order) {
		return a_order < b_order ? -1 : 1;
	}
	if (ea->from->_vec_id != eb->from->_vec_id) {
		return ea->from->_vec_id < eb->from->_vec_id ? -1 : 1;
	}
	return 0;
}

static RzIterator *agraph_out_neighbors(const RzAGraph *g, const RzGraphNode *node);
static RzGraphNode *agraph_nth_neighbour(const RzAGraph *g, const RzGraphNode *node, ut64 nth, bool outgoing);
static RzPVector *agraph_collect_edges(const RzAGraph *g, const RzGraphNode *node, bool outgoing, bool sorted);

/**
 * Determin which node should be drawn first (x-axis)
 */
static int agraph_first_x_node_cmp(const void *_a, const void *_b, void *user) {
	const RzGraphNode *ga = (const RzGraphNode *)_a;
	const RzGraphNode *gb = (const RzGraphNode *)_b;
	const RzANode *a = get_anode((RzGraphNode *)ga);
	const RzANode *b = get_anode((RzGraphNode *)gb);
	if (!a || !b) {
		return !!b - !!a;
	}
	if (b->y != a->y) {
		return b->y < a->y ? -1 : 1;
	}
	if (a->x != b->x) {
		return a->x < b->x ? 1 : -1;
	}
	if (ga->_vec_id != gb->_vec_id) {
		return ga->_vec_id < gb->_vec_id ? -1 : 1;
	}
	return 0;
}

static const RzANode *agraph_visible_draw_target(const RzAGraph *g, const RzGraphNode *node) {
	const RzGraphNode *cur = node;
	const RzANode *an = get_anode((RzGraphNode *)cur);
	if (!an) {
		return NULL;
	}
	ut64 guard = rz_graph_count_nodes(g->graph) + 1;
	while (guard-- && an && an->is_dummy) {
		cur = agraph_nth_neighbour(g, cur, 0, true);
		an = get_anode((RzGraphNode *)cur);
	}
	return an;
}

static int agraph_callgraph_draw_node_cmp(const void *_a, const void *_b, void *user) {
	const RzAGraph *g = (const RzAGraph *)user;
	const RzGraphNode *ga = (const RzGraphNode *)_a;
	const RzGraphNode *gb = (const RzGraphNode *)_b;
	const RzANode *a = g ? agraph_visible_draw_target(g, ga) : get_anode((RzGraphNode *)ga);
	const RzANode *b = g ? agraph_visible_draw_target(g, gb) : get_anode((RzGraphNode *)gb);
	if (!a || !b) {
		return !!b - !!a;
	}
	const bool a_has_vis_node = a->gnode != NULL;
	const bool b_has_vis_node = b->gnode != NULL;
	if (a_has_vis_node != b_has_vis_node) {
		return a_has_vis_node ? -1 : 1;
	}
	if (a_has_vis_node && a->gnode->_vec_id != b->gnode->_vec_id) {
		return a->gnode->_vec_id < b->gnode->_vec_id ? -1 : 1;
	}
	const bool a_has_offset = a->offset != UT64_MAX;
	const bool b_has_offset = b->offset != UT64_MAX;
	if (a_has_offset != b_has_offset) {
		return a_has_offset ? -1 : 1;
	}
	if (a_has_offset && a->offset != b->offset) {
		return a->offset < b->offset ? -1 : 1;
	}
	if (a->x != b->x) {
		return a->x < b->x ? -1 : 1;
	}
	if (a->layer != b->layer) {
		return a->layer < b->layer ? -1 : 1;
	}
	if (ga->_vec_id != gb->_vec_id) {
		return ga->_vec_id < gb->_vec_id ? -1 : 1;
	}
	return 0;
}

static RzPVector *agraph_collect_draw_neighbours(const RzAGraph *g, const RzGraphNode *node) {
	rz_return_val_if_fail(g && node, NULL);
	RzPVector *neighbours = rz_pvector_new(NULL);
	if (!neighbours) {
		return NULL;
	}
	if (g->is_callgraph) {
		RzPVector *edges = agraph_collect_edges(g, node, true, false);
		if (!edges) {
			rz_pvector_free(neighbours);
			return NULL;
		}
		void **it;
		rz_pvector_foreach (edges, it) {
			RzGraphEdge *cur = *it;
			if (cur && cur->to) {
				rz_pvector_push(neighbours, cur->to);
			}
		}
		rz_pvector_free(edges);
		if (rz_pvector_len(neighbours) > 1) {
			rz_pvector_sort(neighbours, agraph_callgraph_draw_node_cmp, (void *)g);
		}
	} else {
		RzIterator *it_neighbours = agraph_out_neighbors(g, node);
		if (!it_neighbours) {
			rz_pvector_free(neighbours);
			return NULL;
		}
		RzGraphNode *neighbour = NULL;
		rz_iterator_foreach(it_neighbours, neighbour) {
			if (neighbour) {
				rz_pvector_push(neighbours, neighbour);
			}
		}
		rz_iterator_free(it_neighbours);
	}
	const size_t len = rz_pvector_len(neighbours);
	if (!g->is_callgraph && len > 2) {
		rz_pvector_sort(neighbours, agraph_first_x_node_cmp, NULL);
	}
	return neighbours;
}

static RzIterator *agraph_get_nodes(const RzAGraph *g) {
	rz_return_val_if_fail(g, NULL);
	return rz_graph_get_nodes(g->graph);
}

/**
 * Collect edges of \p node into an owned PVector.
 * \param sorted When true, sorts by (nth, creation_order, _vec_id) for
 *               deterministic layout traversal; false returns raw order.
 */
static RzPVector *agraph_collect_edges(const RzAGraph *g, const RzGraphNode *node, bool outgoing, bool sorted) {
	rz_return_val_if_fail(g && node, NULL);
	RzIterator *it_edges = outgoing
		? rz_graph_out_edges(g->graph, (RzGraphNode *)node)
		: rz_graph_in_edges(g->graph, (RzGraphNode *)node);
	if (!it_edges) {
		return NULL;
	}
	RzPVector *edges = rz_pvector_new(NULL);
	if (!edges) {
		rz_iterator_free(it_edges);
		return NULL;
	}
	RzGraphEdge *edge = NULL;
	rz_iterator_foreach(it_edges, edge) {
		if (edge) {
			rz_pvector_push(edges, edge);
		}
	}
	rz_iterator_free(it_edges);
	if (sorted && rz_pvector_len(edges) > 1) {
		rz_pvector_sort(edges, outgoing ? agraph_out_edge_order_cmp : agraph_in_edge_order_cmp, NULL);
	}
	return edges;
}

static RzIterator *agraph_neighbours(const RzAGraph *g, const RzGraphNode *node, bool outgoing) {
	rz_return_val_if_fail(g && node, NULL);
	RzPVector *edges = agraph_collect_edges(g, node, outgoing, true);
	if (!edges) {
		edges = rz_pvector_new(NULL);
		if (!edges) {
			return NULL;
		}
	}
	/* Extract the neighbour node pointer from each edge into a new PVector,
	 * then wrap that as an owned iterator. */
	RzPVector *nodes = rz_pvector_new(NULL);
	if (!nodes) {
		rz_pvector_free(edges);
		return NULL;
	}
	void **it;
	rz_pvector_foreach (edges, it) {
		RzGraphEdge *e = (RzGraphEdge *)*it;
		if (e) {
			rz_pvector_push(nodes, outgoing ? e->to : e->from);
		}
	}
	rz_pvector_free(edges);
	return pvector_as_owned_iter(nodes);
}

static RzIterator *agraph_out_neighbors(const RzAGraph *g, const RzGraphNode *node) {
	return agraph_neighbours(g, node, true);
}

static RzIterator *agraph_in_neighbors(const RzAGraph *g, const RzGraphNode *node) {
	return agraph_neighbours(g, node, false);
}

static RzGraphNode *agraph_nth_neighbour(const RzAGraph *g, const RzGraphNode *node, ut64 nth, bool outgoing) {
	RzPVector *edges = agraph_collect_edges(g, node, outgoing, true);
	if (!edges) {
		return NULL;
	}
	RzGraphEdge *edge = rz_pvector_at(edges, nth);
	RzGraphNode *res = edge ? (outgoing ? edge->to : edge->from) : NULL;
	rz_pvector_free(edges);
	return res;
}

/**
 * Comparator forwarding to \c agraph_out_edge_order_cmp for use with
 * \c rz_graph_find_back_edges.  Signature matches \c RzGraphEdgeCmp.
 */
static int agraph_back_edge_cmp(const RzGraphEdge *a, const RzGraphEdge *b, void *user) {
	return agraph_out_edge_order_cmp(a, b, user);
}

static bool agraph_add_graph_edge_ex(RzAGraph *g, RzGraphNode *from, RzGraphNode *to, int nth, int kind, ut64 creation_order) {
	rz_return_val_if_fail(g && from && to, false);
	AGraphEdgeData *edge_data = agraph_edge_data_new(nth, kind, creation_order);
	if (!edge_data) {
		return false;
	}
	if (!rz_graph_add_edge(g->graph, from, to, edge_data)) {
		rz_agraph_edge_data_free(edge_data);
		return false;
	}
	if (creation_order != UT64_MAX && g->next_edge_creation_order <= creation_order) {
		g->next_edge_creation_order = creation_order + 1;
	}
	return true;
}

static bool agraph_add_graph_edge(RzAGraph *g, RzGraphNode *from, RzGraphNode *to, int nth, int kind) {
	rz_return_val_if_fail(g && from && to, false);
	return agraph_add_graph_edge_ex(g, from, to, nth, kind, g->next_edge_creation_order++);
}

static void agraph_del_graph_edge(const RzAGraph *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_if_fail(g && from && to);
	rz_graph_del_edge(g->graph, from, to, NULL);
}

static bool is_offset(const RzAGraph *g) {
	return g->mode == RZ_AGRAPH_MODE_OFFSET;
}

static bool is_mini(const RzAGraph *g) {
	return g->mode == RZ_AGRAPH_MODE_MINI;
}

static bool is_summary(const RzAGraph *g) {
	return g->mode == RZ_AGRAPH_MODE_SUMMARY;
}

static bool is_comments(const RzAGraph *g) {
	return g->mode == RZ_AGRAPH_MODE_COMMENTS;
}

static int next_mode(int mode) {
	return (mode + 1) % RZ_AGRAPH_MODE_MAX;
}

static int prev_mode(int mode) {
	return (mode + RZ_AGRAPH_MODE_MAX - 1) % RZ_AGRAPH_MODE_MAX;
}

static RzGraphNode *agraph_get_title(const RzAGraph *g, RzANode *n, bool in) {
	if (!n) {
		return NULL;
	}
	if (n->title && *n->title) {
		return n->gnode;
	}

	RzIterator *it_nodes = in ? agraph_in_neighbors(g, n->gnode) : agraph_out_neighbors(g, n->gnode);
	if (!it_nodes) {
		return NULL;
	}

	RzGraphNode *gn;
	RzGraphNode *res = NULL;
	rz_iterator_foreach(it_nodes, gn) {
		RzANode *an = gn->data;
		res = agraph_get_title(g, an, in);
		break;
	}
	rz_iterator_free(it_nodes);
	return res;
}

static int mode2opts(const RzAGraph *g) {
	int opts = 0;
	if (is_offset(g)) {
		opts |= BODY_OFFSETS;
	}
	if (is_comments(g)) {
		opts |= BODY_COMMENTS;
	}
	if (is_summary(g)) {
		opts |= BODY_SUMMARY;
	}
	return opts;
}

// duplicated from visual.c
static void rotateAsmemu(RzCore *core) {
	const bool isEmuStr = rz_config_get_i(core->config, "emu.str");
	const bool isEmu = rz_config_get_i(core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			rz_config_set(core->config, "emu.str", "false");
		} else {
			rz_config_set(core->config, "asm.emu", "false");
		}
	} else {
		rz_config_set(core->config, "emu.str", "true");
	}
}

static void showcursor(RzCore *core, int x) {
	if (!x) {
		int wheel = rz_config_get_i(core->config, "scr.wheel");
		if (wheel) {
			rz_cons_enable_mouse(true);
		}
	} else {
		rz_cons_enable_mouse(false);
	}
	rz_cons_show_cursor(x);
}

static char *get_title(ut64 addr) {
	return rz_str_newf("0x%" PFMT64x, addr);
}

static void agraph_node_free(RzANode *n) {
	free(n->title);
	free(n->body);
	free(n);
}

static int agraph_refresh(AGraphContext *grp_ctx);

static void update_node_dimension(const RzAGraph /*<RzANode *>*/ *ag, int is_mini, int zoom, int edgemode, bool callgraph, int layout) {
	RzGraphNode *gn;
	RzANode *n;
	RzIterator *it_nodes = agraph_get_nodes(ag);
	if (!it_nodes) {
		return;
	}

	rz_iterator_foreach(it_nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}
		if (is_mini) {
			n->h = 1;
			n->w = MINIGRAPH_NODE_MIN_WIDTH;
		} else if (n->is_mini) {
			n->h = 1;
			n->w = MININODE_MIN_WIDTH;
		} else {
			n->w = rz_str_bounds(n->body, (int *)&n->h);
			ut32 len = strlen(n->title) + MARGIN_TEXT_X;
			if (len > INT_MAX) {
				len = INT_MAX;
			}
			if (len > n->w) {
				n->w = len;
			}
			// n->w = n->w; //RZ_MIN (n->w, (int)len);
			n->w += (int)(BORDER_WIDTH * 2 + RZ_MIN(n->shortcut_w, 12));
			n->h += BORDER_HEIGHT;
			/* scale node by zoom */
			n->w = RZ_MAX(MIN_NODE_WIDTH, (n->w * zoom) / 100);
			n->h = RZ_MAX(MIN_NODE_HEIGHT, (n->h * zoom) / 100);

			if (edgemode == 2 && !callgraph) {
				if (!layout) {
					n->w = RZ_MAX(n->w, (agraph_out_degree(ag, n->gnode) * 2 + 1) + RZ_EDGES_X_INC * 2);
					n->w = RZ_MAX(n->w, (agraph_in_degree(ag, n->gnode) * 2 + 1) + RZ_EDGES_X_INC * 2);
				} else {
					n->h = RZ_MAX(n->h, (agraph_out_degree(ag, n->gnode) + 1) + RZ_EDGES_X_INC);
					n->h = RZ_MAX(n->h, (agraph_in_degree(ag, n->gnode) + 1) + RZ_EDGES_X_INC);
				}
			}
		}
	}
	rz_iterator_free(it_nodes);
}

static void append_shortcut(const RzAGraph *g, char *title, char *nodetitle, int left) {
	char buf[127] = { 0 };
	rz_strf(buf, "agraph.nodes.%s.shortcut", nodetitle);
	const char *shortcut = sdb_const_get(g->db, buf);
	if (shortcut) {
		if (g->can->color) {
			// XXX: do not hardcode color here
			rz_strf(buf, Color_YELLOW "[o%s]" Color_RESET, shortcut);
			strncat(title, buf, left);
		} else {
			rz_strf(buf, "[o%s]", shortcut);
			strncat(title, buf, left);
		}
	}
}

static void mini_RzANode_print(const RzAGraph *g, const RzANode *n, const AGraphContext *grp_ctx, int cur, bool details) {
	char title[TITLE_LEN];
	int x, delta_x = 0;

	if (!G(n->x + MINIGRAPH_NODE_CENTER_X, n->y) &&
		!G(n->x + MINIGRAPH_NODE_CENTER_X + n->w, n->y)) {
		return;
	}

	x = n->x + MINIGRAPH_NODE_CENTER_X + g->can->sx;
	if (x < 0) {
		delta_x = -x;
	}
	if (!G(n->x + MINIGRAPH_NODE_CENTER_X + delta_x, n->y)) {
		return;
	}

	if (details) {
		if (cur) {
			W(&MINIGRAPH_NODE_TEXT_CUR[delta_x]);
			(void)G(-g->can->sx, -g->can->sy + 2);
			snprintf(title, sizeof(title) - 1,
				"[ %s ]", n->title);
			W(title);
			if (grp_ctx->scroll_position > 0) {
				char *body = rz_str_ansi_crop(n->body, 0, grp_ctx->scroll_position, -1, -1);
				(void)G(-g->can->sx, -g->can->sy + 3);
				W(body);
				free(body);
			} else {
				(void)G(-g->can->sx, -g->can->sy + 3);
				W(n->body);
			}
		} else {
			char *str = "____";
			if (n->title) {
				int l = strlen(n->title);
				str = n->title;
				if (l > MINIGRAPH_NODE_TITLE_LEN) {
					str += l - MINIGRAPH_NODE_TITLE_LEN;
				}
			}
			if (g->can->color) {
				snprintf(title, sizeof(title) - 1, "%s__%s__", Color_RESET, str);
			} else {
				snprintf(title, sizeof(title) - 1, "__%s__", str);
			}
			append_shortcut(g, title, n->title, sizeof(title) - strlen(title) - 1);
			W(rz_str_ansi_crop(title, delta_x, 0, 20, 1));
		}
	} else {
		snprintf(title, sizeof(title) - 1,
			cur ? "[ %s ]" : "  %s  ", n->title);
		W(title);
	}
	return;
}

static inline char *get_node_color(int cur) {
	RzCons *cons = rz_cons_singleton();
	return cur ? cons->context->pal.graph_box2 : cons->context->pal.graph_box;
}

static void normal_RzANode_print(const RzAGraph *g, const RzANode *n, int cur) {
	ut32 center_x = 0, center_y = 0;
	ut32 delta_x = 0, delta_txt_x = 0;
	ut32 delta_y = 0, delta_txt_y = 0;
	char title[TITLE_LEN];
	char *body;
	int x, y;
	const bool showTitle = g->show_node_titles;
	const bool showBody = g->show_node_body;

	x = n->x + g->can->sx;
	y = n->y + g->can->sy;
	if (x + MARGIN_TEXT_X < 0) {
		delta_x = -(x + MARGIN_TEXT_X);
	}
	if (x + n->w < -MARGIN_TEXT_X) {
		return;
	}
	if (y < -1) {
		delta_y = RZ_MIN(n->h - BORDER_HEIGHT - 1, -y - MARGIN_TEXT_Y);
	}
	/* print the title */
	if (showTitle) {
		if (cur) {
			snprintf(title, sizeof(title) - 1, "[%s]", n->title);
		} else {
			char *color = g->can->color ? Color_RESET : "";
			snprintf(title, sizeof(title) - 1, " %s%s ", color, n->title);
			append_shortcut(g, title, n->title, sizeof(title) - strlen(title) - 1);
		}
		if ((delta_x < strlen(title)) && G(n->x + MARGIN_TEXT_X + delta_x, n->y + 1)) {
			char *res = rz_str_ansi_crop(title, delta_x, 0, n->w - BORDER_WIDTH, 1);
			W(res);
			free(res);
		}
	}

	/* print the body */
	if (g->zoom > ZOOM_DEFAULT) {
		center_x = (g->zoom - ZOOM_DEFAULT) / 10;
		center_y = (g->zoom - ZOOM_DEFAULT) / 30;
		delta_txt_x = RZ_MIN(delta_x, center_x);
		delta_txt_y = RZ_MIN(delta_y, center_y);
	}
	if (showBody) {
		if (G(n->x + MARGIN_TEXT_X + delta_x + center_x - delta_txt_x,
			    n->y + MARGIN_TEXT_Y + delta_y + center_y - delta_txt_y)) {
			ut32 body_x = center_x >= delta_x ? 0 : delta_x - center_x;
			ut32 body_y = center_y >= delta_y ? 0 : delta_y - center_y;
			ut32 body_h = BORDER_HEIGHT >= n->h ? 1 : n->h - BORDER_HEIGHT;

			if (g->zoom < ZOOM_DEFAULT) {
				body_h--;
			}
			if (body_y + 1 <= body_h) {
				body = rz_str_ansi_crop(n->body,
					body_x, body_y,
					n->w - BORDER_WIDTH,
					body_h);
				if (body) {
					W(body);
					if (g->zoom < ZOOM_DEFAULT) {
						W("\n");
					}
					free(body);
				} else {
					W(n->body);
				}
			}
			/* print some dots when the body is cropped because of zoom */
			if (n->body && *n->body) {
				if (body_y <= body_h && g->zoom < ZOOM_DEFAULT) {
					char *dots = "...";
					if (delta_x < strlen(dots)) {
						dots += delta_x;
						W(dots);
					}
				}
			}
		}
	}

	// TODO: check if node is traced or not and show proper color
	// This info must be stored inside RzANode* from RzCore*
	rz_cons_canvas_box(g->can, n->x, n->y, n->w, n->h, get_node_color(cur));
}

/* =========================================================================
 * Layout (Sugiyama pipeline):
 *   remove_cycles -> assign_layers -> create_dummy_nodes -> create_layers
 *   -> minimize_crossings -> place_dummies -> place_original
 *   -> coordinate assignment -> backedge_info
 * ========================================================================= */

static int **get_crossing_matrix(const RzAGraph *g,
	const struct layer_t layers[],
	int maxlayer, int i, int from_up,
	int *n_rows) {
	int j, len = layers[i].n_nodes;

	int **m = RZ_NEWS0(int *, len);
	if (!m) {
		return NULL;
	}
	for (j = 0; j < len; j++) {
		m[j] = RZ_NEWS0(int, len);
		if (!m[j]) {
			goto err_row;
		}
	}
	/* calculate crossings between layer i and layer i-1 */
	/* consider the crossings generated by each pair of edges */
	if (i > 0 && from_up) {
		if (rz_cons_is_breaked()) {
			goto err_row;
		}
		for (j = 0; j < layers[i - 1].n_nodes; j++) {
			RzGraphNode *gj = layers[i - 1].nodes[j];
			RzGraphNode *gk;

			RzIterator *it_neighs = agraph_out_neighbors(g, gj);
			if (!it_neighs) {
				goto err_row;
			}

			rz_iterator_foreach(it_neighs, gk) {
				int s;
				// skip self-loop
				if (gj == gk) {
					continue;
				}
				for (s = 0; s < j; s++) {
					RzGraphNode *gs = layers[i - 1].nodes[s];
					RzGraphNode *gt;
					RzIterator *it_neighs_s = agraph_out_neighbors(g, gs);
					if (!it_neighs_s) {
						rz_iterator_free(it_neighs);
						goto err_row;
					}

					rz_iterator_foreach(it_neighs_s, gt) {
						const RzANode *ak, *at; /* k and t should be "indexes" on layer i */
						if (gt == gk || gt == gs) {
							continue;
						}
						ak = get_anode(gk);
						at = get_anode(gt);
						if (ak->layer != i || at->layer != i) {
							// this should never happen
							// but it happens if we do graph.dummy = false, so better hide it for now
							continue;
						}
						m[ak->pos_in_layer][at->pos_in_layer]++;
					}

					rz_iterator_free(it_neighs_s);
				}
			}
			rz_iterator_free(it_neighs);
		}
	}

	/* calculate crossings between layer i and layer i+1 */
	if (i < maxlayer - 1 && !from_up) {
		if (rz_cons_is_breaked()) {
			goto err_row;
		}
		for (j = 0; j < layers[i].n_nodes; j++) {
			RzGraphNode *gj = layers[i].nodes[j];
			const RzANode *ak, *aj = get_anode(gj);
			RzGraphNode *gk;

			if (rz_cons_is_breaked()) {
				goto err_row;
			}

			RzIterator *neighbour_itk = agraph_out_neighbors(g, gj);
			if (!neighbour_itk) {
				goto err_row;
			}

			rz_iterator_foreach(neighbour_itk, gk) {
				if (!(ak = gk->data)) {
					break;
				}
				for (size_t s = 0; s < layers[i].n_nodes; s++) {
					RzGraphNode *gs = layers[i].nodes[s];
					RzGraphNode *gt;
					const RzANode *at, *as = get_anode(gs);

					if (gs == gj) {
						continue;
					}

					RzIterator *it_neighbour_s = agraph_out_neighbors(g, gs);
					if (!it_neighbour_s) {
						rz_iterator_free(neighbour_itk);
						goto err_row;
					}

					rz_iterator_foreach(it_neighbour_s, gt) {
						if (!(at = gt->data)) {
							break;
						}
						if (at->pos_in_layer < ak->pos_in_layer) {
							m[aj->pos_in_layer][as->pos_in_layer]++;
						}
					}

					rz_iterator_free(it_neighbour_s);
				}
			}
			rz_iterator_free(neighbour_itk);
		}
	}

	if (n_rows) {
		*n_rows = len;
	}
	return m;

err_row:
	for (i = 0; i < len; i++) {
		free(m[i]);
	}
	free(m);
	return NULL;
}

static int layer_sweep(const RzAGraph *g, const struct layer_t layers[],
	int maxlayer, int i, int from_up) {
	RzGraphNode *u, *v;
	const RzANode *au, *av;
	int n_rows, j, changed = false;
	int len = layers[i].n_nodes;

	int **cross_matrix = get_crossing_matrix(g, layers, maxlayer, i, from_up, &n_rows);
	if (!cross_matrix) {
		return -1; // ERROR HAPPENS
	}

	for (j = 0; j < len - 1; j++) {
		int auidx, avidx;

		u = layers[i].nodes[j];
		v = layers[i].nodes[j + 1];
		au = get_anode(u);
		av = get_anode(v);
		auidx = au->pos_in_layer;
		avidx = av->pos_in_layer;

		if (cross_matrix[auidx][avidx] > cross_matrix[avidx][auidx]) {
			/* swap elements */
			layers[i].nodes[j] = v;
			layers[i].nodes[j + 1] = u;
			changed = true;
		}
	}

	/* update position in the layer of each node. During the swap of some
	 * elements we didn't swap also the pos_in_layer because the cross_matrix
	 * is indexed by it, so do it now! */
	for (j = 0; j < layers[i].n_nodes; j++) {
		RzANode *n = get_anode(layers[i].nodes[j]);
		n->pos_in_layer = j;
	}

	for (j = 0; j < n_rows; j++) {
		free(cross_matrix[j]);
	}
	free(cross_matrix);
	return changed;
}

static void view_dummy(const RzGraphEdge *e, RzList *long_edges) {
	const RzANode *a = get_anode(e->from);
	const RzANode *b = get_anode(e->to);
	if (!a || !b || RZ_ABS(a->layer - b->layer) <= 1) {
		return;
	}
	RzGraphEdge *new_e = RZ_NEW0(RzGraphEdge);
	if (!new_e) {
		return;
	}
	new_e->from = e->from;
	new_e->to = e->to;
	new_e->data = agraph_edge_data_new(get_edge_nth(e), get_edge_kind(e), get_edge_creation_order(e));
	rz_list_append(long_edges, new_e);
}

/**
 * Find back edges using agraph edge ordering, then invert them to make the
 * graph a DAG.  The greedy selection strategy (which edges become back edges)
 * is determined by \c agraph_back_edge_cmp — identical to the previous
 * DFS-hook approach but without coupling the generic DFS to agraph internals.
 */
static void remove_cycles(RzAGraph *g) {
	/* back_edges owns copies of the edge metadata; the graph edges themselves
	 * are mutated (deleted + re-added reversed) below. */
	g->back_edges = rz_list_newf(free);
	if (!g->back_edges) {
		return;
	}

	/* rz_graph_find_back_edges returns borrowed pointers into g->graph */
	RzList *found = rz_graph_find_back_edges(g->graph, agraph_back_edge_cmp, NULL);
	if (!found) {
		return;
	}

	/* Copy metadata before mutating the graph */
	const RzGraphEdge *e;
	const RzListIter *it;
	rz_list_foreach (found, it, e) {
		RzGraphEdge *copy = RZ_NEW0(RzGraphEdge);
		if (!copy) {
			break;
		}
		copy->from = e->from;
		copy->to = e->to;
		copy->data = agraph_edge_data_new(get_edge_nth(e), get_edge_kind(e), get_edge_creation_order(e));
		rz_list_append(g->back_edges, copy);
	}
	rz_list_free(found);

	/* Invert each back edge to break the cycle */
	rz_list_foreach (g->back_edges, it, e) {
		RzANode *from = e->from ? get_anode(e->from) : NULL;
		RzANode *to = e->to ? get_anode(e->to) : NULL;
		if (from && to) {
			agraph_del_graph_edge(g, from->gnode, to->gnode);
			if (from->gnode == to->gnode) {
				set_edge_tmp_reversed_added((RzGraphEdge *)e, false);
				continue;
			}
			const bool reversed_added = agraph_add_graph_edge_ex(g, to->gnode, from->gnode,
				get_edge_nth(e), get_edge_kind(e), get_edge_creation_order(e));
			set_edge_tmp_reversed_added((RzGraphEdge *)e, reversed_added);
		}
	}
}

/* Assign a layer to each node using Kahn's BFS-based topological algorithm.
 *
 * Each node's layer = max(parent.layer) + 1 (longest path from any source).
 * A node enters the queue only after all its parents have been processed, so
 * when we update a neighbour's layer the incoming maximum is already final.
 *
 * Layer values are independent of queue order: no ordering is required here.
 * Layer values are independent of traversal order. */
static void assign_layers(const RzAGraph *g) {
	rz_return_if_fail(g);

	/* initialise all layers to 0 */
	RzIterator *it = agraph_get_nodes(g);
	if (!it) {
		return;
	}
	RzGraphNode *gn;
	rz_iterator_foreach(it, gn) {
		RzANode *n = get_anode(gn);
		if (n) {
			n->layer = 0;
		}
	}
	rz_iterator_free(it);

	/* build remaining-in-degree table */
	HtPUOptions opt = { 0 };
	HtPU *indegree = ht_pu_new_opt(&opt);
	if (!indegree) {
		return;
	}

	RzList *queue = rz_list_new();
	if (!queue) {
		ht_pu_free(indegree);
		return;
	}

	it = agraph_get_nodes(g);
	if (!it) {
		ht_pu_free(indegree);
		rz_list_free(queue);
		return;
	}
	rz_iterator_foreach(it, gn) {
		ut64 deg = (ut64)agraph_in_degree(g, gn);
		ht_pu_update(indegree, gn, deg);
		if (deg == 0) {
			rz_list_append(queue, gn);
		}
	}
	rz_iterator_free(it);

	/* Kahn's BFS: process each node once all parents are done */
	while (rz_list_length(queue) > 0) {
		RzGraphNode *u = rz_list_pop_head(queue);
		RzANode *au = get_anode(u);
		if (!au) {
			continue;
		}

		RzIterator *out_it = agraph_out_neighbors(g, u);
		if (!out_it) {
			continue;
		}
		RzGraphNode *v;
		rz_iterator_foreach(out_it, v) {
			RzANode *av = get_anode(v);
			if (!av) {
				continue;
			}
			/* critical-path layer: longest incoming path */
			if (au->layer + 1 > av->layer) {
				av->layer = au->layer + 1;
			}
			/* enqueue v once all its parents have been processed */
			bool found = false;
			ut64 deg = ht_pu_find(indegree, v, &found);
			if (found && deg > 0) {
				deg--;
				ht_pu_update(indegree, v, deg);
				if (deg == 0) {
					rz_list_append(queue, v);
				}
			}
		}
		rz_iterator_free(out_it);
	}

	rz_list_free(queue);
	ht_pu_free(indegree);
}

static int find_edge(const RzGraphEdge *a, const RzGraphEdge *b, void *user) {
	return a->from == b->to && a->to == b->from ? 0 : 1;
}

static bool is_reversed(const RzAGraph *g, const RzGraphEdge *e) {
	return (bool)rz_list_find(g->back_edges, e, (RzListComparator)find_edge, NULL);
}

/**
 * Add dummy nodes when there are edges that span multiple layers.
 * After remove_cycles and assign_layers all layers are final, so we can
 * identify multi-layer edges by direct iteration — no DFS required.
 */
static void create_dummy_nodes(RzAGraph *g) {
	if (!g->dummy) {
		return;
	}

	g->long_edges = rz_list_newf((RzListFree)free);
	if (!g->long_edges) {
		return;
	}

	/* Collect all out-edges that span more than one layer */
	RzIterator *nodes_it = agraph_get_nodes(g);
	if (nodes_it) {
		RzGraphNode *gn;
		rz_iterator_foreach(nodes_it, gn) {
			RzPVector *edges = agraph_collect_edges(g, gn, true, false);
			if (!edges) {
				continue;
			}
			void **ep;
			rz_pvector_foreach (edges, ep) {
				const RzGraphEdge *e = (const RzGraphEdge *)*ep;
				if (e) {
					view_dummy(e, g->long_edges);
				}
			}
			rz_pvector_free(edges);
		}
		rz_iterator_free(nodes_it);
	}

	const RzListIter *it;
	const RzGraphEdge *e;
	rz_list_foreach (g->long_edges, it, e) {
		RzANode *from = get_anode(e->from);
		RzANode *to = get_anode(e->to);
		int diff_layer = RZ_ABS(from->layer - to->layer);
		RzANode *prev = get_anode(e->from);
		int i, nth = get_edge_nth(e);
		ut64 creation_order = get_edge_creation_order(e);
		agraph_del_graph_edge(g, from->gnode, to->gnode);
		for (i = 1; i < diff_layer; i++) {
			RzANode *dummy = rz_agraph_add_node(g, NULL, NULL);
			if (!dummy) {
				return;
			}
			dummy->is_dummy = true;
			dummy->layer = from->layer + i;
			dummy->is_reversed = is_reversed(g, e);
			dummy->w = 1;
			// important: first agraph dummy nodes's edge should inherit from parent
			if (i == 1) {
				(void)agraph_add_graph_edge_ex(g, prev->gnode, dummy->gnode,
					nth, get_edge_kind(e), creation_order);
			} else {
				(void)agraph_add_graph_edge(g, prev->gnode, dummy->gnode,
					nth, get_edge_kind(e));
			}
			rz_list_append(g->dummy_nodes, dummy);

			prev = dummy;
			nth = -1;
		}
		(void)agraph_add_graph_edge(g, prev->gnode, e->to,
			-1, get_edge_kind(e));
	}
}

/* create layers and assign an initial ordering of the nodes into them */
static void create_layers(RzAGraph *g) {
	RzGraphNode *gn;
	RzANode *n;
	int i;

	/* identify max layer */
	g->n_layers = 0;
	RzIterator *nodes_it = agraph_get_nodes(g);
	rz_iterator_foreach(nodes_it, gn) {
		if (!(n = gn->data)) {
			break;
		}
		if (n->layer > g->n_layers) {
			g->n_layers = n->layer;
		}
	}
	rz_iterator_free(nodes_it);

	/* create a starting ordering of nodes for each layer */
	g->n_layers++;
	if (sizeof(struct layer_t) * g->n_layers < g->n_layers) {
		return;
	}
	g->layers = RZ_NEWS0(struct layer_t, g->n_layers);

	nodes_it = agraph_get_nodes(g);
	rz_iterator_foreach(nodes_it, gn) {
		if (!(n = gn->data)) {
			break;
		}
		g->layers[n->layer].n_nodes++;
	}
	rz_iterator_free(nodes_it);

	for (i = 0; i < g->n_layers; i++) {
		if (sizeof(RzGraphNode *) * g->layers[i].n_nodes < g->layers[i].n_nodes) {
			continue;
		}
		g->layers[i].nodes = RZ_NEWS0(RzGraphNode *,
			1 + g->layers[i].n_nodes);
		g->layers[i].position = 0;
	}
	nodes_it = agraph_get_nodes(g);
	rz_iterator_foreach(nodes_it, gn) {
		if (!(n = gn->data)) {
			break;
		}
		n->pos_in_layer = g->layers[n->layer].position;
		g->layers[n->layer].nodes[g->layers[n->layer].position++] = gn;
	}
	rz_iterator_free(nodes_it);
}

/* layer-by-layer sweep */
/* it permutes each layer, trying to find the best ordering for each layer
 * to minimize the number of crossing edges */
static void minimize_crossings(const RzAGraph *g) {
	int i, cross_changed, max_changes = 4096;

	do {
		cross_changed = false;
		max_changes--;

		for (i = 0; i < g->n_layers; i++) {
			int rc = layer_sweep(g, g->layers, g->n_layers, i, true);
			if (rc == -1) {
				return;
			}
			cross_changed |= !!rc;
		}
	} while (cross_changed && max_changes);

	max_changes = 4096;

	do {
		cross_changed = false;
		max_changes--;

		for (i = g->n_layers - 1; i >= 0; i--) {
			int rc = layer_sweep(g, g->layers, g->n_layers, i, false);
			if (rc == -1) {
				return;
			}
			cross_changed |= !!rc;
		}
	} while (cross_changed && max_changes);
}

static int find_dist(const struct dist_t *a, const struct dist_t *b) {
	return a->from == b->from && a->to == b->to ? 0 : 1;
}

/* returns the distance between two nodes */
/* if the distance between two nodes were explicitly set, returns that;
 * otherwise calculate the distance of two nodes on the same layer */
static int dist_nodes(const RzAGraph *g, const RzGraphNode *a, const RzGraphNode *b) {
	struct dist_t d;
	const RzANode *aa, *ab;
	RzListIter *it;
	int res = 0;

	if (g->dists) {
		d.from = a;
		d.to = b;
		it = rz_list_find(g->dists, &d, (RzListComparator)find_dist, NULL);
		if (it) {
			struct dist_t *old = (struct dist_t *)rz_list_val(it);
			return old->dist;
		}
	}

	aa = get_anode(a);
	ab = get_anode(b);
	if (aa && ab && aa->layer == ab->layer) {
		int i;

		res = aa == ab && !aa->is_reversed ? HORIZONTAL_NODE_SPACING : 0;
		for (i = aa->pos_in_layer; i < ab->pos_in_layer; i++) {
			const RzGraphNode *cur = g->layers[aa->layer].nodes[i];
			const RzGraphNode *next = g->layers[aa->layer].nodes[i + 1];
			const RzANode *anext = get_anode(next);
			const RzANode *acur = get_anode(cur);
			int found = false;

			if (g->dists) {
				d.from = cur;
				d.to = next;
				it = rz_list_find(g->dists, &d, (RzListComparator)find_dist, NULL);
				if (it) {
					struct dist_t *old = (struct dist_t *)rz_list_val(it);
					res += old->dist;
					found = true;
				}
			}

			if (acur && anext && !found) {
				int space = HORIZONTAL_NODE_SPACING;
				if (acur->is_reversed && anext->is_reversed) {
					if (!acur->is_reversed) {
						res += acur->w / 2;
					} else if (!anext->is_reversed) {
						res += anext->w / 2;
					}
					res += 1;
				} else {
					res += acur->w / 2 + anext->w / 2 + space;
				}
			}
		}
	}

	return res;
}

/* explicitly set the distance between two nodes on the same layer */
static void set_dist_nodes(const RzAGraph *g, int l, int cur, int next) {
	struct dist_t *d, find_el;
	const RzGraphNode *vi, *vip;
	const RzANode *avi, *avip;
	RzListIter *it;

	if (!g->dists) {
		return;
	}
	vi = g->layers[l].nodes[cur];
	vip = g->layers[l].nodes[next];
	avi = get_anode(vi);
	avip = get_anode(vip);

	find_el.from = vi;
	find_el.to = vip;
	it = rz_list_find(g->dists, &find_el, (RzListComparator)find_dist, NULL);
	d = it ? (struct dist_t *)rz_list_val(it) : RZ_NEW0(struct dist_t);

	d->from = vi;
	d->to = vip;
	d->dist = (avip && avi) ? avip->x - avi->x : 0;
	if (!it) {
		rz_list_push(g->dists, d);
	}
}

static int is_valid_pos(const RzAGraph *g, int l, int pos) {
	return pos >= 0 && pos < g->layers[l].n_nodes;
}

static void fini_vertical_nodes_kv(HtPPKv *kv, RZ_UNUSED void *user) {
	rz_list_free(kv->value);
}

/* computes the set of vertical classes in the graph */
/* if v is an original node, L(v) = { v }
 * if v is a dummy node, L(v) is the set of all the dummies node that belongs
 *      to the same long edge */
static HtPP *compute_vertical_nodes(const RzAGraph *g) {
	HtPPOptions ht_opt = { 0 };
	ht_opt.finiKV = fini_vertical_nodes_kv;
	HtPP *res = ht_pp_new_opt(&ht_opt);
	if (!res) {
		return NULL;
	}
	for (int i = 0; i < g->n_layers; i++) {
		for (int j = 0; j < g->layers[i].n_nodes; j++) {
			RzGraphNode *gn = g->layers[i].nodes[j];
			const RzList *Ln = ht_pp_find(res, gn, NULL);
			const RzANode *an = get_anode(gn);

			if (!Ln) {
				RzList *vert = rz_list_new();
				ht_pp_insert(res, gn, vert);
				if (an->is_dummy) {
					RzGraphNode *next = gn;
					const RzANode *anext = get_anode(next);

					while (anext->is_dummy) {
						rz_list_append(vert, next);
						next = agraph_nth_neighbour(g, next, 0, true);
						if (!next) {
							break;
						}
						anext = get_anode(next);
					}
				} else {
					rz_list_append(vert, gn);
				}
			}
		}
	}

	return res;
}

/* computes left or right classes, used to place dummies node */
/* classes respect three properties:
 * - v E C
 * - w E C => L(v) is a subset of C
 * - w E C, the s+(w) exists and is not in any class yet => s+(w) E C */
static RzList /*<RzGraphNode *>*/ **compute_classes(const RzAGraph *g, HtPP *v_nodes, int is_left, int *n_classes) {
	int i, j, c;
	RzList **res = RZ_NEWS0(RzList *, g->n_layers);
	RzGraphNode *gn;
	const RzListIter *it;
	RzANode *n;

	RzIterator *it_nodes = agraph_get_nodes(g);
	rz_iterator_foreach(it_nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}
		n->klass = -1;
	}
	rz_iterator_free(it_nodes);

	for (i = 0; i < g->n_layers; i++) {
		c = i;

		for (j = is_left ? 0 : g->layers[i].n_nodes - 1;
			(is_left && j < g->layers[i].n_nodes) || (!is_left && j >= 0);
			j = is_left ? j + 1 : j - 1) {
			const RzGraphNode *gj = g->layers[i].nodes[j];
			const RzANode *aj = get_anode(gj);

			if (aj->klass == -1) {
				const RzList *laj = ht_pp_find(v_nodes, gj, NULL);

				if (!res[c]) {
					res[c] = rz_list_new();
				}
				rz_list_foreach (laj, it, gn) {
					if (!(n = gn->data)) {
						break;
					}
					rz_list_append(res[c], gn);
					n->klass = c;
				}
			} else {
				c = aj->klass;
			}
		}
	}

	if (n_classes) {
		*n_classes = g->n_layers;
	}
	return res;
}

static int cmp_dist(const size_t a, const size_t b) {
	return (a < b) - (a > b);
}

static RzGraphNode *get_sibling(const RzAGraph *g, const RzANode *n, int is_left, int is_adjust_class) {
	RzGraphNode *res = NULL;
	int pos = n->pos_in_layer;

	if ((is_left && is_adjust_class) || (!is_left && !is_adjust_class)) {
		pos++;
	} else {
		pos--;
	}

	if (is_valid_pos(g, n->layer, pos)) {
		res = g->layers[n->layer].nodes[pos];
	}
	return res;
}

static int hash_get_int(HtPU *ht, const void *key) {
	bool found;
	int val = (int)(size_t)ht_pu_find(ht, key, &found);
	if (!found) {
		val = 0;
	}
	return val;
}

static int adjust_class_val(const RzAGraph *g, const RzGraphNode *gn, const RzGraphNode *sibl, HtPU *res, int is_left) {
	if (is_left) {
		return hash_get_int(res, sibl) - hash_get_int(res, gn) - dist_nodes(g, gn, sibl);
	}
	return hash_get_int(res, gn) - hash_get_int(res, sibl) - dist_nodes(g, sibl, gn);
}

/* adjusts the position of previously placed left/right classes */
/* tries to place classes as close as possible */
static void adjust_class(const RzAGraph *g, int is_left, RzList /*<RzGraphNode *>*/ **classes, HtPU *res, int c) {
	const RzGraphNode *gn;
	const RzListIter *it;
	const RzANode *an;
	int dist = INT_MAX, v, is_first = true;

	rz_list_foreach (classes[c], it, gn) {
		if (!(an = gn->data)) {
			break;
		}
		const RzGraphNode *sibling;
		const RzANode *sibl_anode;

		sibling = get_sibling(g, an, is_left, true);
		if (!sibling) {
			continue;
		}
		sibl_anode = get_anode(sibling);
		if (sibl_anode->klass == c) {
			continue;
		}
		v = adjust_class_val(g, gn, sibling, res, is_left);
		dist = is_first ? v : RZ_MIN(dist, v);
		is_first = false;
	}

	if (is_first) {
		RzList *heap = rz_list_new();
		int len;

		rz_list_foreach (classes[c], it, gn) {
			if (!(an = gn->data)) {
				break;
			}
			// TODO(agraph-refactor): replace rz_graph_all_neighbours() by iterating out+in neighbors (dedupe if needed).
			const RzGraphNode *gk;
			const RzANode *ak;

			RzIterator *it_neigh_in = agraph_in_neighbors(g, gn);
			if (!it_neigh_in) {
				continue;
			}
			rz_iterator_foreach(it_neigh_in, gk) {
				if (!(ak = gk->data)) {
					break;
				}
				if (ak->klass < c) {
					size_t d = (an->x - ak->x);
					if (d > 0) {
						rz_list_append(heap, (void *)d);
					}
				}
			}
			rz_iterator_free(it_neigh_in);

			RzIterator *it_neigh_out = agraph_out_neighbors(g, gn);
			if (!it_neigh_out) {
				continue;
			}
			rz_iterator_foreach(it_neigh_out, gk) {
				if (!(ak = gk->data)) {
					break;
				}
				if (ak->klass < c) {
					size_t d = (ak->x - an->x);
					if (d > 0) {
						rz_list_append(heap, (void *)d);
					}
				}
			}
			rz_iterator_free(it_neigh_out);
		}

		len = rz_list_length(heap);
		if (len == 0) {
			dist = 0;
		} else {
			rz_list_sort(heap, (RzListComparator)cmp_dist, NULL);
			dist = (int)(size_t)rz_list_get_n(heap, len / 2);
		}

		rz_list_free(heap);
	}

	rz_list_foreach (classes[c], it, gn) {
		if (!(an = gn->data)) {
			break;
		}
		const int old_val = hash_get_int(res, gn);
		const int new_val = is_left ? old_val + dist : old_val - dist;
		ht_pu_update(res, gn, (ut64)(size_t)new_val);
	}
}

static int place_nodes_val(const RzAGraph *g, const RzGraphNode *gn, const RzGraphNode *sibl, HtPU *res, int is_left) {
	if (is_left) {
		return hash_get_int(res, sibl) + dist_nodes(g, sibl, gn);
	}
	return hash_get_int(res, sibl) - dist_nodes(g, gn, sibl);
}

static int place_nodes_sel_p(int newval, int oldval, int is_first, int is_left) {
	if (is_first) {
		return newval;
	}
	if (is_left) {
		return RZ_MAX(oldval, newval);
	}
	return RZ_MIN(oldval, newval);
}

/* places left/right the nodes of a class */
static void place_nodes(const RzAGraph *g, const RzGraphNode *gn, int is_left, HtPP *v_nodes, HtPU *res, RzSetU *placed) {
	const RzList *lv = ht_pp_find(v_nodes, gn, NULL);
	int p = 0, v, is_first = true;
	const RzGraphNode *gk;
	const RzListIter *itk;
	const RzANode *ak;

	rz_list_foreach (lv, itk, gk) {
		if (!(ak = gk->data)) {
			break;
		}
		const RzGraphNode *sibling;
		const RzANode *sibl_anode;

		sibling = get_sibling(g, ak, is_left, false);
		if (!sibling) {
			continue;
		}
		sibl_anode = get_anode(sibling);
		if (ak->klass == sibl_anode->klass) {
			if (!rz_set_u_contains(placed, (ut64)sibling)) {
				place_nodes(g, sibling, is_left, v_nodes, res, placed);
			}

			v = place_nodes_val(g, gk, sibling, res, is_left);
			p = place_nodes_sel_p(v, p, is_first, is_left);
			is_first = false;
		}
	}

	if (is_first) {
		p = is_left ? 0 : 50;
	}

	rz_list_foreach (lv, itk, gk) {
		if (!(ak = gk->data)) {
			break;
		}
		ht_pu_update(res, gk, (ut64)(size_t)p);
		rz_set_u_add(placed, (ut64)gk);
	}
}

/* computes the position to the left/right of all the nodes */
static HtPU *compute_pos(const RzAGraph *g, int is_left, HtPP *v_nodes) {
	int n_classes, i;

	RzList **classes = compute_classes(g, v_nodes, is_left, &n_classes);
	if (!classes) {
		return NULL;
	}

	HtPUOptions pu_opt = { 0 };
	HtPU *res = ht_pu_new_opt(&pu_opt);
	RzSetU *placed = rz_set_u_new();
	if (!res || !placed) {
		ht_pu_free(res);
		rz_set_u_free(placed);
		return NULL;
	}
	for (i = 0; i < n_classes; i++) {
		const RzGraphNode *gn;
		const RzListIter *it;

		rz_list_foreach (classes[i], it, gn) {
			if (!rz_set_u_contains(placed, (ut64)gn)) {
				place_nodes(g, gn, is_left, v_nodes, res, placed);
			}
		}

		adjust_class(g, is_left, classes, res, i);
	}

	rz_set_u_free(placed);
	for (i = 0; i < n_classes; i++) {
		if (classes[i]) {
			rz_list_free(classes[i]);
		}
	}
	free(classes);
	return res;
}

/* calculates position of all nodes, but in particular dummies nodes */
/* computes two different placements (called "left"/"right") and set the final
 * position of each node to the average of the values in the two placements */
static void place_dummies(const RzAGraph *g) {
	const RzGraphNode *gn;
	RzANode *n;

	HtPP *vertical_nodes = compute_vertical_nodes(g);
	if (!vertical_nodes) {
		return;
	}
	HtPU *xminus = compute_pos(g, true, vertical_nodes);
	if (!xminus) {
		goto xminus_err;
	}
	HtPU *xplus = compute_pos(g, false, vertical_nodes);
	if (!xplus) {
		goto xplus_err;
	}

	RzIterator *nodes = agraph_get_nodes(g);
	if (!nodes) {
		goto general_err;
	}

	rz_iterator_foreach(nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}
		n->x = (hash_get_int(xminus, gn) + hash_get_int(xplus, gn)) / 2;
	}
	rz_iterator_free(nodes);

general_err:
	ht_pu_free(xplus);
xplus_err:
	ht_pu_free(xminus);
xminus_err:
	ht_pp_free(vertical_nodes);
}

static RzGraphNode *get_right_dummy(const RzAGraph *g, const RzGraphNode *n) {
	const RzANode *an = get_anode(n);
	if (!an) {
		return NULL;
	}
	int k, layer = an->layer;

	for (k = an->pos_in_layer + 1; k < g->layers[layer].n_nodes; k++) {
		RzGraphNode *gk = g->layers[layer].nodes[k];
		const RzANode *ak = get_anode(gk);
		if (!ak) {
			break;
		}

		if (ak->is_dummy) {
			return gk;
		}
	}
	return NULL;
}

static void adjust_directions(const RzAGraph *g, int i, int from_up, HtPU *D, HtPU *P) {
	const RzGraphNode *vm = NULL, *wm = NULL;
	const RzANode *vma = NULL, *wma = NULL;
	int j, d = from_up ? 1 : -1;

	if (i + d < 0 || i + d >= g->n_layers) {
		return;
	}
	for (j = 0; j < g->layers[i + d].n_nodes; j++) {
		const RzGraphNode *wp, *vp = g->layers[i + d].nodes[j];
		const RzANode *wpa, *vpa = get_anode(vp);

		if (!vpa || !vpa->is_dummy) {
			continue;
		}
		if (from_up) {
			// TODO(agraph-refactor): replace rz_graph_innodes() (old list) with rz_graph_in_neighbors() iterator or rz_graph_in_edges().
			wp = agraph_nth_neighbour(g, vp, 0, false);
		} else {
			wp = agraph_nth_neighbour(g, vp, 0, true);
		}
		wpa = get_anode(wp);
		if (!wpa || !wpa->is_dummy) {
			continue;
		}
		if (vm) {
			int p = hash_get_int(P, wm);
			int k;

			for (k = wma->pos_in_layer + 1; k < wpa->pos_in_layer; k++) {
				const RzGraphNode *w = g->layers[wma->layer].nodes[k];
				const RzANode *aw = get_anode(w);
				if (aw && aw->is_dummy) {
					p &= hash_get_int(P, w);
				}
			}
			if (p) {
				ht_pu_update(D, vm, (ut64)(size_t)from_up);
				for (k = vma->pos_in_layer + 1; k < vpa->pos_in_layer; k++) {
					const RzGraphNode *v = g->layers[vma->layer].nodes[k];
					const RzANode *av = get_anode(v);
					if (av && av->is_dummy) {
						ht_pu_update(D, v, (ut64)(size_t)from_up);
					}
				}
			}
		}
		vm = vp;
		wm = wp;
		vma = get_anode(vm);
		wma = get_anode(wm);
	}
}

/* find a placement for a single node */
static void place_single(const RzAGraph *g, int l, const RzGraphNode *bm, const RzGraphNode *bp, int from_up, int va) {
	const RzGraphNode *gk, *v = g->layers[l].nodes[va];
	const RzANode *ak;
	RzANode *av = get_anode(v);
	if (!av) {
		return;
	}
	RzIterator *it_neigh = from_up
		? agraph_in_neighbors(g, v)
		: agraph_out_neighbors(g, v);

	// TODO: narrow the ut64 to int
	int len = from_up
		? rz_graph_in_degree(g->graph, v)
		: rz_graph_out_degree(g->graph, v);
	if (len == 0) {
		return;
	}

	int sum_x = 0;
	if (!it_neigh) {
		return;
	}
	rz_iterator_foreach(it_neigh, gk) {
		if (!(ak = gk->data)) {
			break;
		}
		if (ak->is_reversed) {
			len--;
			continue;
		}
		sum_x += ak->x;
	}
	rz_iterator_free(it_neigh);

	if (len == 0) {
		return;
	}
	if (av) {
		av->x = sum_x / len;
	}
	if (bm) {
		const RzANode *bma = get_anode(bm);
		av->x = RZ_MAX(av->x, bma->x + dist_nodes(g, bm, v));
	}
	if (bp) {
		const RzANode *bpa = get_anode(bp);
		av->x = RZ_MIN(av->x, bpa->x - dist_nodes(g, v, bp));
	}
}

static int RM_listcmp(const struct len_pos_t *a, const struct len_pos_t *b) {
	return (a->pos < b->pos) - (a->pos > b->pos);
}

static int RP_listcmp(const struct len_pos_t *a, const struct len_pos_t *b) {
	return (a->pos > b->pos) - (a->pos < b->pos);
}

static void collect_changes(const RzAGraph *g, int l, const RzGraphNode *b, int from_up, int s, int e, RzList /*<struct len_pos_t *>*/ *list, int is_left) {
	const RzGraphNode *vt = g->layers[l].nodes[e - 1];
	const RzGraphNode *vtp = g->layers[l].nodes[s];
	struct len_pos_t *cx;
	int i;

	RzListComparator lcmp = is_left ? (RzListComparator)RM_listcmp : (RzListComparator)RP_listcmp;

	for (i = is_left ? s : e - 1; (is_left && i < e) || (!is_left && i >= s); i = is_left ? i + 1 : i - 1) {
		const RzGraphNode *v, *vi = g->layers[l].nodes[i];
		const RzANode *av, *avi = get_anode(vi);
		RzIterator *it_neigh;
		int c = 0;

		if (!avi) {
			continue;
		}
		it_neigh = from_up
			? agraph_in_neighbors(g, vi)
			: agraph_out_neighbors(g, vi);
		if (!it_neigh) {
			continue;
		}

		rz_iterator_foreach(it_neigh, v) {
			if (!(av = v->data)) {
				break;
			}
			if ((is_left && av->x >= avi->x) || (!is_left && av->x <= avi->x)) {
				c++;
			} else {
				cx = RZ_NEW(struct len_pos_t);
				c--;
				cx->len = 2;
				cx->pos = av->x;
				if (is_left) {
					cx->pos += dist_nodes(g, vi, vt);
				} else {
					cx->pos -= dist_nodes(g, vtp, vi);
				}
				rz_list_add_sorted(list, cx, lcmp, NULL);
			}
		}
		rz_iterator_free(it_neigh);

		cx = RZ_NEW0(struct len_pos_t);
		cx->len = c;
		cx->pos = avi->x;
		if (is_left) {
			cx->pos += dist_nodes(g, vi, vt);
		} else {
			cx->pos -= dist_nodes(g, vtp, vi);
		}
		rz_list_add_sorted(list, cx, lcmp, NULL);
	}

	if (b) {
		const RzANode *ab = get_anode(b);
		cx = RZ_NEW(struct len_pos_t);
		if (cx) {
			cx->len = is_left ? INT_MAX : INT_MIN;
			cx->pos = ab->x;
			if (is_left) {
				cx->pos += dist_nodes(g, b, vt);
			} else {
				cx->pos -= dist_nodes(g, vtp, b);
			}
			rz_list_add_sorted(list, cx, lcmp, NULL);
		}
	}
}

static void combine_sequences(const RzAGraph *g, int l, const RzGraphNode *bm, const RzGraphNode *bp, int from_up, int a, int r) {
	RzList *Rm = rz_list_new(), *Rp = rz_list_new();
	const RzGraphNode *vt, *vtp;
	RzANode *at, *atp;
	int rm, rp, t, m, i;
	Rm->free = (RzListFree)free;
	Rp->free = (RzListFree)free;

	t = (a + r) / 2;
	vt = g->layers[l].nodes[t - 1];
	vtp = g->layers[l].nodes[t];
	at = get_anode(vt);
	atp = get_anode(vtp);

	collect_changes(g, l, bm, from_up, a, t, Rm, true);
	collect_changes(g, l, bp, from_up, t, r, Rp, false);
	rm = rp = 0;

	m = dist_nodes(g, vt, vtp);
	if (at && atp) {
		while (atp->x - at->x < m) {
			if (atp->x == at->x) {
				int step = m / 2;
				at->x -= step;
				atp->x += m - step;
			} else {
				if (rm < rp) {
					if (rz_list_empty(Rm)) {
						at->x = atp->x - m;
					} else {
						struct len_pos_t *cx = (struct len_pos_t *)rz_list_pop(Rm);
						rm = rm + cx->len;
						at->x = RZ_MAX(cx->pos, atp->x - m);
						free(cx);
					}
				} else {
					if (rz_list_empty(Rp)) {
						atp->x = at->x + m;
					} else {
						struct len_pos_t *cx = (struct len_pos_t *)rz_list_pop(Rp);
						rp = rp + cx->len;
						atp->x = RZ_MIN(cx->pos, at->x + m);
						free(cx);
					}
				}
			}
		}
	}

	rz_list_free(Rm);
	rz_list_free(Rp);

	for (i = t - 2; i >= a; i--) {
		const RzGraphNode *gv = g->layers[l].nodes[i];
		RzANode *av = get_anode(gv);
		if (av && at) {
			av->x = RZ_MIN(av->x, at->x - dist_nodes(g, gv, vt));
		}
	}

	for (i = t + 1; i < r; i++) {
		const RzGraphNode *gv = g->layers[l].nodes[i];
		RzANode *av = get_anode(gv);
		if (av && atp) {
			av->x = RZ_MAX(av->x, atp->x + dist_nodes(g, vtp, gv));
		}
	}
}

/* places a sequence of consecutive original nodes */
/* it tries to minimize the distance between each node in the sequence and its
 * neighbours in the "previous" layer. Those neighbours are considered as
 * "fixed". The previous layer depends on the direction used during the layers
 * traversal */
static void place_sequence(const RzAGraph *g, int l, const RzGraphNode *bm, const RzGraphNode *bp, int from_up, int va, int vr) {
	if (vr == va + 1) {
		place_single(g, l, bm, bp, from_up, va);
	} else if (vr > va + 1) {
		int vt = (vr + va) / 2;
		place_sequence(g, l, bm, bp, from_up, va, vt);
		place_sequence(g, l, bm, bp, from_up, vt, vr);
		combine_sequences(g, l, bm, bp, from_up, va, vr);
	}
}

/* finds the placements of nodes while traversing the graph in the given
 * direction */
/* places all the sequences of consecutive original nodes in each layer. */
static void original_traverse_l(const RzAGraph *g, HtPU *D, HtPU *P, int from_up) {
	int i, k, va, vr;

	for (i = from_up ? 0 : g->n_layers - 1;
		(from_up && i < g->n_layers) || (!from_up && i >= 0);
		i = from_up ? i + 1 : i - 1) {
		int j;
		const RzGraphNode *bm = NULL;
		const RzANode *bma = NULL;

		j = 0;
		while (j < g->layers[i].n_nodes && !bm) {
			const RzGraphNode *gn = g->layers[i].nodes[j];
			const RzANode *an = get_anode(gn);
			if (an && an->is_dummy) {
				va = 0;
				vr = j;
				bm = gn;
				bma = an;
			}
			j++;
		}
		if (!bm) {
			va = 0;
			vr = g->layers[i].n_nodes;
		}
		place_sequence(g, i, NULL, bm, from_up, va, vr);
		for (k = va; k < vr - 1; k++) {
			set_dist_nodes(g, i, k, k + 1);
		}
		if (is_valid_pos(g, i, vr - 1) && bm) {
			set_dist_nodes(g, i, vr - 1, bma->pos_in_layer);
		}
		while (bm) {
			const RzGraphNode *bp = get_right_dummy(g, bm);
			const RzANode *bpa = NULL;
			bma = get_anode(bm);

			if (!bp) {
				va = bma->pos_in_layer + 1;
				vr = g->layers[bma->layer].n_nodes;
				place_sequence(g, i, bm, NULL, from_up, va, vr);
				for (k = va; k < vr - 1; k++) {
					set_dist_nodes(g, i, k, k + 1);
				}

				if (is_valid_pos(g, i, va)) {
					set_dist_nodes(g, i, bma->pos_in_layer, va);
				}
			} else if (hash_get_int(D, bm) == from_up) {
				bpa = get_anode(bp);
				va = bma->pos_in_layer + 1;
				vr = bpa->pos_in_layer;
				place_sequence(g, i, bm, bp, from_up, va, vr);
				ht_pu_update(P, bm, 1);
			}
			bm = bp;
		}
		adjust_directions(g, i, from_up, D, P);
	}
}

/* computes a final position of original nodes, considering dummies nodes as
 * fixed */
/* set the node placements traversing the graph downward and then upward */
static void place_original(RzAGraph *g) {
	const RzGraphNode *gn;
	const RzANode *an;
	HtPUOptions opt = { 0 };

	RzIterator *nodes = agraph_get_nodes(g);
	if (!nodes) {
		return;
	}

	HtPU *D = ht_pu_new_opt(&opt);
	if (!D) {
		return;
	}
	HtPU *P = ht_pu_new_opt(&opt);
	if (!P) {
		ht_pu_free(D);
		return;
	}
	g->dists = rz_list_newf((RzListFree)free);
	if (!g->dists) {
		ht_pu_free(D);
		ht_pu_free(P);
		return;
	}

	rz_iterator_foreach(nodes, gn) {
		if (!(an = gn->data)) {
			break;
		}
		if (!an->is_dummy) {
			continue;
		}
		const RzGraphNode *right_v = get_right_dummy(g, gn);
		const RzANode *right = get_anode(right_v);
		if (right_v && right) {
			ht_pu_update(D, gn, 0);
			int dt_eq = right->x - an->x == dist_nodes(g, gn, right_v);
			ht_pu_update(P, gn, (ut64)(size_t)dt_eq);
		}
	}
	rz_iterator_free(nodes);

	original_traverse_l(g, D, P, true);
	original_traverse_l(g, D, P, false);

	rz_list_free(g->dists);
	g->dists = NULL;
	ht_pu_free(P);
	ht_pu_free(D);
}

static void set_layer_gap(RzAGraph *g) {
	int gap = 0;
	int i = 0, j = 0;
	RzGraphNode *ga, *gb;
	RzANode *a, *b;
	RzIterator *out_nodes_it;

	g->layers[0].gap = 0;
	for (i = 0; i < g->n_layers; i++) {
		gap = 0;
		if (i + 1 < g->n_layers) {
			g->layers[i + 1].gap = gap;
		}
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			ga = g->layers[i].nodes[j];
			if (!ga) {
				continue;
			}
			a = (RzANode *)ga->data;
			out_nodes_it = agraph_out_neighbors(g, ga);

			if (!out_nodes_it || !a) {
				continue;
			}
			rz_iterator_foreach(out_nodes_it, gb) {
				if (!(b = gb->data)) {
					break;
				}
				if (g->layout == 0) { // vertical layout
					if ((b->x != a->x) || b->layer <= a->layer) {
						gap += 1;
						if (b->layer <= a->layer) {
							g->layers[b->layer].gap += 1;
						}
					} else if ((!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
						gap += 1;
					}
				} else {
					if ((b->y == a->y && b->h != a->h) || b->y != a->y || b->layer <= a->layer) {
						gap += 1;
						if (b->layer <= a->layer) {
							g->layers[b->layer].gap += 1;
						}
					} else if ((!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
						gap += 1;
					}
				}
			}
			rz_iterator_free(out_nodes_it);
		}
		if (i + 1 < g->n_layers) {
			g->layers[i + 1].gap += gap;
		}
	}
}

static void fix_back_edge_dummy_nodes(RzAGraph *g, RzANode *from, RzANode *to) {
	RzANode *v, *tmp = NULL;
	RzGraphNode *gv = NULL;
	int i;
	rz_return_if_fail(g && from && to);

	RzIterator *it_neighbours = agraph_out_neighbors(g, to->gnode);
	if (!it_neighbours) {
		return;
	}

	rz_iterator_foreach(it_neighbours, gv) {
		if (!(v = gv->data)) {
			break;
		}
		tmp = v;
		while (tmp->is_dummy) {
			tmp = get_anode(agraph_nth_neighbour(g, tmp->gnode, 0, true));
		}
		if (tmp && tmp->gnode->hash_id == from->gnode->hash_id) {
			break;
		}
		tmp = NULL;
	}
	rz_iterator_free(it_neighbours);

	if (tmp) {
		tmp = v;
		while (tmp->gnode->hash_id != from->gnode->hash_id) {
			v = tmp;
			tmp = get_anode(agraph_nth_neighbour(g, tmp->gnode, 0, true));
			if (!tmp) {
				break;
			}

			i = 0;
			while (i < g->layers[v->layer].n_nodes &&
				(!g->layers[v->layer].nodes[i] || v->gnode->hash_id != g->layers[v->layer].nodes[i]->hash_id)) {
				i += 1;
			}
			if (i >= g->layers[v->layer].n_nodes) {
				break;
			}

			while (i + 1 < g->layers[v->layer].n_nodes) {
				g->layers[v->layer].nodes[i] = g->layers[v->layer].nodes[i + 1];
				i++;
			}
			g->layers[v->layer].nodes[g->layers[v->layer].n_nodes - 1] = 0;
			g->layers[v->layer].n_nodes -= 1;

			rz_graph_del_node(g->graph, v->gnode);
		}
	}
}

/**
 * Layout slot (agraph_get_edge_layout_slot):
 *   The logical index of an edge among a node's outgoing/incoming edges,
 *   determined by creation order and explicit nth metadata set when edges
 *   are added (e.g. jump=0, fail=1). Used during the Sugiyama layout
 *   pipeline to assign x-coordinates and during crossing minimization.
 *   Stable across redraws; does not depend on final node positions.
 *
 * Example: jump edge (nth=0) may end up to the right of the fail edge
 * after layout, giving it draw slot 1 even though its layout slot is 0.
 */
static int agraph_get_edge_layout_slot(const RzAGraph *g, RzANode *src, RzANode *dst, bool outgoing) {
	int cur_nth = 0;

	if (outgoing && src->is_dummy) {
		RzGraphNode *in_node = agraph_nth_neighbour(g, src->gnode, 0, false);
		RzANode *in = (RzANode *)(in_node ? in_node->data : NULL);
		cur_nth = agraph_get_edge_layout_slot(g, in, src, outgoing);
	} else {
		const ut64 exit_edges = outgoing ? agraph_out_degree(g, src->gnode) : agraph_in_degree(g, dst->gnode);
		if (g->is_callgraph) {
			cur_nth = 0;
		} else if (exit_edges == 1) {
			cur_nth = -1;
		} else if (outgoing) {
			RzGraphEdge *edge = agraph_find_graph_edge(g, src->gnode, dst->gnode);
			const int nth = get_edge_nth(edge);
			if (nth >= 0) {
				cur_nth = nth;
			} else {
				RzPVector *edges = agraph_collect_edges(g, src->gnode, true, true);
				if (edges) {
					void **it;
					int idx = 0;
					rz_pvector_foreach (edges, it) {
						RzGraphEdge *cur = *it;
						if (cur && cur->to == dst->gnode) {
							cur_nth = idx;
							break;
						}
						idx++;
					}
					rz_pvector_free(edges);
				}
			}
		} else {
			RzPVector *edges = agraph_collect_edges(g, dst->gnode, false, true);
			if (edges) {
				void **it;
				int idx = 0;
				rz_pvector_foreach (edges, it) {
					RzGraphEdge *cur = *it;
					if (cur && cur->from == src->gnode) {
						cur_nth = idx;
						break;
					}
					idx++;
				}
				rz_pvector_free(edges);
			}
		}
	}
	return cur_nth;
}

/*
 * Draw slot (agraph_get_edge_draw_slot):
 *   final slot rendered in CLI
 *   The visual index of where to draw the edge line, determined by the
 *   final x-coordinates of neighbour nodes after layout is complete.
 *   Neighbours are re-sorted by x position, so the left neighbour
 *   gets slot 0 regardless of creation order.
 *   Used only during rendering to decide horizontal line offsets.
 */
static int agraph_get_edge_draw_slot(const RzAGraph *g, RzANode *src, RzANode *dst) {
	rz_return_val_if_fail(g && src && dst, 0);
	RzANode *anchor = src;
	RzGraphNode *branch = dst->gnode;

	while (anchor && anchor->is_dummy) {
		branch = anchor->gnode;
		RzGraphNode *in_node = agraph_nth_neighbour(g, anchor->gnode, 0, false);
		anchor = in_node ? (RzANode *)in_node->data : NULL;
	}
	if (!anchor || !anchor->gnode || !branch) {
		return agraph_get_edge_layout_slot(g, src, dst, true);
	}
	if (g->is_callgraph) {
		return 0;
	}
	if (agraph_out_degree(g, anchor->gnode) == 1) {
		return -1;
	}

	RzPVector *draw_neighbours = agraph_collect_draw_neighbours(g, anchor->gnode);
	if (!draw_neighbours) {
		return agraph_get_edge_layout_slot(g, src, dst, true);
	}

	int res = agraph_get_edge_layout_slot(g, src, dst, true);
	void **pit;
	int idx = 0;
	rz_pvector_foreach (draw_neighbours, pit) {
		RzGraphNode *cur = *pit;
		if (cur == branch) {
			res = idx;
			break;
		}
		idx++;
	}
	rz_pvector_free(draw_neighbours);
	return res;
}

static int count_edges(const RzAGraph *g, RzANode *src, RzANode *dst) {
	return agraph_get_edge_layout_slot(g, src, dst, true);
}

static void backedge_info(RzAGraph *g) {
	int i, j, k;
	int min, max;
	int inedge = 0;
	int outedge = 0;

	int **arr = RZ_NEWS0(int *, g->n_layers);
	if (!arr) {
		return;
	}
	for (i = 0; i < g->n_layers; i++) {
		arr[i] = RZ_NEWS0(int, 2);
		if (!arr[i]) {
			goto err;
		}
	}

	for (i = 0; i < g->n_layers; i++) {
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RzGraphNode *gt = g->layers[i].nodes[j];
			if (!gt) {
				continue;
			}
			RzANode *t = (RzANode *)gt->data;
			if (!t) {
				continue;
			}
			int tc = g->layout == 0 ? t->x : t->y;
			int tl = g->layout == 0 ? t->w : t->h;
			if (!j) {
				arr[i][0] = tc;
				arr[i][1] = tc + tl;
			}

			if (arr[i][0] > tc) {
				arr[i][0] = tc;
			}

			if (arr[i][1] < tc + tl) {
				arr[i][1] = tc + tl;
			}
		}

		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RzANode *a = get_anode(g->layers[i].nodes[j]);
			if (!a || a->is_dummy) {
				continue;
			}

			RzGraphNode *gb;
			RzANode *b;

			if (i == 0) {
				// TODO: narrow ut64 to int now
				inedge += rz_graph_in_degree(g->graph, a->gnode);
			} else if (i == g->n_layers - 1) {
				outedge += rz_graph_out_degree(g->graph, a->gnode);
			}

			RzIterator *it_neighbours = agraph_out_neighbors(g, a->gnode);
			if (!it_neighbours) {
				continue;
			}

			rz_iterator_foreach(it_neighbours, gb) {
				if (!(b = gb->data)) {
					break;
				}
				if (b->layer > a->layer) {
					continue;
				}

				int nth = count_edges(g, a, b);
				int xinc = RZ_EDGES_X_INC + 2 * (nth + 1);

				int ax = g->layout == 0 ? a->x + xinc : a->y + (a->h / 2) + nth;
				int bx = g->layout == 0 ? b->x + xinc : b->y + (b->h / 2) + nth;

				if (g->layout == 0 && nth == 0 && bx > ax) {
					ax += 4;
				}

				min = arr[b->layer][0];
				max = arr[b->layer][1];
				for (k = b->layer; k <= a->layer; k++) {
					if (min > arr[k][0]) {
						min = arr[k][0];
					}

					if (max < arr[k][1]) {
						max = arr[k][1];
					}
				}

				int l = (ax - min) + (bx - min);
				int r = (max - ax) + (max - bx);

				for (k = b->layer; k <= a->layer; k++) {
					if (r < l) {
						arr[k][1] = max + 1;
					} else {
						arr[k][0] = min - 1;
					}
				}

				AEdge *e = RZ_NEW0(AEdge);
				if (!e) {
					free(arr);
					return;
				}

				e->is_reversed = true;
				e->from = a;
				e->to = b;
				e->x = rz_list_new();
				e->y = rz_list_new();

				if (r < l) {
					rz_list_append((g->layout == 0 ? e->x : e->y), (void *)(size_t)(max + 1));
				} else {
					rz_list_append((g->layout == 0 ? e->x : e->y), (void *)(size_t)(min - 1));
				}

				rz_list_append(g->edges, e);
			}
			rz_iterator_free(it_neighbours);
		}
	}

	// Assumption: layer layout is not changed w.r.t x-coordinate/y-coordinate for horizontal/vertical layout respectively.
	if (inedge) {
		RzANode *n = (RzANode *)g->layers[0].nodes[0]->data;
		AEdge *e = RZ_NEW0(AEdge);
		if (!e) {
			free(arr);
			return;
		}
		e->is_reversed = true;
		e->from = NULL;
		e->to = NULL;
		e->x = rz_list_new();
		e->y = rz_list_new();
		if (g->layout == 0) {
			rz_list_append(e->y, (void *)(size_t)(n->y - 1 - inedge));
		} else {
			rz_list_append(e->x, (void *)(size_t)(n->x - 1 - inedge));
		}
		rz_list_append(g->edges, e);
	}

	if (outedge) {
		RzANode *n = (RzANode *)g->layers[g->n_layers - 1].nodes[0]->data;
		AEdge *e = RZ_NEW0(AEdge);
		if (!e) {
			free(arr);
			return;
		}

		e->is_reversed = true;
		e->from = NULL;
		e->to = NULL;
		e->x = rz_list_new();
		e->y = rz_list_new();
		if (g->layout == 0) {
			rz_list_append(e->y, (void *)(size_t)(n->y + g->layers[g->n_layers - 1].height + 2 + outedge));
		} else {
			rz_list_append(e->x, (void *)(size_t)(n->x + g->layers[g->n_layers - 1].width + 2 + outedge));
		}
		rz_list_append(g->edges, e);
	}
err:
	for (i = i - 1; i >= 0; i--) {
		free(arr[i]);
	}
	free(arr);
	return;
}

static void agraph_edge_free(AEdge *e) {
	rz_list_free(e->x);
	rz_list_free(e->y);
	free(e);
}

/* 1) trasform the graph into a DAG
 * 2) partition the nodes in layers
 * 3) split long edges that traverse multiple layers
 * 4) reorder nodes in each layer to reduce the number of edge crossing
 * 5) assign x and y coordinates to each node
 * 6) restore the original graph, with long edges and cycles */
static void set_layout(RzAGraph *g) {
	int i, j, k;

	rz_list_free(g->edges);
	g->edges = rz_list_newf((RzListFree)agraph_edge_free);

	remove_cycles(g);
	assign_layers(g);
	create_dummy_nodes(g);
	create_layers(g);
	minimize_crossings(g);

	if (rz_cons_is_breaked()) {
		rz_cons_break_end();
		return;
	}
	/* identify row height */
	for (i = 0; i < g->n_layers; i++) {
		int rh = 0;
		int rw = 0;
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			const RzANode *n = get_anode(g->layers[i].nodes[j]);
			if (n->h > rh) {
				rh = n->h;
			}
			if (n->w > rw) {
				rw = n->w;
			}
		}
		g->layers[i].height = rh;
		g->layers[i].width = rw;
	}

	for (i = 0; i < g->n_layers; i++) {
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RzANode *a = (RzANode *)g->layers[i].nodes[j]->data;
			if (a->is_dummy) {
				if (g->layout == 0) {
					a->h = g->layers[i].height;
				} else {
					a->w = g->layers[i].width;
				}
			}
			a->layer_height = g->layers[i].height;
			a->layer_width = g->layers[i].width;
		}
	}

	/* x-coordinate assignment: algorithm based on:
	 * A Fast Layout Algorithm for k-Level Graphs
	 * by C. Buchheim, M. Junger, S. Leipert */
	place_dummies(g);
	place_original(g);

	/* IDEA: need to put this hack because of the way algorithm is implemented.
	 * I think backedges should be restored to their original state instead of
	 * converting them to longedges and adding dummy nodes. */
	const RzListIter *it;
	const RzGraphEdge *e;
	rz_list_foreach (g->back_edges, it, e) {
		RzANode *from = e->from ? get_anode(e->from) : NULL;
		RzANode *to = e->to ? get_anode(e->to) : NULL;
		if (!from || !to) {
			continue;
		}
		if (get_edge_tmp_reversed_added(e)) {
			fix_back_edge_dummy_nodes(g, from, to);
			rz_agraph_del_edge(g, to, from);
		}
		(void)agraph_add_graph_edge_ex(g, from->gnode, to->gnode, get_edge_nth(e), get_edge_kind(e), get_edge_creation_order(e));
	}

	switch (g->layout) {
	default:
	case 0: // vertical layout
		/* horizontal finalize x coordinate */
		for (i = 0; i < g->n_layers; i++) {
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RzANode *n = get_anode(g->layers[i].nodes[j]);
				if (n) {
					n->x -= n->w / 2;
				}
			}
		}

		set_layer_gap(g);

		/* vertical align */
		for (i = 0; i < g->n_layers; i++) {
			int tmp_y = 0;
			tmp_y = g->layers[0].gap; // TODO: XXX: set properly
			for (k = 1; k <= i; k++) {
				tmp_y += g->layers[k - 1].height + g->layers[k].gap + 3; // XXX: should be 4?
			}
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RzANode *n = get_anode(g->layers[i].nodes[j]);
				if (n) {
					n->y = tmp_y;
				}
			}
		}
		break;
		/* experimental */
	case 1: // horizontal layout
		/* vertical y coordinate */
		for (i = 0; i < g->n_layers; i++) {
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RzANode *n = get_anode(g->layers[i].nodes[j]);
				n->y = 1;
				for (k = 0; k < j; k++) {
					RzANode *m = get_anode(g->layers[i].nodes[k]);
					n->y -= (m->h + VERTICAL_NODE_SPACING);
				}
			}
		}

		set_layer_gap(g);

		/* horizontal align */
		for (i = 0; i < g->n_layers; i++) {
			int xval = 1 + g->layers[0].gap + 1;
			for (k = 1; k <= i; k++) {
				xval += g->layers[k - 1].width + g->layers[k].gap + 3;
			}
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RzANode *n = get_anode(g->layers[i].nodes[j]);
				n->x = xval;
			}
		}
		break;
	}

	backedge_info(g);

	/* free all temporary structures used during layout */
	for (i = 0; i < g->n_layers; i++) {
		free(g->layers[i].nodes);
	}

	free(g->layers);
	rz_list_free(g->long_edges);
	rz_list_free(g->back_edges);
	rz_cons_break_pop();
}

static char *get_body(RzCore *core, ut64 addr, int size, int opts) {
	char *body;
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return NULL;
	}
	rz_config_hold_i(hc, "asm.lines", "asm.bytes",
		"asm.cmt.col", "asm.marks", "asm.offset",
		"asm.comments", "asm.cmt.right", "asm.bb.line", NULL);
	const bool o_comments = rz_config_get_i(core->config, "graph.comments");
	const bool o_cmtright = rz_config_get_i(core->config, "graph.cmtright");
	const bool o_bytes = rz_config_get_i(core->config, "graph.bytes");
	const bool o_flags_in_bytes = rz_config_get_i(core->config, "asm.flags.inbytes");
	const bool o_asm_offset = rz_config_get_i(core->config, "asm.offset");
	int o_cursor = core->print->cur_enabled;
	if (opts & BODY_COMMENTS) {
		rz_core_visual_toggle_decompiler_disasm(core, true, false);
		char *res = rz_core_cmd_strf(core, "pD %d @ 0x%08" PFMT64x, size, addr);
		res = rz_str_replace(res, "; ", "", true);
		// res = rz_str_replace (res, "\n", "(\n)", true);
		rz_str_trim(res);
		res = rz_str_trim_lines(res);
		rz_core_visual_toggle_decompiler_disasm(core, true, false);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		return res;
	}
	const char *cmd = (opts & BODY_SUMMARY) ? "pds" : "pD";

	// configure options
	rz_config_set_i(core->config, "asm.bb.line", false);
	rz_config_set_i(core->config, "asm.lines", false);
	rz_config_set_i(core->config, "asm.cmt.col", 0);
	rz_config_set_i(core->config, "asm.marks", false);
	rz_config_set_i(core->config, "asm.cmt.right", (opts & BODY_SUMMARY) || o_cmtright);
	rz_config_set_i(core->config, "asm.comments", (opts & BODY_SUMMARY) || o_comments);
	rz_config_set_i(core->config, "asm.bytes",
		(opts & (BODY_SUMMARY | BODY_OFFSETS)) || o_bytes || o_flags_in_bytes);
	rz_config_set_i(core->config, "asm.bb.middle", false);
	core->print->cur_enabled = false;

	rz_config_set_b(core->config, "asm.offset",
		(opts & BODY_OFFSETS) || (opts & BODY_SUMMARY) || o_asm_offset);

	bool html = rz_config_get_i(core->config, "scr.html");
	rz_config_set_i(core->config, "scr.html", 0);
	if (rz_config_get_i(core->config, "graph.aeab")) {
		body = rz_core_cmd_strf(core, "%s 0x%08" PFMT64x, "aeab", addr);
	} else {
		body = rz_core_cmd_strf(core, "%s %d @ 0x%08" PFMT64x, cmd, size, addr);
	}
	rz_config_set_i(core->config, "scr.html", html);

	// restore original options
	core->print->cur_enabled = o_cursor;
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return body;
}

static char *get_bb_body(RzCore *core, RzAnalysisBlock *b, int opts, RzAnalysisFunction *fcn, bool emu, ut64 saved_gp, ut8 *saved_arena) {
	if (emu) {
		core->analysis->gp = saved_gp;
		if (b->parent_reg_arena) {
			rz_reg_arena_poke(core->analysis->reg, b->parent_reg_arena);
			RZ_FREE(b->parent_reg_arena);
			ut64 gp = rz_reg_getv(core->analysis->reg, "gp");
			if (gp) {
				core->analysis->gp = gp;
			}
		} else {
			rz_reg_arena_poke(core->analysis->reg, saved_arena);
		}
	}
	char *body = get_body(core, b->addr, b->size, opts);
	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RzAnalysisBlock *jumpbb = rz_analysis_get_block_at(b->analysis, b->jump);
			if (jumpbb && rz_list_contains(jumpbb->fcns, fcn)) {
				if (emu && core->analysis->last_disasm_reg != NULL && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = rz_reg_arena_dup(core->analysis->reg, core->analysis->last_disasm_reg);
				}
			}
		}
	}
	if (b->fail != UT64_MAX) {
		if (b->fail > b->addr) {
			RzAnalysisBlock *failbb = rz_analysis_get_block_at(b->analysis, b->fail);
			if (failbb && rz_list_contains(failbb->fcns, fcn)) {
				if (emu && core->analysis->last_disasm_reg != NULL && !failbb->parent_reg_arena) {
					failbb->parent_reg_arena = rz_reg_arena_dup(core->analysis->reg, core->analysis->last_disasm_reg);
				}
			}
		}
	}
	return body;
}

static int bbcmp(RzAnalysisBlock *a, RzAnalysisBlock *b) {
	return a->addr - b->addr;
}

static void get_bbupdate(RzAGraph *g, RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	void **iter;
	bool emu = rz_config_get_i(core->config, "asm.emu");
	ut64 saved_gp = core->analysis->gp;
	ut8 *saved_arena = NULL;
	char *shortcut = 0;
	int shortcuts = 0;
	core->keep_asmqjmps = false;

	if (emu) {
		saved_arena = rz_reg_arena_peek(core->analysis->reg);
	}
	if (!fcn) {
		RZ_FREE(saved_arena);
		return;
	}
	rz_pvector_sort(fcn->bbs, (RzPVectorComparator)bbcmp, NULL);

	shortcuts = rz_config_get_i(core->config, "graph.nodejmps");
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *body = get_bb_body(core, bb, mode2opts(g), fcn, emu, saved_gp, saved_arena);
		char *title = get_title(bb->addr);

		if (shortcuts) {
			shortcut = rz_core_add_asmqjmp(core, bb->addr);
			if (shortcut) {
				char buf[384] = { 0 };
				rz_strf(buf, "agraph.nodes.%s.shortcut", title);
				sdb_set(g->db, buf, shortcut);
				free(shortcut);
			}
		}
		RzANode *node = rz_agraph_get_node(g, title);
		if (node) {
			free(node->body);
			node->body = body;
		} else {
			free(body);
		}
		free(title);
		core->keep_asmqjmps = true;
	}

	if (emu) {
		core->analysis->gp = saved_gp;
		if (saved_arena) {
			rz_reg_arena_poke(core->analysis->reg, saved_arena);
			RZ_FREE(saved_arena);
		}
	}
}

static void fold_asm_trace(RzCore *core, RzAGraph *g) {
	RzGraphNode *gn;
	RzANode *n;

	RzANode *curnode = get_anode(g->curnode);

	RzIterator *nodes = agraph_get_nodes(g);
	if (!nodes) {
		return;
	}

	rz_iterator_foreach(nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}
		if (curnode == n) {
			n->is_mini = false;
			g->need_reload_nodes = true;
			continue;
		}
		ut64 addr = rz_num_get(NULL, n->title);
		RzDebugTracepoint *tp = rz_debug_trace_get(core->dbg, addr);
		n->is_mini = (tp == NULL);
	}
	rz_iterator_free(nodes);
	g->need_update_dim = 1;
	// agraph_refresh (rz_cons_singleton ()->event_data);
}

static void delete_dup_edges(RzAGraph *g) {
	RzIterator *node_it = agraph_get_nodes(g);
	RzGraphNode *n;
	rz_iterator_foreach(node_it, n) {
		RzPVector *seen = rz_pvector_new(NULL);
		RzPVector *dups = rz_pvector_new(NULL);

		RzIterator *out_it = agraph_out_neighbors(g, n);
		RzGraphNode *target;
		if (out_it) {
			rz_iterator_foreach(out_it, target) {
				bool found = false;
				void **pit;
				rz_pvector_foreach (seen, pit) {
					if (*pit == target) {
						found = true;
						break;
					}
				}
				if (found) {
					rz_pvector_push(dups, target);
				} else {
					rz_pvector_push(seen, target);
				}
			}
			rz_iterator_free(out_it);
		}

		void **pit;
		rz_pvector_foreach (dups, pit) {
			agraph_del_graph_edge(g, n, (RzGraphNode *)*pit);
		}

		rz_pvector_free(seen);
		rz_pvector_free(dups);
	}
	rz_iterator_free(node_it);
}

static bool isbbfew(RzAnalysisBlock *curbb, RzAnalysisBlock *bb) {
	if (bb->addr == curbb->addr || bb->addr == curbb->jump || bb->addr == curbb->fail) {
		// do nothing
		return true;
	}
	if (curbb->switch_op) {
		RzListIter *it;
		RzAnalysisCaseOp *cop;
		rz_list_foreach (curbb->switch_op->cases, it, cop) {
			if (cop->addr == bb->addr) {
				return true;
			}
		}
	}
	return false;
}

/* build the RzGraph inside the RzAGraph g, starting from the Basic Blocks */
static int get_bbnodes(RzAGraph *g, RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	void **iter;
	bool emu = rz_config_get_i(core->config, "asm.emu");
	bool few = rz_config_get_i(core->config, "graph.few");
	int ret = false;
	ut64 saved_gp = core->analysis->gp;
	ut8 *saved_arena = NULL;
	core->keep_asmqjmps = false;

	if (!fcn) {
		return false;
	}
	if (emu) {
		saved_arena = rz_reg_arena_peek(core->analysis->reg);
	}
	rz_pvector_sort(fcn->bbs, (RzPVectorComparator)bbcmp, NULL);
	RzAnalysisBlock *curbb = NULL;
	if (few) {
		rz_pvector_foreach (fcn->bbs, iter) {
			bb = (RzAnalysisBlock *)*iter;
			if (!curbb) {
				curbb = bb;
			}
			if (rz_analysis_block_contains(bb, core->offset)) {
				curbb = bb;
				break;
			}
		}
	}

	core->keep_asmqjmps = false;
	bool shortcuts = rz_core_agraph_is_shortcuts(core, g);
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		if (bb->addr == UT64_MAX) {
			continue;
		}
		if (few && !isbbfew(curbb, bb)) {
			continue;
		}
		char *body = get_bb_body(core, bb, mode2opts(g), fcn, emu, saved_gp, saved_arena);
		char *title = get_title(bb->addr);

		RzANode *node = rz_agraph_add_node(g, title, body);
		if (shortcuts) {
			rz_core_agraph_add_shortcut(core, g, node, bb->addr, title);
		}
		free(body);
		free(title);
		if (!node) {
			goto cleanup;
		}
		core->keep_asmqjmps = true;
	}

	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		if (bb->addr == UT64_MAX) {
			continue;
		}
		if (few && !isbbfew(curbb, bb)) {
			continue;
		}

		char *title = get_title(bb->addr);
		RzANode *u = rz_agraph_get_node(g, title);
		RzANode *v;
		free(title);
		if (bb->jump != UT64_MAX) {
			title = get_title(bb->jump);
			v = rz_agraph_get_node(g, title);
			free(title);
			rz_agraph_add_edge_at(g, u, v, 0);
			set_edge_kind(agraph_find_graph_edge(g, u->gnode, v->gnode), AGRAPH_EDGE_KIND_TRUE);
		}
		if (bb->fail != UT64_MAX) {
			title = get_title(bb->fail);
			v = rz_agraph_get_node(g, title);
			free(title);
			rz_agraph_add_edge_at(g, u, v, 1);
			set_edge_kind(agraph_find_graph_edge(g, u->gnode, v->gnode), AGRAPH_EDGE_KIND_FALSE);
			if (bb->jump != UT64_MAX && u->title && v->title) {
				char buf[384] = { 0 };
				rz_strf(buf, "agraph.nodes.%s.neighbours", u->title);
				char *db_val = rz_str_newf(",%s", v->title);
				if (db_val) {
					sdb_set(g->db, buf, db_val);
					free(db_val);
				}
			}
		}
		if (bb->switch_op) {
			RzListIter *it;
			RzAnalysisCaseOp *cop;
			rz_list_foreach (bb->switch_op->cases, it, cop) {
				title = get_title(cop->addr);
				v = rz_agraph_get_node(g, title);
				free(title);
				rz_agraph_add_edge(g, u, v);
			}
		}
	}

	delete_dup_edges(g);
	ret = true;

cleanup:
	if (emu) {
		core->analysis->gp = saved_gp;
		if (saved_arena) {
			rz_reg_arena_poke(core->analysis->reg, saved_arena);
			RZ_FREE(saved_arena);
		}
	}
	return ret;
}

/* build the RzGraph inside the RzAGraph g, starting from the Call Graph
 * information */
static bool get_cgnodes(RzAGraph *g, RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	RzANode *node, *fcn_anode;
	RzListIter *iter;
	RzAnalysisXRef *xref;
	if (!f) {
		return false;
	}
	if (!fcn) {
		fcn = f;
	}

	rz_core_seek(core, f->addr, true);

	char *title = get_title(fcn->addr);
	fcn_anode = rz_agraph_add_node(g, title, "");

	free(title);
	if (!fcn_anode) {
		return false;
	}

	fcn_anode->x = 10;
	fcn_anode->y = 3;

	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xref) {
		title = get_title(xref->to);
		if (rz_agraph_get_node(g, title) != NULL) {
			continue;
		}
		free(title);

		int size = 0;
		RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, xref->to);
		if (bb) {
			size = bb->size;
		}

		char *body = get_body(core, xref->to, size, mode2opts(g));
		title = get_title(xref->to);

		node = rz_agraph_add_node(g, title, body);
		if (!node) {
			return false;
		}

		free(title);
		free(body);

		node->x = 10;
		node->y = 10;

		rz_agraph_add_edge(g, fcn_anode, node);
	}
	rz_list_free(xrefs);

	return true;
}

static bool reload_nodes(RzAGraph *g, RzCore *core, RzAnalysisFunction *fcn) {
	const bool is_c = g->is_callgraph;
	return is_c ? get_cgnodes(g, core, fcn) : get_bbnodes(g, core, fcn);
}

static void update_seek(RzConsCanvas *can, RzANode *n, int force) {
	if (!n) {
		return;
	}
	int x = n->x + can->sx;
	int y = n->y + can->sy;
	int w = can->w;
	int h = can->h;

	const bool doscroll = force || y < 0 || y + 5 > h || x + 5 > w || x + n->w + 5 < 0;
	if (doscroll) {
		if (n->w > w) { // too big for centering
			can->sx = -n->x;
		} else {
			can->sx = -n->x - n->w / 2 + w / 2;
		}
		if (n->h > h) { // too big for centering
			can->sy = -n->y;
		} else {
			can->sy = -n->y - n->h / 8 + h / 4;
		}
	}
}

static int is_near(const RzANode *n, int x, int y, int is_next) {
	if (is_next) {
		return (n->y == y && n->x > x) || n->y > y;
	}
	return (n->y == y && n->x < x) || n->y < y;
}

/// XXX is wrong
static int is_near_h(const RzANode *n, int x, int y, int is_next) {
	if (is_next) {
		return (n->x == x && n->y > y) || n->x > x;
	}
	return (n->x == x && n->y < y) || n->x < x;
}

static const RzGraphNode *find_near_of(const RzAGraph *g, const RzGraphNode *cur, int is_next) {
	/* XXX: it's slow */
	const RzGraphNode *gn, *resgn = NULL;
	const RzANode *n, *acur = cur ? get_anode(cur) : NULL;
	const int default_v = is_next ? INT_MIN : INT_MAX;
	const int start_x = acur ? acur->x : default_v;
	const int start_y = acur ? acur->y : default_v;

	RzIterator *nodes = agraph_get_nodes(g);
	if (!nodes) {
		return NULL;
	}

	rz_iterator_foreach(nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}
		// tab in horizontal layout is not correct, lets force vertical nextnode for now (g->layout == 0)
		bool isNear = true
			? is_near(n, start_x, start_y, is_next)
			: is_near_h(n, start_x, start_y, is_next);
		if (isNear) {
			const RzANode *resn;

			if (!resgn) {
				resgn = gn;
				continue;
			}

			resn = get_anode(resgn);
			if ((is_next && resn->y > n->y) || (!is_next && resn->y < n->y)) {
				resgn = gn;
			} else if ((is_next && resn->y == n->y && resn->x > n->x) ||
				(!is_next && resn->y == n->y && resn->x < n->x)) {
				resgn = gn;
			}
		}
	}
	rz_iterator_free(nodes);

	if (!resgn && cur) {
		resgn = find_near_of(g, NULL, is_next);
	}
	return resgn;
}

static void update_graph_sizes(RzAGraph *g) {
	RzListIter *it;
	RzGraphNode *gk;
	RzANode *ak, *min_gn, *max_gn;
	int max_x, max_y;
	int delta_x, delta_y;
	AEdge *e;

	g->x = g->y = INT_MAX;
	max_x = max_y = INT_MIN;
	min_gn = max_gn = NULL;

	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}

	rz_iterator_foreach(it_nodes, gk) {
		if (!(ak = gk->data)) {
			break;
		}
		int len;
		if (ak->x < g->x) {
			g->x = ak->x;
		}

		// Compatibility: old agraph always reserved one line above a node,
		// because the old list API returned an empty neighbour list, not NULL.
		int in_degree = agraph_in_degree(g, gk);
		len = in_degree + 1;
		if (ak->y - len < g->y) {
			g->y = ak->y - len;
			min_gn = ak;
		}

		if (ak->x + ak->w > max_x) {
			max_x = ak->x + ak->w;
		}

		// Compatibility: old agraph always reserved two lines below a node.
		int out_degree = agraph_out_degree(g, gk);
		len = out_degree + 2;
		if (ak->y + ak->h + len > max_y) {
			max_y = ak->y + ak->h + len;
			max_gn = ak;
		}
	}
	rz_iterator_free(it_nodes);

	/* while calculating the graph size, take into account long edges */
	rz_list_foreach (g->edges, it, e) {
		RzListIter *kt;
		void *vv;
		int v;
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_list_foreach (e->x, kt, vv) {
			v = (int)(size_t)vv;
			if (v < g->x) {
				g->x = v;
			}
			if (v + 1 > max_x) {
				max_x = v + 1;
			}
		}
		rz_list_foreach (e->y, kt, vv) {
			v = (int)(size_t)vv;
			if (v < g->y) {
				g->y = v;
			}
			if (v + 1 > max_y) {
				max_y = v + 1;
			}
		}
	}
	rz_cons_break_pop();

	if (min_gn) {
		ut64 in_degree = agraph_in_degree(g, min_gn->gnode);
		if (in_degree > 0) {
			g->y--;
			max_y++;
		}
		if (max_gn) {
			// Compatibility: preserve the old min-node based bottom padding.
			ut64 out_degree = agraph_out_degree(g, min_gn->gnode);
			if (out_degree > 0) {
				max_y++;
			}
		}
	}

	if (g->x != INT_MAX && g->y != INT_MAX) {
		g->w = max_x - g->x;
		if (g->title) {
			size_t len = strlen(g->title);
			if (len > INT_MAX) {
				g->w = INT_MAX;
			}
			if ((int)len > g->w) {
				g->w = len;
			}
		}
		g->h = max_y - g->y;
	} else {
		g->x = g->y = 0;
		g->w = g->h = 0;
	}

	sdb_num_set(g->db, "agraph.w", g->w);
	sdb_num_set(g->db, "agraph.h", g->h);
	/* delta_x, delta_y are needed to make every other x,y coordinates
	 * unsigned, so that we can use sdb_num_ API */
	delta_x = g->x < 0 ? -g->x : 0;
	delta_y = g->y < 0 ? -g->y : 0;
	sdb_num_set(g->db, "agraph.delta_x", delta_x);
	sdb_num_set(g->db, "agraph.delta_y", delta_y);
}

RZ_API void rz_agraph_set_curnode(RzAGraph *g, RzANode *a) {
	if (!a) {
		return;
	}
	g->curnode = a->gnode;
	if (a->title) {
		sdb_set(g->db, "agraph.curnode", a->title);
		if (g->on_curnode_change) {
			g->on_curnode_change(a, g->on_curnode_change_data);
		}
	}
}

/* =========================================================================
 * Rendering:
 *   agraph_set_layout (trigger) -> agraph_print_nodes -> agraph_print_edges
 *   -> rz_cons_canvas_* (draw primitives)
 * ========================================================================= */

static ut64 rebase(RzAGraph *g, int v) {
	return g->x < 0 ? -g->x + v : v;
}

static void agraph_set_layout(RzAGraph *g) {
	RzGraphNode *n;
	RzANode *a;

	set_layout(g);

	update_graph_sizes(g);

	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}

	rz_iterator_foreach(it_nodes, n) {
		if (!(a = n->data)) {
			break;
		}
		if (a->is_dummy) {
			continue;
		}
		char buf[384] = { 0 };
		rz_strf(buf, "agraph.nodes.%s.x", a->title);
		sdb_num_set(g->db, buf, rebase(g, a->x));
		rz_strf(buf, "agraph.nodes.%s.y", a->title);
		sdb_num_set(g->db, buf, rebase(g, a->y));
		rz_strf(buf, "agraph.nodes.%s.w", a->title);
		sdb_num_set(g->db, buf, a->w);
		rz_strf(buf, "agraph.nodes.%s.h", a->title);
		sdb_num_set(g->db, buf, a->h);
	}
	rz_iterator_free(it_nodes);
}

/* set the willing to center the screen on a particular node */
static void agraph_update_seek(RzAGraph *g, RzANode *n, int force) {
	g->update_seek_on = n;
	g->force_update_seek = force;
}

static void agraph_print_node(const RzAGraph *g, RzANode *n, const AGraphContext *grp_ctx) {
	if (n->is_dummy) {
		return;
	}
	const int cur = g->curnode && get_anode(g->curnode) == n;
	const bool isMini = is_mini(g);
	if (isMini || n->is_mini) {
		mini_RzANode_print(g, n, grp_ctx, cur, isMini);
	} else {
		normal_RzANode_print(g, n, cur);
	}
}

static void agraph_print_nodes(const RzAGraph *g, const AGraphContext *grp_ctx) {
	RzGraphNode *gn;
	RzANode *n;

	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}

	rz_iterator_foreach(it_nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}
		if (gn != g->curnode) {
			agraph_print_node(g, n, grp_ctx);
		}
	}
	rz_iterator_free(it_nodes);

	/* draw current node now to make it appear on top */
	if (g->curnode) {
		agraph_print_node(g, get_anode(g->curnode), grp_ctx);
	}
}

struct tmplayer {
	int layer;
	int edgectr;
	int revedgectr;
	int minx;
	int maxx;
};
struct tmpbackedgeinfo {
	int ax;
	int ay;
	int bx;
	int by;
	int edgectr;
	int fromlayer;
	int tolayer;
	RzCanvasLineStyle style;
};

int tmplayercmp(const void *a, const void *b, void *user) {
	return ((struct tmplayer *)a)->layer > ((struct tmplayer *)b)->layer;
}

static void agraph_print_edges_simple(RzAGraph *g) {
	RzCanvasLineStyle style = { 0 };
	RzANode *n, *n2;
	RzGraphNode *gn, *gn2;

	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}

	rz_iterator_foreach(it_nodes, gn) {
		if (!(n = gn->data)) {
			break;
		}

		RzIterator *it_outnodes = agraph_out_neighbors(g, gn);
		if (!it_outnodes) {
			continue;
		}

		rz_iterator_foreach(it_outnodes, gn2) {
			if (!(n2 = gn2->data)) {
				break;
			}
			int sx = n->w / 2;
			int sy = n->h;
			int sx2 = n2->w / 2;
			// TODO: better alignments here
			rz_cons_canvas_line(g->can,
				n->x + sx, n->y + sy,
				n2->x + sx2, n2->y, &style);

			if (n2->is_dummy) {
				rz_cons_canvas_line(g->can,
					n2->x + sx2, n2->y - 1,
					n2->x + sx2, n2->y + n2->h, &style);
			}
		}
		rz_iterator_free(it_outnodes);
	}
	rz_iterator_free(it_nodes);
}

static void agraph_print_edges(RzAGraph *g) {
	if (!g->edgemode) {
		return;
	}
	if (g->edgemode == 1) {
		agraph_print_edges_simple(g);
		return;
	}
	int out_nth, in_nth, bendpoint;
	RzListIter *itm, *ito;
	RzCanvasLineStyle style = { 0 };
	RzGraphNode *ga;
	RzANode *a;
	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}

	RzList *lyr = rz_list_new();
	RzList *bckedges = rz_list_new();
	struct tmplayer *tl, *tm;

	rz_iterator_foreach(it_nodes, ga) {
		if (!(a = ga->data)) {
			break;
		}
		const RzGraphNode *gb;
		RzANode *b;

		int ax, ay, bx, by, a_x_inc, b_x_inc;
		tl = tm = NULL;
		if (rz_cons_is_breaked()) {
			break;
		}

		rz_list_foreach (lyr, ito, tl) {
			if (tl->layer == a->layer) {
				tm = tl;
				if (g->layout == 0) { // vertical layout
					if (tm->minx > a->x) {
						tm->minx = a->x;
					}
					if (tm->maxx < a->x + a->w) {
						tm->maxx = a->x + a->w;
					}
				} else {
					if (tm->minx > a->y) {
						tm->minx = a->y;
					}
					if (tm->maxx < a->y + a->h) {
						tm->maxx = a->y + a->h;
					}
				}
				break;
			}
		}

		if (!tm) {
			tm = RZ_NEW0(struct tmplayer);
			if (tm) {
				tm->layer = a->layer;
				tm->edgectr = 0;
				tm->revedgectr = 0;
				if (g->layout == 0) { // vertical layout
					tm->minx = a->x;
					tm->maxx = a->x + a->w;
				} else {
					tm->minx = a->y;
					tm->maxx = a->y + a->h;
				}
				rz_list_add_sorted(lyr, tm, tmplayercmp, NULL);
			}
		}

		ut64 ga_out_degree = rz_graph_out_degree(g->graph, ga);
		bool many = ga_out_degree > 2;
		RzPVector *draw_neighbours = agraph_collect_draw_neighbours(g, ga);
		if (!draw_neighbours) {
			continue;
		}
		size_t draw_idx = 0;
		void **pit;
		rz_pvector_foreach (draw_neighbours, pit) {
			gb = *pit;
			if (!(b = gb->data)) {
				draw_idx++;
				continue;
			}
			RzGraphEdge *edge = agraph_find_graph_edge(g, a->gnode, b->gnode);
			out_nth = agraph_get_edge_draw_slot(g, a, b);
			in_nth = agraph_get_edge_layout_slot(g, a, b, false);
			bool parent_many = false;
			if (a->is_dummy) {
				RzANode *in = get_anode(agraph_nth_neighbour(g, ga, 0, false));
				while (in && in->is_dummy) {
					in = get_anode(agraph_nth_neighbour(g, in->gnode, 0, false));
				}
				if (in && in->gnode) {
					const ut64 parent_out_degree = rz_graph_out_degree(g->graph, in->gnode);
					parent_many = parent_out_degree > 2;
				} else {
					parent_many = false;
				}
			}

			style.dot_style = DOT_STYLE_NORMAL;
			if (many || parent_many || g->is_il) {
				style.color = LINE_UNCJMP;
			} else {
				int edge_kind = out_nth >= 0 && agraph_out_degree(g, a->gnode) > 1
					? get_edge_kind(edge)
					: AGRAPH_EDGE_KIND_UNKNOWN;
				switch (edge_kind != AGRAPH_EDGE_KIND_UNKNOWN ? edge_kind : out_nth) {
				case 0:
					style.color = LINE_TRUE;
					style.dot_style = DOT_STYLE_CONDITIONAL;
					break;
				case 1:
					style.color = LINE_FALSE;
					style.dot_style = DOT_STYLE_CONDITIONAL;
					break;
				case -1:
					style.color = LINE_UNCJMP;
					break;
				default:
					style.color = LINE_NONE;
					break;
				}
			}

			switch (g->layout) {
			case 0:
			default:
				style.symbol = (!g->hints || a->is_dummy) ? LINE_NOSYM_VERT : style.color;
				if (a->y + a->h > b->y) {
					style.dot_style = DOT_STYLE_BACKEDGE;
				}

				a_x_inc = RZ_EDGES_X_INC + 2 * (out_nth + 1);
				b_x_inc = RZ_EDGES_X_INC + 2 * (in_nth + 1);

				bx = b->is_dummy ? b->x : (b->x + b_x_inc);
				ay = a->y + a->h;
				by = b->y - 1;

				if (many && !g->is_callgraph) {
					int t = RZ_EDGES_X_INC + 2 * (ga_out_degree + 1);
					ax = a->is_dummy ? a->x : (a->x + a->w / 2 + (t / 2 - a_x_inc));
					bendpoint = bx < ax ? ga_out_degree - out_nth : out_nth;
				} else {
					ax = a->is_dummy ? a->x : (a->x + a_x_inc);
					bendpoint = tm->edgectr;
				}

				/* Compatibility: pre-refactor agraph only nudged the actual head
				 * entry of the neighbour list, not the first edge that happened to
				 * satisfy the condition later during iteration. */
				if (!a->is_dummy && draw_idx == 0 && out_nth == 0 && bx > ax) {
					ax += (many && !g->is_callgraph) ? 0 : 4;
				}
				if (a->h < a->layer_height) {
					rz_cons_canvas_line(g->can, ax, ay, ax, ay + a->layer_height - a->h, &style);
					ay = a->y + a->layer_height;
					style.symbol = LINE_NOSYM_VERT;
				}
				if (by >= ay) {
					rz_cons_canvas_line_square_defined(g->can, ax, ay, bx, by, &style, bendpoint, true);
				} else {
					struct tmpbackedgeinfo *tmp = calloc(1, sizeof(struct tmpbackedgeinfo));
					tmp->ax = ax;
					tmp->bx = bx;
					tmp->ay = ay;
					tmp->by = by;
					tmp->edgectr = bendpoint;
					tmp->fromlayer = a->layer;
					tmp->tolayer = b->layer;
					tmp->style = style;
					rz_list_append(bckedges, tmp);
				}
				if (b->is_dummy) {
					style.symbol = LINE_NOSYM_VERT;
					rz_cons_canvas_line(g->can, bx, by, bx, b->y + b->h, &style);
				}
				if (b->x != a->x || b->layer <= a->layer || (!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
					if (tm) {
						tm->edgectr++;
					}
				}
				break;
			case 1:
				style.symbol = (!g->hints || a->is_dummy) ? LINE_NOSYM_HORIZ : style.color;
				if (a->x + a->w > b->x) {
					style.dot_style = DOT_STYLE_BACKEDGE;
				}

				ax = a->x;
				if (g->zoom > 0) {
					ax += a->w;
				} else {
					ax++;
				}
				ay = a->y;
				if (!a->is_dummy && g->zoom > 0) {
					ay += RZ_EDGES_X_INC + out_nth;
				}
				bx = b->x - 1;
				by = b->y;
				if (!b->is_dummy && g->zoom > 0) {
					by += RZ_EDGES_X_INC + out_nth;
				}

				if (a->w < a->layer_width) {
					rz_cons_canvas_line_square_defined(g->can, ax, ay, a->x + a->layer_width, ay, &style, 0, false);
					ax = a->x;
					if (g->zoom > 1) {
						ax += a->layer_width;
					} else {
						ax += 1;
					}
					style.symbol = LINE_NOSYM_HORIZ;
				}
				if (bx >= ax) {
					rz_cons_canvas_line_square_defined(g->can, ax, ay, bx, by, &style, tm->edgectr, false);
				} else {
					struct tmpbackedgeinfo *tmp = calloc(1, sizeof(struct tmpbackedgeinfo));
					if (tmp) {
						tmp->ax = ax;
						tmp->bx = bx;
						tmp->ay = ay;
						tmp->by = by;
						tmp->edgectr = tm->edgectr;
						tmp->fromlayer = a->layer;
						tmp->tolayer = b->layer;
						tmp->style = style;
						rz_list_append(bckedges, tmp);
					}
				}
				if (b->is_dummy) {
					style.symbol = LINE_NOSYM_HORIZ;
					rz_cons_canvas_line_square_defined(g->can, bx, by, bx + b->layer_width, by, &style, 0, false);
				}
				if ((b->y == a->y && b->h != a->h) || b->y != a->y || b->layer <= a->layer || (!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
					tm->edgectr += 1;
				}
				break;
			}
			draw_idx++;
		}
		rz_pvector_free(draw_neighbours);
	}
	rz_iterator_free(it_nodes);

	struct tmpbackedgeinfo *temp;
	rz_list_foreach (bckedges, itm, temp) {
		int leftlen, rightlen;
		int minx = 0, maxx = 0;
		struct tmplayer *tt = NULL;
		if (rz_cons_is_breaked()) {
			break;
		}

		rz_list_foreach (lyr, ito, tl) {
			if (tl->layer <= temp->tolayer) {
				tt = tl;
				minx = tl->minx;
				maxx = tl->maxx;
				continue;
			}
			minx = minx < tl->minx ? minx : tl->minx;
			maxx = maxx > tl->maxx ? maxx : tl->maxx;
			if (tl->layer >= temp->fromlayer) {
				break;
			}
		}

		if (tt) {
			tt->revedgectr += 1;
		}
		if (g->layout == 0) {
			leftlen = (temp->ax - minx) + (temp->bx - minx);
			rightlen = (maxx - temp->ax) + (maxx - temp->bx);
		} else {
			leftlen = (temp->ay - minx) + (temp->by - minx);
			rightlen = (maxx - temp->ay) + (maxx - temp->by);
		}

		if (tt) {
			int arg = (rightlen < leftlen) ? maxx + 1 : minx - 1;
			rz_cons_canvas_line_back_edge(g->can, temp->ax, temp->ay, temp->bx, temp->by, &(temp->style), temp->edgectr, arg, tt->revedgectr, !g->layout);
		}

		rz_list_foreach (lyr, ito, tl) {
			if (tl->layer < temp->tolayer) {
				continue;
			}
			if (rightlen < leftlen) {
				tl->maxx = maxx + 1;
			} else {
				tl->minx = minx - 1;
			}
			if (tl->layer >= temp->fromlayer) {
				break;
			}
		}
	}

	rz_list_foreach (lyr, ito, tl) {
		free(tl);
	}

	rz_list_foreach (bckedges, ito, tl) {
		free(tl);
	}

	rz_list_free(lyr);
	rz_list_free(bckedges);
	rz_cons_break_pop();
}

static void agraph_toggle_callgraph(RzAGraph *g) {
	g->is_callgraph = !g->is_callgraph;
	g->need_reload_nodes = true;
	g->force_update_seek = true;
}

static void agraph_set_zoom(RzAGraph *g, int v) {
	if (v >= -10) {
		if (v == 0) {
			g->mode = RZ_AGRAPH_MODE_MINI;
		} else {
			g->mode = RZ_AGRAPH_MODE_NORMAL;
		}
		const int K = 920;
		if (g->zoom < v) {
			g->can->sy = (g->can->sy * K) / 1000;
		} else {
			g->can->sy = (g->can->sy * 1000) / K;
		}
		g->zoom = v;
		g->need_update_dim = true;
		g->need_set_layout = true;
	}
}

/* reload all the info in the nodes, depending on the type of the graph
 * (callgraph, CFG, etc.), set the default layout for these nodes and center
 * the screen on the selected one */
static bool agraph_reload_nodes(RzAGraph *g, RzCore *core, RzAnalysisFunction *fcn) {
	rz_agraph_reset(g);
	return reload_nodes(g, core, fcn);
}

static void follow_nth(RzAGraph *g, int nth) {
	const RzGraphNode *cn = agraph_nth_neighbour(g, g->curnode, nth, true);
	RzANode *a = get_anode(cn);

	while (a && a->is_dummy) {
		cn = agraph_nth_neighbour(g, a->gnode, 0, true);
		a = get_anode(cn);
	}
	if (a) {
		rz_agraph_set_curnode(g, a);
	}
}

static void move_current_node(RzAGraph *g, int xdiff, int ydiff) {
	RzANode *n = get_anode(g->curnode);
	if (n) {
		n->x += xdiff;
		n->y += ydiff;
	}
}

static void agraph_toggle_mini(RzAGraph *g) {
	RzANode *n = get_anode(g->curnode);
	if (n) {
		n->is_mini = !n->is_mini;
	}
	g->need_update_dim = 1;
	agraph_refresh(rz_cons_singleton()->event_data);
	agraph_set_layout((RzAGraph *)g);
}

static void agraph_follow_innodes(RzAGraph *g, bool in) {
	int count = 0;
	RzANode *an = get_anode(g->curnode);
	if (!an) {
		return;
	}
	// TODO: narrow the degree
	const int gdegree = in ? rz_graph_in_degree(g->graph, an->gnode) : rz_graph_out_degree(g->graph, an->gnode);
	int nth = -1;
	if (gdegree == 0) {
		return;
	}
	rz_cons_gotoxy(0, 2);
	rz_cons_printf(in ? "Input nodes:\n" : "Output nodes:\n");
	RzList *options = rz_list_newf(NULL);
	RzIterator *it_gnodes = in ? agraph_in_neighbors(g, an->gnode) : agraph_out_neighbors(g, an->gnode);
	if (!it_gnodes) {
		rz_list_free(options);
		return;
	}
	RzGraphNode *gn;
	rz_iterator_foreach(it_gnodes, gn) {
		RzANode *an = get_anode(gn);
		RzGraphNode *gnn = agraph_get_title(g, an, in);
		if (gnn) {
			RzANode *nnn = gnn->data;
			RzANode *o;
			RzListIter *iter2;
			// avoid dupes
			rz_list_foreach (options, iter2, o) {
				if (!strcmp(o->title, nnn->title)) {
					continue;
				}
			}
			rz_cons_printf("%d %s\n", count, nnn->title);
			rz_list_append(options, nnn);
			count++;
		}
	}
	rz_iterator_free(it_gnodes);

	rz_cons_flush();
	if (gdegree == 1) {
		nth = 0;
	} else if (gdegree < 10) {
		// just 1 key
		char ch = rz_cons_readchar();
		if (ch >= '0' && ch <= '9') {
			nth = ch - '0';
		}
	} else {
		rz_cons_show_cursor(true);
		rz_cons_enable_mouse(false);
		char *nth_string = rz_cons_input("index> ");
		nth = atoi(nth_string);
		if (nth == 0 && *nth_string != '0') {
			nth = -1;
		}
		free(nth_string);
	}
	if (nth != -1) {
		RzANode *selected_node = rz_list_get_n(options, nth);
		rz_agraph_set_curnode(g, selected_node);
	}
	rz_list_free(options);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

static void agraph_follow_true(RzAGraph *g) {
	follow_nth(g, 0);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

static void agraph_follow_false(RzAGraph *g) {
	follow_nth(g, 1);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

/* seek the next node in visual order */
static void agraph_next_node(RzAGraph *g) {
	RzANode *a = get_anode(find_near_of(g, g->curnode, true));
	while (a && a->is_dummy) {
		a = get_anode(find_near_of(g, a->gnode, true));
	}
	rz_agraph_set_curnode(g, a);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

/* seek the previous node in visual order */
static void agraph_prev_node(RzAGraph *g) {
	RzANode *a = get_anode(find_near_of(g, g->curnode, false));
	while (a && a->is_dummy) {
		a = get_anode(find_near_of(g, a->gnode, false));
	}
	rz_agraph_set_curnode(g, a);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

static void agraph_update_title(RzCore *core, RzAGraph *g, RzAnalysisFunction *fcn, const AGraphContext *grp_ctx) {
	RzANode *a = get_anode(g->curnode);
	char *sig = rz_core_analysis_function_signature(core, RZ_OUTPUT_MODE_STANDARD, NULL);
	char *new_title = rz_str_newf(
		"%s[0x%08" PFMT64x "]> %s # %s ",
		grp_ctx->graph_cursor ? "(cursor)" : "",
		fcn->addr, a ? a->title : "", sig);
	rz_agraph_set_title(g, new_title);
	free(new_title);
	free(sig);
}

/* look for any change in the state of the graph
 * and update what's necessary */
static bool check_changes(RzAGraph *g, int is_interactive, RzCore *core, RzAnalysisFunction *fcn, const AGraphContext *grp_ctx) {
	int oldpos[2] = {
		0, 0
	};
	if (g->need_reload_nodes && core) {
		if (!g->update_seek_on && !g->force_update_seek) {
			// save scroll here
			oldpos[0] = g->can->sx;
			oldpos[1] = g->can->sy;
		}
		if (!agraph_reload_nodes(g, core, fcn)) {
			return false;
		}
	}
	if (core && core->config) {
		if (rz_config_get_i(core->config, "graph.trace")) {
			// fold all bbs not traced
			fold_asm_trace(core, g);
		}
	}
	if (g->need_update_dim || g->need_reload_nodes || !is_interactive) {
		update_node_dimension(g, is_mini(g), g->zoom, g->edgemode, g->is_callgraph, g->layout);
	}
	if (g->need_set_layout || g->need_reload_nodes || !is_interactive) {
		agraph_set_layout(g);
	}
	if (core) {
		RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
		if (block) {
			char *title = get_title(block->addr);
			RzANode *cur_anode = get_anode(g->curnode);
			if (fcn && ((is_interactive && !cur_anode) || (cur_anode && strcmp(cur_anode->title, title)))) {
				g->update_seek_on = rz_agraph_get_node(g, title);
				if (g->update_seek_on) {
					rz_agraph_set_curnode(g, g->update_seek_on);
					g->force_update_seek = true;
				}
			}
			free(title);
		}
		g->can->color = rz_config_get_i(core->config, "scr.color");
		g->hints = rz_config_get_i(core->config, "graph.hints");
	}
	if (g->update_seek_on || g->force_update_seek) {
		RzANode *n = g->update_seek_on;
		if (!n && g->curnode) {
			n = get_anode(g->curnode);
		}
		if (n) {
			update_seek(g->can, n, g->force_update_seek);
		}
	}
	if (fcn) {
		agraph_update_title(core, g, fcn, grp_ctx);
	}
	if (oldpos[0] || oldpos[1]) {
		g->can->sx = oldpos[0];
		g->can->sy = oldpos[1];
	}
	g->need_reload_nodes = false;
	g->need_update_dim = false;
	g->need_set_layout = false;
	g->update_seek_on = NULL;
	g->force_update_seek = false;
	return true;
}

static int agraph_print(RzAGraph *g, int is_interactive, RzCore *core, RzAnalysisFunction *fcn, const AGraphContext *grp_ctx) {
	int h, w = rz_cons_get_size(&h);
	bool ret = check_changes(g, is_interactive, core, fcn, grp_ctx);
	if (!ret) {
		return false;
	}

	if (is_interactive) {
		rz_cons_clear00();
	} else {
		/* TODO: limit to screen size when the output is not redirected to file */
		update_graph_sizes(g);
	}

	h = is_interactive ? h : g->h + 1;
	w = is_interactive ? w : g->w + 2;
	if (!rz_cons_canvas_resize(g->can, w, h)) {
		return false;
	}
	if (!is_interactive) {
		g->can->sx = -g->x;
		g->can->sy = -g->y - 1;
	}
	if (g->is_dis) {
		(void)G(-g->can->sx + 1, -g->can->sy + 2);
		int scr_utf8 = rz_config_get_i(core->config, "scr.utf8");
		int asm_bytes = rz_config_get_i(core->config, "asm.bytes");
		int asm_cmt_right = rz_config_get_i(core->config, "asm.cmt.right");
		rz_config_set_i(core->config, "scr.utf8", 0);
		rz_config_set_i(core->config, "asm.bytes", 0);
		rz_config_set_i(core->config, "asm.cmt.right", 0);
		char *str = rz_core_cmd_str(core, "pd $r");
		if (str) {
			W(str);
			free(str);
		}
		rz_config_set_i(core->config, "scr.utf8", scr_utf8);
		rz_config_set_i(core->config, "asm.bytes", asm_bytes);
		rz_config_set_i(core->config, "asm.cmt.right", asm_cmt_right);
	}
	if (g->title && *g->title) {
		g->can->sy++;
	}

	agraph_print_edges(g);
	agraph_print_nodes(g, grp_ctx);
	if (g->title && *g->title) {
		g->can->sy--;
	}
	/* print the graph title */
	(void)G(-g->can->sx, -g->can->sy);
	W(g->title);
	if (is_interactive && g->title) {
		int title_len = strlen(g->title);
		rz_cons_canvas_fill(g->can, -g->can->sx + title_len, -g->can->sy,
			w - title_len, 1, ' ');
	}

	rz_cons_canvas_print_region(g->can);

	if (is_interactive) {
		rz_cons_newline();
		const char *cmdv = rz_config_get(core->config, "cmd.gprompt");
		bool mustFlush = false;
		rz_cons_visual_flush();
		if (cmdv && *cmdv) {
			rz_cons_gotoxy(0, 2);
			rz_cons_strcat(Color_RESET);
			rz_core_cmd0(core, cmdv);
			mustFlush = true;
		}
		if (mustFlush) {
			rz_cons_flush();
		}
	}
	return true;
}

static void check_function_modified(RzCore *core, RzAnalysisFunction *fcn) {
	if (rz_analysis_function_was_modified(fcn)) {
		if (rz_config_get_i(core->config, "analysis.detectwrites") || rz_cons_yesno('y', "Function was modified. Reanalyze? (Y/n)")) {
			rz_analysis_function_update_analysis(fcn);
		}
	}
}

static int agraph_refresh(AGraphContext *grp_ctx) {
	if (!grp_ctx) {
		return 0;
	}

	rz_cons_singleton()->event_data = grp_ctx;
	RzCore *core = grp_ctx->core;
	RzAGraph *g = grp_ctx->g;
	RzAnalysisFunction *f = NULL;
	RzAnalysisFunction **fcn = grp_ctx->fcn;

	if (!fcn) {
		return agraph_print(g, grp_ctx->fs, core, NULL, grp_ctx);
	}

	// allow to change the current function during debugging
	if (g->is_instep && core->bin->is_debugger) {
		// seek only when the graph node changes
		const char *pc = rz_reg_get_name(core->dbg->reg, RZ_REG_NAME_PC);
		RzRegItem *r = rz_reg_get(core->dbg->reg, pc, -1);
		ut64 addr = rz_reg_get_value(core->dbg->reg, r);
		RzANode *acur = get_anode(g->curnode);

		RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
		char *title = get_title(block ? block->addr : addr);
		if (!acur || strcmp(acur->title, title)) {
			rz_core_seek_to_register(core, "PC", false);
		}
		free(title);
		g->is_instep = false;
	}

	if (grp_ctx->follow_offset) {
		if (rz_io_is_valid_offset(core->io, core->offset, 0)) {
			f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			if (!f) {
				if (!g->is_dis) {
					if (!rz_cons_yesno('y', "\rNo function at 0x%08" PFMT64x ". Define it here (Y/n)? ", core->offset)) {
						return 0;
					}
					rz_core_analysis_function_add(core, NULL, core->offset, false);
				}
				f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
				g->need_reload_nodes = true;
			}
			if (f && fcn && f != *fcn) {
				*fcn = f;
				check_function_modified(core, *fcn);
				g->need_reload_nodes = true;
				g->force_update_seek = true;
			}
		} else {
			// TODO: maybe go back to avoid seeking from graph view to an scary place?
			rz_cons_message("This is not a valid offset\n");
			rz_cons_flush();
		}
	}

	int res = agraph_print(g, grp_ctx->fs, core, *fcn, grp_ctx);

	if (rz_config_get_i(core->config, "scr.scrollbar")) {
		rz_core_visual_scrollbar(core);
	}

	return res;
}

static void agraph_refresh_oneshot(AGraphContext *grp_ctx) {
	rz_core_task_enqueue_oneshot(&grp_ctx->core->tasks, (RzCoreTaskOneShot)agraph_refresh, grp_ctx);
}

static void agraph_set_need_reload_nodes(AGraphContext *grp_ctx) {
	grp_ctx->g->need_reload_nodes = true;
}

static void agraph_toggle_speed(RzAGraph *g, RzCore *core) {
	const int alt = rz_config_get_i(core->config, "graph.scroll");
	g->movspeed = g->movspeed == DEFAULT_SPEED ? alt : DEFAULT_SPEED;
}

static void free_node(RzANode *n) {
	if (n && !n->is_dummy) {
		agraph_node_free(n);
	}
}

static void agraph_init(RzAGraph *g) {
	g->is_callgraph = false;
	g->is_il = false;
	g->is_instep = false;
	g->need_reload_nodes = true;
	g->show_node_titles = true;
	g->show_node_body = true;
	g->force_update_seek = true;
	g->graph = rz_graph_new(RZ_GRAPH_IMPL_LIST, NULL, NULL, rz_agraph_edge_data_free);
	g->nodes = ht_sp_new(HT_STR_CONST, NULL, (HtSPFreeValue)free_node);
	g->dummy_nodes = rz_list_newf((RzListFree)agraph_node_free);
	g->edgemode = 2;
	g->zoom = ZOOM_DEFAULT;
	g->hints = 1;
	g->movspeed = DEFAULT_SPEED;
	g->next_edge_creation_order = 0;
	g->db = sdb_new0();
	rz_vector_init(&g->ghits.word_list, sizeof(struct rz_agraph_location), NULL, NULL);
}

static void graphNodeMove(RzAGraph *g, AGraphContext *grp_ctx, int dir, int speed) {
	int delta = (dir == 'k') ? -1 : 1;
	if (dir == 'H') {
		return;
	}
	if (dir == 'h' || dir == 'l') {
		// horizontal scroll
		if (is_mini(g)) {
			grp_ctx->scroll_position = 0;
		} else {
			int delta = (dir == 'l') ? 1 : -1;
			move_current_node(g, speed * delta, 0);
		}
		return;
	}
	RzCore *core = NULL;
	// vertical scroll
	if (is_mini(g)) {
		grp_ctx->scroll_position += (delta * speed);
	} else if (g->is_dis) {
		rz_core_seek_opcode(core, (delta * 4) * speed, false);
	} else {
		move_current_node(g, 0, delta * speed);
	}
}

static void sdb_set_enc(Sdb *db, const char *key, const char *v) {
	char *estr = sdb_encode((const void *)v, -1);
	sdb_set(db, key, estr);
	free(estr);
}

static void agraph_sdb_init(const RzAGraph *g) {
	sdb_bool_set(g->db, "agraph.is_callgraph", g->is_callgraph);
	RzCons *cons = rz_cons_singleton();
	sdb_set_enc(g->db, "agraph.color_box", cons->context->pal.graph_box);
	sdb_set_enc(g->db, "agraph.color_box2", cons->context->pal.graph_box2);
	sdb_set_enc(g->db, "agraph.color_box3", cons->context->pal.graph_box3);
	sdb_set_enc(g->db, "agraph.color_true", cons->context->pal.graph_true);
	sdb_set_enc(g->db, "agraph.color_false", cons->context->pal.graph_false);
}

static char *agraph_build_sdb_neighbours(const RzAGraph *g, const RzGraphNode *node) {
	RzPVector *edges = agraph_collect_edges(g, node, true, true);
	if (!edges || rz_pvector_len(edges) == 0) {
		rz_pvector_free(edges);
		return NULL;
	}

	bool has_known_kind = false;
	bool has_false = false;
	int max_nth = -1;
	void **pit;
	rz_pvector_foreach (edges, pit) {
		const RzGraphEdge *edge = *pit;
		const int kind = get_edge_kind(edge);
		const int nth = get_edge_nth(edge);
		has_known_kind |= kind != AGRAPH_EDGE_KIND_UNKNOWN;
		has_false |= kind == AGRAPH_EDGE_KIND_FALSE;
		if (nth > max_nth) {
			max_nth = nth;
		}
	}

	RzStrBuf sb;
	rz_strbuf_init(&sb);
	if (has_known_kind && has_false && max_nth >= 0) {
		char **slots = RZ_NEWS0(char *, max_nth + 1);
		if (!slots) {
			rz_pvector_free(edges);
			rz_strbuf_fini(&sb);
			return NULL;
		}
		rz_pvector_foreach (edges, pit) {
			const RzGraphEdge *edge = *pit;
			const RzANode *dst = get_anode(edge->to);
			const int kind = get_edge_kind(edge);
			const int nth = get_edge_nth(edge);
			if (!dst || !dst->title || kind == AGRAPH_EDGE_KIND_TRUE) {
				continue;
			}
			if (nth >= 0 && nth <= max_nth && !slots[nth]) {
				slots[nth] = dst->title;
			}
		}
		for (int i = 0; i <= max_nth; i++) {
			if (i > 0) {
				rz_strbuf_append(&sb, ",");
			}
			if (slots[i]) {
				rz_strbuf_append(&sb, slots[i]);
			}
		}
		free(slots);
	} else {
		bool first = true;
		rz_pvector_foreach (edges, pit) {
			const RzGraphEdge *edge = *pit;
			const RzANode *dst = get_anode(edge->to);
			if (!dst || !dst->title) {
				continue;
			}
			if (!first) {
				rz_strbuf_append(&sb, ",");
			}
			rz_strbuf_append(&sb, dst->title);
			first = false;
		}
	}

	rz_pvector_free(edges);
	if (rz_strbuf_is_empty(&sb)) {
		rz_strbuf_fini(&sb);
		return NULL;
	}
	return rz_strbuf_drain_nofree(&sb);
}

static void agraph_sync_sdb_neighbours(const RzAGraph *g) {
	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}
	RzGraphNode *node;
	rz_iterator_foreach(it_nodes, node) {
		RzANode *anode = get_anode(node);
		if (!anode || RZ_STR_ISEMPTY(anode->title)) {
			continue;
		}
		char key[384] = { 0 };
		rz_strf(key, "agraph.nodes.%s.neighbours", anode->title);
		char *value = agraph_build_sdb_neighbours(g, node);
		sdb_set(g->db, key, value);
		free(value);
	}
	rz_iterator_free(it_nodes);
}

RZ_API Sdb *rz_agraph_get_sdb(RzAGraph *g) {
	g->need_update_dim = true;
	g->need_set_layout = true;
	AGraphContext grp_ctx = { 0 };
	(void)check_changes(g, false, NULL, NULL, &grp_ctx);
	agraph_sync_sdb_neighbours(g);
	// remove_dummy_nodes (g);
	return g->db;
}

RZ_API void rz_agraph_print(RzAGraph *g) {
	AGraphContext grp_ctx = { 0 };
	agraph_print(g, false, NULL, NULL, &grp_ctx);
	if (g->graph->n_nodes > 0) {
		rz_cons_newline();
	}
}

RZ_API void rz_agraph_print_json(RzAGraph *g, PJ *pj) {
	RzGraphNode *node = NULL, *neighbour = NULL;
	if (!pj) {
		return;
	}

	RzIterator *it_nodes = agraph_get_nodes(g);
	if (!it_nodes) {
		return;
	}

	rz_iterator_foreach(it_nodes, node) {
		RzANode *anode = (RzANode *)node->data;
		char *label = rz_str_dup(anode->body);
		pj_o(pj);

		pj_ki(pj, "id", rz_graph_adapter_get_node_id(anode->gnode));
		pj_ks(pj, "title", anode->title);
		pj_ks(pj, "body", label);
		pj_k(pj, "out_nodes");
		pj_a(pj);

		RzIterator *neighbours = agraph_out_neighbors(g, anode->gnode);
		if (neighbours) {
			rz_iterator_foreach(neighbours, neighbour) {
				// TODO: use accesser mode
				pj_i(pj, rz_graph_adapter_get_node_id(neighbour));
			}
			rz_iterator_free(neighbours);
		}

		pj_end(pj);
		pj_end(pj);
		free(label);
	}
	rz_iterator_free(it_nodes);
}

RZ_API void rz_agraph_set_title(RzAGraph *g, const char *title) {
	free(g->title);
	g->title = rz_str_dup(title);
	sdb_set(g->db, "agraph.title", g->title);
}

/**
 * \brief Convert a RzGraphNodeInfo \p info to RzANode and add to \p g.
 *
 * \param g The agraph to append the nodes to.
 * \param info The node info to add.
 * \param utf8 If true, the node title can contain UTF-8 characters. If false, it will only contain ASCII.
 *
 * \return Pointer to the added node. Or NULL in case of failure.
 */
RZ_API RZ_BORROW RzANode *rz_agraph_add_node_from_node_info(RZ_NONNULL const RzAGraph *g, RZ_NONNULL const RzGraphNodeInfo *info, bool utf8) {
	rz_return_val_if_fail(g && info, NULL);
	RzANode *an = NULL;
	char title[64] = { 0 };
	switch (info->type) {
	default:
		RZ_LOG_ERROR("Node type %d not handled.\n", info->type);
		break;
	case RZ_GRAPH_NODE_TYPE_DEFAULT:
		an = rz_agraph_add_node(g, info->def.title, info->def.body);
		if (!an) {
			return NULL;
		}
		an->offset = info->def.offset;
		break;
	case RZ_GRAPH_NODE_TYPE_CFG: {
		char *annotation = rz_graph_get_node_subtype_annotation(info->subtype, utf8);
		rz_return_val_if_fail(annotation, NULL);
		char *cfg_title = rz_str_appendf(NULL, "0x%" PFMT64x "%s", info->cfg.address, annotation);
		rz_return_val_if_fail(cfg_title, NULL);
		an = rz_agraph_add_node(g, cfg_title, "");
		free(annotation);
		free(cfg_title);
		if (!an) {
			return NULL;
		}
		an->offset = info->cfg.address;
		break;
	}
	case RZ_GRAPH_NODE_TYPE_ICFG:
		rz_strf(title, "0x%" PFMT64x "%s", info->icfg.address,
			info->subtype & RZ_GRAPH_NODE_SUBTYPE_ICFG_MALLOC ? " (alloc)" : "");
		an = rz_agraph_add_node(g, title, "");
		if (!an) {
			return NULL;
		}
		an->offset = info->icfg.address;
		break;
	}
	return an;
}

RZ_API RzANode *rz_agraph_add_node(const RzAGraph *g, const char *title, const char *body) {
	RzANode *res = rz_agraph_get_node(g, title);
	if (res) {
		return res;
	}
	res = RZ_NEW0(RzANode);
	if (!res) {
		return NULL;
	}

	res->title = title ? rz_str_trunc_ellipsis(title, 255) : rz_str_dup("");
	res->body = rz_str_dup(body ? body : "");
	res->layer = -1;
	res->pos_in_layer = -1;
	res->is_dummy = false;
	res->is_reversed = false;
	res->klass = -1;
	res->offset = UT64_MAX;
	res->shortcut_w = 0;
	res->gnode = rz_graph_add_node(g->graph, res, NULL);
	if (RZ_STR_ISNOTEMPTY(res->title) && !g->is_il) {
		ht_sp_update(g->nodes, res->title, res);
		char *s, *estr, *b;
		size_t len;
		sdb_array_add(g->db, "agraph.nodes", res->title);
		b = rz_str_dup(res->body);
		len = strlen(b);
		if (len > 0 && b[len - 1] == '\n') {
			b[len - 1] = '\0';
		}
		estr = sdb_encode((const void *)b, -1);
		s = rz_str_newf("base64:%s", estr);
		free(estr);
		free(b);
		char buf[384] = { 0 };
		rz_strf(buf, "agraph.nodes.%s.body", res->title);
		sdb_set_owned(g->db, buf, s);
	}
	return res;
}

RZ_API bool rz_agraph_del_node(const RzAGraph *g, const char *title) {
	char *title_trunc = rz_str_trunc_ellipsis(title, 255);
	RzANode *an, *res = rz_agraph_get_node(g, title_trunc);
	free(title_trunc);
	RzGraphNode *gn;

	if (!res) {
		return false;
	}
	char buf[384] = { 0 };
	sdb_array_remove(g->db, "agraph.nodes", res->title);
	rz_strf(buf, "agraph.nodes.%s", res->title);
	sdb_set(g->db, buf, NULL);
	rz_strf(buf, "agraph.nodes.%s.body", res->title);
	sdb_set(g->db, buf, 0);
	rz_strf(buf, "agraph.nodes.%s.x", res->title);
	sdb_set(g->db, buf, NULL);
	rz_strf(buf, "agraph.nodes.%s.y", res->title);
	sdb_set(g->db, buf, NULL);
	rz_strf(buf, "agraph.nodes.%s.w", res->title);
	sdb_set(g->db, buf, NULL);
	rz_strf(buf, "agraph.nodes.%s.h", res->title);
	sdb_set(g->db, buf, NULL);
	rz_strf(buf, "agraph.nodes.%s.neighbours", res->title);
	sdb_set(g->db, buf, NULL);

	RzIterator *it_innodes = agraph_in_neighbors(g, res->gnode);
	if (it_innodes) {
		rz_iterator_foreach(it_innodes, gn) {
			if (!(an = gn->data)) {
				break;
			}
			rz_strf(buf, "agraph.nodes.%s.neighbours", res->title);
			const char *key = buf;
			sdb_array_remove(g->db, key, res->title);
		}
		rz_iterator_free(it_innodes);
	}

	rz_graph_del_node(g->graph, res->gnode);
	res->gnode = NULL;

	ht_sp_delete(g->nodes, res->title);
	return true;
}

static bool user_node_cb(struct g_cb *user, RZ_UNUSED const char *k, const void *v) {
	RzANodeCallback cb = user->node_cb;
	void *user_data = user->data;
	RzANode *n = (RzANode *)v;
	if (n) {
		cb(n, user_data);
	}
	return true;
}

static bool user_edge_cb(struct g_cb *user, RZ_UNUSED const char *k, const void *v) {
	RAEdgeCallback cb = user->edge_cb;
	RzAGraph *g = user->graph;
	void *user_data = user->data;
	RzANode *an, *n = (RzANode *)v;
	if (!n) {
		return false;
	}

	RzIterator *it_neigh = agraph_out_neighbors(g, n->gnode);
	RzGraphNode *gn;
	if (!it_neigh) {
		return true;
	}

	rz_iterator_foreach(it_neigh, gn) {
		if (!(an = gn->data)) {
			break;
		}
		cb(n, an, user_data);
	}
	rz_iterator_free(it_neigh);
	return true;
}

RZ_API void rz_agraph_foreach(RzAGraph *g, RzANodeCallback cb, void *user) {
	struct g_cb u = {
		.node_cb = cb,
		.data = user
	};
	ht_sp_foreach(g->nodes, (HtSPForeachCallback)user_node_cb, &u);
}

RZ_API void rz_agraph_foreach_edge(RzAGraph *g, RAEdgeCallback cb, void *user) {
	struct g_cb u = {
		.graph = g,
		.edge_cb = cb,
		.data = user
	};
	ht_sp_foreach(g->nodes, (HtSPForeachCallback)user_edge_cb, &u);
}

RZ_API RzANode *rz_agraph_get_first_node(const RzAGraph *g) {
	RzIterator *it = agraph_get_nodes(g);
	if (!it) {
		return NULL;
	}
	RzGraphNode *rgn = rz_iterator_next(it);
	rz_iterator_free(it);
	return get_anode(rgn);
}

RZ_API RzANode *rz_agraph_get_node(const RzAGraph *g, const char *title) {
	char *title_trunc = title ? rz_str_trunc_ellipsis(title, 255) : NULL;
	if (!title_trunc) {
		return NULL;
	}
	RzANode *node = ht_sp_find(g->nodes, title_trunc, NULL);
	free(title_trunc);
	return node;
}

RZ_API void rz_agraph_add_edge(RzAGraph *g, RzANode *a, RzANode *b) {
	rz_return_if_fail(g && a && b);
	agraph_add_graph_edge(g, a->gnode, b->gnode, -1, AGRAPH_EDGE_KIND_UNKNOWN);
	if (a->title && b->title) {
		char buf[384] = { 0 };
		rz_strf(buf, "agraph.nodes.%s.neighbours", a->title);
		char *k = buf;
		sdb_array_add(g->db, k, b->title);
	}
}

RZ_API void rz_agraph_add_edge_at(RzAGraph *g, RzANode *a, RzANode *b, int nth) {
	rz_return_if_fail(g && a && b);
	if (a->title && b->title) {
		char buf[384] = { 0 };
		rz_strf(buf, "agraph.nodes.%s.neighbours", a->title);
		char *k = buf;
		sdb_array_insert(g->db, k, nth, b->title);
	}
	agraph_add_graph_edge(g, a->gnode, b->gnode, nth, AGRAPH_EDGE_KIND_UNKNOWN);
}

RZ_API void rz_agraph_del_edge(const RzAGraph *g, RzANode *a, RzANode *b) {
	rz_return_if_fail(g && a && b);
	if (a->title && b->title) {
		char buf[384] = { 0 };
		rz_strf(buf, "agraph.nodes.%s.neighbours", a->title);
		char *k = buf;
		sdb_array_remove(g->db, k, b->title);
	}
	agraph_del_graph_edge(g, a->gnode, b->gnode);
}

RZ_API void rz_agraph_reset(RzAGraph *g) {
	ht_sp_free(g->nodes);
	rz_list_free(g->dummy_nodes);
	rz_graph_reset(g->graph);
	rz_agraph_set_title(g, NULL);
	sdb_reset(g->db);
	if (g->edges) {
		rz_list_purge(g->edges);
	}
	g->nodes = ht_sp_new(HT_STR_CONST, NULL, (HtSPFreeValue)free_node);
	g->dummy_nodes = rz_list_newf((RzListFree)agraph_node_free);
	g->update_seek_on = NULL;
	g->need_reload_nodes = false;
	g->need_set_layout = true;
	g->need_update_dim = true;
	g->next_edge_creation_order = 0;
	g->x = g->y = g->w = g->h = 0;
	agraph_sdb_init(g);
	g->curnode = NULL;
}

RZ_API void rz_agraph_free(RzAGraph *g) {
	if (!g) {
		return;
	}
	ht_sp_free(g->nodes);
	rz_list_free(g->dummy_nodes);
	rz_graph_free(g->graph);
	rz_list_free(g->edges);
	rz_agraph_set_title(g, NULL);
	sdb_free(g->db);
	rz_cons_canvas_free(g->can);
	free(g);
}

RZ_API RzAGraph *rz_agraph_new(RzConsCanvas *can) {
	RzAGraph *g = RZ_NEW0(RzAGraph);
	if (!g) {
		return NULL;
	}
	g->can = can;
	g->dummy = true;
	agraph_init(g);
	agraph_sdb_init(g);
	return g;
}

static void visual_offset(RzAGraph *g, RzCore *core) {
	char buf[256];
	int rows;
	RzLine *line = core->cons->line;
	rz_cons_get_size(&rows);
	rz_cons_gotoxy(0, rows);
	rz_cons_flush();
	line->prompt_type = RZ_LINE_PROMPT_OFFSET;
	rz_line_set_hist_callback(line, &rz_line_hist_offset_up, &rz_line_hist_offset_down);
	rz_line_set_prompt(line, "[offset]> ");
	strcpy(buf, "s ");
	if (rz_cons_fgets(buf + 2, sizeof(buf) - 2, 0, NULL) > 0) {
		if (buf[2] == '.') {
			buf[1] = '.';
		}
		rz_core_cmd0(core, buf);
		rz_line_set_hist_callback(core->cons->line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	line->prompt_type = RZ_LINE_PROMPT_DEFAULT;
}

static void goto_asmqjmps(RzAGraph *g, RzCore *core) {
	const char *h = "[Fast goto call/jmp]> ";
	char obuf[RZ_CORE_ASMQJMPS_LEN_LETTERS + 1];
	int rows, i = 0;
	bool cont;

	rz_cons_get_size(&rows);
	rz_cons_gotoxy(0, rows);
	rz_cons_clear_line(stdout);
	rz_cons_print(Color_RESET);
	rz_cons_print(h);
	rz_cons_flush();

	do {
		char ch = rz_cons_readchar();
		obuf[i++] = ch;
		rz_cons_printf("%c", ch);
		cont = isalpha((ut8)ch) && !islower((ut8)ch);
	} while (i < RZ_CORE_ASMQJMPS_LEN_LETTERS && cont);
	rz_cons_flush();

	obuf[i] = '\0';
	ut64 addr = rz_core_get_asmqjmps(core, obuf);
	if (addr != UT64_MAX) {
		char *title = get_title(addr);
		RzANode *addr_node = rz_agraph_get_node(g, title);
		if (addr_node) {
			rz_agraph_set_curnode(g, addr_node);
			rz_core_seek(core, addr, false);
			agraph_update_seek(g, addr_node, true);
		} else {
			rz_core_seek_and_save(core, addr, false);
		}
		free(title);
	}
}

static void seek_to_node(RzANode *n, RzCore *core) {
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	char *title = get_title(block ? block->addr : core->offset);

	if (title && strcmp(title, n->title)) {
		char *cmd = rz_str_newf("s %s", n->title);
		if (cmd) {
			if (*cmd) {
				rz_core_cmd0(core, cmd);
			}
			free(cmd);
		}
	}
	free(title);
}

static void graph_single_step_in(RzCore *core, RzAGraph *g) {
	rz_core_debug_single_step_in(core);
	g->is_instep = true;
	g->need_reload_nodes = true;
}

static void graph_single_step_over(RzCore *core, RzAGraph *g) {
	rz_core_debug_single_step_over(core);
	g->is_instep = true;
	g->need_reload_nodes = true;
}

static void graph_breakpoint(RzCore *core) {
	ut64 addr = core->print->cur_enabled ? core->offset + core->print->cur : core->offset;
	rz_core_debug_breakpoint_toggle(core, addr);
}

static void graph_continue(RzCore *core) {
	rz_core_debug_continue(core);
}
static void applyDisMode(RzCore *core, const AGraphContext *grp_ctx) {
	switch (grp_ctx->display_mode) {
	case 0:
		rz_config_set(core->config, "asm.pseudo", "false");
		rz_config_set(core->config, "asm.esil", "false");
		break;
	case 1:
		rz_config_set(core->config, "asm.pseudo", "true");
		rz_config_set(core->config, "asm.esil", "false");
		break;
	case 2:
		rz_config_set(core->config, "asm.pseudo", "false");
		rz_config_set(core->config, "asm.esil", "true");
		break;
	}
}

static void rotateColor(RzCore *core) {
	int color = rz_config_get_i(core->config, "scr.color");
	if (++color > 2) {
		color = 0;
	}
	rz_config_set_i(core->config, "scr.color", color);
}

static char *get_graph_string(RzCore *core, RzAGraph *g) {
	int c = rz_config_get_i(core->config, "scr.color");
	int u = rz_config_get_i(core->config, "scr.utf8");
	rz_config_set_i(core->config, "scr.color", 0);
	rz_config_set_i(core->config, "scr.utf8", 0);
	rz_core_visual_graph(core, g, NULL, false);
	char *s = rz_cons_get_buffer_dup();
	rz_cons_reset();
	rz_config_set_i(core->config, "scr.color", c);
	rz_config_set_i(core->config, "scr.utf8", u);
	return s;
}

static void nextword(RzCore *core, RzAGraph *g, const char *word) {
	rz_return_if_fail(core && core->graph && g && g->can && word);
	if (RZ_STR_ISEMPTY(word)) {
		return;
	}
	RzAGraphHits *gh = &g->ghits;
	RzConsCanvas *can = g->can;
	if (gh->word_list.len && gh->old_word && !strcmp(word, gh->old_word)) {
		if (gh->word_nth >= gh->word_list.len) {
			gh->word_nth = 0;
		}

		struct rz_agraph_location *pos = rz_vector_index_ptr(&gh->word_list, gh->word_nth);
		gh->word_nth++;
		if (pos) {
			can->sx = -pos->x + can->w / 2;
			can->sy = -pos->y + can->h / 2;
		}
		return;
	} else {
		rz_vector_clear(&gh->word_list);
	}
	char *s = get_graph_string(core, g);
	rz_cons_clear00();
	rz_cons_flush();
	const size_t MAX_COUNT = 4096;
	const char *a = NULL;
	size_t count = 0;
	int x = 0, y = 0;
	for (count = 0; count < MAX_COUNT; count++) {
		a = rz_str_str_xy(s, word, a, &x, &y);
		if (!a) {
			break;
		}
		struct rz_agraph_location *pos = rz_vector_push(&gh->word_list, NULL);
		if (pos) {
			pos->x = x + g->x;
			pos->y = y + g->y;
		}
	}
	free(gh->old_word);
	gh->old_word = rz_str_dup(word);
	free(s);
	if (!a && count == 0) {
		return;
	}
	nextword(core, g, word);
}

RZ_IPI int rz_core_visual_graph(RzCore *core, RzAGraph *g, RzAnalysisFunction *_fcn, int is_interactive) {
	if (is_interactive && !rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: interactive graph mode requires scr.interactive=true.\n");
		return 0;
	}
	int o_asmqjmps_letter = core->is_asmqjmps_letter;
	int o_vmode = core->vmode;
	int exit_graph = false, is_error = false;
	int update_seek = false;
	int okey, key;
	RzAnalysisFunction *fcn = NULL;
	const char *key_s;
	RzConsCanvas *can, *o_can = NULL;
	RzCoreVisual *visual = core->visual;
	RzLine *line = core->cons->line;
	bool graph_allocated = false;
	int movspeed;
	int ret, invscroll;
	RzConfigHold *hc = rz_config_hold_new(core->config);
	AGraphContext grp_ctx = { 0 };
	if (!hc) {
		return false;
	}
	rz_config_hold_i(hc, "asm.pseudo", "asm.esil", "asm.cmt.right", NULL);

	int h, w = rz_cons_get_size(&h);
	can = rz_cons_canvas_new(w, h);
	if (!can) {
		w = 80;
		h = 25;
		can = rz_cons_canvas_new(w, h);
		if (!can) {
			RZ_LOG_ERROR("core: cannot create RzCons.canvas context. Invalid screen "
				     "size? See scr.columns + scr.rows\n");
			rz_config_hold_free(hc);
			return false;
		}
	}
	can->linemode = rz_config_get_i(core->config, "graph.linemode");
	can->color = rz_config_get_i(core->config, "scr.color");

	if (!g) {
		graph_allocated = true;
		fcn = _fcn ? _fcn : rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (!fcn) {
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			rz_cons_canvas_free(can);
			return false;
		}
		check_function_modified(core, fcn);
		g = rz_agraph_new(can);
		if (!g) {
			rz_cons_canvas_free(can);
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			return false;
		}
		g->layout = rz_config_get_i(core->config, "graph.layout");
		g->dummy = rz_config_get_i(core->config, "graph.dummy");
		g->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	} else {
		o_can = g->can;
	}
	g->can = can;
	g->movspeed = rz_config_get_i(core->config, "graph.scroll");
	g->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	g->show_node_body = rz_config_get_b(core->config, "graph.body");
	g->on_curnode_change = (RzANodeCallback)seek_to_node;
	g->on_curnode_change_data = core;
	g->edgemode = rz_config_get_i(core->config, "graph.edges");
	g->hints = rz_config_get_i(core->config, "graph.hints");
	g->is_interactive = is_interactive;
	bool asm_comments = rz_config_get_i(core->config, "asm.comments");
	rz_config_set(core->config, "asm.comments",
		rz_str_bool(rz_config_get_i(core->config, "graph.comments")));

	/* we want letters as shortcuts for call/jmps */
	core->is_asmqjmps_letter = true;
	core->vmode = true;

	grp_ctx.g = g;
	grp_ctx.fs = is_interactive == 1;
	grp_ctx.core = core;
	grp_ctx.follow_offset = _fcn == NULL;
	grp_ctx.fcn = fcn != NULL ? &fcn : NULL;
	ret = agraph_refresh(&grp_ctx);
	if (!ret || is_interactive != 1) {
		rz_cons_newline();
		exit_graph = true;
		is_error = !ret;
	}

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = &grp_ctx;
	core->cons->event_resize = (RzConsEvent)agraph_refresh_oneshot;

	rz_cons_break_push(NULL, NULL);

	while (!exit_graph && !is_error && !rz_cons_is_breaked()) {
		rz_cons_get_size(&h);
		invscroll = rz_config_get_i(core->config, "graph.invscroll");
		ret = agraph_refresh(&grp_ctx);

		if (!ret) {
			is_error = true;
			break;
		}
		showcursor(core, false);

		// rz_core_graph_inputhandle()
		okey = rz_cons_readchar();
		key = rz_cons_arrow_to_hjkl(okey);

		if (core->cons->mouse_event) {
			movspeed = rz_config_get_i(core->config, "scr.wheel.speed");
			switch (key) {
			case 'j':
			case 'k':
				switch (grp_ctx.mouse_mode) {
				case 0: break;
				case 1: key = key == 'k' ? 'h' : 'l'; break;
				case 2: key = key == 'k' ? 'J' : 'K'; break;
				case 3: key = key == 'k' ? 'L' : 'H'; break;
				}
				break;
			}
		} else {
			movspeed = g->movspeed;
		}
		const char *cmd;
		switch (key) {
		case '-':
			agraph_set_zoom(g, g->zoom - ZOOM_STEP);
			g->force_update_seek = true;
			break;
		case '+':
			agraph_set_zoom(g, g->zoom + ZOOM_STEP);
			g->force_update_seek = true;
			break;
		case '0':
			agraph_set_zoom(g, ZOOM_DEFAULT);
			agraph_update_seek(g, get_anode(g->curnode), true);
			// update scroll (with minor shift)
			break;
		case '=': { // TODO: edit
			showcursor(core, true);
			const char *cmd = rz_config_get(core->config, "cmd.gprompt");
			rz_line_set_prompt(line, "cmd.gprompt> ");
			line->contents = rz_str_dup(cmd);
			const char *buf = rz_line_readline(line);
			line->contents = NULL;
			rz_config_set(core->config, "cmd.gprompt", buf);
			showcursor(core, false);
		} break;
		case '|': {
			int e = rz_config_get_i(core->config, "graph.layout");
			if (++e > 1) {
				e = 0;
			}
			rz_config_set_i(core->config, "graph.layout", e);
			g->layout = rz_config_get_i(core->config, "graph.layout");
			g->need_update_dim = true;
			g->need_set_layout = true;
		}
			grp_ctx.scroll_position = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'e': {
			int e = rz_config_get_i(core->config, "graph.edges");
			e++;
			if (e > 2) {
				e = 0;
			}
			rz_config_set_i(core->config, "graph.edges", e);
			g->edgemode = e;
			g->need_update_dim = true;
			get_bbupdate(g, core, fcn);
		} break;
		case '\\':
			nextword(core, g, rz_cons_singleton()->highlight);
			break;
		case 'b':
			rz_core_visual_browse(core, "");
			break;
		case 'E': {
			int e = rz_config_get_i(core->config, "graph.linemode");
			e--;
			if (e < 0) {
				e = 1;
			}
			rz_config_set_i(core->config, "graph.linemode", e);
			g->can->linemode = e;
			get_bbupdate(g, core, fcn);
		} break;
		case 13:
			agraph_update_seek(g, get_anode(g->curnode), true);
			update_seek = true;
			exit_graph = true;
			break;
		case '>':
			if (rz_cons_yesno('y', "Compute function callgraph? (Y/n)")) {
				RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
				if (!function) {
					RZ_LOG_INFO("No function found at current address\n");
					break;
				}
				RzGraph *graph = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_FUNCALL, function->addr);
				if (!graph) {
					RZ_LOG_INFO("failed to compute callgraph\n");
					break;
				}
				rz_core_agraph_reset(core);
				if (rz_core_agraph_apply(core, graph)) {
					// TODO: Convert to the API
					rz_core_cmd0(core, ".axfg @$FB");
					rz_core_agraph_print_interactive(core);
				}
				rz_graph_free(graph);
			}
			break;
		case '<':
			// rz_core_visual_xrefs (core, true, false);
			if (fcn) {
				rz_core_agraph_reset(core);
				rz_core_cmd0(core, ".axtg $FB");
				rz_core_agraph_print_interactive(core);
			}
			break;
		case 'G':
			rz_core_agraph_reset(core);
			rz_core_cmd0(core, ".dtg*");
			rz_core_agraph_print_interactive(core);
			break;
		case 'V':
			if (fcn) {
				agraph_toggle_callgraph(g);
			}
			break;
		case 'Z':
			if (okey == 27) { // shift-tab
				agraph_prev_node(g);
			}
			break;
		case 's':
			if (!fcn) {
				break;
			}
			key_s = rz_config_get(core->config, "key.s");
			if (key_s && *key_s) {
				rz_core_cmd0(core, key_s);
			} else {
				graph_single_step_in(core, g);
			}
			grp_ctx.scroll_position = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'S':
			if (fcn) {
				graph_single_step_over(core, g);
			}
			break;
		case 'x':
		case 'X': {
			if (!fcn) {
				break;
			}
			ut64 old_off = core->offset;
			RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
			if (block) {
				rz_core_seek(core, block->addr, false);
			}
			if ((key == 'x' && !rz_core_visual_xrefs(core, true, true)) ||
				(key == 'X' && !rz_core_visual_xrefs(core, false, true))) {
				rz_core_seek(core, old_off, false);
			}
			break;
		}
		case 9: // tab
			agraph_next_node(g);
			grp_ctx.scroll_position = 0;
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf("Visual Ascii Art function graph keybindings:\n"
				       " :e cmd.gprompt = agf   - show graph in one side\n"
				       " +/-/0        - zoom in/out/default\n"
				       " ;            - add comment in current basic block\n"
				       " . (dot)      - center graph to the current node\n"
				       " , (comma)    - toggle graph.few\n"
				       " ^            - seek to the first bb of the function\n"
				       " =            - toggle graph.layout\n"
				       " :cmd         - run rizin command\n"
				       " '            - toggle graph.comments\n"
				       " \"            - toggle graph.refs\n"
				       " #            - toggle graph.hints\n"
				       " /            - highlight text\n"
				       " \\            - scroll the graph canvas to the next highlight location\n"
				       " |            - set cmd.gprompt\n"
				       " _            - enter hud selector\n"
				       " >            - show function callgraph (see graph.refs)\n"
				       " <            - show program callgraph (see graph.refs)\n"
				       " (            - reverse conditional branch of last instruction in bb\n"
				       " )            - rotate asm.emu and emu.str\n"
				       " Home/End     - go to the top/bottom of the canvas\n"
				       " Page-UP/DOWN - scroll canvas up/down\n"
				       " b            - visual browse things\n"
				       " c            - toggle graph cursor mode\n"
				       " C            - toggle scr.color\n"
				       " d            - rename function\n"
				       " D            - toggle the mixed graph+disasm mode\n"
				       " e            - rotate graph.edges (show/hide edges)\n"
				       " E            - rotate graph.linemode (square/diagonal lines)\n"
				       " F            - enter flag selector\n"
				       " g            - go/seek to given offset\n"
				       " G            - debug trace callgraph (generated with dtc)\n"
				       " hjkl/HJKL    - scroll canvas or node depending on graph cursor (uppercase for faster)\n"
				       " i            - select input nodes by index\n"
				       " I            - select output node by index\n"
				       " m/M          - change mouse modes\n"
				       " n/N          - next/previous scr.nkey (function/flag..)\n"
				       " o([A-Za-z]*) - follow jmp/call identified by shortcut (like ;[oa])\n"
				       " O            - toggle asm.pseudo and asm.esil\n"
				       " p/P          - rotate graph modes (normal, display offsets, minigraph, summary)\n"
				       " q            - back to Visual mode\n"
				       " r            - toggle jmphints/leahints\n"
				       " R            - randomize colors\n"
				       " s/S          - step / step over\n"
				       " tab          - select next node\n"
				       " TAB          - select previous node\n"
				       " t/f          - follow true/false edges\n"
				       " u/U          - undo/redo seek\n"
				       " V            - toggle basicblock / call graphs\n"
				       " w            - toggle between movements speed 1 and graph.scroll\n"
				       " x/X          - jump to xref/ref\n"
				       " z            - toggle node folding\n"
				       " Z            - toggle basic block folding");
			rz_cons_less();
			rz_cons_any_key(NULL);
			break;
		case '"':
			rz_config_toggle(core->config, "graph.refs");
			break;
		case '#':
			if (g->mode == RZ_AGRAPH_MODE_COMMENTS) {
				g->mode = RZ_AGRAPH_MODE_NORMAL;
			} else {
				g->mode = RZ_AGRAPH_MODE_COMMENTS;
			}
			g->need_reload_nodes = true;
			grp_ctx.scroll_position = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			// rz_config_toggle (core->config, "graph.hints");
			break;
		case 'p':
			g->mode = next_mode(g->mode);
			g->need_reload_nodes = true;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'P':
			if (!fcn) {
				break;
			}
			g->mode = prev_mode(g->mode);
			g->need_reload_nodes = true;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'o':
			goto_asmqjmps(g, core);
			break;
		case 'g':
			showcursor(core, true);
			visual_offset(g, core);
			showcursor(core, false);
			break;
		case 'O':
			if (!fcn) {
				break;
			}
			grp_ctx.display_mode = (grp_ctx.display_mode + 1) % 3;
			applyDisMode(core, &grp_ctx);
			g->need_reload_nodes = true;
			get_bbupdate(g, core, fcn);
			break;
		case 'u': {
			if (!fcn) {
				break;
			}
			if (!rz_core_seek_undo(core)) {
				RZ_LOG_ERROR("core: cannot undo\n");
			}
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		}
		case 'U': {
			if (!fcn) {
				break;
			}
			if (!rz_core_seek_redo(core)) {
				RZ_LOG_ERROR("core: cannot redo\n");
			}
			break;
		}
		case 'r':
			if (fcn) {
				g->layout = rz_config_get_i(core->config, "graph.layout");
				g->need_reload_nodes = true;
			}
			// TODO: toggle shortcut hotkeys
			rz_core_visual_toggle_hints(core);
			break;
		case '$': {
			ut64 dst =
				core->print->cur_enabled
				? core->offset + core->print->cur
				: core->offset;
			rz_core_reg_set_by_role_or_name(core, "PC", dst);
			rz_core_seek_to_register(core, "PC", false);
			g->need_reload_nodes = true;
			break;
		}
		case 'R':
			if (rz_config_get_i(core->config, "scr.randpal")) {
				rz_cons_pal_random();
			} else {
				rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_NEXT);
			}
			if (!fcn) {
				break;
			}
			g->edgemode = rz_config_get_i(core->config, "graph.edges");
			get_bbupdate(g, core, fcn);
			break;
		case '!':
			rz_core_visual_panels_root(core, visual->panels_root);
			break;
		case '\'':
			if (fcn) {
				rz_config_toggle(core->config, "graph.comments");
				g->need_reload_nodes = true;
			}
			break;
		case ';':
			if (fcn) {
				showcursor(core, true);
				char buf[256];
				rz_line_set_prompt(line, "[comment]> ");
				if (rz_cons_fgets(buf, sizeof(buf), 0, NULL) > 0) {
					rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset, buf);
				}
				g->need_reload_nodes = true;
				showcursor(core, false);
			}
			break;
		case 'C':
			rotateColor(core);
			break;
		case 'm':
			grp_ctx.mouse_mode++;
			if (!mousemodes[grp_ctx.mouse_mode]) {
				grp_ctx.mouse_mode = 0;
			}
			break;
		case 'M':
			grp_ctx.mouse_mode--;
			if (grp_ctx.mouse_mode < 0) {
				grp_ctx.mouse_mode = 3;
			}
			break;
		case '(': {
			if (!fcn) {
				break;
			}
			if (!rz_core_seek_bb_instruction(core, -1)) {
				break;
			}
			ut64 oldseek = core->offset;
			core->tmpseek = true;
			rz_core_hack(core, "recj");
			core->tmpseek = false;
			rz_core_seek(core, oldseek, true);
			g->need_reload_nodes = true;
			break;
		}
		case ')':
			if (fcn) {
				rotateAsmemu(core);
				g->need_reload_nodes = true;
			}
			break;
		case 'd': {
			showcursor(core, true);
			rz_core_visual_define(core, "", 0);
			get_bbupdate(g, core, fcn);
			showcursor(core, false);
		} break;
		case 'D':
			g->is_dis = !g->is_dis;
			break;
		case 'n':
			rz_core_seek_next(core, rz_config_get(core->config, "scr.nkey"), true);
			break;
		case 'N':
			rz_core_seek_prev(core, rz_config_get(core->config, "scr.nkey"), true);
			break;
		case 'z':
			agraph_toggle_mini(g);
			grp_ctx.scroll_position = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'v':
			rz_core_visual_analysis(core, NULL);
			break;
		case 'J':
			// copypaste from 'j'
			if (grp_ctx.graph_cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, &grp_ctx, 'j', speed * 2);
			} else {
				can->sy -= (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'K':
			if (grp_ctx.graph_cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, &grp_ctx, 'k', speed * 2);
			} else {
				can->sy += (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'H':
			if (grp_ctx.graph_cursor) {
				// move node canvas faster
				graphNodeMove(g, &grp_ctx, 'h', movspeed * 2);
			} else {
				// scroll canvas faster
				if (okey == 27) {
					// handle home key
					const RzGraphNode *gn = find_near_of(g, NULL, true);
					g->update_seek_on = get_anode(gn);
				} else {
					can->sx += (5 * movspeed) * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'L':
			if (grp_ctx.graph_cursor) {
				graphNodeMove(g, &grp_ctx, 'l', movspeed * 2);
			} else {
				can->sx -= (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'c':
			grp_ctx.graph_cursor = !grp_ctx.graph_cursor;
			break;
		case 'j':
			if (g->is_dis) {
				rz_core_seek_opcode(core, 1, false);
			} else {
				if (grp_ctx.graph_cursor) {
					int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
					graphNodeMove(g, &grp_ctx, 'j', speed);
				} else {
					// scroll canvas
					can->sy -= movspeed * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'k':
			if (g->is_dis) {
				rz_core_seek_opcode(core, -1, false);
			} else {
				if (grp_ctx.graph_cursor) {
					int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
					graphNodeMove(g, &grp_ctx, 'k', speed);
				} else {
					// scroll canvas
					can->sy += movspeed * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'l':
			if (grp_ctx.graph_cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, &grp_ctx, 'l', speed);
			} else {
				can->sx -= movspeed * (invscroll ? -1 : 1);
			}
			break;
		case 'h':
			if (grp_ctx.graph_cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, &grp_ctx, 'h', speed);
			} else {
				can->sx += movspeed * (invscroll ? -1 : 1);
			}
			break;
		case '^': {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			if (fcn) {
				rz_core_seek(core, fcn->addr, false);
			}
		}
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case ',':
			rz_config_toggle(core->config, "graph.few");
			g->need_reload_nodes = true;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case '.':
			grp_ctx.scroll_position = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'i':
			agraph_follow_innodes(g, true);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 'I':
			agraph_follow_innodes(g, false);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 't':
			agraph_follow_true(g);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 'T':
			// XXX WIP	agraph_merge_child (g, 0);
			break;
		case 'f':
			agraph_follow_false(g);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 'F':
			if (okey == 27) {
				// handle end key
				const RzGraphNode *gn = find_near_of(g, NULL, false);
				g->update_seek_on = get_anode(gn);
			} else {
				// agraph_merge_child (g, 1);
				rz_core_visual_trackflags(core);
			}
			break;
		case '/':
			showcursor(core, true);
			rz_core_prompt_highlight(core);
			showcursor(core, false);
			break;
		case ':':
			core->cons->event_resize = (RzConsEvent)agraph_set_need_reload_nodes;
			rz_core_visual_prompt_input(core);
			core->cons->event_resize = (RzConsEvent)agraph_refresh_oneshot;
			break;
		case 'w':
			agraph_toggle_speed(g, core);
			break;
		case '_':
			rz_core_visual_hudstuff(core);
			break;
		case RZ_CONS_KEY_F1:
			cmd = rz_config_get(core->config, "key.f1");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F2:
			cmd = rz_config_get(core->config, "key.f2");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_breakpoint(core);
			}
			break;
		case RZ_CONS_KEY_F3:
			cmd = rz_config_get(core->config, "key.f3");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F4:
			cmd = rz_config_get(core->config, "key.f4");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F5:
			cmd = rz_config_get(core->config, "key.f5");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F6:
			cmd = rz_config_get(core->config, "key.f6");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F7:
			cmd = rz_config_get(core->config, "key.f7");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_single_step_in(core, g);
			}
			break;
		case RZ_CONS_KEY_F8:
			cmd = rz_config_get(core->config, "key.f8");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_single_step_over(core, g);
			}
			break;
		case RZ_CONS_KEY_F9:
			cmd = rz_config_get(core->config, "key.f9");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_continue(core);
			}
			break;
		case RZ_CONS_KEY_F10:
			cmd = rz_config_get(core->config, "key.f10");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F11:
			cmd = rz_config_get(core->config, "key.f11");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F12:
			cmd = rz_config_get(core->config, "key.f12");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case -1: // EOF
		case ' ':
		case 'Q':
		case 'q':
			if (g->is_callgraph) {
				agraph_toggle_callgraph(g);
			} else {
				exit_graph = true;
			}
			break;
		case 27: // ESC
			if (rz_cons_readchar() == 91) {
				if (rz_cons_readchar() == 90) {
					agraph_prev_node(g);
				}
			}
			break;
		default:
			break;
		}
	}
	rz_vector_fini(&g->ghits.word_list);
	rz_cons_break_pop();
	rz_config_set(core->config, "asm.comments", rz_str_bool(asm_comments));
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->vmode = o_vmode;
	core->is_asmqjmps_letter = o_asmqjmps_letter;
	core->keep_asmqjmps = false;

	if (graph_allocated) {
		rz_agraph_free(g);
	} else {
		rz_cons_canvas_free(g->can);
		g->can = o_can;
	}
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	if (update_seek) {
		return -1;
	}
	return !is_error;
}

/**
 * \brief Create RzAGraph from generic RzGraph with RzGraphNodeInfo as node data at \p ag from \p g
 *
 * \param ag The RzAGraph to append the nodes to.
 * \param g The graph to build the RzAGraph from.
 * \param info The node info to add.
 * \param free_on_fail If true, \p ag will be freed in case of failure. If false, \p ag is not freed.
 * \param utf8 If true, the node titles can contain UTF-8 characters. If false, they will only contain ASCII.
 *
 * \return true In case of success.
 * \return false In case of failure.
 */
RZ_API bool create_agraph_from_graph_at(RZ_NONNULL RzAGraph *ag, RZ_NONNULL const RzGraph /*<RzGraphNodeInfo *>*/ *g, bool free_on_fail, bool utf8) {
	rz_return_val_if_fail(ag && g, false);
	ag->need_reload_nodes = false;
	// Cache lookup to build edges
	HtPPOptions pointer_options = { 0 };
	HtPP /*<RzGraphNode *node, RzANode *anode>*/ *hashmap = ht_pp_new_opt(&pointer_options);

	if (!hashmap) {
		goto failure;
	}
	// List of the new RzANodes
	RzGraphNode *node;
	// Traverse the list, create new ANode for each Node
	RzIterator *it_nodes = rz_graph_get_nodes(g);
	if (!it_nodes) {
		goto failure;
	}

	rz_iterator_foreach(it_nodes, node) {
		RzGraphNodeInfo *info = node->data;
		RzANode *a_node = rz_agraph_add_node_from_node_info(ag, info, utf8);
		if (!a_node) {
			goto failure;
		}
		ht_pp_insert(hashmap, node, a_node);
	}
	rz_iterator_free(it_nodes);

	// Traverse the nodes again, now build up the edges
	it_nodes = rz_graph_get_nodes(g);
	if (!it_nodes) {
		goto failure;
	}

	rz_iterator_foreach(it_nodes, node) {
		RzANode *a_node = ht_pp_find(hashmap, node, NULL);
		if (!a_node) {
			goto failure; // shouldn't happen in correct graph state
		}
		RzGraphNodeInfo *info = node->data;

		if (info && info->type == RZ_GRAPH_NODE_TYPE_CFG) {
			RzGraphEdge *out_edge;
			RzIterator *out_edge_iter = rz_graph_out_edges((RzGraph *)g, node);
			ut64 edge_idx = 0;
			if (!out_edge_iter) {
				continue;
			}

			rz_iterator_foreach(out_edge_iter, out_edge) {
				RzGraphNode *to_node = out_edge ? out_edge->to : NULL;
				RzANode *a_neighbour = ht_pp_find(hashmap, to_node, NULL);
				if (!a_neighbour) {
					rz_iterator_free(out_edge_iter);
					goto failure;
				}
				if ((info->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_COND) && edge_idx < 2) {
					rz_agraph_add_edge_at(ag, a_node, a_neighbour, (int)edge_idx);
					RzGraphEdge *new_edge = agraph_find_graph_edge(ag, a_node->gnode, a_neighbour->gnode);
					// migrate from original implement, 0 as TRUE branch, 1 as FALSE branch
					set_edge_kind(new_edge, edge_idx == 0 ? AGRAPH_EDGE_KIND_TRUE : AGRAPH_EDGE_KIND_FALSE);
				} else {
					rz_agraph_add_edge(ag, a_node, a_neighbour);
				}
				edge_idx++;
			}
			rz_iterator_free(out_edge_iter);
			continue;
		}

		/* Compatibility: pre-refactor agraph imported edges destination-first by
		 * iterating each source graph node's in-neighbours. That implicit import
		 * order shaped both global creation_order and each source node's
		 * out-edge order, which downstream layout/drawing still depends on. */
		RzGraphEdge *in_edge;
		RzIterator *in_edge_iter = rz_graph_in_edges((RzGraph *)g, node);
		if (!in_edge_iter) {
			continue;
		}

		rz_iterator_foreach(in_edge_iter, in_edge) {
			RzGraphNode *from_node = in_edge ? in_edge->from : NULL;
			RzANode *a_neighbour = ht_pp_find(hashmap, from_node, NULL);
			if (!a_neighbour) {
				rz_iterator_free(in_edge_iter);
				goto failure;
			}
			rz_agraph_add_edge(ag, a_neighbour, a_node);
		}
		rz_iterator_free(in_edge_iter);
	}
	rz_iterator_free(it_nodes);

	ht_pp_free(hashmap);
	return true;
failure:
	ht_pp_free(hashmap);
	if (free_on_fail) {
		rz_agraph_free(ag);
	} else {
		rz_agraph_reset(ag);
	}
	return false;
}

/**
 * \brief Create RzAGraph from generic RzGraph with RzGraphNodeInfo as node data
 *
 * \param graph The graph to create the RzAGraph from.
 * \param utf8 If true, the node titles can contain UTF-8 characters. If false, they are ASCII only.
 *
 * \return RzAGraph* The agraph or NULL in case of failure
 */
RZ_API RZ_OWN RzAGraph *create_agraph_from_graph(RZ_NONNULL const RzGraph /*<RzGraphNodeInfo *>*/ *graph, bool utf8) {
	rz_return_val_if_fail(graph, NULL);

	RzAGraph *result_agraph = rz_agraph_new(rz_cons_canvas_new(1, 1));
	if (!result_agraph) {
		return NULL;
	}
	if (!create_agraph_from_graph_at(result_agraph, graph, true, utf8)) {
		return NULL;
	}
	return result_agraph;
}

/**
 * Run the full Sugiyama layout pipeline on \p g.
 * After this call each \c RzANode has its \c layer, \c x and \c y fields set.
 * Intended for unit-testing the layout stages without requiring a canvas or
 * interactive rendering context.
 */
RZ_API void rz_agraph_compute_layout(RZ_NONNULL RzAGraph *g) {
	rz_return_if_fail(g);
	set_layout(g);
}
