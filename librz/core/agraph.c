// SPDX-FileCopyrightText: 2014-2020 pancake
// SPDX-FileCopyrightText: 2014-2020 ret2libc
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_util/rz_graph_drawable.h>
#include <ht_pu.h>
#include <ctype.h>
#include <limits.h>
#include "core_private.h"

static int mousemode = 0;
static int disMode = 0;
static int discroll = 0;
static bool graphCursor = false;
static const char *mousemodes[] = {
	"canvas-y",
	"canvas-x",
	"node-y",
	"node-x",
	NULL
};

#define GRAPH_MERGE_FEATURE 0

#define BORDER                  3
#define BORDER_WIDTH            4
#define BORDER_HEIGHT           3
#define MARGIN_TEXT_X           2
#define MARGIN_TEXT_Y           2
#define HORIZONTAL_NODE_SPACING 4
#define VERTICAL_NODE_SPACING   2
#define MIN_NODE_WIDTH          22
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

#define graph_foreach_anode(list, it, pos, anode) \
	if (list) \
		for ((it) = (list)->head; (it) && ((pos) = (it)->data) && (pos) && ((anode) = (RzANode *)(pos)->data); (it) = (it)->n)

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
	RzList *x, *y;
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

struct agraph_refresh_data {
	RzCore *core;
	RzAGraph *g;
	RzAnalysisFunction **fcn;
	bool follow_offset;
	int fs;
};

struct rz_agraph_location {
	int x;
	int y;
};

#define G(x, y)            rz_cons_canvas_gotoxy(g->can, x, y)
#define W(x)               rz_cons_canvas_write(g->can, x)
#define F(x, y, x2, y2, c) rz_cons_canvas_fill(g->can, x, y, x2, y2, c)

static bool is_offset(const RzAGraph *g) {
	return g->mode == RZ_AGRAPH_MODE_OFFSET;
}

static bool is_mini(const RzAGraph *g) {
	return g->mode == RZ_AGRAPH_MODE_MINI;
}

static bool is_tiny(const RzAGraph *g) {
	return g->is_tiny || g->mode == RZ_AGRAPH_MODE_TINY;
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
	const RzList *outnodes = in ? n->gnode->in_nodes : n->gnode->out_nodes;
	RzGraphNode *gn;
	RzListIter *iter;

	rz_list_foreach (outnodes, iter, gn) {
		RzANode *an = gn->data;
		return agraph_get_title(g, an, in);
	}
	return NULL;
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

static int agraph_refresh(struct agraph_refresh_data *grd);

static void update_node_dimension(const RzGraph *g, int is_mini, int zoom, int edgemode, bool callgraph, int layout) {
	const RzList *nodes = rz_graph_get_nodes(g);
	RzGraphNode *gn;
	RzListIter *it;
	RzANode *n;
	graph_foreach_anode (nodes, it, gn, n) {
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
			n->w += BORDER_WIDTH;
			n->h += BORDER_HEIGHT;
			/* scale node by zoom */
			n->w = RZ_MAX(MIN_NODE_WIDTH, (n->w * zoom) / 100);
			n->h = RZ_MAX(MIN_NODE_HEIGHT, (n->h * zoom) / 100);

			if (edgemode == 2 && !callgraph) {
				if (!layout) {
					n->w = RZ_MAX(n->w, (rz_list_length(n->gnode->out_nodes) * 2 + 1) + RZ_EDGES_X_INC * 2);
					n->w = RZ_MAX(n->w, (rz_list_length(n->gnode->in_nodes) * 2 + 1) + RZ_EDGES_X_INC * 2);
				} else {
					n->h = RZ_MAX(n->h, (rz_list_length(n->gnode->out_nodes) + 1) + RZ_EDGES_X_INC);
					n->h = RZ_MAX(n->h, (rz_list_length(n->gnode->in_nodes) + 1) + RZ_EDGES_X_INC);
				}
			}
		}
	}
}

static void append_shortcut(const RzAGraph *g, char *title, char *nodetitle, int left) {
	const char *shortcut = sdb_const_get(g->db, sdb_fmt("agraph.nodes.%s.shortcut", nodetitle), 0);
	if (shortcut) {
		if (g->can->color) {
			// XXX: do not hardcode color here
			strncat(title, sdb_fmt(Color_YELLOW "[o%s]" Color_RESET, shortcut), left);
		} else {
			strncat(title, sdb_fmt("[o%s]", shortcut), left);
		}
	}
}

static void mini_RzANode_print(const RzAGraph *g, const RzANode *n, int cur, bool details) {
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
			if (discroll > 0) {
				char *body = rz_str_ansi_crop(n->body, 0, discroll, -1, -1);
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

static void tiny_RzANode_print(const RzAGraph *g, const RzANode *n, int cur) {
	G(n->x, n->y);
	RzCons *cons = rz_cons_singleton();
	char *circle = cons->use_utf8 ? UTF_CIRCLE : "()";
	if (cur) {
		W("##");
	} else {
		W(circle);
	}
}

static char *get_node_color(int color, int cur) {
	RzCons *cons = rz_cons_singleton();
	if (color == -1) {
		return cur ? cons->context->pal.graph_box2 : cons->context->pal.graph_box;
	}
	return color ? (
			       color == RZ_ANALYSIS_DIFF_TYPE_MATCH ? cons->context->pal.diff_match : color == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? cons->context->pal.diff_unmatch
																	     : cons->context->pal.diff_new)
		     : cons->context->pal.diff_unknown;
}

static void normal_RzANode_print(const RzAGraph *g, const RzANode *n, int cur) {
	ut32 center_x = 0, center_y = 0;
	ut32 delta_x = 0, delta_txt_x = 0;
	ut32 delta_y = 0, delta_txt_y = 0;
	char title[TITLE_LEN];
	char *body;
	int x, y;
	int color = n->difftype;
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
	rz_cons_canvas_box(g->can, n->x, n->y, n->w, n->h, get_node_color(color, cur));
}

static int **get_crossing_matrix(const RzGraph *g,
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
			const RzGraphNode *gj = layers[i - 1].nodes[j];
			const RzList *neigh = rz_graph_get_neighbours(g, gj);
			RzGraphNode *gk;
			RzListIter *itk;

			rz_list_foreach (neigh, itk, gk) {
				int s;
				// skip self-loop
				if (gj == gk) {
					continue;
				}
				for (s = 0; s < j; s++) {
					const RzGraphNode *gs = layers[i - 1].nodes[s];
					const RzList *neigh_s = rz_graph_get_neighbours(g, gs);
					RzGraphNode *gt;
					RzListIter *itt;

					rz_list_foreach (neigh_s, itt, gt) {
						const RzANode *ak, *at; /* k and t should be "indexes" on layer i */
						if (gt == gk || gt == gs) {
							continue;
						}
						ak = get_anode(gk);
						at = get_anode(gt);
						if (ak->layer != i || at->layer != i) {
							// this should never happen
							// but it happens if we do graph.dummy = false, so better hide it for now
#if 0
							eprintf ("(WARNING) \"%s\" (%d) or \"%s\" (%d) are not on the right layer (%d)\n",
								ak->title, ak->layer,
								at->title, at->layer,
								i);
#endif
							continue;
						}
						m[ak->pos_in_layer][at->pos_in_layer]++;
					}
				}
			}
		}
	}

	/* calculate crossings between layer i and layer i+1 */
	if (i < maxlayer - 1 && !from_up) {
		if (rz_cons_is_breaked()) {
			goto err_row;
		}
		for (j = 0; j < layers[i].n_nodes; j++) {
			const RzGraphNode *gj = layers[i].nodes[j];
			const RzList *neigh = rz_graph_get_neighbours(g, gj);
			const RzANode *ak, *aj = get_anode(gj);
			RzGraphNode *gk;
			RzListIter *itk;

			if (rz_cons_is_breaked()) {
				goto err_row;
			}
			graph_foreach_anode (neigh, itk, gk, ak) {
				int s;
				for (s = 0; s < layers[i].n_nodes; s++) {
					const RzGraphNode *gs = layers[i].nodes[s];
					const RzList *neigh_s;
					RzGraphNode *gt;
					RzListIter *itt;
					const RzANode *at, *as = get_anode(gs);

					if (gs == gj) {
						continue;
					}
					neigh_s = rz_graph_get_neighbours(g, gs);
					graph_foreach_anode (neigh_s, itt, gt, at) {
						if (at->pos_in_layer < ak->pos_in_layer) {
							m[aj->pos_in_layer][as->pos_in_layer]++;
						}
					}
				}
			}
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

static int layer_sweep(const RzGraph *g, const struct layer_t layers[],
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

static void view_cyclic_edge(const RzGraphEdge *e, const RzGraphVisitor *vis) {
	const RzAGraph *g = (RzAGraph *)vis->data;
	RzGraphEdge *new_e = RZ_NEW0(RzGraphEdge);
	if (!new_e) {
		return;
	}
	new_e->from = e->from;
	new_e->to = e->to;
	new_e->nth = e->nth;
	rz_list_append(g->back_edges, new_e);
}

static void view_dummy(const RzGraphEdge *e, const RzGraphVisitor *vis) {
	const RzANode *a = get_anode(e->from);
	const RzANode *b = get_anode(e->to);
	RzList *long_edges = (RzList *)vis->data;
	if (!a || !b) {
		return;
	}
	if (RZ_ABS(a->layer - b->layer) > 1) {
		RzGraphEdge *new_e = RZ_NEW0(RzGraphEdge);
		if (!new_e) {
			return;
		}
		new_e->from = e->from;
		new_e->to = e->to;
		new_e->nth = e->nth;
		rz_list_append(long_edges, new_e);
	}
}

/* find a set of edges that, removed, makes the graph acyclic */
/* invert the edges identified in the previous step */
static void remove_cycles(RzAGraph *g) {
	RzGraphVisitor cyclic_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RzGraphEdge *e;
	const RzListIter *it;

	g->back_edges = rz_list_newf(free);
	cyclic_vis.back_edge = (RzGraphEdgeCallback)view_cyclic_edge;
	cyclic_vis.data = g;
	rz_graph_dfs(g->graph, &cyclic_vis);

	rz_list_foreach (g->back_edges, it, e) {
		RzANode *from = e->from ? get_anode(e->from) : NULL;
		RzANode *to = e->to ? get_anode(e->to) : NULL;
		if (from && to) {
			rz_agraph_del_edge(g, from, to);
			rz_agraph_add_edge_at(g, to, from, e->nth);
		}
	}
}

static void add_sorted(RzGraphNode *n, RzGraphVisitor *vis) {
	RzList *l = (RzList *)vis->data;
	rz_list_prepend(l, n);
}

/* assign a layer to each node of the graph.
 *
 * It visits the nodes of the graph in the topological sort, so that every time
 * you visit a node, you can be sure that you have already visited all nodes
 * that can lead to that node and thus you can easily compute the layer based
 * on the layer of these "parent" nodes. */
static void assign_layers(const RzAGraph *g) {
	RzGraphVisitor layer_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RzGraphNode *gn;
	const RzListIter *it;
	RzANode *n;
	RzList *topological_sort = rz_list_new();

	layer_vis.data = topological_sort;
	layer_vis.finish_node = (RzGraphNodeCallback)add_sorted;
	rz_graph_dfs(g->graph, &layer_vis);

	graph_foreach_anode (topological_sort, it, gn, n) {
		const RzList *innodes = rz_graph_innodes(g->graph, gn);
		RzListIter *it;
		RzGraphNode *prev;
		RzANode *preva;

		n->layer = 0;
		graph_foreach_anode (innodes, it, prev, preva) {
			if (preva->layer + 1 > n->layer) {
				n->layer = preva->layer + 1;
			}
		}
	}

	rz_list_free(topological_sort);
}

static int find_edge(const RzGraphEdge *a, const RzGraphEdge *b) {
	return a->from == b->to && a->to == b->from ? 0 : 1;
}

static bool is_reversed(const RzAGraph *g, const RzGraphEdge *e) {
	return (bool)rz_list_find(g->back_edges, e, (RzListComparator)find_edge);
}

/* add dummy nodes when there are edges that span multiple layers */
static void create_dummy_nodes(RzAGraph *g) {
	if (!g->dummy) {
		return;
	}
	RzGraphVisitor dummy_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RzListIter *it;
	const RzGraphEdge *e;

	g->long_edges = rz_list_newf((RzListFree)free);
	dummy_vis.data = g->long_edges;
	dummy_vis.tree_edge = (RzGraphEdgeCallback)view_dummy;
	dummy_vis.fcross_edge = (RzGraphEdgeCallback)view_dummy;
	rz_graph_dfs(g->graph, &dummy_vis);

	rz_list_foreach (g->long_edges, it, e) {
		RzANode *from = get_anode(e->from);
		RzANode *to = get_anode(e->to);
		int diff_layer = RZ_ABS(from->layer - to->layer);
		RzANode *prev = get_anode(e->from);
		int i, nth = e->nth;

		rz_agraph_del_edge(g, from, to);
		for (i = 1; i < diff_layer; i++) {
			RzANode *dummy = rz_agraph_add_node(g, NULL, NULL);
			if (!dummy) {
				return;
			}
			dummy->is_dummy = true;
			dummy->layer = from->layer + i;
			dummy->is_reversed = is_reversed(g, e);
			dummy->w = 1;
			rz_agraph_add_edge_at(g, prev, dummy, nth);
			rz_list_append(g->dummy_nodes, dummy);

			prev = dummy;
			nth = -1;
		}
		rz_graph_add_edge(g->graph, prev->gnode, e->to);
	}
}

/* create layers and assign an initial ordering of the nodes into them */
static void create_layers(RzAGraph *g) {
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	RzGraphNode *gn;
	const RzListIter *it;
	RzANode *n;
	int i;

	/* identify max layer */
	g->n_layers = 0;
	graph_foreach_anode (nodes, it, gn, n) {
		if (n->layer > g->n_layers) {
			g->n_layers = n->layer;
		}
	}

	/* create a starting ordering of nodes for each layer */
	g->n_layers++;
	if (sizeof(struct layer_t) * g->n_layers < g->n_layers) {
		return;
	}
	g->layers = RZ_NEWS0(struct layer_t, g->n_layers);

	graph_foreach_anode (nodes, it, gn, n) {
		g->layers[n->layer].n_nodes++;
	}

	for (i = 0; i < g->n_layers; i++) {
		if (sizeof(RzGraphNode *) * g->layers[i].n_nodes < g->layers[i].n_nodes) {
			continue;
		}
		g->layers[i].nodes = RZ_NEWS0(RzGraphNode *,
			1 + g->layers[i].n_nodes);
		g->layers[i].position = 0;
	}
	graph_foreach_anode (nodes, it, gn, n) {
		n->pos_in_layer = g->layers[n->layer].position;
		g->layers[n->layer].nodes[g->layers[n->layer].position++] = gn;
	}
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
			int rc = layer_sweep(g->graph, g->layers, g->n_layers, i, true);
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
			int rc = layer_sweep(g->graph, g->layers, g->n_layers, i, false);
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
		it = rz_list_find(g->dists, &d, (RzListComparator)find_dist);
		if (it) {
			struct dist_t *old = (struct dist_t *)rz_list_iter_get_data(it);
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
				it = rz_list_find(g->dists, &d, (RzListComparator)find_dist);
				if (it) {
					struct dist_t *old = (struct dist_t *)rz_list_iter_get_data(it);
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
	it = rz_list_find(g->dists, &find_el, (RzListComparator)find_dist);
	d = it ? (struct dist_t *)rz_list_iter_get_data(it) : RZ_NEW0(struct dist_t);

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

static void free_vertical_nodes_kv(HtPPKv *kv) {
	rz_list_free(kv->value);
}

/* computes the set of vertical classes in the graph */
/* if v is an original node, L(v) = { v }
 * if v is a dummy node, L(v) is the set of all the dummies node that belongs
 *      to the same long edge */
static HtPP *compute_vertical_nodes(const RzAGraph *g) {
	HtPPOptions ht_opt = { 0 };
	ht_opt.freefn = free_vertical_nodes_kv;
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
						next = rz_graph_nth_neighbour(g->graph, next, 0);
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
static RzList **compute_classes(const RzAGraph *g, HtPP *v_nodes, int is_left, int *n_classes) {
	int i, j, c;
	RzList **res = RZ_NEWS0(RzList *, g->n_layers);
	RzGraphNode *gn;
	const RzListIter *it;
	RzANode *n;

	graph_foreach_anode (rz_graph_get_nodes(g->graph), it, gn, n) {
		n->klass = -1;
	}

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
				graph_foreach_anode (laj, it, gn, n) {
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
static void adjust_class(const RzAGraph *g, int is_left, RzList **classes, HtPU *res, int c) {
	const RzGraphNode *gn;
	const RzListIter *it;
	const RzANode *an;
	int dist = INT_MAX, v, is_first = true;

	graph_foreach_anode (classes[c], it, gn, an) {
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

		graph_foreach_anode (classes[c], it, gn, an) {
			const RzList *neigh = rz_graph_all_neighbours(g->graph, gn);
			const RzGraphNode *gk;
			const RzListIter *itk;
			const RzANode *ak;

			graph_foreach_anode (neigh, itk, gk, ak) {
				if (ak->klass < c) {
					size_t d = (ak->x - an->x);
					if (d > 0) {
						rz_list_append(heap, (void *)d);
					}
				}
			}
		}

		len = rz_list_length(heap);
		if (len == 0) {
			dist = 0;
		} else {
			rz_list_sort(heap, (RzListComparator)cmp_dist);
			dist = (int)(size_t)rz_list_get_n(heap, len / 2);
		}

		rz_list_free(heap);
	}

	graph_foreach_anode (classes[c], it, gn, an) {
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
static void place_nodes(const RzAGraph *g, const RzGraphNode *gn, int is_left, HtPP *v_nodes, RzList **classes, HtPU *res, SetP *placed) {
	const RzList *lv = ht_pp_find(v_nodes, gn, NULL);
	int p = 0, v, is_first = true;
	const RzGraphNode *gk;
	const RzListIter *itk;
	const RzANode *ak;

	graph_foreach_anode (lv, itk, gk, ak) {
		const RzGraphNode *sibling;
		const RzANode *sibl_anode;

		sibling = get_sibling(g, ak, is_left, false);
		if (!sibling) {
			continue;
		}
		sibl_anode = get_anode(sibling);
		if (ak->klass == sibl_anode->klass) {
			if (!set_p_contains(placed, sibling)) {
				place_nodes(g, sibling, is_left, v_nodes, classes, res, placed);
			}

			v = place_nodes_val(g, gk, sibling, res, is_left);
			p = place_nodes_sel_p(v, p, is_first, is_left);
			is_first = false;
		}
	}

	if (is_first) {
		p = is_left ? 0 : 50;
	}

	graph_foreach_anode (lv, itk, gk, ak) {
		ht_pu_update(res, gk, (ut64)(size_t)p);
		set_p_add(placed, gk);
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
	HtPPOptions pp_opt = { 0 };
	HtPU *res = ht_pu_new_opt(&pu_opt);
	SetP *placed = (SetP *)ht_pp_new_opt(&pp_opt);
	if (!res || !placed) {
		ht_pu_free(res);
		set_p_free(placed);
		return NULL;
	}
	for (i = 0; i < n_classes; i++) {
		const RzGraphNode *gn;
		const RzListIter *it;

		rz_list_foreach (classes[i], it, gn) {
			if (!set_p_contains(placed, gn)) {
				place_nodes(g, gn, is_left, v_nodes, classes, res, placed);
			}
		}

		adjust_class(g, is_left, classes, res, i);
	}

	set_p_free(placed);
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
	const RzList *nodes;
	const RzGraphNode *gn;
	const RzListIter *it;
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

	nodes = rz_graph_get_nodes(g->graph);
	graph_foreach_anode (nodes, it, gn, n) {
		n->x = (hash_get_int(xminus, gn) + hash_get_int(xplus, gn)) / 2;
	}

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
			wp = rz_list_get_n(rz_graph_innodes(g->graph, vp), 0);
		} else {
			wp = rz_graph_nth_neighbour(g->graph, vp, 0);
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
	const RzListIter *itk;

	const RzList *neigh = from_up
		? rz_graph_innodes(g->graph, v)
		: rz_graph_get_neighbours(g->graph, v);

	int len = rz_list_length(neigh);
	if (len == 0) {
		return;
	}

	int sum_x = 0;
	graph_foreach_anode (neigh, itk, gk, ak) {
		if (ak->is_reversed) {
			len--;
			continue;
		}
		sum_x += ak->x;
	}

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

static void collect_changes(const RzAGraph *g, int l, const RzGraphNode *b, int from_up, int s, int e, RzList *list, int is_left) {
	const RzGraphNode *vt = g->layers[l].nodes[e - 1];
	const RzGraphNode *vtp = g->layers[l].nodes[s];
	struct len_pos_t *cx;
	int i;

	RzListComparator lcmp = is_left ? (RzListComparator)RM_listcmp : (RzListComparator)RP_listcmp;

	for (i = is_left ? s : e - 1; (is_left && i < e) || (!is_left && i >= s); i = is_left ? i + 1 : i - 1) {
		const RzGraphNode *v, *vi = g->layers[l].nodes[i];
		const RzANode *av, *avi = get_anode(vi);
		const RzList *neigh;
		const RzListIter *it;
		int c = 0;

		if (!avi) {
			continue;
		}
		neigh = from_up
			? rz_graph_innodes(g->graph, vi)
			: rz_graph_get_neighbours(g->graph, vi);

		graph_foreach_anode (neigh, it, v, av) {
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
				rz_list_add_sorted(list, cx, lcmp);
			}
		}

		cx = RZ_NEW0(struct len_pos_t);
		cx->len = c;
		cx->pos = avi->x;
		if (is_left) {
			cx->pos += dist_nodes(g, vi, vt);
		} else {
			cx->pos -= dist_nodes(g, vtp, vi);
		}
		rz_list_add_sorted(list, cx, lcmp);
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
			rz_list_add_sorted(list, cx, lcmp);
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
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	const RzGraphNode *gn;
	const RzListIter *itn;
	const RzANode *an;
	HtPUOptions opt = { 0 };

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

	graph_foreach_anode (nodes, itn, gn, an) {
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

	original_traverse_l(g, D, P, true);
	original_traverse_l(g, D, P, false);

	rz_list_free(g->dists);
	g->dists = NULL;
	ht_pu_free(P);
	ht_pu_free(D);
}

#if 0
static void remove_dummy_nodes(const RzAGraph *g) {
	const RzList *nodes = rz_graph_get_nodes (g->graph);
	RzGraphNode *gn;
	RzListIter *it;
	RzANode *n;

	graph_foreach_anode (nodes, it, gn, n) {
		if (n->is_dummy) {
			rz_graph_del_node (g->graph, gn);
			n->gnode = NULL;
			free_anode (n);
		}
	}
}
#endif

static void set_layer_gap(RzAGraph *g) {
	int gap = 0;
	int i = 0, j = 0;
	RzListIter *itn;
	RzGraphNode *ga, *gb;
	RzANode *a, *b;
	const RzList *outnodes;

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
			outnodes = ga->out_nodes;

			if (!outnodes || !a) {
				continue;
			}
			graph_foreach_anode (outnodes, itn, gb, b) {
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
		}
		if (i + 1 < g->n_layers) {
			g->layers[i + 1].gap += gap;
		}
	}
}

static void fix_back_edge_dummy_nodes(RzAGraph *g, RzANode *from, RzANode *to) {
	RzANode *v, *tmp = NULL;
	RzGraphNode *gv = NULL;
	RzListIter *it;
	int i;
	rz_return_if_fail(g && from && to);
	const RzList *neighbours = rz_graph_get_neighbours(g->graph, to->gnode);
	graph_foreach_anode (neighbours, it, gv, v) {
		tmp = v;
		while (tmp->is_dummy) {
			tmp = (RzANode *)(((RzGraphNode *)rz_list_first(tmp->gnode->out_nodes))->data);
		}
		if (tmp->gnode->idx == from->gnode->idx) {
			break;
		}
		tmp = NULL;
	}
	if (tmp) {
		tmp = v;
		while (tmp->gnode->idx != from->gnode->idx) {
			v = tmp;
			tmp = (RzANode *)(((RzGraphNode *)rz_list_first(v->gnode->out_nodes))->data);

			i = 0;
			while (v->gnode->idx != g->layers[v->layer].nodes[i]->idx) {
				i += 1;
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

static int get_edge_number(const RzAGraph *g, RzANode *src, RzANode *dst, bool outgoing) {
	RzListIter *itn;
	RzGraphNode *gv;
	int cur_nth = 0;
	int nth = 0;
	RzANode *v;

	if (outgoing && src->is_dummy) {
		RzANode *in = (RzANode *)(((RzGraphNode *)rz_list_first((src->gnode)->in_nodes))->data);
		cur_nth = get_edge_number(g, in, src, outgoing);
	} else {
		const RzList *neighbours = outgoing
			? rz_graph_get_neighbours(g->graph, src->gnode)
			: rz_graph_innodes(g->graph, dst->gnode);
		const int exit_edges = rz_list_length(neighbours);
		graph_foreach_anode (neighbours, itn, gv, v) {
			cur_nth = nth;
			if (g->is_callgraph) {
				cur_nth = 0;
			} else if (exit_edges == 1) {
				cur_nth = -1;
			}
			if (outgoing && gv->idx == (dst->gnode)->idx) {
				break;
			}
			if (!outgoing && gv->idx == (src->gnode)->idx) {
				break;
			}
			nth++;
		}
	}
	return cur_nth;
}

static int count_edges(const RzAGraph *g, RzANode *src, RzANode *dst) {
	return get_edge_number(g, src, dst, true);
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

			const RzList *neighbours = rz_graph_get_neighbours(g->graph, a->gnode);
			RzGraphNode *gb;
			RzANode *b;
			RzListIter *itm;

			if (i == 0) {
				inedge += rz_list_length(rz_graph_innodes(g->graph, a->gnode));
			} else if (i == g->n_layers - 1) {
				outedge += rz_list_length(neighbours);
			}

			graph_foreach_anode (neighbours, itm, gb, b) {
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
		fix_back_edge_dummy_nodes(g, from, to);
		rz_agraph_del_edge(g, to, from);
		rz_agraph_add_edge_at(g, from, to, e->nth);
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
					if (g->is_tiny) {
						n->x /= 8;
					}
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
			if (g->is_tiny) {
				tmp_y = i;
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
	const bool o_graph_offset = rz_config_get_i(core->config, "graph.offset");
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

	if (opts & BODY_OFFSETS || opts & BODY_SUMMARY || o_graph_offset) {
		rz_config_set_i(core->config, "asm.offset", true);
	} else {
		rz_config_set_i(core->config, "asm.offset", false);
	}

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
	if (b->parent_stackptr != INT_MAX) {
		core->analysis->stackptr = b->parent_stackptr;
	}
	char *body = get_body(core, b->addr, b->size, opts);
	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RzAnalysisBlock *jumpbb = rz_analysis_get_block_at(b->analysis, b->jump);
			if (jumpbb && rz_list_contains(jumpbb->fcns, fcn)) {
				if (emu && core->analysis->last_disasm_reg != NULL && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = rz_reg_arena_dup(core->analysis->reg, core->analysis->last_disasm_reg);
				}
				if (jumpbb->parent_stackptr == INT_MAX) {
					jumpbb->parent_stackptr = core->analysis->stackptr + b->stackptr;
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
				if (failbb->parent_stackptr == INT_MAX) {
					failbb->parent_stackptr = core->analysis->stackptr + b->stackptr;
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
	RzListIter *iter;
	bool emu = rz_config_get_i(core->config, "asm.emu");
	ut64 saved_gp = core->analysis->gp;
	ut8 *saved_arena = NULL;
	int saved_stackptr = core->analysis->stackptr;
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
	rz_list_sort(fcn->bbs, (RzListComparator)bbcmp);

	shortcuts = rz_config_get_i(core->config, "graph.nodejmps");
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *body = get_bb_body(core, bb, mode2opts(g), fcn, emu, saved_gp, saved_arena);
		char *title = get_title(bb->addr);

		if (shortcuts) {
			shortcut = rz_core_add_asmqjmp(core, bb->addr);
			if (shortcut) {
				sdb_set(g->db, sdb_fmt("agraph.nodes.%s.shortcut", title), shortcut, 0);
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
	core->analysis->stackptr = saved_stackptr;
}

static void fold_asm_trace(RzCore *core, RzAGraph *g) {
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	RzGraphNode *gn;
	RzListIter *it;
	RzANode *n;

	RzANode *curnode = get_anode(g->curnode);
	graph_foreach_anode (nodes, it, gn, n) {
		if (curnode == n) {
			n->is_mini = false;
			g->need_reload_nodes = true;
			continue;
		}
		ut64 addr = rz_num_get(NULL, n->title);
		RzDebugTracepoint *tp = rz_debug_trace_get(core->dbg, addr);
		n->is_mini = (tp == NULL);
	}
	g->need_update_dim = 1;
	// agraph_refresh (rz_cons_singleton ()->event_data);
}

static void delete_dup_edges(RzAGraph *g) {
	RzListIter *it, *in_it, *in_it2, *in_it2_tmp;
	RzGraphNode *n, *a, *b;
	rz_list_foreach (g->graph->nodes, it, n) {
		rz_list_foreach (n->out_nodes, in_it, a) {
			for (in_it2 = in_it->n; in_it2 && (b = in_it2->data, in_it2_tmp = in_it2->n, 1); in_it2 = in_it2_tmp) {
				if (a->idx == b->idx) {
					rz_list_delete(n->out_nodes, in_it2);
					rz_list_delete_data(n->all_neighbours, b);
					rz_list_delete_data(b->in_nodes, n);
					rz_list_delete_data(b->all_neighbours, n);
					g->graph->n_edges--;
				}
			}
		}
	}
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
	RzListIter *iter;
	char *shortcut = NULL;
	int shortcuts = 0;
	bool emu = rz_config_get_i(core->config, "asm.emu");
	bool few = rz_config_get_i(core->config, "graph.few");
	int ret = false;
	ut64 saved_gp = core->analysis->gp;
	ut8 *saved_arena = NULL;
	int saved_stackptr = core->analysis->stackptr;
	core->keep_asmqjmps = false;

	if (!fcn) {
		return false;
	}
	if (emu) {
		saved_arena = rz_reg_arena_peek(core->analysis->reg);
	}
	rz_list_sort(fcn->bbs, (RzListComparator)bbcmp);
	RzAnalysisBlock *curbb = NULL;
	if (few) {
		rz_list_foreach (fcn->bbs, iter, bb) {
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
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		if (few && !isbbfew(curbb, bb)) {
			continue;
		}
		char *body = get_bb_body(core, bb, mode2opts(g), fcn, emu, saved_gp, saved_arena);
		char *title = get_title(bb->addr);

		RzANode *node = rz_agraph_add_node(g, title, body);
		shortcuts = g->is_interactive ? rz_config_get_i(core->config, "graph.nodejmps") : false;

		if (shortcuts) {
			shortcut = rz_core_add_asmqjmp(core, bb->addr);
			if (shortcut) {
				sdb_set(g->db, sdb_fmt("agraph.nodes.%s.shortcut", title), shortcut, 0);
				free(shortcut);
			}
		}
		free(body);
		free(title);
		if (!node) {
			goto cleanup;
		}
		core->keep_asmqjmps = true;
	}

	rz_list_foreach (fcn->bbs, iter, bb) {
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
			rz_agraph_add_edge(g, u, v);
		}
		if (bb->fail != UT64_MAX) {
			title = get_title(bb->fail);
			v = rz_agraph_get_node(g, title);
			free(title);
			rz_agraph_add_edge(g, u, v);
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
	core->analysis->stackptr = saved_stackptr;
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
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	const RzListIter *it;
	const RzGraphNode *gn, *resgn = NULL;
	const RzANode *n, *acur = cur ? get_anode(cur) : NULL;
	const int default_v = is_next ? INT_MIN : INT_MAX;
	const int start_x = acur ? acur->x : default_v;
	const int start_y = acur ? acur->y : default_v;

	graph_foreach_anode (nodes, it, gn, n) {
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

	graph_foreach_anode (rz_graph_get_nodes(g->graph), it, gk, ak) {
		const RzList *nd = NULL;
		int len;
		if (ak->x < g->x) {
			g->x = ak->x;
		}

		nd = rz_graph_innodes(g->graph, gk);
		len = nd ? rz_list_length(nd) + 1 : 0;
		if (ak->y - len < g->y) {
			g->y = ak->y - len;
			min_gn = ak;
		}

		if (ak->x + ak->w > max_x) {
			max_x = ak->x + ak->w;
		}

		nd = NULL;
		nd = rz_graph_get_neighbours(g->graph, gk);
		len = nd ? rz_list_length(nd) + 2 : 0;
		if (ak->y + ak->h + len > max_y) {
			max_y = ak->y + ak->h + len;
			max_gn = ak;
		}
	}
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
		const RzList *neigh = rz_graph_innodes(g->graph, min_gn->gnode);
		if (rz_list_length(neigh) > 0) {
			g->y--;
			max_y++;
		}
		if (max_gn) {
			const RzList *neigh = rz_graph_get_neighbours(g->graph, min_gn->gnode);
			if (rz_list_length(neigh) > 0) {
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

	sdb_num_set(g->db, "agraph.w", g->w, 0);
	sdb_num_set(g->db, "agraph.h", g->h, 0);
	/* delta_x, delta_y are needed to make every other x,y coordinates
	 * unsigned, so that we can use sdb_num_ API */
	delta_x = g->x < 0 ? -g->x : 0;
	delta_y = g->y < 0 ? -g->y : 0;
	sdb_num_set(g->db, "agraph.delta_x", delta_x, 0);
	sdb_num_set(g->db, "agraph.delta_y", delta_y, 0);
}

RZ_API void rz_agraph_set_curnode(RzAGraph *g, RzANode *a) {
	if (!a) {
		return;
	}
	g->curnode = a->gnode;
	if (a->title) {
		sdb_set(g->db, "agraph.curnode", a->title, 0);
		if (g->on_curnode_change) {
			g->on_curnode_change(a, g->on_curnode_change_data);
		}
	}
}

static ut64 rebase(RzAGraph *g, int v) {
	return g->x < 0 ? -g->x + v : v;
}

static void agraph_set_layout(RzAGraph *g) {
	RzListIter *it;
	RzGraphNode *n;
	RzANode *a;

	set_layout(g);

	update_graph_sizes(g);
	graph_foreach_anode (rz_graph_get_nodes(g->graph), it, n, a) {
		if (a->is_dummy) {
			continue;
		}
		const char *k;
		k = sdb_fmt("agraph.nodes.%s.x", a->title);
		sdb_num_set(g->db, k, rebase(g, a->x), 0);
		k = sdb_fmt("agraph.nodes.%s.y", a->title);
		sdb_num_set(g->db, k, rebase(g, a->y), 0);
		k = sdb_fmt("agraph.nodes.%s.w", a->title);
		sdb_num_set(g->db, k, a->w, 0);
		k = sdb_fmt("agraph.nodes.%s.h", a->title);
		sdb_num_set(g->db, k, a->h, 0);
	}
}

/* set the willing to center the screen on a particular node */
static void agraph_update_seek(RzAGraph *g, RzANode *n, int force) {
	g->update_seek_on = n;
	g->force_update_seek = force;
}

static void agraph_print_node(const RzAGraph *g, RzANode *n) {
	if (n->is_dummy) {
		return;
	}
	const int cur = g->curnode && get_anode(g->curnode) == n;
	const bool isMini = is_mini(g);
	if (g->is_tiny) {
		tiny_RzANode_print(g, n, cur);
	} else if (isMini || n->is_mini) {
		mini_RzANode_print(g, n, cur, isMini);
	} else {
		normal_RzANode_print(g, n, cur);
	}
}

static void agraph_print_nodes(const RzAGraph *g) {
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	RzGraphNode *gn;
	RzListIter *it;
	RzANode *n;

	graph_foreach_anode (nodes, it, gn, n) {
		if (gn != g->curnode) {
			agraph_print_node(g, n);
		}
	}

	/* draw current node now to make it appear on top */
	if (g->curnode) {
		agraph_print_node(g, get_anode(g->curnode));
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

int tmplayercmp(const void *a, const void *b) {
	return ((struct tmplayer *)a)->layer > ((struct tmplayer *)b)->layer;
}

static void agraph_print_edges_simple(RzAGraph *g) {
	RzCanvasLineStyle style = { 0 };
	RzANode *n, *n2;
	RzGraphNode *gn, *gn2;
	RzListIter *iter, *iter2;
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	graph_foreach_anode (nodes, iter, gn, n) {
		const RzList *outnodes = n->gnode->out_nodes;
		graph_foreach_anode (outnodes, iter2, gn2, n2) {
			int sx = n->w / 2;
			int sy = n->h;
			int sx2 = n2->w / 2;
			if (g->is_tiny) {
				sx = 0;
				sy = 0;
				sx2 = 0;
			}
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
	}
}

static int first_x_cmp(const void *_a, const void *_b) {
	RzGraphNode *ga = (RzGraphNode *)_a;
	RzGraphNode *gb = (RzGraphNode *)_b;
	RzANode *a = (RzANode *)ga->data;
	RzANode *b = (RzANode *)gb->data;
	if (b->y < a->y) {
		return -1;
	}
	if (b->y > a->y) {
		return 1;
	}
	if (a->x < b->x) {
		return 1;
	}
	if (a->x > b->x) {
		return -1;
	}
	return 0;
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
	RzListIter *itn, *itm, *ito;
	RzCanvasLineStyle style = { 0 };
	const RzList *nodes = rz_graph_get_nodes(g->graph);
	RzGraphNode *ga;
	RzANode *a;

	RzList *lyr = rz_list_new();
	RzList *bckedges = rz_list_new();
	struct tmplayer *tl, *tm;

	graph_foreach_anode (nodes, itm, ga, a) {
		const RzGraphNode *gb;
		RzANode *b;
		RzList *neighbours = (RzList *)rz_graph_get_neighbours(g->graph, ga);
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
				rz_list_add_sorted(lyr, tm, tmplayercmp);
			}
		}

		bool many = rz_list_length(neighbours) > 2;

		if (many && !g->is_callgraph) {
			ga->out_nodes->sorted = false;
			rz_list_sort(neighbours, first_x_cmp);
		}

		graph_foreach_anode (neighbours, itn, gb, b) {
			out_nth = get_edge_number(g, a, b, true);
			in_nth = get_edge_number(g, a, b, false);

			bool parent_many = false;
			if (a->is_dummy) {
				RzANode *in = (RzANode *)(((RzGraphNode *)rz_list_first(ga->in_nodes))->data);
				while (in && in->is_dummy) {
					in = (RzANode *)(((RzGraphNode *)rz_list_first((in->gnode)->in_nodes))->data);
				}
				if (in && in->gnode) {
					parent_many = rz_list_length(in->gnode->out_nodes) > 2;
				} else {
					parent_many = false;
				}
			}

			style.dot_style = DOT_STYLE_NORMAL;
			if (many || parent_many) {
				style.color = LINE_UNCJMP;
			} else {
				switch (out_nth) {
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
					int t = RZ_EDGES_X_INC + 2 * (neighbours->length + 1);
					ax = a->is_dummy ? a->x : (a->x + a->w / 2 + (t / 2 - a_x_inc));
					bendpoint = bx < ax ? neighbours->length - out_nth : out_nth;
				} else {
					ax = a->is_dummy ? a->x : (a->x + a_x_inc);
					bendpoint = tm->edgectr;
				}

				if (!a->is_dummy && itn == neighbours->head && out_nth == 0 && bx > ax) {
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
		}
	}

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
		g->is_tiny = false;
		if (v == 0) {
			g->mode = RZ_AGRAPH_MODE_MINI;
		} else if (v < 0) {
			g->mode = RZ_AGRAPH_MODE_TINY;
			g->is_tiny = true;
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
	const RzGraphNode *cn = rz_graph_nth_neighbour(g->graph, g->curnode, nth);
	RzANode *a = get_anode(cn);

	while (a && a->is_dummy) {
		cn = rz_graph_nth_neighbour(g->graph, a->gnode, 0);
		a = get_anode(cn);
	}
	if (a) {
		rz_agraph_set_curnode(g, a);
	}
}

static void move_current_node(RzAGraph *g, int xdiff, int ydiff) {
	RzANode *n = get_anode(g->curnode);
	if (n) {
		if (is_tiny(g)) {
			xdiff = NORMALIZE_MOV(xdiff);
			ydiff = NORMALIZE_MOV(ydiff);
		}
		n->x += xdiff;
		n->y += ydiff;
	}
}

#if GRAPH_MERGE_FEATURE
#define K_NEIGHBOURS(x) (sdb_fmt("agraph.nodes.%s.neighbours", x->title))
static void agraph_merge_child(RzAGraph *g, int idx) {
	const RzGraphNode *nn = rz_graph_nth_neighbour(g->graph, g->curnode, idx);
	const RzGraphNode *cn = g->curnode;
	if (cn && nn) {
		RzANode *ann = get_anode(nn);
		RzANode *acn = get_anode(cn);
		acn->body = rz_str_append(acn->body, ann->title);
		acn->body = rz_str_append(acn->body, "\n");
		acn->body = rz_str_append(acn->body, ann->body);
		/* remove node from the graph */
		acn->h += ann->h - 3;
		free(ann->body);
		// TODO: do not merge nodes if those have edges targeting them
		// TODO: Add children neighbours to current one
		// nn->body
		// rz_agraph_set_curnode (g, get_anode (cn));
		// agraph_refresh (grd);
		// rz_agraph_add_edge (g, from, to);
		char *neis = sdb_get(g->db, K_NEIGHBOURS(ann), 0);
		if (neis) {
			sdb_set_owned(g->db, K_NEIGHBOURS(ann), neis, 0);
			rz_agraph_del_node(g, ann->title);
			agraph_print_nodes(g);
			agraph_print_edges(g);
		}
	}
	// agraph_update_seek (g, get_anode (g->curnode), false);
}
#endif

static void agraph_toggle_tiny(RzAGraph *g) {
	g->is_tiny = !g->is_tiny;
	g->need_update_dim = 1;
	agraph_refresh(rz_cons_singleton()->event_data);
	agraph_set_layout((RzAGraph *)g);
	// remove_dummy_nodes (g);
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
	RzListIter *iter;
	RzANode *an = get_anode(g->curnode);
	if (!an) {
		return;
	}
	const RzList *list = in ? an->gnode->in_nodes : an->gnode->out_nodes;
	int nth = -1;
	if (rz_list_length(list) == 0) {
		return;
	}
	rz_cons_gotoxy(0, 2);
	rz_cons_printf(in ? "Input nodes:\n" : "Output nodes:\n");
	RzList *options = rz_list_newf(NULL);
	RzList *gnodes = in ? an->gnode->in_nodes : an->gnode->out_nodes;
	RzGraphNode *gn;
	rz_list_foreach (gnodes, iter, gn) {
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
	rz_cons_flush();
	if (rz_list_length(list) == 1) {
		nth = 0;
	} else if (rz_list_length(list) < 10) {
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

static void agraph_update_title(RzCore *core, RzAGraph *g, RzAnalysisFunction *fcn) {
	RzANode *a = get_anode(g->curnode);
	char *sig = rz_core_analysis_function_signature(core, RZ_OUTPUT_MODE_STANDARD, NULL);
	char *new_title = rz_str_newf(
		"%s[0x%08" PFMT64x "]> %s # %s ",
		graphCursor ? "(cursor)" : "",
		fcn->addr, a ? a->title : "", sig);
	rz_agraph_set_title(g, new_title);
	free(new_title);
	free(sig);
}

/* look for any change in the state of the graph
 * and update what's necessary */
static bool check_changes(RzAGraph *g, int is_interactive, RzCore *core, RzAnalysisFunction *fcn) {
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
	if (fcn) {
		agraph_update_title(core, g, fcn);
	}
	if (core && core->config) {
		if (rz_config_get_i(core->config, "graph.trace")) {
			// fold all bbs not traced
			fold_asm_trace(core, g);
		}
	}
	if (g->need_update_dim || g->need_reload_nodes || !is_interactive) {
		update_node_dimension(g->graph, is_mini(g), g->zoom, g->edgemode, g->is_callgraph, g->layout);
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

static int agraph_print(RzAGraph *g, int is_interactive, RzCore *core, RzAnalysisFunction *fcn) {
	int h, w = rz_cons_get_size(&h);
	bool ret = check_changes(g, is_interactive, core, fcn);
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
	// rz_cons_canvas_clear (g->can);
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
	agraph_print_nodes(g);
	if (g->title && *g->title) {
		g->can->sy--;
	}
	/* print the graph title */
	(void)G(-g->can->sx, -g->can->sy);
	if (!g->is_tiny) {
		W(g->title);
	}
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
		if (core && core->scr_gadgets) {
			rz_core_cmd0(core, "pg");
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

static int agraph_refresh(struct agraph_refresh_data *grd) {
	if (!grd) {
		return 0;
	}
	rz_cons_singleton()->event_data = grd;
	RzCore *core = grd->core;
	RzAGraph *g = grd->g;
	RzAnalysisFunction *f = NULL;
	RzAnalysisFunction **fcn = grd->fcn;

	if (!fcn) {
		return agraph_print(g, grd->fs, core, NULL);
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

	if (grd->follow_offset) {
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

	int res = agraph_print(g, grd->fs, core, *fcn);

	if (rz_config_get_i(core->config, "scr.scrollbar")) {
		rz_core_print_scrollbar(core);
	}

	return res;
}

static void agraph_refresh_oneshot(struct agraph_refresh_data *grd) {
	rz_core_task_enqueue_oneshot(&grd->core->tasks, (RzCoreTaskOneShot)agraph_refresh, grd);
}

static void agraph_set_need_reload_nodes(struct agraph_refresh_data *grd) {
	grd->g->need_reload_nodes = true;
}

static void agraph_toggle_speed(RzAGraph *g, RzCore *core) {
	const int alt = rz_config_get_i(core->config, "graph.scroll");
	g->movspeed = g->movspeed == DEFAULT_SPEED ? alt : DEFAULT_SPEED;
}

static void free_nodes_kv(HtPPKv *kv) {
	RzANode *n = (RzANode *)kv->value;
	if (!n->is_dummy) {
		agraph_node_free(n);
	}
}

static HtPPOptions nodes_opt = {
	.cmp = (HtPPListComparator)strcmp,
	.hashfn = (HtPPHashFunction)sdb_hash,
	.dupkey = NULL,
	.dupvalue = NULL,
	.calcsizeK = (HtPPCalcSizeK)strlen,
	.calcsizeV = NULL,
	.freefn = free_nodes_kv,
	.elem_size = sizeof(HtPPKv),
};

static void agraph_init(RzAGraph *g) {
	g->is_callgraph = false;
	g->is_instep = false;
	g->need_reload_nodes = true;
	g->show_node_titles = true;
	g->show_node_body = true;
	g->force_update_seek = true;
	g->graph = rz_graph_new();
	g->nodes = ht_pp_new_opt(&nodes_opt);
	g->dummy_nodes = rz_list_newf((RzListFree)agraph_node_free);
	g->edgemode = 2;
	g->zoom = ZOOM_DEFAULT;
	g->hints = 1;
	g->movspeed = DEFAULT_SPEED;
	g->db = sdb_new0();
	rz_vector_init(&g->ghits.word_list, sizeof(struct rz_agraph_location), NULL, NULL);
}

static void graphNodeMove(RzAGraph *g, int dir, int speed) {
	int delta = (dir == 'k') ? -1 : 1;
	if (dir == 'H') {
		return;
	}
	if (dir == 'h' || dir == 'l') {
		// horizontal scroll
		if (is_mini(g)) {
			discroll = 0;
		} else {
			int delta = (dir == 'l') ? 1 : -1;
			move_current_node(g, speed * delta, 0);
		}
		return;
	}
	RzCore *core = NULL;
	// vertical scroll
	if (is_mini(g)) {
		discroll += (delta * speed);
	} else if (g->is_dis) {
		rz_core_seek_opcode(core, (delta * 4) * speed, false);
	} else {
		move_current_node(g, 0, delta * speed);
	}
}

static void sdb_set_enc(Sdb *db, const char *key, const char *v, ut32 cas) {
	char *estr = sdb_encode((const void *)v, -1);
	sdb_set(db, key, estr, cas);
	free(estr);
}

static void agraph_sdb_init(const RzAGraph *g) {
	sdb_bool_set(g->db, "agraph.is_callgraph", g->is_callgraph, 0);
	RzCons *cons = rz_cons_singleton();
	sdb_set_enc(g->db, "agraph.color_box", cons->context->pal.graph_box, 0);
	sdb_set_enc(g->db, "agraph.color_box2", cons->context->pal.graph_box2, 0);
	sdb_set_enc(g->db, "agraph.color_box3", cons->context->pal.graph_box3, 0);
	sdb_set_enc(g->db, "agraph.color_true", cons->context->pal.graph_true, 0);
	sdb_set_enc(g->db, "agraph.color_false", cons->context->pal.graph_false, 0);
}

RZ_API Sdb *rz_agraph_get_sdb(RzAGraph *g) {
	g->need_update_dim = true;
	g->need_set_layout = true;
	(void)check_changes(g, false, NULL, NULL);
	// remove_dummy_nodes (g);
	return g->db;
}

RZ_API void rz_agraph_print(RzAGraph *g) {
	agraph_print(g, false, NULL, NULL);
	if (g->graph->n_nodes > 0) {
		rz_cons_newline();
	}
}

RZ_API void rz_agraph_print_json(RzAGraph *g, PJ *pj) {
	RzList *nodes = g->graph->nodes, *neighbours = NULL;
	RzListIter *it, *itt;
	RzGraphNode *node = NULL, *neighbour = NULL;
	if (!pj) {
		return;
	}
	rz_list_foreach (nodes, it, node) {
		RzANode *anode = (RzANode *)node->data;
		char *label = strdup(anode->body);
		pj_o(pj);
		pj_ki(pj, "id", anode->gnode->idx);
		pj_ks(pj, "title", anode->title);
		pj_ks(pj, "body", label);
		pj_k(pj, "out_nodes");
		pj_a(pj);
		neighbours = anode->gnode->out_nodes;
		rz_list_foreach (neighbours, itt, neighbour) {
			pj_i(pj, neighbour->idx);
		}
		pj_end(pj);
		pj_end(pj);
		free(label);
	}
}

RZ_API void rz_agraph_set_title(RzAGraph *g, const char *title) {
	free(g->title);
	g->title = title ? strdup(title) : NULL;
	sdb_set(g->db, "agraph.title", g->title, 0);
}

RZ_API RzANode *rz_agraph_add_node_with_color(const RzAGraph *g, const char *title, const char *body, int color) {
	RzANode *res = rz_agraph_get_node(g, title);
	if (res) {
		return res;
	}
	res = RZ_NEW0(RzANode);
	if (!res) {
		return NULL;
	}

	res->title = title ? rz_str_trunc_ellipsis(title, 255) : strdup("");
	res->body = body ? strdup(body) : strdup("");
	res->layer = -1;
	res->pos_in_layer = -1;
	res->is_dummy = false;
	res->is_reversed = false;
	res->klass = -1;
	res->difftype = color;
	res->gnode = rz_graph_add_node(g->graph, res);
	if (RZ_STR_ISNOTEMPTY(res->title)) {
		ht_pp_update(g->nodes, res->title, res);
		char *s, *estr, *b;
		size_t len;
		sdb_array_add(g->db, "agraph.nodes", res->title, 0);
		b = strdup(res->body);
		len = strlen(b);
		if (len > 0 && b[len - 1] == '\n') {
			b[len - 1] = '\0';
		}
		estr = sdb_encode((const void *)b, -1);
		// s = sdb_fmt ("base64:%s", estr);
		s = rz_str_newf("base64:%s", estr);
		free(estr);
		free(b);
		sdb_set_owned(g->db, sdb_fmt("agraph.nodes.%s.body", res->title), s, 0);
	}
	return res;
}

RZ_API RzANode *rz_agraph_add_node(const RzAGraph *g, const char *title, const char *body) {
	return rz_agraph_add_node_with_color(g, title, body, -1);
}

RZ_API bool rz_agraph_del_node(const RzAGraph *g, const char *title) {
	char *title_trunc = rz_str_trunc_ellipsis(title, 255);
	RzANode *an, *res = rz_agraph_get_node(g, title_trunc);
	free(title_trunc);
	RzGraphNode *gn;
	RzListIter *it;

	if (!res) {
		return false;
	}
	sdb_array_remove(g->db, "agraph.nodes", res->title, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s", res->title), NULL, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s.body", res->title), 0, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s.x", res->title), NULL, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s.y", res->title), NULL, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s.w", res->title), NULL, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s.h", res->title), NULL, 0);
	sdb_set(g->db, sdb_fmt("agraph.nodes.%s.neighbours", res->title), NULL, 0);

	const RzList *innodes = rz_graph_innodes(g->graph, res->gnode);
	graph_foreach_anode (innodes, it, gn, an) {
		const char *key = sdb_fmt("agraph.nodes.%s.neighbours", an->title);
		sdb_array_remove(g->db, key, res->title, 0);
	}

	rz_graph_del_node(g->graph, res->gnode);
	res->gnode = NULL;

	ht_pp_delete(g->nodes, res->title);
	return true;
}

static bool user_node_cb(struct g_cb *user, const void *k UNUSED, const void *v) {
	RzANodeCallback cb = user->node_cb;
	void *user_data = user->data;
	RzANode *n = (RzANode *)v;
	if (n) {
		cb(n, user_data);
	}
	return true;
}

static bool user_edge_cb(struct g_cb *user, const void *k UNUSED, const void *v) {
	RAEdgeCallback cb = user->edge_cb;
	RzAGraph *g = user->graph;
	void *user_data = user->data;
	RzANode *an, *n = (RzANode *)v;
	if (!n) {
		return false;
	}
	const RzList *neigh = rz_graph_get_neighbours(g->graph, n->gnode);
	RzListIter *it;
	RzGraphNode *gn;

	graph_foreach_anode (neigh, it, gn, an) {
		cb(n, an, user_data);
	}
	return true;
}

RZ_API void rz_agraph_foreach(RzAGraph *g, RzANodeCallback cb, void *user) {
	struct g_cb u = {
		.node_cb = cb,
		.data = user
	};
	ht_pp_foreach(g->nodes, (HtPPForeachCallback)user_node_cb, &u);
}

RZ_API void rz_agraph_foreach_edge(RzAGraph *g, RAEdgeCallback cb, void *user) {
	struct g_cb u = {
		.graph = g,
		.edge_cb = cb,
		.data = user
	};
	ht_pp_foreach(g->nodes, (HtPPForeachCallback)user_edge_cb, &u);
}

RZ_API RzANode *rz_agraph_get_first_node(const RzAGraph *g) {
	const RzList *l = rz_graph_get_nodes(g->graph);
	RzGraphNode *rgn = rz_list_first(l);
	return get_anode(rgn);
}

RZ_API RzANode *rz_agraph_get_node(const RzAGraph *g, const char *title) {
	char *title_trunc = title ? rz_str_trunc_ellipsis(title, 255) : NULL;
	if (!title_trunc) {
		return NULL;
	}
	RzANode *node = ht_pp_find(g->nodes, title_trunc, NULL);
	free(title_trunc);
	return node;
}

RZ_API void rz_agraph_add_edge(const RzAGraph *g, RzANode *a, RzANode *b) {
	rz_return_if_fail(g && a && b);
	rz_graph_add_edge(g->graph, a->gnode, b->gnode);
	if (a->title && b->title) {
		char *k = sdb_fmt("agraph.nodes.%s.neighbours", a->title);
		sdb_array_add(g->db, k, b->title, 0);
	}
}

RZ_API void rz_agraph_add_edge_at(const RzAGraph *g, RzANode *a, RzANode *b, int nth) {
	rz_return_if_fail(g && a && b);
	if (a->title && b->title) {
		char *k = sdb_fmt("agraph.nodes.%s.neighbours", a->title);
		sdb_array_insert(g->db, k, nth, b->title, 0);
	}
	rz_graph_add_edge_at(g->graph, a->gnode, b->gnode, nth);
}

RZ_API void rz_agraph_del_edge(const RzAGraph *g, RzANode *a, RzANode *b) {
	rz_return_if_fail(g && a && b);
	if (a->title && b->title) {
		const char *k = sdb_fmt("agraph.nodes.%s.neighbours", a->title);
		sdb_array_remove(g->db, k, b->title, 0);
	}
	rz_graph_del_edge(g->graph, a->gnode, b->gnode);
}

RZ_API void rz_agraph_reset(RzAGraph *g) {
	ht_pp_free(g->nodes);
	rz_list_free(g->dummy_nodes);
	rz_graph_reset(g->graph);
	rz_agraph_set_title(g, NULL);
	sdb_reset(g->db);
	if (g->edges) {
		rz_list_purge(g->edges);
	}
	g->nodes = ht_pp_new_opt(&nodes_opt);
	g->dummy_nodes = rz_list_newf((RzListFree)agraph_node_free);
	g->update_seek_on = NULL;
	g->need_reload_nodes = false;
	g->need_set_layout = true;
	g->need_update_dim = true;
	g->x = g->y = g->w = g->h = 0;
	agraph_sdb_init(g);
	g->curnode = NULL;
}

RZ_API void rz_agraph_free(RzAGraph *g) {
	if (g) {
		ht_pp_free(g->nodes);
		rz_list_free(g->dummy_nodes);
		rz_graph_free(g->graph);
		rz_list_free(g->edges);
		rz_agraph_set_title(g, NULL);
		sdb_free(g->db);
		rz_cons_canvas_free(g->can);
		free(g);
	}
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
	rz_cons_get_size(&rows);
	rz_cons_gotoxy(0, rows);
	rz_cons_flush();
	core->cons->line->prompt_type = RZ_LINE_PROMPT_OFFSET;
	rz_line_set_hist_callback(core->cons->line, &rz_line_hist_offset_up, &rz_line_hist_offset_down);
	rz_line_set_prompt("[offset]> ");
	strcpy(buf, "s ");
	if (rz_cons_fgets(buf + 2, sizeof(buf) - 2, 0, NULL) > 0) {
		if (buf[2] == '.') {
			buf[1] = '.';
		}
		rz_core_cmd0(core, buf);
		rz_line_set_hist_callback(core->cons->line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	core->cons->line->prompt_type = RZ_LINE_PROMPT_DEFAULT;
}

static void goto_asmqjmps(RzAGraph *g, RzCore *core) {
	const char *h = "[Fast goto call/jmp]> ";
	char obuf[RZ_CORE_ASMQJMPS_LEN_LETTERS + 1];
	int rows, i = 0;
	bool cont;

	rz_cons_get_size(&rows);
	rz_cons_gotoxy(0, rows);
	rz_cons_clear_line(0);
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
static void applyDisMode(RzCore *core) {
	switch (disMode) {
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
	gh->old_word = strdup(word);
	free(s);
	if (!a && count == 0) {
		return;
	}
	nextword(core, g, word);
}

RZ_API int rz_core_visual_graph(RzCore *core, RzAGraph *g, RzAnalysisFunction *_fcn, int is_interactive) {
	if (is_interactive && !rz_cons_is_interactive()) {
		eprintf("Interactive graph mode requires scr.interactive=true.\n");
		return 0;
	}
	int o_asmqjmps_letter = core->is_asmqjmps_letter;
	int o_vmode = core->vmode;
	int exit_graph = false, is_error = false;
	int update_seek = false;
	struct agraph_refresh_data *grd;
	int okey, key;
	RzAnalysisFunction *fcn = NULL;
	const char *key_s;
	RzConsCanvas *can, *o_can = NULL;
	bool graph_allocated = false;
	int movspeed;
	int ret, invscroll;
	RzConfigHold *hc = rz_config_hold_new(core->config);
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
			eprintf("Cannot create RzCons.canvas context. Invalid screen "
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
		g->is_tiny = is_interactive == 2;
		g->layout = rz_config_get_i(core->config, "graph.layout");
		g->dummy = rz_config_get_i(core->config, "graph.dummy");
		g->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	} else {
		o_can = g->can;
	}
	g->can = can;
	g->movspeed = rz_config_get_i(core->config, "graph.scroll");
	g->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	g->show_node_body = rz_config_get_i(core->config, "graph.body");
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

	grd = RZ_NEW0(struct agraph_refresh_data);
	if (!grd) {
		rz_cons_canvas_free(can);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		rz_agraph_free(g);
		return false;
	}
	grd->g = g;
	grd->fs = is_interactive == 1;
	grd->core = core;
	grd->follow_offset = _fcn == NULL;
	grd->fcn = fcn != NULL ? &fcn : NULL;
	ret = agraph_refresh(grd);
	if (!ret || is_interactive != 1) {
		rz_cons_newline();
		exit_graph = true;
		is_error = !ret;
	}

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = grd;
	core->cons->event_resize = (RzConsEvent)agraph_refresh_oneshot;

	rz_cons_break_push(NULL, NULL);

	while (!exit_graph && !is_error && !rz_cons_is_breaked()) {
		rz_cons_get_size(&h);
		invscroll = rz_config_get_i(core->config, "graph.invscroll");
		ret = agraph_refresh(grd);

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
				switch (mousemode) {
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
			rz_line_set_prompt("cmd.gprompt> ");
			core->cons->line->contents = strdup(cmd);
			const char *buf = rz_line_readline();
			core->cons->line->contents = NULL;
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
			discroll = 0;
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
			nextword(core, g, rz_config_get(core->config, "scr.highlight"));
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
			if (fcn && rz_cons_yesno('y', "Compute function callgraph? (Y/n)")) {
				rz_core_agraph_reset(core);
				rz_core_cmd0(core, ".agc* @$FB;.axfg @$FB");
				rz_core_agraph_print_interactive(core);
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
			discroll = 0;
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
			discroll = 0;
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf("Visual Ascii Art graph keybindings:\n"
				       " :e cmd.gprompt = agft   - show tinygraph in one side\n"
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
				       " C            - toggle scr.colors\n"
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
				       " Y            - toggle tiny graph\n"
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
			discroll = 0;
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
			disMode = (disMode + 1) % 3;
			applyDisMode(core);
			g->need_reload_nodes = true;
			get_bbupdate(g, core, fcn);
			break;
		case 'u': {
			if (!fcn) {
				break;
			}
			if (!rz_core_seek_undo(core)) {
				eprintf("Cannot undo\n");
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
				eprintf("Cannot redo\n");
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
				rz_core_theme_nextpal(core, 'n');
			}
			if (!fcn) {
				break;
			}
			g->edgemode = rz_config_get_i(core->config, "graph.edges");
			get_bbupdate(g, core, fcn);
			break;
		case '!':
			rz_core_visual_panels_root(core, core->panels_root);
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
				rz_line_set_prompt("[comment]> ");
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
			mousemode++;
			if (!mousemodes[mousemode]) {
				mousemode = 0;
			}
			break;
		case 'M':
			mousemode--;
			if (mousemode < 0) {
				mousemode = 3;
			}
			break;
		case '(':
			if (fcn) {
				rz_core_cmd0(core, "wao recj@B:-1");
				g->need_reload_nodes = true;
			}
			break;
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
		case 'Y':
			agraph_toggle_tiny(g);
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'z':
			agraph_toggle_mini(g);
			discroll = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'v':
			rz_core_visual_analysis(core, NULL);
			break;
		case 'J':
			// copypaste from 'j'
			if (graphCursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'j', speed * 2);
			} else {
				can->sy -= (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'K':
			if (graphCursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'k', speed * 2);
			} else {
				can->sy += (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'H':
			if (graphCursor) {
				// move node canvas faster
				graphNodeMove(g, 'h', movspeed * 2);
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
			if (graphCursor) {
				graphNodeMove(g, 'l', movspeed * 2);
			} else {
				can->sx -= (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'c':
			graphCursor = !graphCursor;
			break;
		case 'j':
			if (g->is_dis) {
				rz_core_seek_opcode(core, 1, false);
			} else {
				if (graphCursor) {
					int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
					graphNodeMove(g, 'j', speed);
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
				if (graphCursor) {
					int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
					graphNodeMove(g, 'k', speed);
				} else {
					// scroll canvas
					can->sy += movspeed * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'l':
			if (graphCursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'l', speed);
			} else {
				can->sx -= movspeed * (invscroll ? -1 : 1);
			}
			break;
		case 'h':
			if (graphCursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'h', speed);
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
			discroll = 0;
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
			rz_core_cmd0(core, "?i highlight;e scr.highlight=`yp`");
			showcursor(core, false);
			break;
		case ':':
			core->cons->event_resize = (RzConsEvent)agraph_set_need_reload_nodes;
			rz_core_visual_prompt_input(core);
			core->cons->event_resize = (RzConsEvent)agraph_refresh_oneshot;
			if (!g) {
				g->need_reload_nodes = true; // maybe too slow and unnecessary sometimes? better be safe and reload
				get_bbupdate(g, core, fcn);
			}
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

	free(grd);
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
 * @brief Create RzAGraph from generic RzGraph with RzGraphNodeInfo as node data
 *
 * @param graph <RzGraphNodeInfo>
 * @return RzAGraph* NULL if failure
 */
RZ_API RzAGraph *create_agraph_from_graph(const RzGraph /*<RzGraphNodeInfo>*/ *graph) {
	rz_return_val_if_fail(graph, NULL);

	RzAGraph *result_agraph = rz_agraph_new(rz_cons_canvas_new(1, 1));
	if (!result_agraph) {
		return NULL;
	}
	result_agraph->need_reload_nodes = false;
	// Cache lookup to build edges
	HtPPOptions pointer_options = { 0 };
	HtPP /*<RzGraphNode *node, RzANode *anode>*/ *hashmap = ht_pp_new_opt(&pointer_options);

	if (!hashmap) {
		rz_agraph_free(result_agraph);
		return NULL;
	}
	// List of the new RzANodes
	RzListIter *iter;
	RzGraphNode *node;
	// Traverse the list, create new ANode for each Node
	rz_list_foreach (graph->nodes, iter, node) {
		RzGraphNodeInfo *info = node->data;
		RzANode *a_node = rz_agraph_add_node(result_agraph, info->title, info->body);
		if (!a_node) {
			goto failure;
		}
		ht_pp_insert(hashmap, node, a_node);
	}

	// Traverse the nodes again, now build up the edges
	rz_list_foreach (graph->nodes, iter, node) {
		RzANode *a_node = ht_pp_find(hashmap, node, NULL);
		if (!a_node) {
			goto failure; // shouldn't happen in correct graph state
		}

		RzListIter *neighbour_iter;
		RzGraphNode *neighbour;
		rz_list_foreach (node->in_nodes, neighbour_iter, neighbour) {
			RzANode *a_neighbour = ht_pp_find(hashmap, neighbour, NULL);
			if (!a_neighbour) {
				goto failure;
			}
			rz_agraph_add_edge(result_agraph, a_neighbour, a_node);
		}
	}

	ht_pp_free(hashmap);
	return result_agraph;
failure:
	ht_pp_free(hashmap);
	rz_agraph_free(result_agraph);
	return NULL;
}
