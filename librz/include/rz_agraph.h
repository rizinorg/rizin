#ifndef RZ_AGRAPH_H
#define RZ_AGRAPH_H

#include <rz_types.h>
#include <rz_cons.h>
#include <rz_util/rz_graph.h>
#include <rz_util/rz_graph_drawable.h>

typedef struct rz_ascii_node_t {
	RzGraphNode *gnode;
	char *title;
	char *body;

	int x;
	int y;
	int w;
	int h;

	int layer;
	int layer_height;
	int layer_width;
	int pos_in_layer;
	int is_dummy;
	int is_reversed;
	int klass;
	ut32 shortcut_w;
	bool is_mini;
	ut64 offset;
} RzANode;

typedef struct rz_core_graph_hits_t {
	char *old_word;
	RzVector /*<struct struct rz_agraph_location>*/ word_list;
	int word_nth;
} RzAGraphHits;

#define RZ_AGRAPH_MODE_NORMAL   0
#define RZ_AGRAPH_MODE_OFFSET   1
#define RZ_AGRAPH_MODE_MINI     2
#define RZ_AGRAPH_MODE_SUMMARY  3
#define RZ_AGRAPH_MODE_COMMENTS 4
#define RZ_AGRAPH_MODE_MAX      5

typedef void (*RzANodeCallback)(RzANode *n, void *user);
typedef void (*RAEdgeCallback)(RzANode *from, RzANode *to, void *user);

typedef struct rz_ascii_graph_t {
	RzConsCanvas *can;
	RzGraph /*<RzANode *>*/ *graph;
	const RzGraphNode *curnode;
	char *title;
	Sdb *db;
	HtSP *nodes; // HT with title(key)=RzANode*(value)
	RzList /*<RzANode *>*/ *dummy_nodes;

	int layout;
	int is_instep;
	bool is_dis;
	int edgemode;
	int mode;
	bool is_callgraph;
	bool is_il;
	bool is_interactive;
	int zoom;
	int movspeed;
	bool hints;

	RzANode *update_seek_on;
	bool need_reload_nodes;
	bool need_set_layout;
	int need_update_dim;
	int force_update_seek;

	/* events */
	RzANodeCallback on_curnode_change;
	void *on_curnode_change_data;
	bool dummy; // enable the dummy nodes for better layouting
	bool show_node_titles;
	bool show_node_body;

	int x, y;
	int w, h;

	/* layout algorithm info */
	RzList /*<RzGraphEdge *>*/ *back_edges;
	RzList /*<RzGraphEdge *>*/ *long_edges;
	struct layer_t *layers;
	unsigned int n_layers;
	RzList /*<struct dist_t *>*/ *dists;
	RzList /*<AEdge *>*/ *edges;
	RzAGraphHits ghits;
} RzAGraph;

#ifdef RZ_API
RZ_API RzAGraph *rz_agraph_new(RzConsCanvas *can);
RZ_API void rz_agraph_free(RzAGraph *g);
RZ_API void rz_agraph_reset(RzAGraph *g);
RZ_API void rz_agraph_set_title(RzAGraph *g, const char *title);
RZ_API RzANode *rz_agraph_get_first_node(const RzAGraph *g);
RZ_API RzANode *rz_agraph_get_node(const RzAGraph *g, const char *title);
RZ_API RzANode *rz_agraph_add_node(const RzAGraph *g, const char *title, const char *body);
RZ_API RZ_BORROW RzANode *rz_agraph_add_node_from_node_info(RZ_NONNULL const RzAGraph *g, RZ_NONNULL const RzGraphNodeInfo *info, bool utf8);
RZ_API bool rz_agraph_del_node(const RzAGraph *g, const char *title);
RZ_API void rz_agraph_add_edge(const RzAGraph *g, RzANode *a, RzANode *b);
RZ_API void rz_agraph_add_edge_at(const RzAGraph *g, RzANode *a, RzANode *b, int nth);
RZ_API void rz_agraph_del_edge(const RzAGraph *g, RzANode *a, RzANode *b);
RZ_API void rz_agraph_print(RzAGraph *g);
RZ_API void rz_agraph_print_json(RzAGraph *g, PJ *pj);
RZ_API Sdb *rz_agraph_get_sdb(RzAGraph *g);
RZ_API void rz_agraph_foreach(RzAGraph *g, RzANodeCallback cb, void *user);
RZ_API void rz_agraph_foreach_edge(RzAGraph *g, RAEdgeCallback cb, void *user);
RZ_API void rz_agraph_set_curnode(RzAGraph *g, RzANode *node);
RZ_API bool create_agraph_from_graph_at(RZ_NONNULL RzAGraph *ag, RZ_NONNULL const RzGraph /*<RzGraphNodeInfo *>*/ *g, bool free_on_fail, bool utf8);
RZ_API RZ_OWN RzAGraph *create_agraph_from_graph(RZ_NONNULL const RzGraph /*<RzGraphNodeInfo *>*/ *graph, bool utf8);
#endif

#endif
