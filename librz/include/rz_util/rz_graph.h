#ifndef RZ_GRAPH_H
#define RZ_GRAPH_H

#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_graph_node_t {
	unsigned int idx;
	void *data;
	RzList *out_nodes;
	RzList *in_nodes;
	RzList *all_neighbours;
	RzListFree free;
} RzGraphNode;

typedef struct rz_graph_edge_t {
	RzGraphNode *from;
	RzGraphNode *to;
	int nth;
} RzGraphEdge;

typedef struct rz_graph_t {
	unsigned int n_nodes;
	unsigned int n_edges;
	int last_index;
	RzList *nodes; /* RzGraphNode */
} RzGraph;

typedef struct rz_graph_visitor_t {
	void (*discover_node)(RzGraphNode *n, struct rz_graph_visitor_t *vis);
	void (*finish_node)(RzGraphNode *n, struct rz_graph_visitor_t *vis);
	void (*tree_edge)(const RzGraphEdge *e, struct rz_graph_visitor_t *vis);
	void (*back_edge)(const RzGraphEdge *e, struct rz_graph_visitor_t *vis);
	void (*fcross_edge)(const RzGraphEdge *e, struct rz_graph_visitor_t *vis);
	void *data;
} RzGraphVisitor;
typedef void (*RzGraphNodeCallback)(RzGraphNode *n, RzGraphVisitor *vis);
typedef void (*RzGraphEdgeCallback)(const RzGraphEdge *e, RzGraphVisitor *vis);

// Contrructs a new RzGraph, returns heap-allocated graph.
RZ_API RzGraph *rz_graph_new(void);
// Destroys the graph and all nodes.
RZ_API void rz_graph_free(RzGraph *g);
// Gets the data of a node by index.
RZ_API RzGraphNode *rz_graph_get_node(const RzGraph *g, unsigned int idx);
RZ_API RzListIter *rz_graph_node_iter(const RzGraph *g, unsigned int idx);
RZ_API void rz_graph_reset(RzGraph *g);
RZ_API RzGraphNode *rz_graph_add_node(RzGraph *g, void *data);
RZ_API RzGraphNode *rz_graph_add_nodef(RzGraph *g, void *data, RzListFree user_free);
// XXX 'n' is destroyed after calling this function.
RZ_API void rz_graph_del_node(RzGraph *g, RzGraphNode *n);
RZ_API void rz_graph_add_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to);
RZ_API void rz_graph_add_edge_at(RzGraph *g, RzGraphNode *from, RzGraphNode *to, int nth);
RZ_API RzGraphNode *rz_graph_node_split_forward(RzGraph *g, RzGraphNode *split_me, void *data);
RZ_API void rz_graph_del_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to);
RZ_API const RzList *rz_graph_get_neighbours(const RzGraph *g, const RzGraphNode *n);
RZ_API RzGraphNode *rz_graph_nth_neighbour(const RzGraph *g, const RzGraphNode *n, int nth);
RZ_API const RzList *rz_graph_innodes(const RzGraph *g, const RzGraphNode *n);
RZ_API const RzList *rz_graph_all_neighbours(const RzGraph *g, const RzGraphNode *n);
RZ_API const RzList *rz_graph_get_nodes(const RzGraph *g);
RZ_API bool rz_graph_adjacent(const RzGraph *g, const RzGraphNode *from, const RzGraphNode *to);
RZ_API void rz_graph_dfs_node(RzGraph *g, RzGraphNode *n, RzGraphVisitor *vis);
RZ_API void rz_graph_dfs_node_reverse(RzGraph *g, RzGraphNode *n, RzGraphVisitor *vis);
RZ_API void rz_graph_dfs(RzGraph *g, RzGraphVisitor *vis);

#ifdef __cplusplus
}
#endif

#endif //  RZ_GRAPH_H
