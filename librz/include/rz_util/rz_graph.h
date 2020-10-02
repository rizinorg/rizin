#ifndef RZ_GRAPH_H
#define RZ_GRAPH_H

#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generic graph node info
 */
typedef struct rz_anal_graph_node_info_t {
	char *title;
	char *body;
	ut64 offset;
} RGraphNodeInfo;

typedef struct rz_graph_node_t {
	unsigned int idx;
	void *data;
	RzList *out_nodes;
	RzList *in_nodes;
	RzList *all_neighbours;
	RzListFree free;
} RGraphNode;

typedef struct rz_graph_edge_t {
	RGraphNode *from;
	RGraphNode *to;
	int nth;
} RGraphEdge;

typedef struct rz_graph_t {
	unsigned int n_nodes;
	unsigned int n_edges;
	int last_index;
	RzList *nodes; /* RGraphNode */
} RGraph;

typedef struct rz_graph_visitor_t {
	void (*discover_node)(RGraphNode *n, struct rz_graph_visitor_t *vis);
	void (*finish_node)(RGraphNode *n, struct rz_graph_visitor_t *vis);
	void (*tree_edge)(const RGraphEdge *e, struct rz_graph_visitor_t *vis);
	void (*back_edge)(const RGraphEdge *e, struct rz_graph_visitor_t *vis);
	void (*fcross_edge)(const RGraphEdge *e, struct rz_graph_visitor_t *vis);
	void *data;
} RGraphVisitor;
typedef void (*RGraphNodeCallback)(RGraphNode *n, RGraphVisitor *vis);
typedef void (*RGraphEdgeCallback)(const RGraphEdge *e, RGraphVisitor *vis);

// Contrructs a new RGraph, returns heap-allocated graph.
RZ_API RGraph *rz_graph_new(void);
// Destroys the graph and all nodes.
RZ_API void rz_graph_free(RGraph* g);
// Gets the data of a node by index.
RZ_API RGraphNode *rz_graph_get_node(const RGraph *g, unsigned int idx);
RZ_API RzListIter *rz_graph_node_iter(const RGraph *g, unsigned int idx);
RZ_API void rz_graph_reset(RGraph *g);
RZ_API RGraphNode *rz_graph_add_node(RGraph *g, void *data);
// XXX 'n' is destroyed after calling this function.
RZ_API void rz_graph_del_node(RGraph *g, RGraphNode *n);
RZ_API void rz_graph_add_edge(RGraph *g, RGraphNode *from, RGraphNode *to);
RZ_API void rz_graph_add_edge_at(RGraph *g, RGraphNode *from, RGraphNode *to, int nth);
RZ_API RGraphNode *rz_graph_node_split_forward(RGraph *g, RGraphNode *split_me, void *data);
RZ_API void rz_graph_del_edge(RGraph *g, RGraphNode *from, RGraphNode *to);
RZ_API const RzList *rz_graph_get_neighbours(const RGraph *g, const RGraphNode *n);
RZ_API RGraphNode *rz_graph_nth_neighbour(const RGraph *g, const RGraphNode *n, int nth);
RZ_API const RzList *rz_graph_innodes(const RGraph *g, const RGraphNode *n);
RZ_API const RzList *rz_graph_all_neighbours(const RGraph *g, const RGraphNode *n);
RZ_API const RzList *rz_graph_get_nodes(const RGraph *g);
RZ_API bool rz_graph_adjacent(const RGraph *g, const RGraphNode *from, const RGraphNode *to);
RZ_API void rz_graph_dfs_node(RGraph *g, RGraphNode *n, RGraphVisitor *vis);
RZ_API void rz_graph_dfs_node_reverse(RGraph *g, RGraphNode *n, RGraphVisitor *vis);
RZ_API void rz_graph_dfs(RGraph *g, RGraphVisitor *vis);
RZ_API void rz_graph_free_node_info(void *ptr);
RZ_API RGraphNodeInfo *rz_graph_create_node_info(char *title, char *body, ut64 offset);

#ifdef __cplusplus
}
#endif

#endif //  RZ_GRAPH_H
