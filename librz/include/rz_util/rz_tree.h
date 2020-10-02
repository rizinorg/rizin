#ifndef RZ_TREE_H
#define RZ_TREE_H
#include <rz_list.h>
#include <rz_util/rz_queue.h>

struct rz_tree_t;

typedef struct rz_tree_node_t {
	struct rz_tree_node_t *parent;
	struct rz_tree_t *tree;
	RzList *children; // <RTreeNode>
	unsigned int n_children;
	int depth;
	RzListFree free;
	void *data;
} RTreeNode;

typedef struct rz_tree_t {
	RTreeNode *root;
} RTree;

typedef struct rz_tree_visitor_t {
	void (*pre_visit)(RTreeNode *, struct rz_tree_visitor_t *);
	void (*post_visit)(RTreeNode *, struct rz_tree_visitor_t *);
	void (*discover_child)(RTreeNode *, struct rz_tree_visitor_t *);
	void *data;
} RTreeVisitor;
typedef void (*RTreeNodeVisitCb)(RTreeNode *n, RTreeVisitor *vis);

RZ_API RTree *rz_tree_new(void);
RZ_API RTreeNode *rz_tree_add_node(RTree *t, RTreeNode *node, void *child_data);
RZ_API void rz_tree_reset(RTree *t);
RZ_API void rz_tree_free(RTree *t);
RZ_API void rz_tree_dfs(RTree *t, RTreeVisitor *vis);
RZ_API void rz_tree_bfs(RTree *t, RTreeVisitor *vis);
#endif //  RZ_TREE_H
