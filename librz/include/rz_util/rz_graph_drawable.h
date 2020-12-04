#ifndef RZ_GRAPH_DRAWABLE_H
#define RZ_GRAPH_DRAWABLE_H

#include <rz_types.h>
#include <rz_util/rz_graph.h>
#include <rz_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generic drawable graph node.
 *
 * Provides minimal information to draw something without output format specific details.
 */
typedef struct rz_analysis_graph_node_info_t {
	char *title;
	char *body;
	/**
	 * @brief Optional offset for the object corresponding to node.
	 *
	 * Interactive output modes can use it to provide actions like seeking to
	 * this position or modify the object.
	 */
	ut64 offset;
} RzGraphNodeInfo;

RZ_API void rz_graph_free_node_info(void *ptr);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info(const char *title, const char *body, ut64 offset);
RZ_API RzGraphNode *rz_graph_add_node_info(RzGraph *graph, const char *title, const char *body, ut64 offset);

/**
 * @brief Convert graph to Graphviz dot format.
 *
 * @param graph Graph with RzGraphNodeInfo used as node user data
 * @param node_properties List node styling attributes. Can be set to NULL.
 * @param edge_properties List edge styling attributes. Can be set to NULL.
 */
RZ_API char *rz_graph_drawable_to_dot(RzGraph /*RzGraphNodeInfo*/ *graph, const char *node_properties, const char *edge_properties);
/**
 * @brief Convert graph to JSON.
 *
 * @param[in] graph Graph to convert
 * @param[out] pj Json output structure. Can be used to include the resulting JSON value inside bigger JSON.
 * @param[in] use_offset Set this to true if graph uses \ref RzGraphNodeInfo::offset offset field.
 */
RZ_API void rz_graph_drawable_to_json(RzGraph /*RzGraphNodeInfo*/ *graph, PJ *pj, bool use_offset);

#ifdef __cplusplus
}
#endif
#endif
