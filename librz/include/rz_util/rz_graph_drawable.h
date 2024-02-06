#ifndef RZ_GRAPH_DRAWABLE_H
#define RZ_GRAPH_DRAWABLE_H

#include <rz_types.h>
#include <rz_util/rz_graph.h>
#include <rz_config.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_GRAPH_NODE_TYPE_GROUP_MASK 0xff000000

typedef enum {
	RZ_GRAPH_NODE_TYPE_NONE = 0, ///< No type for this node specified.
	RZ_GRAPH_NODE_TYPE_DEFAULT = 0x80000000, ///< Node contains a title string, a body string and an absract offset value.
	RZ_GRAPH_NODE_TYPE_CFG = 0x40000000, ///< Node is part of an control flow graph of a procedure.
	RZ_GRAPH_NODE_TYPE_CFG_NONE = RZ_GRAPH_NODE_TYPE_CFG | 0, ///< No details given to this CFG node.
	RZ_GRAPH_NODE_TYPE_CFG_ENTRY = RZ_GRAPH_NODE_TYPE_CFG | 1, ///< Entry node of the procedure CFG.
	RZ_GRAPH_NODE_TYPE_CFG_CALL = RZ_GRAPH_NODE_TYPE_CFG | 2, ///> A node which calls another procedure.
	RZ_GRAPH_NODE_TYPE_CFG_RETURN = RZ_GRAPH_NODE_TYPE_CFG | 3, ///< A return node of the procedure.
	RZ_GRAPH_NODE_TYPE_CFG_EXIT = RZ_GRAPH_NODE_TYPE_CFG | 4, ///< A node which exits the program (precedure does not return).
	RZ_GRAPH_NODE_TYPE_ICFG = 0x20000000, ///< Node is part of an inter-procedural control flow graph.
	RZ_GRAPH_NODE_TYPE_ICFG_NONE = RZ_GRAPH_NODE_TYPE_ICFG | 0, ///< No details given to this iCFG node.
	RZ_GRAPH_NODE_TYPE_ICFG_MALLOC = RZ_GRAPH_NODE_TYPE_ICFG | 1, ///< Node represents a memory allocating procedure.
} RzGraphNodeType;

typedef struct {
	char *title;
	char *body;
	/**
	 * \brief Optional offset for the object corresponding to node.
	 *
	 * Interactive output modes can use it to provide actions like seeking to
	 * this position or modify the object.
	 */
	ut64 offset;
} RzGraphNodeInfoDataDefault;

typedef struct {
	/**
	 * \brief Address of the node.
	 */
	ut64 address;
	/**
	 * \brief Address of called procedure, if node is of type RZ_GRAPH_NODE_TYPE_CFG_CALL.
	 * It is set to UT64_MAX if invalid.
	 */
	ut64 call_address;
} RzGraphNodeInfoDataCFG;

typedef struct {
	/**
	 * \brief Address of the node.
	 */
	ut64 address;
} RzGraphNodeInfoDataICFG;

/**
 * \brief Generic drawable graph node.
 *
 * Provides minimal information to draw something without output format specific details.
 */
typedef struct rz_analysis_graph_node_info_t {
	/**
	 * \brief Optional flags which describe the node further.
	 */
	RzGraphNodeType type;
	union {
		RzGraphNodeInfoDataDefault def;
		RzGraphNodeInfoDataCFG cfg;
		RzGraphNodeInfoDataICFG icfg;
	};
} RzGraphNodeInfo;

RZ_API RZ_OWN RzStrBuf *rz_graph_get_node_info_str(RzGraphNodeInfo info);
RZ_API void rz_graph_free_node_info(void *ptr);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_default(const char *title, const char *body, ut64 offset);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_icfg(ut64 address, RzGraphNodeType flags);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_cfg(ut64 address, ut64 call_target_addr, RzGraphNodeType flags);
RZ_API RzGraphNode *rz_graph_add_node_info(RzGraph /*<RzGraphNodeInfo *>*/ *graph, const char *title, const char *body, ut64 offset);

/**
 * @brief Convert graph to Graphviz dot format.
 *
 * @param graph Graph with RzGraphNodeInfo used as node user data
 * @param node_properties List node styling attributes. Can be set to NULL.
 * @param edge_properties List edge styling attributes. Can be set to NULL.
 */
RZ_API RZ_OWN char *rz_graph_drawable_to_dot(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RZ_NULLABLE const char *node_properties, RZ_NULLABLE const char *edge_properties);
/**
 * @brief Convert graph to JSON.
 *
 * @param[in] graph Graph to convert
 * @param[out] pj Json output structure. Can be used to include the resulting JSON value inside bigger JSON.
 * @param[in] use_offset Set this to true if graph uses \ref RzGraphNodeInfo::offset offset field.
 */
RZ_API void rz_graph_drawable_to_json(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RZ_NONNULL PJ *pj, bool use_offset);
RZ_API RZ_OWN char *rz_graph_drawable_to_json_str(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, bool use_offset);
RZ_API RZ_OWN char *rz_graph_drawable_to_cmd(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph);
RZ_API RZ_OWN char *rz_graph_drawable_to_gml(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph);

#ifdef __cplusplus
}
#endif
#endif
