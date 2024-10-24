#ifndef RZ_GRAPH_DRAWABLE_H
#define RZ_GRAPH_DRAWABLE_H

#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_util/rz_graph.h>
#include <rz_config.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_GRAPH_NODE_TYPE_GROUP_MASK 0xff000000

typedef enum {
	RZ_GRAPH_NODE_TYPE_NONE = 0, ///< No type for this node specified.
	RZ_GRAPH_NODE_TYPE_DEFAULT, ///< Node contains a title string, a body string and an absract offset value.
	RZ_GRAPH_NODE_TYPE_CFG, ///< Node is part of an control flow graph of a procedure.
	RZ_GRAPH_NODE_TYPE_CFG_IWORD, ///< Node is part of an control flow graph of instruction words.
	RZ_GRAPH_NODE_TYPE_ICFG, ///< Node is part of an inter-procedural control flow graph.
} RzGraphNodeType;

typedef enum {
	RZ_GRAPH_NODE_SUBTYPE_ICFG_NONE = 0, ///< No details given to this node.
	RZ_GRAPH_NODE_SUBTYPE_ICFG_MALLOC = 1 << 5, ///< Node represents a memory allocating procedure.
} RzGraphNodeiCFGSubType;

typedef enum {
	RZ_GRAPH_NODE_SUBTYPE_CFG_NONE = 0, ///< No details given to this node.
	RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY = 1 << 0, ///< Entry node of the procedure CFG.
	RZ_GRAPH_NODE_SUBTYPE_CFG_CALL = 1 << 1, ///> A node which calls another procedure.
	RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN = 1 << 2, ///< A return node of the procedure.
	RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT = 1 << 3, ///< A node which exits the program (precedure does not return).
	RZ_GRAPH_NODE_SUBTYPE_CFG_COND = 1 << 4, ///< A conditional instruction node.
	RZ_GRAPH_NODE_SUBTYPE_CFG_JUMP = 1 << 5, ///> A node which jumps to another node.
	RZ_GRAPH_NODE_SUBTYPE_CFG_TAIL = 1 << 6, ///> A tail call node.
	RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_CALL = RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY | RZ_GRAPH_NODE_SUBTYPE_CFG_CALL,
	RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_RETURN = RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY | RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN,
	RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_EXIT = RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY | RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT,
} RzGraphNodeCFGSubType;

/**
 * \brief Flags which describes instruction word nodes in a CFG.
 * Note: These flags are *not* a replacement for the flags assigned to each single instruction within the node.
 * But they are kept in sync with RzGraphNodeCFGSubType, so they can use the same parser.
 */
typedef enum {
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_NONE = 0, ///< No details given to this node.
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_ENTRY = 1 << 0, ///< Entry node of the procedure CFG with iwords
	// Call = 1 << 1
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_RETURN = 1 << 2, ///< A return node of the procedure.
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_EXIT = 1 << 3, ///< Node exits the program.
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_COND = 1 << 4, ///< A conditional instruction word.
	// Jump = 1 << 1
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_TAIL = 1 << 6, ///< A tail call node.
	RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_ENTRY_RETURN = RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY | RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN,
} RzGraphNodeCFGIWordSubType;

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

/**
 * \brief Info struct for a CFG node with single instructions.
 */
typedef struct {
	ut64 address; ///< Address of the node.
	ut64 call_address; ///< Address of called procedure, if node is of type RZ_GRAPH_NODE_TYPE_CFG_CALL. It is set to UT64_MAX if invalid.
	ut64 jump_address; ///< Address this instr. jumps to. It is set to UT64_MAX if invalid.
	ut64 next; ///< Address of following instruction. It is set to UT64_MAX if it is a return instruction.
	RzGraphNodeCFGSubType subtype; ///< Optional flags which describe the node further.
} RzGraphNodeInfoDataCFG;

/**
 * \brief A node of a CFG with instruction words.
 * Each instruction word can consist of multiiple instructions.
 * So an instruction word node is an unification of all its member instructions.
 */
typedef struct {
	ut64 address; ///< Address of the instruction word.
	RzPVector /* RzGraphNodeInfoDataCFG * */ *insn; ///< Single instruction node.
	RzGraphNodeCFGIWordSubType subtype; ///< Optional flags which describe the node further.
} RzGraphNodeInfoDataCFGIWord;

typedef struct {
	ut64 address; ///< Address of the node.
	bool is_malloc; ///< Flag set if this node is a memory allocating function.
	RzGraphNodeiCFGSubType subtype; ///< Optional flags which describe the node further.
} RzGraphNodeInfoDataICFG;

/**
 * \brief Generic drawable graph node.
 *
 * Provides minimal information to draw something without output format specific details.
 */
typedef struct rz_analysis_graph_node_info_t {
	RzGraphNodeType type; ///< Node type. Determines which node info is set below.
	union {
		RzGraphNodeInfoDataDefault def;
		RzGraphNodeInfoDataCFG cfg;
		RzGraphNodeInfoDataCFGIWord cfg_iword;
		RzGraphNodeInfoDataICFG icfg;
	};
} RzGraphNodeInfo;

RZ_API RZ_OWN char *rz_graph_get_node_subtype_annotation_cfg(RzGraphNodeCFGSubType subtype, bool letter_abbr, bool utf8);
RZ_API RZ_OWN char *rz_graph_get_node_subtype_annotation_cfg_iword(RzGraphNodeCFGIWordSubType subtype, bool letter_abbr, bool utf8);
RZ_API RZ_OWN RzGraphNodeInfo *rz_graph_get_node_info_data(RZ_BORROW void *data);
RZ_API void rz_graph_free_node_info(RZ_NULLABLE void *ptr);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_default(const char *title, const char *body, ut64 offset);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_icfg(ut64 address, RzGraphNodeiCFGSubType subtype);
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_cfg(ut64 address, ut64 call_target_addr, ut64 jump_target_addr, ut64 next, RzGraphNodeCFGSubType subtype);
RZ_API RzGraphNode *rz_graph_add_node_info(RzGraph /*<RzGraphNodeInfo *>*/ *graph, const char *title, const char *body, ut64 offset);
RZ_API void rz_graph_node_info_data_cfg_iword_init(RZ_BORROW RzGraphNodeInfoDataCFGIWord *info);
RZ_API void rz_graph_node_info_data_cfg_iword_fini(RZ_NULLABLE RZ_OWN RzGraphNodeInfoDataCFGIWord *node_info);

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
