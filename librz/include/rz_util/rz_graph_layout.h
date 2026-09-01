// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file rz_graph_layout.h
 * \brief Generic, UI-agnostic graph layout for RzGraph.
 *
 * This is the data/geometry half of the old agraph.c layout pass, lifted out
 * of librz/core per rizinorg/rizin#992 so it lives in RzUtil and carries no
 * dependency on RzCore, RzCons or the analysis layer.
 *
 * The layout computes, for an already-built RzGraph, a layered (Sugiyama-style)
 * placement: it assigns each node a layer and an (x, y) position given the
 * node's box dimensions. It never reads node text, never touches a console
 * canvas, and never decides how a node is drawn. The caller is responsible for
 * supplying the per-node width/height (which in agraph's case come from the
 * rendered body text) and for drawing the result.
 *
 * Cancellation (historically rz_cons_is_breaked()) is injected through the
 * \ref RzGraphLayoutConfig.is_cancelled callback, keeping this module free of
 * any console dependency.
 */

#ifndef RZ_GRAPH_LAYOUT_H
#define RZ_GRAPH_LAYOUT_H

#include <rz_util/rz_graph.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Which layout algorithm to run.
 */
typedef enum {
	RZ_GRAPH_LAYOUT_LAYERED = 0, ///< Sugiyama-style layered layout (the agraph default).
} RzGraphLayoutType;

/**
 * \brief Per-node geometry for the layout pass.
 *
 * The array is indexed by the node's stable vec id
 * (\ref rz_graph_node_get_vec_id), so the layout never needs to know about
 * the caller's node payload type (e.g. RzANode).
 *
 * \p w and \p h are inputs (the box dimensions the caller wants laid out).
 * The remaining fields are outputs written by \ref rz_graph_layout.
 */
typedef struct rz_graph_layout_node_t {
	int w; ///< IN: node box width.
	int h; ///< IN: node box height.
	int x; ///< OUT: assigned x position.
	int y; ///< OUT: assigned y position.
	int layer; ///< OUT: assigned layer index.
	int pos_in_layer; ///< OUT: position within the layer.
	bool is_dummy; ///< OUT: true for synthetic edge-routing nodes.
} RzGraphLayoutNode;

/**
 * \brief Cancellation callback. Return true to abort the (potentially slow)
 * crossing-minimization loop. \p user is \ref RzGraphLayoutConfig.user.
 */
typedef bool (*RzGraphLayoutCancel)(void *user);

/**
 * \brief Inputs controlling a layout run.
 */
typedef struct rz_graph_layout_config_t {
	RzGraphLayoutType type; ///< Algorithm selector.
	bool use_dummy_nodes; ///< Insert dummy nodes on long edges for smoother routing.
	int horizontal_spacing; ///< Minimum horizontal gap between nodes.
	int vertical_spacing; ///< Minimum vertical gap between layers.
	RZ_NULLABLE RzGraphLayoutCancel is_cancelled; ///< Optional abort check; NULL never cancels.
	void *user; ///< Opaque pointer passed to \ref is_cancelled.
} RzGraphLayoutConfig;

#ifdef __cplusplus
}
#endif

#endif /* RZ_GRAPH_LAYOUT_H */
