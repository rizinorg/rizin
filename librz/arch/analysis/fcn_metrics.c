// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

/**
 * \brief Returns the amount of loops located in the \p fcn function
 */
RZ_API ut32 rz_analysis_function_loops(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	ut32 loops = 0;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops++;
		}
	}
	return loops;
}

/**
 * \brief Returns cyclomatic complexity of the function
 *
 * It calculated using this formula:
 *
 * CC = E - N + 2P
 * where
 * E is the number of edges of the graph.
 * N is the number of nodes of the graph.
 * P is the number of connected components (exit nodes).
 *
 */
RZ_API ut32 rz_analysis_function_complexity(RzAnalysisFunction *fcn) {
	RzAnalysis *analysis = fcn->analysis;
	ut32 E = 0, N = 0, P = 0;
	RzAnalysisBlock *bb;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		N++; // nodes
		if (!analysis && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			RZ_LOG_DEBUG("invalid bb jump/fail pair at 0x%08" PFMT64x " (fcn 0x%08" PFMT64x "\n", bb->addr, fcn->addr);
		}
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			P++; // exit nodes
		} else {
			E++; // edges
			if (bb->fail != UT64_MAX) {
				E++;
			}
		}
		if (bb->switch_op && bb->switch_op->cases) {
			E += rz_list_length(bb->switch_op->cases);
		}
	}

	return E - N + (2 * P);
}

// compute the cyclomatic cost
RZ_API ut32 rz_analysis_function_cost(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzAnalysisOp op = { 0 };
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RzAnalysis *analysis = fcn->analysis;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op_init(&op);
			(void)rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_BASIC);
			if (op.size < 1) {
				op.size = 1;
			}
			idx += op.size;
			at += op.size;
			totalCycles += op.cycles;
			rz_analysis_op_fini(&op);
		}
		free(buf);
	}
	return totalCycles;
}

RZ_API ut32 rz_analysis_function_count_edges(const RzAnalysisFunction *fcn, RZ_NULLABLE int *ebbs) {
	rz_return_val_if_fail(fcn, 0);
	RzAnalysisBlock *bb;
	ut32 edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges++;
			}
			if (bb->fail != UT64_MAX) {
				edges++;
			}
		}
	}
	return edges;
}
