// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The header file for the RzInquiry module provides the declarations
 * for RzInquiry plugins. As well as access to broader analysis functions.
 */

#ifndef RZ_INQUIRY
#define RZ_INQUIRY

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_inquiry/rz_interpreter.h>
#include <rz_inquiry/rz_bb_graph.h>

/**
 * \brief The number of iterations inquiry checks for a user given signal.
 * Checking it costs performance, so it is just checked the X iterations.
 */
#define RZ_INQUIRY_CHECK_USER_SIGNAL_ITC 1000

typedef struct rz_inquiry_plugin_t {
	RzInterpreterPlugin *p_interpreter;
} RzInquiryPlugin;

typedef struct {
	/**
	 * \brief RzInquiry interpreter plugins. Indexed by name.
	 */
	HtSP /*<RzInquiryPlugin *>*/ *plugins;
	HtSP /*<void *>*/ *plugins_data;

	HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates; ///< Indexed by address of basic block with the call candidate.
	RzVector /*<RzAnalysisXRef>*/ *xrefs; ///< All xrefs it detected.
	RzInquiryBBCFG *bb_cfg; ///< The control flow graph all the basic blocks build.
} RzInquiry;

RZ_IPI bool rz_inquiry_bb_cfg_complement(RzInquiry *iq, RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges);

RZ_IPI void rz_inquiry_add_xref(RzInquiry *iq, const RzAnalysisXRef *xref);

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);
RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void);
RZ_API void rz_inquiry_free(RZ_OWN RZ_NULLABLE RzInquiry *q);

RZ_API RZ_OWN RzInterpreterILBB *rz_inquiry_gen_il_bb(RZ_NONNULL RzAnalysis *analysis, RZ_BORROW RZ_NONNULL RzIO *io, ut64 addr);

RZ_API bool rz_inquiry_xref_interpreter_filter(ut64 *xref_to_addr, RZ_NONNULL const RzPVector /*<RzBinSection *>*/ *allowed_segments);

RZ_API bool rz_inquiry_interpreter(RzCore *core, RZ_OWN RzSetU /*<ut64>*/ *entry_points, RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);

RZ_API bool rz_inquiry_function_deduction(RzAnalysis *analysis,
	RzInquiry *inquiry,
	RzSetU *symbol_addresses,
	const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);

//============
// Algorithms
//============

/**
 * \brief A simple function deduced by inquiry algorithms.
 */
typedef struct {
	RzVector /*<ut64>*/ *entry_points;
	RzInquiryBBCFG *bb_cfg;
} RzInquiryFunction;

RZ_IPI RZ_OWN RzInquiryFunction *rz_inquiry_function_new();
RZ_API RZ_OWN char *rz_inquiry_function_str(const RzInquiryFunction *fcn);

RZ_API bool rz_inquiry_get_fcn_symbol_addr(RzCore *core, RZ_OUT RzSetU *symbol_targets);

RZ_API void rz_inquiry_function_free(RZ_NULLABLE RZ_OWN RzInquiryFunction *fcn);

RZ_API bool rz_inquiry_algo_revng_fcn_detection(
	RzSetU *symbol_addresses,
	const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	const RzInquiryBBCFG *bb_cfg,
	RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *fcns,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);

#ifdef __cplusplus
}
#endif
#endif // RZ_INQUIRY
