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

#include <rz_inquiry/rz_il_cache.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_inquiry/rz_bcfg.h>

/**
 * \brief The number of iterations inquiry checks for a user given signal.
 * Checking it costs performance, so it is just checked the X iterations.
 */
#define RZ_INQUIRY_CHECK_USER_SIGNAL_ITC 1000

typedef struct rz_inquiry_plugin_t {
	const char *name;
	const char *author;
	const char *version;
	const char *desc;
	const char *license;
	RzInterpValueAbstraction *value_abstraction;
} RzInquiryPlugin;

typedef struct {
	/**
	 * \brief RzInquiry interpreter plugins. Indexed by name.
	 */
	HtSP /*<RzInquiryPlugin *>*/ *plugins;
	HtSP /*<void *>*/ *plugins_data;

	HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates; ///< Indexed by address of basic block with the call candidate.
	RzVector /*<RzAnalysisXRef>*/ *dynamic_xrefs; ///< All xrefs the interpreter detected.
	RzInquiryBCFG *bcfg; ///< The control flow graph all the basic blocks build.
} RzInquiry;

RZ_IPI bool rz_inquiry_bcfg_complement(RzInquiry *iq, RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges);

RZ_IPI void rz_inquiry_add_xref(RzInquiry *iq, const RzAnalysisXRef *xref);

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);
RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void);
RZ_API void rz_inquiry_free(RZ_OWN RZ_NULLABLE RzInquiry *q);

RZ_API bool rz_inquiry_xref_interpreter_filter(RZ_NONNULL const RzAnalysisXRef *xref, RZ_NONNULL const RzPVector /*<RzBinSection *>*/ *allowed_segments);

RZ_API bool rz_inquiry_interpreter(RzCore *core, RZ_OWN RzSetU /*<ut64>*/ *entry_points, RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);

RZ_API bool rz_inquiry_function_deduction(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RzInquiry *inquiry,
	RZ_NONNULL RZ_BORROW RzSetU *symbol_addresses,
	RZ_NONNULL const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code,
	RZ_NONNULL RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *inquiry_fcns);

//============
// Algorithms
//============

/**
 * \brief A simple function deduced by inquiry algorithms.
 */
typedef struct {
	RzVector /*<ut64>*/ *entry_points;
	RzInquiryBCFG *bcfg;
} RzInquiryFunction;

RZ_IPI RZ_OWN RzInquiryFunction *rz_inquiry_function_new();
RZ_API RZ_OWN char *rz_inquiry_function_str(const RzInquiryFunction *fcn);

RZ_API bool rz_inquiry_get_fcn_symbol_addr(RzCore *core, RZ_OUT RzSetU *symbol_targets);

RZ_API void rz_inquiry_function_free(RZ_NULLABLE RZ_OWN RzInquiryFunction *fcn);

RZ_API bool rz_inquiry_algo_revng_fcn_detection(
	RzSetU *symbol_addresses,
	const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	const RzInquiryBCFG *bcfg,
	RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *fcns,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);

RZ_IPI bool rz_inquiry_convert_and_add_to_analysis(
	RzAnalysis *analysis,
	RzInquiry *inquiry,
	const RzPVector /*<RzInquiryFunction *>*/ *fcns,
	const RzPVector /*<RzBinSymbol *>*/ *symbols);

#ifdef __cplusplus
}
#endif
#endif // RZ_INQUIRY
