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

typedef struct rz_inquiry_plugin_t {
	RzInterpreterPlugin *p_interpreter;
} RzInquiryPlugin;

typedef struct {
	/**
	 * \brief RzInquiry interpreter plugins. Indexed by name.
	 */
	HtSP /*<RzInquiryPlugin *>*/ *plugins;
	HtSP /*<void *>*/ *plugins_data;

	HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates; ///< Indexed by address of candidate instruction.
} RzInquiry;

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);
RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void);
RZ_API void rz_inquiry_free(RZ_OWN RZ_NULLABLE RzInquiry *q);

RZ_API RZ_OWN RzInterpreterILBB *rz_inquiry_gen_il_bb(RZ_NONNULL RzAnalysis *analysis, RZ_BORROW RZ_NONNULL RzIO *io, ut64 addr, RZ_NULLABLE RZ_OUT size_t *bb_size);

RZ_API bool rz_inquiry_xref_interpreter_filter(ut64 *xref_to_addr, RZ_NONNULL const RzPVector /*<RzBinSection *>*/ *allowed_segments);

RZ_API bool rz_inquiry_interpreter(RzCore *core, RZ_OWN RzVector /*<ut64>*/ *entry_points);

#ifdef __cplusplus
}
#endif
#endif // RZ_INQUIRY
