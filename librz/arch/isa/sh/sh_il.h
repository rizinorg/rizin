// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SH_RZIL_H
#define SH_RZIL_H

#include <rz_analysis.h>
#include "disassembler.h"

/**
 * \brief To store the context of the IL lifter ; Used to pass around information outside effects
 * Other context variables *may* be added in the future when the rest of the instructions are lifted
 */
typedef struct sh_il_context_t {
	bool privilege_check; ///< Set to true whenever the privilege mode is calculated (used to add a `SETL` effect for the privilege bit, in case it is used) ; Set to false (by default)
	bool use_banked; ///< Set to true (default) whenever the IL should use banked registers in case of privileged mode ; Setting to false means only un-banked gpr will be used
} SHILContext;

RZ_IPI bool rz_sh_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const SHOp *op, RZ_NULLABLE SHILContext *ctx);
RZ_IPI RzAnalysisILConfig *rz_sh_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif /* SH_RZIL_H */
