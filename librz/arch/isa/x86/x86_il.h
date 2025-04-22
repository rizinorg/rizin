// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_X86_IL_H
#define RZIL_ANALYSIS_X86_IL_H

#include <rz_lib.h>
#include <rz_analysis.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

#define BITS_PER_BYTE    8
#define GPR_FAMILY_COUNT 10

typedef x86_reg X86Reg;
typedef cs_x86_op X86Op;
typedef x86_op_mem X86Mem;
typedef cs_x86 X86Ins;
typedef x86_insn X86InsMnem;

typedef struct x86_il_instruction_t {
	const X86Ins *structure; ///< Capstone instruction data
	X86InsMnem mnem; ///< Instruction mnemonic (enum)
	ut8 ins_size; ///< Size of instruction (in bytes)
} X86ILIns;

/**
 * \brief To store the context of the IL lifter ; Used to pass around information outside effects
 * Other context variables *may* be added in the future when the rest of the instructions are lifted
 */
typedef struct x86_il_context_t {
	bool use_rmode; ///< Set to true whenever the rounding mode is calculated (used to add a `SETL` effect for the rounding mode local variable, in case it is used) ; Set to false (by default)
} X86ILContext;

RZ_IPI bool rz_x86_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const X86ILIns *ins);
RZ_IPI RzAnalysisILConfig *rz_x86_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif /* RZIL_ANALYSIS_X86_IL_H */
