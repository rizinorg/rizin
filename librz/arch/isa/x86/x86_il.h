// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-FileCopyrightText: 2024-2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_X86_IL_H
#define RZIL_ANALYSIS_X86_IL_H

#include <rz_lib.h>
#include <rz_analysis.h>

#if USE_SYS_ZYDIS
#include <Zydis/Zydis.h>
#else
#include <Zydis.h>
#endif

#define BITS_PER_BYTE    8
#define GPR_FAMILY_COUNT 10

typedef ZydisRegister X86Reg;
typedef ZydisDecodedOperand X86Op;
typedef ZydisDecodedOperandMem X86Mem;
typedef ZydisDecodedInstruction X86Ins;
typedef ZydisMnemonic X86InsMnem;

typedef struct x86_il_instruction_t {
	const X86Ins *structure; ///< Capstone instruction data
	const X86Op *operands;
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

#define imm_value(op, pc) (ut64)((op.imm.is_relative) ? (op.imm.value.s + pc) : (op.imm.value.u))

#endif /* RZIL_ANALYSIS_X86_IL_H */
