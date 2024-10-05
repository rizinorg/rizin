// SPDX-FileCopyrightText: 2024 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SPARC_IL_H
#define SPARC_IL_H

/**
 * \file This is the include file for using the SPARC RzIL lifter.
 *
 *
 * References used:
 *   - https://www.cs.utexas.edu/users/novak/sparcv9.pdf
 */

#include <rz_lib.h>
#include <rz_analysis.h>

/* Here we don't interop with GNU because the GNU disassembler does not expose
 * the instructions and the registers nicely. We only interface with Capstone. */
#include <capstone/capstone.h>
#include <capstone/sparc.h>

#define BITS_PER_BYTE 8

typedef sparc_reg SparcReg;
typedef cs_sparc_op SparcOp;
typedef cs_sparc SparcIns;
typedef sparc_insn SparcInsMnem;

typedef struct sparc_il_instruction_t {
	const SparcIns *structure; ///< Capstone instruction data
	SparcInsMnem mnem; ///< Instruction mnemonic (enum)
	ut8 ins_size; ///< Size of instruction (in bytes)
} SparcILIns;

RZ_IPI bool rz_sparc_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const SparcILIns *ins);
RZ_IPI RzAnalysisILConfig *rz_sparc_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // SPARC_IL_H
