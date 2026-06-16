// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320C55X_INSN_H
#define RZ_TMS320C55X_INSN_H

#include <rz_types.h>

/**
 * \file tms320c55x_insn.h
 *
 * Named instruction identifiers for the TMS320 C55x / C55x+ families,
 * in the same spirit as Capstone's per-architecture instruction enums
 * (e.g. ARM_INS_BL, X86_INS_MOV). Rather than dispatching analysis on
 * raw opcode bytes, the disassembler tags each decoded instruction with
 * one of these IDs and the analyzers switch on the ID.
 *
 * The prefix is TMS320C55_ (not just TMS320_) because the other TMS320
 * families -- C54x, C64x, C28x, ... -- have substantially different
 * instruction sets; this enum is specific to the C55x / C55x+ ISA. The
 * namespace is shared between C55x and C55x+ because those two share the
 * bulk of their mnemonics; instructions that exist only on one of them
 * (e.g. SWAP / SIM_TRIG on C55x+) are still part of the single enum.
 *
 * The mnemonic set was extracted from the C55x decoder opcode table
 * (librz/arch/isa/tms320/c55x/table.h) and the C55x+ token decoder, and
 * cross-referenced with TI SPRU374 (C55x) and SWPU086 / SWPU104 (C55x+).
 */
typedef enum {
	TMS320C55_INS_INVALID = 0,
	TMS320C55_INS_AADD,
	TMS320C55_INS_ABDST,
	TMS320C55_INS_ABS,
	TMS320C55_INS_ADD,
	TMS320C55_INS_ADDV,
	TMS320C55_INS_ADDRV,
	TMS320C55_INS_ADDSUB,
	TMS320C55_INS_ADDSUB2CC,
	TMS320C55_INS_ADDSUBCC,
	TMS320C55_INS_AMAR,
	TMS320C55_INS_AMOV,
	TMS320C55_INS_AND,
	TMS320C55_INS_ASUB,
	TMS320C55_INS_B,
	TMS320C55_INS_BAND,
	TMS320C55_INS_BCC,
	TMS320C55_INS_BCLR,
	TMS320C55_INS_BCNT,
	TMS320C55_INS_BFXPA,
	TMS320C55_INS_BFXTR,
	TMS320C55_INS_BNOT,
	TMS320C55_INS_BSET,
	TMS320C55_INS_BTST,
	TMS320C55_INS_BTSTCLR,
	TMS320C55_INS_BTSTNOT,
	TMS320C55_INS_BTSTP,
	TMS320C55_INS_BTSTSET,
	TMS320C55_INS_CALL,
	TMS320C55_INS_CALLCC,
	TMS320C55_INS_CIRC,
	TMS320C55_INS_CMP,
	TMS320C55_INS_CMPAND,
	TMS320C55_INS_CMPOR,
	TMS320C55_INS_DELAY,
	TMS320C55_INS_DMAXDIFF,
	TMS320C55_INS_DMINDIFF,
	TMS320C55_INS_EXP,
	TMS320C55_INS_FIRSADD,
	TMS320C55_INS_FIRSSUB,
	TMS320C55_INS_IDLE,
	TMS320C55_INS_INTR,
	TMS320C55_INS_LMS,
	TMS320C55_INS_LMSF,
	TMS320C55_INS_MAC,
	TMS320C55_INS_MACK,
	TMS320C55_INS_MACM,
	TMS320C55_INS_MACMK,
	TMS320C55_INS_MANT,
	TMS320C55_INS_MAS,
	TMS320C55_INS_MASM,
	TMS320C55_INS_MAX,
	TMS320C55_INS_MAXDIFF,
	TMS320C55_INS_MIN,
	TMS320C55_INS_MINDIFF,
	TMS320C55_INS_MOV,
	TMS320C55_INS_MPY,
	TMS320C55_INS_MPYK,
	TMS320C55_INS_MPYM,
	TMS320C55_INS_MPYMK,
	TMS320C55_INS_NEG,
	TMS320C55_INS_NOP,
	TMS320C55_INS_NOT,
	TMS320C55_INS_OR,
	TMS320C55_INS_POP,
	TMS320C55_INS_POPBOTH,
	TMS320C55_INS_PSH,
	TMS320C55_INS_PSHBOTH,
	TMS320C55_INS_RESET,
	TMS320C55_INS_RET,
	TMS320C55_INS_RETCC,
	TMS320C55_INS_RETI,
	TMS320C55_INS_ROL,
	TMS320C55_INS_ROR,
	TMS320C55_INS_ROUND,
	TMS320C55_INS_RPT,
	TMS320C55_INS_RPTADD,
	TMS320C55_INS_RPTB,
	TMS320C55_INS_RPTBLOCAL,
	TMS320C55_INS_RPTCC,
	TMS320C55_INS_RPTSUB,
	TMS320C55_INS_SAT,
	TMS320C55_INS_SFTCC,
	TMS320C55_INS_SFTL,
	TMS320C55_INS_SFTS,
	TMS320C55_INS_SFTSC,
	TMS320C55_INS_SIM_TRIG,
	TMS320C55_INS_SQA,
	TMS320C55_INS_SQAM,
	TMS320C55_INS_SQDST,
	TMS320C55_INS_SQR,
	TMS320C55_INS_SQRM,
	TMS320C55_INS_SQS,
	TMS320C55_INS_SQSM,
	TMS320C55_INS_SUB,
	TMS320C55_INS_SUBADD,
	TMS320C55_INS_SUBC,
	TMS320C55_INS_SWAP,
	TMS320C55_INS_TRAP,
	TMS320C55_INS_XCC,
	TMS320C55_INS_XCCPART,
	TMS320C55_INS_XOR,
	// Appended at the end to keep the numeric ids of the entries above stable
	// (op->id values are asserted by the analysis tests).
	TMS320C55_INS_COPY,
	TMS320C55_INS_SWAPP,
	TMS320C55_INS_SWAP4,
	TMS320C55_INS_NOP_16,
	TMS320C55_INS_ESTOP,
	TMS320C55_INS_ECOPR,
} TMS320C55InsID;

/** Human-readable mnemonic for a TMS320C55InsID (never NULL). */
RZ_API const char *tms320c55x_insn_name(TMS320C55InsID id);

/** Resolve the leading mnemonic of a decoded syntax string to its
 * TMS320C55InsID. Parses the first whitespace-delimited token, skipping a
 * leading C55x+ parallel marker ("|| ") if present. Returns
 * TMS320C55_INS_INVALID when no mnemonic matches. */
RZ_API TMS320C55InsID tms320c55x_insn_id_from_syntax(const char *syntax);

/** Map a TMS320C55InsID to the closest RzAnalysisOp type
 * (RZ_ANALYSIS_OP_TYPE_*), returned as int to avoid pulling rz_analysis.h
 * into this header. Returns RZ_ANALYSIS_OP_TYPE_NULL (0) for instructions
 * with no clean scalar type (control flow, repeats, and forms whose type
 * the analyzer derives from operands). This is the authoritative type for
 * the arithmetic / logical / move / stack families, where a leading-byte
 * switch cannot tell e.g. ADD from SUB or AND from XOR. */
RZ_API int tms320c55x_insn_optype(TMS320C55InsID id);

#endif /* RZ_TMS320C55X_INSN_H */
