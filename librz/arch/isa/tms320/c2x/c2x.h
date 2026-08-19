// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320_C2X_H
#define RZ_TMS320_C2X_H

#include "../c55_ir.h"
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * TMS320C2x (legacy, e.g. TMS320C25) disassembly + RzIL, plugged into the
 * shared C55 decode engine. The C2x is a 16-bit word-addressed fixed-point DSP
 * with a single 32-bit accumulator (ACC) plus carry, a 16-bit temporary T, a
 * 32-bit product register P (with a programmable product shifter PM), eight
 * 16-bit auxiliary registers AR0..7 selected by the 3-bit ARP, a 9-bit data
 * page pointer DP, and ST0/ST1 status words. Program/data addresses are 16-bit.
 *
 * Encodings are taken from the public TMS320C2x instruction set (the opcode bit
 * patterns match MAME's tested TMS320x25 disassembler). Instruction words are
 * stored MSB-first (big-endian), so the engine's words_le swap is NOT used: the
 * leading byte already carries the opcode field that the table matches on.
 */

/// TMS320C2x instruction identifiers (the C55Insn.id / RzAnalysisOp.id values).
enum {
	C2X_INS_INVALID = 0,
	C2X_INS_NOP,
	// accumulator arithmetic
	C2X_INS_ADD,
	C2X_INS_ADDH,
	C2X_INS_ADDS,
	C2X_INS_ADDT,
	C2X_INS_ADDC,
	C2X_INS_SUB,
	C2X_INS_SUBH,
	C2X_INS_SUBS,
	C2X_INS_SUBT,
	C2X_INS_SUBC,
	C2X_INS_SUBB,
	C2X_INS_LAC,
	C2X_INS_LACT,
	C2X_INS_LACK,
	C2X_INS_ZAC,
	C2X_INS_ZALH,
	C2X_INS_ZALS,
	C2X_INS_ZALR,
	C2X_INS_ADDK,
	C2X_INS_SUBK,
	C2X_INS_ABS,
	C2X_INS_NEG,
	C2X_INS_CMPL,
	C2X_INS_SFL,
	C2X_INS_SFR,
	C2X_INS_ROL,
	C2X_INS_ROR,
	C2X_INS_NORM,
	// store / load accumulator parts
	C2X_INS_SACL,
	C2X_INS_SACH,
	C2X_INS_PAC,
	C2X_INS_APAC,
	C2X_INS_SPAC,
	C2X_INS_LPH,
	C2X_INS_SPL,
	C2X_INS_SPH,
	// auxiliary registers / pointers
	C2X_INS_LAR,
	C2X_INS_SAR,
	C2X_INS_LARK,
	C2X_INS_LARP,
	C2X_INS_MAR,
	C2X_INS_LDP,
	C2X_INS_LDPK,
	C2X_INS_ADRK,
	C2X_INS_SBRK,
	// T / P register and multiply
	C2X_INS_LT,
	C2X_INS_LTA,
	C2X_INS_LTD,
	C2X_INS_LTP,
	C2X_INS_LTS,
	C2X_INS_MPY,
	C2X_INS_MPYK,
	C2X_INS_MPYA,
	C2X_INS_MPYS,
	C2X_INS_MPYU,
	C2X_INS_SQRA,
	C2X_INS_SQRS,
	C2X_INS_MAC,
	C2X_INS_MACD,
	// logical
	C2X_INS_AND,
	C2X_INS_OR,
	C2X_INS_XOR,
	C2X_INS_ANDK,
	C2X_INS_ORK,
	C2X_INS_XORK,
	// status / long immediate
	C2X_INS_LST,
	C2X_INS_LST1,
	C2X_INS_SST,
	C2X_INS_SST1,
	C2X_INS_LALK,
	C2X_INS_ADLK,
	C2X_INS_SBLK,
	C2X_INS_LRLK,
	C2X_INS_RPT,
	C2X_INS_RPTK,
	// memory move / table / IO
	C2X_INS_DMOV,
	C2X_INS_PSHD,
	C2X_INS_POPD,
	C2X_INS_PUSH,
	C2X_INS_POP,
	C2X_INS_BITT,
	C2X_INS_BIT,
	C2X_INS_TBLR,
	C2X_INS_TBLW,
	C2X_INS_BLKD,
	C2X_INS_BLKP,
	C2X_INS_IN,
	C2X_INS_OUT,
	// control flow
	C2X_INS_B,
	C2X_INS_BACC,
	C2X_INS_CALA,
	C2X_INS_CALL,
	C2X_INS_RET,
	C2X_INS_BANZ,
	C2X_INS_BV,
	C2X_INS_BGZ,
	C2X_INS_BLEZ,
	C2X_INS_BLZ,
	C2X_INS_BGEZ,
	C2X_INS_BNZ,
	C2X_INS_BZ,
	C2X_INS_BNV,
	C2X_INS_BBZ,
	C2X_INS_BBNZ,
	C2X_INS_BIOZ,
	C2X_INS_BC,
	C2X_INS_BNC,
	C2X_INS_TRAP,
	C2X_INS_IDLE,
	// status-bit / mode controls (CE block)
	C2X_INS_EINT,
	C2X_INS_DINT,
	C2X_INS_ROVM,
	C2X_INS_SOVM,
	C2X_INS_CNFD,
	C2X_INS_CNFP,
	C2X_INS_RSXM,
	C2X_INS_SSXM,
	C2X_INS_SPM,
	C2X_INS_RXF,
	C2X_INS_SXF,
	C2X_INS_FORT,
	C2X_INS_RC,
	C2X_INS_SC,
	C2X_INS_RTC,
	C2X_INS_STC,
	C2X_INS_RFSM,
	C2X_INS_SFSM,
	C2X_INS_RHM,
	C2X_INS_SHM,
	C2X_INS_RTXM,
	C2X_INS_STXM,
	C2X_INS_CMPR,
	C2X_INS_CONF,
};

// Legacy C2x/C5x memory model (shared by both cores). The data/program space
// is word-addressed, but the RzIL VM memory is byte-addressed, so a word
// address scales to a byte address by C2X_WORD_BYTES. C2X_MEM_ADDR_BITS is the
// width of that byte-address space (the il_config mem_key_size): 24 bits leave
// room for a 16-bit word address to scale x2 without wrapping.
#define C2X_WORD_BYTES    2
#define C2X_MEM_ADDR_BITS 24

extern const C55ArchDesc c2x_arch_desc;

// Shared decode-table pieces, reused by the C5x superset (c5x/c5x.c). The
// operand extractors are referenced by the row macros in c2x_rowdefs.h; the
// resolver/classifier/mnemonic helpers are reused (and extended) by C5x.
RZ_IPI void c2x_x_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
RZ_IPI void c2x_x_nextarp(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
RZ_IPI void c2x_x_shift(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
RZ_IPI void c2x_x_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
RZ_IPI void c2x_x_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
RZ_IPI void c2x_x_branch(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
RZ_IPI const C55RegInfo *c2x_reg_info(C55RegClass cls, ut8 num, C55SubReg sub);
RZ_IPI ut32 c2x_op_type(ut16 id);
RZ_IPI const char *c2x_mnemonic(ut16 id);

RZ_IPI int tms320_c2x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask);
RZ_IPI void c2x_fill_op_access(RzAnalysis *analysis, const C55ArchDesc *a, const C55Insn *insn, RzAnalysisOp *op);

RZ_IPI RzAnalysisILConfig *tms320_c2x_il_config(RZ_NONNULL RzAnalysis *analysis);

RZ_IPI RzILOpEffect *c2x_lift(const C55Insn *insn, ut64 pc);

RZ_IPI RzILOpPure *c2x_ea(const C55ArchDesc *a, const C55Operand *m);

#ifdef __cplusplus
}
#endif

#endif /* RZ_TMS320_C2X_H */
