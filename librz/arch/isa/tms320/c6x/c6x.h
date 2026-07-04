// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320_C6X_H
#define RZ_TMS320_C6X_H

#include <rz_types.h>
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * Shared decode/format core for the TMS320C6000 VLIW DSP family (C62x / C64x /
 * C64x+ / C67x / C67x+ / C674x / C66x).
 *
 * Every C6000 generation shares one instruction container: a 32-bit opcode with
 * a fixed low-bit frame (bit 0 = parallel, bit 1 = dst side, bits 31:28 = the
 * creg/z predicate) and a functional-unit-selected body. The families differ
 * only in *which* opcodes decode -- C67x adds the floating-point set on top of
 * the C62x fixed-point base, C64x adds the SIMD/packed set, C66x adds more --
 * so a single decode engine driven by one instruction table plus a per-variant
 * \ref C6xArchDesc feature gate covers them all, mirroring how the C55 engine
 * serves C54x/C55x/C55x+.
 *
 * The decoder (c6x_decode()) runs once and fills a \ref C6xInsn; two pure
 * consumers read it and never re-parse: c6x_format() (asm string) and
 * c6x_fill_analysis() (RzAnalysisOp). RzIL uplifting is a planned third
 * consumer and attaches the same way.
 */

/** Family member; gates variant-specific opcodes and register width. */
/** Instruction id/opcode; c6x_ins_name() renders its mnemonic. */
typedef enum {
	C6X_INS_INVALID = 0, ///< not a recognised opcode
	C6X_INS_FPHEAD,
	C6X_INS_ABS,
	C6X_INS_ABS2,
	C6X_INS_ABSDP,
	C6X_INS_ABSSP,
	C6X_INS_ADD,
	C6X_INS_ADD2,
	C6X_INS_ADD4,
	C6X_INS_ADDAB,
	C6X_INS_ADDAD,
	C6X_INS_ADDAH,
	C6X_INS_ADDAW,
	C6X_INS_ADDDP,
	C6X_INS_ADDK,
	C6X_INS_ADDKPC,
	C6X_INS_ADDSP,
	C6X_INS_ADDU,
	C6X_INS_AND,
	C6X_INS_ANDN,
	C6X_INS_AVG2,
	C6X_INS_AVGU4,
	C6X_INS_B,
	C6X_INS_BDEC,
	C6X_INS_BITC4,
	C6X_INS_BITR,
	C6X_INS_BNOP,
	C6X_INS_BPOS,
	C6X_INS_CALLP,
	C6X_INS_CLR,
	C6X_INS_CMATMPY,
	C6X_INS_CMATMPYR1,
	C6X_INS_CMPEQ,
	C6X_INS_CMPEQ2,
	C6X_INS_CMPEQ4,
	C6X_INS_CMPEQDP,
	C6X_INS_CMPEQSP,
	C6X_INS_CMPGT,
	C6X_INS_CMPGT2,
	C6X_INS_CMPGTDP,
	C6X_INS_CMPGTSP,
	C6X_INS_CMPGTU,
	C6X_INS_CMPGTU4,
	C6X_INS_CMPLT,
	C6X_INS_CMPLTDP,
	C6X_INS_CMPLTSP,
	C6X_INS_CMPLTU,
	C6X_INS_CMPY,
	C6X_INS_CMPYR,
	C6X_INS_CMPYR1,
	C6X_INS_DADD,
	C6X_INS_DCCMPYR1,
	C6X_INS_DCMPYR1,
	C6X_INS_DDOTPH2,
	C6X_INS_DDOTPL2,
	C6X_INS_DEAL,
	C6X_INS_DINT,
	C6X_INS_DMPYSP,
	C6X_INS_DOTP2,
	C6X_INS_DOTP4H,
	C6X_INS_DOTPN2,
	C6X_INS_DOTPNRSU2,
	C6X_INS_DOTPRSU2,
	C6X_INS_DOTPSU4,
	C6X_INS_DOTPSU4H,
	C6X_INS_DOTPU4,
	C6X_INS_DPINT,
	C6X_INS_DPSP,
	C6X_INS_DPTRUNC,
	C6X_INS_DSUB,
	C6X_INS_EXT,
	C6X_INS_EXTU,
	C6X_INS_GMPY,
	C6X_INS_GMPY4,
	C6X_INS_IDLE,
	C6X_INS_INTDP,
	C6X_INS_INTDPU,
	C6X_INS_INTSP,
	C6X_INS_INTSPU,
	C6X_INS_LDB,
	C6X_INS_LDBU,
	C6X_INS_LDDW,
	C6X_INS_LDH,
	C6X_INS_LDHU,
	C6X_INS_LDNDW,
	C6X_INS_LDNW,
	C6X_INS_LDW,
	C6X_INS_LMBD,
	C6X_INS_MAX2,
	C6X_INS_MAXU4,
	C6X_INS_MIN2,
	C6X_INS_MINU4,
	C6X_INS_MPY,
	C6X_INS_MPY2,
	C6X_INS_MPY32,
	C6X_INS_MPY32SU,
	C6X_INS_MPY32U,
	C6X_INS_MPY32US,
	C6X_INS_MPYDP,
	C6X_INS_MPYH,
	C6X_INS_MPYHI,
	C6X_INS_MPYHIR,
	C6X_INS_MPYHL,
	C6X_INS_MPYHLU,
	C6X_INS_MPYHSLU,
	C6X_INS_MPYHSU,
	C6X_INS_MPYHU,
	C6X_INS_MPYHULS,
	C6X_INS_MPYHUS,
	C6X_INS_MPYI,
	C6X_INS_MPYID,
	C6X_INS_MPYLH,
	C6X_INS_MPYLHU,
	C6X_INS_MPYLI,
	C6X_INS_MPYLIR,
	C6X_INS_MPYLSHU,
	C6X_INS_MPYLUHS,
	C6X_INS_MPYSP,
	C6X_INS_MPYSP2DP,
	C6X_INS_MPYSPDP,
	C6X_INS_MPYSU,
	C6X_INS_MPYSU4,
	C6X_INS_MPYU,
	C6X_INS_MPYU4,
	C6X_INS_MPYUS,
	C6X_INS_MV,
	C6X_INS_MVC,
	C6X_INS_MVD,
	C6X_INS_MVK,
	C6X_INS_MVKH,
	C6X_INS_NEG,
	C6X_INS_NOP,
	C6X_INS_NORM,
	C6X_INS_NOT,
	C6X_INS_OR,
	C6X_INS_PACK2,
	C6X_INS_PACKH2,
	C6X_INS_PACKH4,
	C6X_INS_PACKHL2,
	C6X_INS_PACKL4,
	C6X_INS_PACKLH2,
	C6X_INS_QMPY32,
	C6X_INS_QMPYSP,
	C6X_INS_QSMPY32R1,
	C6X_INS_RINT,
	C6X_INS_ROTL,
	C6X_INS_RPACK2,
	C6X_INS_RSQRDP,
	C6X_INS_SADD,
	C6X_INS_SADD2,
	C6X_INS_SADDU4,
	C6X_INS_SADDUS2,
	C6X_INS_SAT,
	C6X_INS_SET,
	C6X_INS_SHFL,
	C6X_INS_SHL,
	C6X_INS_SHLMB,
	C6X_INS_SHR,
	C6X_INS_SHR2,
	C6X_INS_SHRMB,
	C6X_INS_SHRU,
	C6X_INS_SHRU2,
	C6X_INS_SMPY,
	C6X_INS_SMPY2,
	C6X_INS_SMPYH,
	C6X_INS_SMPYHL,
	C6X_INS_SMPYLH,
	C6X_INS_SPACK2,
	C6X_INS_SPACKU4,
	C6X_INS_SPDP,
	C6X_INS_SPINT,
	C6X_INS_SPLOOP,
	C6X_INS_SPLOOPD,
	C6X_INS_SPLOOPW,
	C6X_INS_SPKERNEL,
	C6X_INS_SPKERNELR,
	C6X_INS_SPMASK,
	C6X_INS_SPMASKR,
	C6X_INS_SPTRUNC,
	C6X_INS_SSHL,
	C6X_INS_SSHVL,
	C6X_INS_SSHVR,
	C6X_INS_SSUB,
	C6X_INS_SSUB2,
	C6X_INS_STB,
	C6X_INS_STDW,
	C6X_INS_STH,
	C6X_INS_STNDW,
	C6X_INS_STNW,
	C6X_INS_STW,
	C6X_INS_SUB,
	C6X_INS_SUB2,
	C6X_INS_SUB4,
	C6X_INS_SUBAB,
	C6X_INS_SUBAH,
	C6X_INS_SUBAW,
	C6X_INS_SUBC,
	C6X_INS_SUBDP,
	C6X_INS_SUBSP,
	C6X_INS_SUBU,
	C6X_INS_SWAP4,
	C6X_INS_UNPKHU4,
	C6X_INS_UNPKLU4,
	C6X_INS_XOR,
	C6X_INS_XORMPY,
	C6X_INS_XPND2,
	C6X_INS_XPND4,
	C6X_INS_ZERO,
	C6X_INS_LAST,
} C6xInsnId;

typedef enum {
	C6X_GEN_C62X = 0, ///< TMS320C62x (fixed-point base, 16+16 registers)
	C6X_GEN_C67X, ///< TMS320C67x/C67x+ (adds floating-point)
	C6X_GEN_C64X, ///< TMS320C64x/C64x+ (adds SIMD, 32+32 registers)
	C6X_GEN_C674X, ///< TMS320C674x (unified C64x+ and C67x+)
	C6X_GEN_C66X, ///< TMS320C66x (adds 4x SIMD / complex arithmetic)
} C6xGen;

/** Register file an operand, unit or base register belongs to. */
typedef enum {
	C6X_SIDE_A = 0, ///< A datapath (a0-a31, .x1 units)
	C6X_SIDE_B, ///< B datapath (b0-b31, .x2 units)
} C6xSide;

/** Functional unit an instruction issues on. */
typedef enum {
	C6X_UNIT_NONE = 0, ///< no unit (NOP, IDLE, loop buffer, emulation)
	C6X_UNIT_L, ///< .L1 / .L2 (arithmetic, logical, compares)
	C6X_UNIT_S, ///< .S1 / .S2 (shifts, branches, moves, field ops)
	C6X_UNIT_M, ///< .M1 / .M2 (multiplies)
	C6X_UNIT_D, ///< .D1 / .D2 (loads, stores, address arithmetic)
} C6xUnit;

/** Data-memory addressing modes for .D loads/stores (Table 3-11). */
typedef enum {
	C6X_AM_NONE = 0,
	C6X_AM_NEG_CST, ///< *-R[ucst5]
	C6X_AM_POS_CST, ///< *+R[ucst5]
	C6X_AM_NEG_REG, ///< *-R[offsetR]
	C6X_AM_POS_REG, ///< *+R[offsetR]
	C6X_AM_PREDEC_CST, ///< *--R[ucst5]
	C6X_AM_PREINC_CST, ///< *++R[ucst5]
	C6X_AM_POSTDEC_CST, ///< *R--[ucst5]
	C6X_AM_POSTINC_CST, ///< *R++[ucst5]
	C6X_AM_PREDEC_REG, ///< *--R[offsetR]
	C6X_AM_PREINC_REG, ///< *++R[offsetR]
	C6X_AM_POSTDEC_REG, ///< *R--[offsetR]
	C6X_AM_POSTINC_REG, ///< *R++[offsetR]
	C6X_AM_BASE_LONG, ///< *+B14/B15[ucst15] long-immediate offset
} C6xAddrMode;

/** Operand kind within a decoded instruction. */
typedef enum {
	C6X_OP_NONE = 0,
	C6X_OP_REG, ///< general-purpose register (side + num)
	C6X_OP_REGPAIR, ///< register pair reg+1:reg (odd:even), 64-bit
	C6X_OP_REGQUAD, ///< register quad reg+3:reg+2:reg+1:reg (C66x 128-bit ops)
	C6X_OP_IMM, ///< immediate constant (signed value in \ref C6xOperand::imm)
	C6X_OP_CTRLREG, ///< control register named by \ref C6xOperand::name (MVC)
	C6X_OP_MEM, ///< *baseR addressing (see \ref C6xAddrMode)
	C6X_OP_PCREL, ///< PC-relative branch target (absolute address in imm)
	C6X_OP_UNITMASK, ///< SPMASK unit list, one bit per functional unit
} C6xOpKind;

/** Register operand: a single register, or the low member of a pair or quad. */
typedef struct {
	C6xSide side; ///< register file the operand reads or writes
	ut8 num; ///< register number
} C6xRegOperand;

/** Immediate operand: a constant, a displacement, or a resolved branch target. */
typedef struct {
	st64 value;
	bool decimal; ///< render as a count in decimal rather than a value in hex
} C6xImmOperand;

/** Memory operand: *baseR addressing on the .D unit. */
typedef struct {
	C6xAddrMode mode;
	ut8 base; ///< base register number
	C6xSide base_side; ///< register file of the base register
	ut8 off_reg; ///< register offset number (register-offset modes)
	ut32 off_cst; ///< constant offset (ucst5 / ucst15), unscaled
	bool scaled; ///< offset is scaled by the access size (bracket syntax)
} C6xMemOperand;

/** One decoded operand; \ref C6xOperand::kind selects the union member. */
typedef struct {
	C6xOpKind kind;
	union {
		C6xRegOperand reg; ///< C6X_OP_REG, C6X_OP_REGPAIR, C6X_OP_REGQUAD
		C6xImmOperand imm; ///< C6X_OP_IMM, C6X_OP_PCREL
		C6xMemOperand mem; ///< C6X_OP_MEM
		const char *ctrl; ///< C6X_OP_CTRLREG: control-register name
		ut8 units; ///< C6X_OP_UNITMASK: functional-unit bitmap
	} v;
} C6xOperand;

#define C6X_MAX_OPS 4
/** Operand \p i of the instruction named "insn" in the enclosing scope. */
#define OP(i) (insn->ops[i])

/** Bits 2:1 of a compact opcode: which unit space the rest of it is decoded in. */
typedef enum {
	C6X_CSPACE_L = 0x0, ///< .L unit forms
	C6X_CSPACE_S = 0x2, ///< .S unit forms
	C6X_CSPACE_D = 0x4, ///< .D unit forms
	C6X_CSPACE_SHARED = 0x6, ///< forms shared between units
} C6xCompactSpace;

/** Bits 31:28 of the last word of a fetch packet, marking it a compact header. */
#define C6X_FP_HEADER_TAG 0xe

#define C6X_WORD_SIZE         4 ///< a full instruction word
#define C6X_COMPACT_SIZE      2 ///< a slot of a compact fetch packet
#define C6X_FETCH_PACKET_SIZE 32 ///< eight words fetched and branched to as a unit

/** A fully decoded C6000 instruction. */
typedef struct {
	ut32 word; ///< raw 32-bit opcode (little-endian host value)
	ut32 size; ///< C6X_WORD_SIZE, or C6X_COMPACT_SIZE in a compact packet
	const char *mnemonic; ///< base mnemonic ("add", "ldw", "mpysp", ...)
	C6xInsnId id; ///< Instruction id/opcode.
	C6xUnit unit; ///< functional unit
	C6xSide unit_side; ///< datapath the unit belongs to
	bool cross; ///< src2 uses the register-file cross path (x bit)
	bool parallel; ///< p-bit: the *following* instruction runs in parallel
	bool cont; ///< this instruction continues the previous execute packet (renders "||")
	bool is_fp; ///< the operation is floating-point (selects the FPU family)
	ut8 creg; ///< predicate register code (bits 31:29); 0 = unconditional
	bool z; ///< predicate sense (bit 28): 0 = nonzero, 1 = zero
	_RzAnalysisOpType op_type; ///< analysis classification
	C6xOperand ops[C6X_MAX_OPS];
	ut8 nops; ///< number of valid operands
	bool is_header; ///< compact fetch-packet header word (renders as .fphead)
} C6xInsn;

/** Per-variant feature gate and register-set descriptor. */
/** Optional instruction groups a family member may implement. */
typedef enum {
	C6X_FEAT_FP = 1 << 0, ///< floating-point set (C67x/C674x/C66x)
	C6X_FEAT_SIMD = 1 << 1, ///< SIMD/packed set (C64x/C674x/C66x)
} C6xFeature;

typedef struct {
	C6xGen gen; ///< which family member
	ut8 num_regs; ///< registers per side (16 for C62x/C67x, 32 otherwise)
	ut32 features; ///< C6xFeature bitmap
} C6xArchDesc;

/**
 * Base address of the fetch packet holding \p pc. Branch displacements are
 * relative to this (PCE1), not to the instruction itself.
 */
static inline ut64 c6x_packet_base(ut64 pc) {
	return pc & ~(ut64)(C6X_FETCH_PACKET_SIZE - 1);
}

RZ_IPI const C6xArchDesc *c6x_desc_from_cpu(const char *cpu);

RZ_IPI bool c6x_decode(const C6xArchDesc *desc, const ut8 *buf, int len, ut64 pc, bool big_endian, RZ_OUT C6xInsn *insn);

RZ_IPI void c6x_mark_parallel(RZ_INOUT C6xInsn *insn, ut64 addr, RZ_INOUT ut64 *prev_end, RZ_INOUT bool *prev_par);

RZ_IPI RZ_OWN char *c6x_format(const C6xArchDesc *desc, const C6xInsn *insn, ut64 pc);

RZ_IPI void c6x_fill_analysis(const C6xArchDesc *desc, const C6xInsn *insn, ut64 addr, RZ_OUT RzAnalysisOp *op);

RZ_IPI RZ_OWN RzStructuredData *c6x_opex(const C6xInsn *insn);

RZ_IPI const char *c6x_pred_reg_name(ut8 creg);

RZ_IPI const char *c6x_ins_name(C6xInsnId id);

RZ_IPI RZ_OWN char *c6x_reg_operand_str(const C6xOperand *o);

RZ_IPI const char *c6x_unit_name(ut8 bit);

RZ_IPI RzAnalysisILConfig *tms320_c6x_il_config(RZ_NONNULL RzAnalysis *analysis);

RZ_IPI RZ_OWN RzILOpEffect *c6x_lift(const C6xInsn *insn, ut64 pc);

RZ_IPI RZ_OWN RzPVector /*<const char *>*/ *c6x_mnemonics(void);

#ifdef __cplusplus
}
#endif

#endif
