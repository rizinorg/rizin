// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c6x.h"

// The C6000 opcode is a fixed 32-bit word. Bit 0 is the parallel bit, bit 1 the
// destination side, bits 31:28 the creg/z predicate; the remaining bits select a
// functional unit and operation through the formats of SPRU733 Appendix C-G.
// Each format is recognised from its fixed low-bit signature, its operand fields
// are sliced out, and the op field is matched in that unit's table below.

#define BITS(w, hi, lo) (((w) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define BIT(w, n)       (((w) >> (n)) & 1u)

// src1 (bits 17:13) is either a register or a short constant, fixed per opcode.
typedef enum {
	SRC1_REG = 0, ///< src1 is a register
	SRC1_SCST5, ///< src1 is a signed 5-bit constant
	SRC1_UCST5, ///< src1 is an unsigned 5-bit constant
	SRC1_NONE, ///< no src1 (unary)
} C6xSrc1Kind;

// A row only decodes on a variant that has the required instruction set.
typedef enum {
	FEAT_BASE = 0, ///< C62x base, present on every generation
	FEAT_FP, ///< floating-point (C67x and up)
	FEAT_SIMD, ///< SIMD/packed (C64x and up)
	FEAT_CPLX, ///< complex/matrix multiply (C674x and C66x: has_fp && has_simd)
	FEAT_C66X, ///< C66x-only additions (4-way dot products, double complex)
} C6xFeat;

// Some floating-point ops mix single registers and 64-bit pairs in ways that
// `pair` alone cannot express, so a row may override the src2/dst shape.
typedef enum {
	OSHAPE_UNIFORM = 0, ///< every register operand follows `pair`
	OSHAPE_CMP_DP, ///< src1/src2 are pairs, dst is a single sint (DP compares)
	OSHAPE_CMP_LONG, ///< src2 is a pair (40-bit long), dst and src1 are singles
	OSHAPE_TO_DP, ///< src2 single widens into a pair dst; src1 (if any) single
	OSHAPE_LONG_DST, ///< src1 single, src2 a pair, dst a pair (long ADD)
} C6xOShape;

// Printed form of every opcode, indexed by C6xInsnId, so an opcode is named
// exactly once and the decode tables carry identity instead of text.
static const char *const c6x_ins_names[C6X_INS_LAST] = {
	[C6X_INS_FPHEAD] = ".fphead",
	[C6X_INS_ABS] = "abs",
	[C6X_INS_ABS2] = "abs2",
	[C6X_INS_ABSDP] = "absdp",
	[C6X_INS_ABSSP] = "abssp",
	[C6X_INS_ADD] = "add",
	[C6X_INS_ADD2] = "add2",
	[C6X_INS_ADD4] = "add4",
	[C6X_INS_ADDAB] = "addab",
	[C6X_INS_ADDAD] = "addad",
	[C6X_INS_ADDAH] = "addah",
	[C6X_INS_ADDAW] = "addaw",
	[C6X_INS_ADDDP] = "adddp",
	[C6X_INS_ADDK] = "addk",
	[C6X_INS_ADDKPC] = "addkpc",
	[C6X_INS_ADDSP] = "addsp",
	[C6X_INS_ADDU] = "addu",
	[C6X_INS_AND] = "and",
	[C6X_INS_ANDN] = "andn",
	[C6X_INS_AVG2] = "avg2",
	[C6X_INS_AVGU4] = "avgu4",
	[C6X_INS_B] = "b",
	[C6X_INS_BDEC] = "bdec",
	[C6X_INS_BITC4] = "bitc4",
	[C6X_INS_BITR] = "bitr",
	[C6X_INS_BNOP] = "bnop",
	[C6X_INS_BPOS] = "bpos",
	[C6X_INS_CALLP] = "callp",
	[C6X_INS_CLR] = "clr",
	[C6X_INS_CMATMPY] = "cmatmpy",
	[C6X_INS_CMATMPYR1] = "cmatmpyr1",
	[C6X_INS_CMPEQ] = "cmpeq",
	[C6X_INS_CMPEQ2] = "cmpeq2",
	[C6X_INS_CMPEQ4] = "cmpeq4",
	[C6X_INS_CMPEQDP] = "cmpeqdp",
	[C6X_INS_CMPEQSP] = "cmpeqsp",
	[C6X_INS_CMPGT] = "cmpgt",
	[C6X_INS_CMPGT2] = "cmpgt2",
	[C6X_INS_CMPGTDP] = "cmpgtdp",
	[C6X_INS_CMPGTSP] = "cmpgtsp",
	[C6X_INS_CMPGTU] = "cmpgtu",
	[C6X_INS_CMPGTU4] = "cmpgtu4",
	[C6X_INS_CMPLT] = "cmplt",
	[C6X_INS_CMPLTDP] = "cmpltdp",
	[C6X_INS_CMPLTSP] = "cmpltsp",
	[C6X_INS_CMPLTU] = "cmpltu",
	[C6X_INS_CMPY] = "cmpy",
	[C6X_INS_CMPYR] = "cmpyr",
	[C6X_INS_CMPYR1] = "cmpyr1",
	[C6X_INS_DADD] = "dadd",
	[C6X_INS_DCCMPYR1] = "dccmpyr1",
	[C6X_INS_DCMPYR1] = "dcmpyr1",
	[C6X_INS_DDOTPH2] = "ddotph2",
	[C6X_INS_DDOTPL2] = "ddotpl2",
	[C6X_INS_DEAL] = "deal",
	[C6X_INS_DINT] = "dint",
	[C6X_INS_DMPYSP] = "dmpysp",
	[C6X_INS_DOTP2] = "dotp2",
	[C6X_INS_DOTP4H] = "dotp4h",
	[C6X_INS_DOTPN2] = "dotpn2",
	[C6X_INS_DOTPNRSU2] = "dotpnrsu2",
	[C6X_INS_DOTPRSU2] = "dotprsu2",
	[C6X_INS_DOTPSU4] = "dotpsu4",
	[C6X_INS_DOTPSU4H] = "dotpsu4h",
	[C6X_INS_DOTPU4] = "dotpu4",
	[C6X_INS_DPINT] = "dpint",
	[C6X_INS_DPSP] = "dpsp",
	[C6X_INS_DPTRUNC] = "dptrunc",
	[C6X_INS_DSUB] = "dsub",
	[C6X_INS_EXT] = "ext",
	[C6X_INS_EXTU] = "extu",
	[C6X_INS_GMPY] = "gmpy",
	[C6X_INS_GMPY4] = "gmpy4",
	[C6X_INS_IDLE] = "idle",
	[C6X_INS_INTDP] = "intdp",
	[C6X_INS_INTDPU] = "intdpu",
	[C6X_INS_INTSP] = "intsp",
	[C6X_INS_INTSPU] = "intspu",
	[C6X_INS_LDB] = "ldb",
	[C6X_INS_LDBU] = "ldbu",
	[C6X_INS_LDDW] = "lddw",
	[C6X_INS_LDH] = "ldh",
	[C6X_INS_LDHU] = "ldhu",
	[C6X_INS_LDNDW] = "ldndw",
	[C6X_INS_LDNW] = "ldnw",
	[C6X_INS_LDW] = "ldw",
	[C6X_INS_LMBD] = "lmbd",
	[C6X_INS_MAX2] = "max2",
	[C6X_INS_MAXU4] = "maxu4",
	[C6X_INS_MIN2] = "min2",
	[C6X_INS_MINU4] = "minu4",
	[C6X_INS_MPY] = "mpy",
	[C6X_INS_MPY2] = "mpy2",
	[C6X_INS_MPY32] = "mpy32",
	[C6X_INS_MPY32SU] = "mpy32su",
	[C6X_INS_MPY32U] = "mpy32u",
	[C6X_INS_MPY32US] = "mpy32us",
	[C6X_INS_MPYDP] = "mpydp",
	[C6X_INS_MPYH] = "mpyh",
	[C6X_INS_MPYHI] = "mpyhi",
	[C6X_INS_MPYHIR] = "mpyhir",
	[C6X_INS_MPYHL] = "mpyhl",
	[C6X_INS_MPYHLU] = "mpyhlu",
	[C6X_INS_MPYHSLU] = "mpyhslu",
	[C6X_INS_MPYHSU] = "mpyhsu",
	[C6X_INS_MPYHU] = "mpyhu",
	[C6X_INS_MPYHULS] = "mpyhuls",
	[C6X_INS_MPYHUS] = "mpyhus",
	[C6X_INS_MPYI] = "mpyi",
	[C6X_INS_MPYID] = "mpyid",
	[C6X_INS_MPYLH] = "mpylh",
	[C6X_INS_MPYLHU] = "mpylhu",
	[C6X_INS_MPYLI] = "mpyli",
	[C6X_INS_MPYLIR] = "mpylir",
	[C6X_INS_MPYLSHU] = "mpylshu",
	[C6X_INS_MPYLUHS] = "mpyluhs",
	[C6X_INS_MPYSP] = "mpysp",
	[C6X_INS_MPYSP2DP] = "mpysp2dp",
	[C6X_INS_MPYSPDP] = "mpyspdp",
	[C6X_INS_MPYSU] = "mpysu",
	[C6X_INS_MPYSU4] = "mpysu4",
	[C6X_INS_MPYU] = "mpyu",
	[C6X_INS_MPYU4] = "mpyu4",
	[C6X_INS_MPYUS] = "mpyus",
	[C6X_INS_MV] = "mv",
	[C6X_INS_MVC] = "mvc",
	[C6X_INS_MVD] = "mvd",
	[C6X_INS_MVK] = "mvk",
	[C6X_INS_MVKH] = "mvkh",
	[C6X_INS_NEG] = "neg",
	[C6X_INS_NOP] = "nop",
	[C6X_INS_NORM] = "norm",
	[C6X_INS_NOT] = "not",
	[C6X_INS_OR] = "or",
	[C6X_INS_PACK2] = "pack2",
	[C6X_INS_PACKH2] = "packh2",
	[C6X_INS_PACKH4] = "packh4",
	[C6X_INS_PACKHL2] = "packhl2",
	[C6X_INS_PACKL4] = "packl4",
	[C6X_INS_PACKLH2] = "packlh2",
	[C6X_INS_QMPY32] = "qmpy32",
	[C6X_INS_QMPYSP] = "qmpysp",
	[C6X_INS_QSMPY32R1] = "qsmpy32r1",
	[C6X_INS_RINT] = "rint",
	[C6X_INS_ROTL] = "rotl",
	[C6X_INS_RPACK2] = "rpack2",
	[C6X_INS_RSQRDP] = "rsqrdp",
	[C6X_INS_SADD] = "sadd",
	[C6X_INS_SADD2] = "sadd2",
	[C6X_INS_SADDU4] = "saddu4",
	[C6X_INS_SADDUS2] = "saddus2",
	[C6X_INS_SAT] = "sat",
	[C6X_INS_SET] = "set",
	[C6X_INS_SHFL] = "shfl",
	[C6X_INS_SHL] = "shl",
	[C6X_INS_SHLMB] = "shlmb",
	[C6X_INS_SHR] = "shr",
	[C6X_INS_SHR2] = "shr2",
	[C6X_INS_SHRMB] = "shrmb",
	[C6X_INS_SHRU] = "shru",
	[C6X_INS_SHRU2] = "shru2",
	[C6X_INS_SMPY] = "smpy",
	[C6X_INS_SMPY2] = "smpy2",
	[C6X_INS_SMPYH] = "smpyh",
	[C6X_INS_SMPYHL] = "smpyhl",
	[C6X_INS_SMPYLH] = "smpylh",
	[C6X_INS_SPACK2] = "spack2",
	[C6X_INS_SPACKU4] = "spacku4",
	[C6X_INS_SPDP] = "spdp",
	[C6X_INS_SPINT] = "spint",
	[C6X_INS_SPLOOP] = "sploop",
	[C6X_INS_SPLOOPD] = "sploopd",
	[C6X_INS_SPLOOPW] = "sploopw",
	[C6X_INS_SPKERNEL] = "spkernel",
	[C6X_INS_SPKERNELR] = "spkernelr",
	[C6X_INS_SPMASK] = "spmask",
	[C6X_INS_SPMASKR] = "spmaskr",
	[C6X_INS_SPTRUNC] = "sptrunc",
	[C6X_INS_SSHL] = "sshl",
	[C6X_INS_SSHVL] = "sshvl",
	[C6X_INS_SSHVR] = "sshvr",
	[C6X_INS_SSUB] = "ssub",
	[C6X_INS_SSUB2] = "ssub2",
	[C6X_INS_STB] = "stb",
	[C6X_INS_STDW] = "stdw",
	[C6X_INS_STH] = "sth",
	[C6X_INS_STNDW] = "stndw",
	[C6X_INS_STNW] = "stnw",
	[C6X_INS_STW] = "stw",
	[C6X_INS_SUB] = "sub",
	[C6X_INS_SUB2] = "sub2",
	[C6X_INS_SUB4] = "sub4",
	[C6X_INS_SUBAB] = "subab",
	[C6X_INS_SUBAH] = "subah",
	[C6X_INS_SUBAW] = "subaw",
	[C6X_INS_SUBC] = "subc",
	[C6X_INS_SUBDP] = "subdp",
	[C6X_INS_SUBSP] = "subsp",
	[C6X_INS_SUBU] = "subu",
	[C6X_INS_SWAP4] = "swap4",
	[C6X_INS_UNPKHU4] = "unpkhu4",
	[C6X_INS_UNPKLU4] = "unpklu4",
	[C6X_INS_XOR] = "xor",
	[C6X_INS_XORMPY] = "xormpy",
	[C6X_INS_XPND2] = "xpnd2",
	[C6X_INS_XPND4] = "xpnd4",
	[C6X_INS_ZERO] = "zero",
};

/**
 * Printed mnemonic of \p id, or NULL when the opcode is not recognised.
 */
RZ_IPI const char *c6x_ins_name(C6xInsnId id) {
	return id > C6X_INS_INVALID && id < C6X_INS_LAST ? c6x_ins_names[id] : NULL;
}

// Record identity and printed form together so the two cannot drift apart.
static void set_ins(C6xInsn *insn, C6xInsnId id) {
	insn->id = id;
	insn->mnemonic = c6x_ins_name(id);
}

typedef struct {
	ut16 op; ///< opfield value within the format
	C6xInsnId id; ///< opcode identity
	ut8 src1; ///< C6xSrc1Kind
	ut8 feat; ///< C6xFeat gate
	_RzAnalysisOpType type; ///< analysis classification
	bool pair; ///< operands are 64-bit register pairs (double precision)
	ut8 oshape; ///< C6xOShape override for mixed single/pair operands
	bool src1_cross; ///< the cross-path (x) bit selects src1's side, not src2's
	bool no_operand_swap; ///< keep the src1, src2 print order for shift-typed ops
			      ///< that are not reversed-syntax (SHLMB/SHRMB)
} C6xRow;

// .L unit, 7-bit opfield at bits 11:5 (SPRU733 Table 3-12 and per-instruction
// opcodes). Fixed-point base plus the C67x floating-point set.
static const C6xRow c6x_l_rows[] = {
	{ 0x03, C6X_INS_ADD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x23, C6X_INS_ADD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD, false, OSHAPE_TO_DP },
	{ 0x21, C6X_INS_ADD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD, false, OSHAPE_LONG_DST, true },
	{ 0x02, C6X_INS_ADD, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x20, C6X_INS_ADD, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x2b, C6X_INS_ADDU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x29, C6X_INS_ADDU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x07, C6X_INS_SUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x17, C6X_INS_SUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_UNIFORM, true },
	{ 0x27, C6X_INS_SUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_TO_DP },
	{ 0x37, C6X_INS_SUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_TO_DP, true },
	{ 0x06, C6X_INS_SUB, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x24, C6X_INS_SUB, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x4b, C6X_INS_SUBC, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x2f, C6X_INS_SUBU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	// unsigned subtract widening into a register pair: both sources stay single
	{ 0x3f, C6X_INS_SUBU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_TO_DP, true },
	{ 0x0f, C6X_INS_SSUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x0e, C6X_INS_SSUB, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x13, C6X_INS_SADD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x12, C6X_INS_SADD, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x7f, C6X_INS_OR, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x7e, C6X_INS_OR, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x7b, C6X_INS_AND, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x7a, C6X_INS_AND, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x6f, C6X_INS_XOR, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x6e, C6X_INS_XOR, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x7c, C6X_INS_ANDN, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x53, C6X_INS_CMPEQ, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x52, C6X_INS_CMPEQ, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x51, C6X_INS_CMPEQ, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x50, C6X_INS_CMPEQ, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x47, C6X_INS_CMPGT, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x46, C6X_INS_CMPGT, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x45, C6X_INS_CMPGT, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x44, C6X_INS_CMPGT, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x4f, C6X_INS_CMPGTU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x4e, C6X_INS_CMPGTU, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x4d, C6X_INS_CMPGTU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x4c, C6X_INS_CMPGTU, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x57, C6X_INS_CMPLT, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x56, C6X_INS_CMPLT, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x55, C6X_INS_CMPLT, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x54, C6X_INS_CMPLT, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x5f, C6X_INS_CMPLTU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x5e, C6X_INS_CMPLTU, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x5d, C6X_INS_CMPLTU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x5c, C6X_INS_CMPLTU, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x6b, C6X_INS_LMBD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x6a, C6X_INS_LMBD, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x63, C6X_INS_NORM, SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x60, C6X_INS_NORM, SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	{ 0x61, C6X_INS_SHLMB, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SHL, false, OSHAPE_UNIFORM, false, true },
	{ 0x62, C6X_INS_SHRMB, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SHR, false, OSHAPE_UNIFORM, false, true },
	{ 0x1a, C6X_INS_ABS, SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ABS },
	{ 0x38, C6X_INS_ABS, SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ABS, true },
	{ 0x40, C6X_INS_SAT, SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	// C67x floating-point on .L. Single precision uses scalar registers;
	// double precision uses 64-bit register pairs.
	{ 0x10, C6X_INS_ADDSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x11, C6X_INS_SUBSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x18, C6X_INS_ADDDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD, true },
	{ 0x19, C6X_INS_SUBDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true },
	// src1-cross forms of the non-commutative FP subtracts (x selects src1).
	{ 0x15, C6X_INS_SUBSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_UNIFORM, true },
	{ 0x1d, C6X_INS_SUBDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true, OSHAPE_UNIFORM, true },
	// int/float conversions and truncation (unary src2 -> dst).
	{ 0x4a, C6X_INS_INTSP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x49, C6X_INS_INTSPU, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x0a, C6X_INS_SPINT, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x0b, C6X_INS_SPTRUNC, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x39, C6X_INS_INTDP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_TO_DP },
	{ 0x3b, C6X_INS_INTDPU, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_TO_DP },
	// double-precision -> integer / single conversions (unary DP pair src2 ->
	// single dst; op fields 0x08/0x09/0x01 per SPRUFE8, encoded but not
	// disassembled by dis6x). CMP_LONG shapes the pair src2 and single dst.
	{ 0x08, C6X_INS_DPINT, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	{ 0x09, C6X_INS_DPSP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	{ 0x01, C6X_INS_DPTRUNC, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	// C64x+ SIMD pack/interleave: pack halfwords or bytes from two source
	// registers into one; single registers, src1/src2/dst in the usual order.
	{ 0x00, C6X_INS_PACK2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x1e, C6X_INS_PACKH2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x1b, C6X_INS_PACKLH2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x1c, C6X_INS_PACKHL2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x68, C6X_INS_PACKL4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x69, C6X_INS_PACKH4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	// C64x+ packed add/sub (halfword pairs, byte quads) and lane min/max. The
	// saturating ssub2 and the *4 byte forms are single registers throughout.
	{ 0x04, C6X_INS_SUB2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x05, C6X_INS_ADD2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x41, C6X_INS_MIN2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x42, C6X_INS_MAX2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x43, C6X_INS_MAXU4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x48, C6X_INS_MINU4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x64, C6X_INS_SSUB2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x65, C6X_INS_ADD4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x66, C6X_INS_SUB4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SUB },
	// C66x SIMD double add: scst5 src1 with register-pair src2 and dst.
	{ 0x22, C6X_INS_DADD, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD, true },
};

// Floating-point add/sub also issue on the .S unit. They share the .L
// 1-or-2-source format (bits 4:2 == 110, 7-bit opfield) but their opfields
// (0x70..0x77) name the .S unit. SUBSP/SUBDP have a second, cross-path
// (xsint) opfield like their .L counterparts; the DP forms are register pairs.
static const C6xRow c6x_s_fp_rows[] = {
	{ 0x70, C6X_INS_ADDSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x71, C6X_INS_SUBSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x75, C6X_INS_SUBSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_UNIFORM, true },
	{ 0x72, C6X_INS_ADDDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD, true },
	{ 0x73, C6X_INS_SUBDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true },
	{ 0x77, C6X_INS_SUBDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true, OSHAPE_UNIFORM, true },
};

// .D-unit extended logic/arith (C64x+): bits 5:2 == 1100, bits 11:10 == 10,
// 4-bit opfield at bits 9:6. Operand layout matches the standard 3-op form
// (src1, src2, dst; the x bit crosses src2). AND/OR/XOR each have a register
// (uint) and a scst5 form; ADD carries a 5-bit signed constant. OR with a zero
// constant is the MV idiom, but the underlying opcode is what we render.
static const C6xRow c6x_d_ext_rows[] = {
	{ 0x2, C6X_INS_OR, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x3, C6X_INS_OR, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x6, C6X_INS_AND, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x7, C6X_INS_AND, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0xb, C6X_INS_ADD, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0xe, C6X_INS_XOR, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0xf, C6X_INS_XOR, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_XOR },
};

// .S unit, 6-bit opfield at bits 11:6, signature bits 5:2 == 1000.
static const C6xRow c6x_s_rows[] = {
	{ 0x07, C6X_INS_ADD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x06, C6X_INS_ADD, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x17, C6X_INS_SUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x16, C6X_INS_SUB, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x01, C6X_INS_ADD2, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x11, C6X_INS_SUB2, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	// Shifts (S3/S3i, SPRUFE8 SHL/SHR/SHRU/SSHL opcode maps). op bit 0 selects
	// the register (1) vs ucst5 (0) src1 form. The slong (40-bit, register-pair)
	// variants are omitted; they need src2/dst-only pairing that this shared
	// path cannot yet express.
	{ 0x33, C6X_INS_SHL, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x32, C6X_INS_SHL, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x31, C6X_INS_SHL, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL, true },
	{ 0x30, C6X_INS_SHL, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL, true },
	{ 0x13, C6X_INS_SHL, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x12, C6X_INS_SHL, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x37, C6X_INS_SHR, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SAR },
	{ 0x36, C6X_INS_SHR, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SAR },
	{ 0x27, C6X_INS_SHRU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHR },
	{ 0x26, C6X_INS_SHRU, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHR },
	{ 0x23, C6X_INS_SSHL, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x22, C6X_INS_SSHL, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x1f, C6X_INS_AND, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x1e, C6X_INS_AND, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x0b, C6X_INS_XOR, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x0a, C6X_INS_XOR, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x1b, C6X_INS_OR, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x1a, C6X_INS_OR, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x36, C6X_INS_ANDN, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	// single-precision float compares: src1, src2, dst all single
	{ 0x38, C6X_INS_CMPEQSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x39, C6X_INS_CMPGTSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x3a, C6X_INS_CMPLTSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP },
	// double-precision float compares: src1/src2 pairs, dst single sint
	{ 0x28, C6X_INS_CMPEQDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP, true, OSHAPE_CMP_DP },
	{ 0x29, C6X_INS_CMPGTDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP, true, OSHAPE_CMP_DP },
	{ 0x2a, C6X_INS_CMPLTDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP, true, OSHAPE_CMP_DP },
	// abs (unary, src2 -> dst): single for SP, pair for DP
	{ 0x3c, C6X_INS_ABSSP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ABS },
	{ 0x2c, C6X_INS_ABSDP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ABS, true },
	// reciprocal square-root, DP (unary, pair)
	{ 0x2e, C6X_INS_RSQRDP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, true },
	// SP -> DP widening convert (unary, single src2 -> pair dst)
	{ 0x02, C6X_INS_SPDP, SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_TO_DP },
	// C64x+ packed byte/halfword reshuffles and packed compares (normal .S
	// format). The compares set one result bit per lane in the dst.
	{ 0x08, C6X_INS_PACKHL2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x10, C6X_INS_PACKLH2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x14, C6X_INS_CMPGT2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x15, C6X_INS_CMPGTU4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x1c, C6X_INS_CMPEQ4, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x1d, C6X_INS_CMPEQ2, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
};

// .M unit, 5-bit opfield at bits 11:7, signature bits 6:2 == 00000.
static const C6xRow c6x_m_rows[] = {
	{ 0x18, C6X_INS_MPY, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x19, C6X_INS_MPY, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1f, C6X_INS_MPYU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1d, C6X_INS_MPYUS, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1b, C6X_INS_MPYSU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1e, C6X_INS_MPYSU, SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x01, C6X_INS_MPYH, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x07, C6X_INS_MPYHU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x05, C6X_INS_MPYHUS, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x03, C6X_INS_MPYHSU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x11, C6X_INS_MPYLH, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x17, C6X_INS_MPYLHU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x15, C6X_INS_MPYLUHS, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x13, C6X_INS_MPYLSHU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x09, C6X_INS_MPYHL, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0f, C6X_INS_MPYHLU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0d, C6X_INS_MPYHULS, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0b, C6X_INS_MPYHSLU, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1a, C6X_INS_SMPY, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x02, C6X_INS_SMPYH, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0a, C6X_INS_SMPYHL, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x12, C6X_INS_SMPYLH, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1c, C6X_INS_MPYSP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0e, C6X_INS_MPYDP, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL, true },
	{ 0x04, C6X_INS_MPYI, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL },
	// MPYID writes the full 64-bit product of the same 32x32 into a pair.
	{ 0x08, C6X_INS_MPYID, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL, false, OSHAPE_TO_DP },
	// MPY32 (C64x+): 32x32 multiply. The op-0x10 slot keeps the low 32 bits in
	// a single dst; op-0x14/0x16 write the full 64-bit product to a pair.
	{ 0x10, C6X_INS_MPY32, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x14, C6X_INS_MPY32, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MUL, false, OSHAPE_TO_DP },
	{ 0x16, C6X_INS_MPY32SU, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MUL, false, OSHAPE_TO_DP },
};

// Extended .M (C64x+): bits 5:2 == 1100 with bits 11:10 in {0,1} select the .M
// unit, and the (bits 11:10, bits 9:6) pair names the operation. The wide
// multiplies write a register pair; mpyspdp additionally reads a pair src2.
typedef struct {
	ut8 sub; ///< bits 11:10
	ut8 op; ///< bits 9:6
	C6xInsnId id;
	ut8 feat;
	bool dst_pair; ///< dst is a 64-bit register pair
	bool src2_pair; ///< src2 is a 64-bit register pair
	_RzAnalysisOpType type;
	bool src1_cross; ///< the cross-path (x) bit selects src1's side (mpyspdp)
	bool swap; ///< reversed syntax src2, src1, dst (sshvl/sshvr/rotl)
	bool src1_cst; ///< src1 is a 5-bit constant rather than a register
} C6xMExtRow;

static const C6xMExtRow c6x_m_ext_rows[] = {
	{ 0, 0, C6X_INS_MPY2, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 1, C6X_INS_SMPY2, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 2, C6X_INS_DOTPSU4, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 4, C6X_INS_MPYU4, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 5, C6X_INS_MPYSU4, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 6, C6X_INS_DOTPU4, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 7, C6X_INS_DOTPNRSU2, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 9, C6X_INS_DOTPN2, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 12, C6X_INS_DOTP2, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 13, C6X_INS_DOTPRSU2, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 14, C6X_INS_MPYLIR, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 0, C6X_INS_MPYHIR, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 1, C6X_INS_GMPY4, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 4, C6X_INS_MPYHI, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 5, C6X_INS_MPYLI, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 6, C6X_INS_MPYSPDP, FEAT_FP, true, true, RZ_ANALYSIS_OP_TYPE_MUL, true },
	{ 1, 7, C6X_INS_MPYSP2DP, FEAT_FP, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 8, C6X_INS_MPY32U, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 9, C6X_INS_MPY32US, FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 2, C6X_INS_AVGU4, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 1, 3, C6X_INS_AVG2, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 1, 10, C6X_INS_SSHVR, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_SHR, false, true },
	{ 1, 12, C6X_INS_SSHVL, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_SHL, false, true },
	{ 1, 13, C6X_INS_ROTL, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ROL },
	{ 1, 14, C6X_INS_ROTL, FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ROL, false, true, true },
};

// The bits 11:10 == 0, bits 9:6 == 3 slot is a family of unary moves and
// bit/byte shuffles (src2 -> dst) selected by the src1 field.
typedef struct {
	ut8 src1;
	C6xInsnId id;
} C6xMUnaryRow;

static const C6xMUnaryRow c6x_m_unary_rows[] = {
	{ 24, C6X_INS_XPND4 }, { 25, C6X_INS_XPND2 }, { 26, C6X_INS_MVD }, { 28, C6X_INS_SHFL },
	{ 29, C6X_INS_DEAL }, { 30, C6X_INS_BITC4 }, { 31, C6X_INS_BITR }
};

// C66x complex/matrix multiplies and 4-way dot products live in the extended
// .M space too, but are always unconditional and mark it with z = 1, creg = 0
// -- that pattern tells them apart from the C64x+ op in the same slot. The
// complex multiplies and Galois ops reach C674x; the double/4H forms are C66x.
typedef struct {
	ut8 sub; ///< bits 11:10
	ut8 op; ///< bits 9:6
	C6xInsnId id;
	ut8 feat;
	ut8 k1; ///< src1 operand kind (C6X_OP_REG / _REGPAIR / _REGQUAD)
	ut8 k2; ///< src2 operand kind
	ut8 k3; ///< dst operand kind
} C6xMCplxRow;

static const C6xMCplxRow c6x_m_cplx_rows[] = {
	{ 0, 5, C6X_INS_DOTPSU4H, FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REG },
	{ 0, 6, C6X_INS_DOTP4H, FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REG },
	{ 0, 10, C6X_INS_CMPY, FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REGPAIR },
	{ 0, 11, C6X_INS_CMPYR, FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG },
	{ 0, 12, C6X_INS_CMPYR1, FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG },
	{ 0, 13, C6X_INS_DCMPYR1, FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REGPAIR },
	{ 0, 14, C6X_INS_DCCMPYR1, FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REGPAIR },
	{ 1, 6, C6X_INS_DDOTPL2, FEAT_CPLX, C6X_OP_REGPAIR, C6X_OP_REG, C6X_OP_REGPAIR },
	{ 1, 7, C6X_INS_DDOTPH2, FEAT_CPLX, C6X_OP_REGPAIR, C6X_OP_REG, C6X_OP_REGPAIR },
	{ 1, 10, C6X_INS_QSMPY32R1, FEAT_C66X, C6X_OP_REGQUAD, C6X_OP_REGQUAD, C6X_OP_REGQUAD },
	{ 1, 11, C6X_INS_XORMPY, FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG },
	{ 1, 15, C6X_INS_GMPY, FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG }
};

// C66x quad/matrix multiplies sit in the normal .M format but, like the complex
// ops, mark themselves unconditional with z = 1, creg = 0. They take 128-bit
// register quads; cmatmpy reads its pair src1 and quad src2 from swapped fields.
typedef struct {
	ut8 op; ///< opcode bits 11:7
	C6xInsnId id;
	ut8 k1; ///< src1 operand kind (C6X_OP_REG / _REGPAIR / _REGQUAD)
	ut8 k2; ///< src2 operand kind
	ut8 k3; ///< dst operand kind
	bool swap; ///< src1 is in the src2 field and vice versa
} C6xMWideRow;

static const C6xMWideRow c6x_m_wide_rows[] = {
	{ 0x04, C6X_INS_CMATMPY, C6X_OP_REGPAIR, C6X_OP_REGQUAD, C6X_OP_REGQUAD, true },
	{ 0x06, C6X_INS_CMATMPYR1, C6X_OP_REGPAIR, C6X_OP_REGQUAD, C6X_OP_REGPAIR, true },
	{ 0x10, C6X_INS_QMPY32, C6X_OP_REGQUAD, C6X_OP_REGQUAD, C6X_OP_REGQUAD, false },
	{ 0x1c, C6X_INS_DMPYSP, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REGPAIR, false },
	{ 0x1d, C6X_INS_QMPYSP, C6X_OP_REGQUAD, C6X_OP_REGQUAD, C6X_OP_REGQUAD, false }
};

// Extended .S (C64x+): bits 5:2 == 1100, bits 11:10 == 11, op at bits 9:6.
// Packed shifts, saturating add/pack and andn; register src1, src2, dst.
typedef struct {
	ut8 op; ///< bits 9:6
	C6xInsnId id;
	_RzAnalysisOpType type;
	bool swap; ///< render src2 (value) before src1 (count), as shifts do
} C6xSExtRow;

static const C6xSExtRow c6x_s_ext_rows[] = {
	{ 0, C6X_INS_SADD2, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 1, C6X_INS_SADDUS2, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 3, C6X_INS_SADDU4, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 2, C6X_INS_SPACK2, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 4, C6X_INS_SPACKU4, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 6, C6X_INS_ANDN, RZ_ANALYSIS_OP_TYPE_AND },
	{ 7, C6X_INS_SHR2, RZ_ANALYSIS_OP_TYPE_SHR, true },
	{ 8, C6X_INS_SHRU2, RZ_ANALYSIS_OP_TYPE_SHR, true },
	{ 9, C6X_INS_SHLMB, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 10, C6X_INS_SHRMB, RZ_ANALYSIS_OP_TYPE_SHR },
	{ 11, C6X_INS_RPACK2, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 15, C6X_INS_PACK2, RZ_ANALYSIS_OP_TYPE_MOV }
};

// The .L opfield 0x1a (nominally ABS) is shared by unary byte/halfword
// reshuffles on C64x+, selected by the src1 field (src2 -> dst).
static const C6xMUnaryRow c6x_l_unary_rows[] = {
	{ 1, C6X_INS_SWAP4 }, { 2, C6X_INS_UNPKLU4 }, { 3, C6X_INS_UNPKHU4 }, { 4, C6X_INS_ABS2 }
};

// .D unit arithmetic and address ops, 6-bit opfield at bits 12:7, signature
// bits 6:2 == 10000 (SPRU733 Figure C-1 body).
static const C6xRow c6x_d_rows[] = {
	{ 0x10, C6X_INS_ADD, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x12, C6X_INS_ADD, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x11, C6X_INS_SUB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x13, C6X_INS_SUB, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x30, C6X_INS_ADDAB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x32, C6X_INS_ADDAB, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x34, C6X_INS_ADDAH, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x36, C6X_INS_ADDAH, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x38, C6X_INS_ADDAW, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3a, C6X_INS_ADDAW, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3c, C6X_INS_ADDAD, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3c, C6X_INS_ADDAD, SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3d, C6X_INS_ADDAD, SRC1_UCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3d, C6X_INS_ADDAD, SRC1_UCST5, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x31, C6X_INS_SUBAB, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x35, C6X_INS_SUBAH, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x37, C6X_INS_SUBAH, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x39, C6X_INS_SUBAW, SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x3b, C6X_INS_SUBAW, SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
};

// .D-unit extended logical/arith (C64x+): SPRUFE8 Dx2/Dx5 family, marked by
// bits 5:2 == 1100 with bits 11:10 == 10 selecting the .D unit. The op is a
// 4-bit field at bits 9:6; OR with a zero source constant becomes MV.
static const C6xRow c6x_dext_rows[] = {
	{ 0x0, C6X_INS_ANDN, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x2, C6X_INS_OR, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x3, C6X_INS_OR, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x6, C6X_INS_AND, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x7, C6X_INS_AND, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0xa, C6X_INS_ADD, SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0xf, C6X_INS_XOR, SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_XOR },
};

// .D unit loads/stores, 3-bit opfield at bits 6:4, signature bits 3:2 == 01
// (SPRU733 Tables 3-17/3-19). The op encodes access width and direction.
static const struct {
	ut8 op;
	C6xInsnId id;
	bool store;
} c6x_mem_rows[] = {
	{ 0x0, C6X_INS_LDHU, false },
	{ 0x1, C6X_INS_LDBU, false },
	{ 0x2, C6X_INS_LDB, false },
	{ 0x3, C6X_INS_STB, true },
	{ 0x4, C6X_INS_LDH, false },
	{ 0x5, C6X_INS_STH, true },
	{ 0x6, C6X_INS_LDW, false },
	{ 0x7, C6X_INS_STW, true },
};

static const C6xArchDesc c6x_desc_c62x = { C6X_GEN_C62X, 16, 0 };
static const C6xArchDesc c6x_desc_c67x = { C6X_GEN_C67X, 16, C6X_FEAT_FP };
static const C6xArchDesc c6x_desc_c64x = { C6X_GEN_C64X, 32, C6X_FEAT_SIMD };
static const C6xArchDesc c6x_desc_c674x = { C6X_GEN_C674X, 32, C6X_FEAT_FP | C6X_FEAT_SIMD };
static const C6xArchDesc c6x_desc_c66x = { C6X_GEN_C66X, 32, C6X_FEAT_FP | C6X_FEAT_SIMD };

/** Resolve an asm.cpu string to a descriptor, or NULL if it is not a C6000 cpu. */
RZ_IPI const C6xArchDesc *c6x_desc_from_cpu(const char *cpu) {
	if (!cpu) {
		return NULL;
	}
	if (!rz_str_casecmp(cpu, "c62x")) {
		return &c6x_desc_c62x;
	}
	if (!rz_str_casecmp(cpu, "c67x")) {
		return &c6x_desc_c67x;
	}
	if (!rz_str_casecmp(cpu, "c64x")) {
		return &c6x_desc_c64x;
	}
	// C64x+ is a superset of C64x; the extra instructions this engine decodes
	// are gated by the SIMD feature the C64x descriptor already carries.
	if (!rz_str_casecmp(cpu, "c64x+") || !rz_str_casecmp(cpu, "c64xp") ||
		!rz_str_casecmp(cpu, "c64x_plus")) {
		return &c6x_desc_c64x;
	}
	if (!rz_str_casecmp(cpu, "c674x")) {
		return &c6x_desc_c674x;
	}
	if (!rz_str_casecmp(cpu, "c66x")) {
		return &c6x_desc_c66x;
	}
	return NULL;
}

/**
 * \brief Flag whether \p insn continues the previous execute packet.
 *
 * TI marks an instruction with "||" when it runs in parallel with the one
 * before it, i.e. when the *previous* word set its parallel bit. Decoding is
 * stateless, so \p prev_end (address just past the last instruction) and
 * \p prev_par (its parallel bit) carry that one-word look-back across calls;
 * both are updated for the next call.
 */
RZ_IPI void c6x_mark_parallel(RZ_INOUT C6xInsn *insn, ut64 addr, RZ_INOUT ut64 *prev_end, RZ_INOUT bool *prev_par) {
	if (insn->is_header) {
		// a fetch-packet header occupies a word but is not part of any execute
		// packet: keep it out of the "||" chain and pass the previous parallel
		// state through unchanged so an execute packet can span the header
		insn->cont = false;
		*prev_end = addr + insn->size;
		return;
	}
	// only a word landing exactly after the previous one continues its packet;
	// a gap (random-access disassembly, region restart) starts fresh
	insn->cont = addr == *prev_end && *prev_par;
	*prev_end = addr + insn->size;
	*prev_par = insn->parallel;
}

static bool feat_ok(const C6xArchDesc *d, ut8 feat) {
	switch (feat) {
	case FEAT_FP:
		return d->features & C6X_FEAT_FP;
	case FEAT_SIMD:
		return d->features & C6X_FEAT_SIMD;
	case FEAT_CPLX:
		return (d->features & (C6X_FEAT_FP | C6X_FEAT_SIMD)) == (C6X_FEAT_FP | C6X_FEAT_SIMD); // C674x and C66x
	case FEAT_C66X:
		return d->gen == C6X_GEN_C66X;
	default:
		return true;
	}
}

static const C6xRow *row_find(const C6xRow *rows, size_t n, ut16 op, const C6xArchDesc *d) {
	for (size_t i = 0; i < n; i++) {
		if (rows[i].op == op && feat_ok(d, rows[i].feat)) {
			return &rows[i];
		}
	}
	return NULL;
}

static void op_reg(C6xOperand *o, ut8 side, ut8 num) {
	o->kind = C6X_OP_REG;
	o->v.reg.side = side;
	o->v.reg.num = num;
}

static void op_regpair(C6xOperand *o, ut8 side, ut8 num) {
	o->kind = C6X_OP_REGPAIR;
	o->v.reg.side = side;
	o->v.reg.num = num & ~1u;
}

static void op_regquad(C6xOperand *o, ut8 side, ut8 num) {
	o->kind = C6X_OP_REGQUAD;
	o->v.reg.side = side;
	o->v.reg.num = num & ~3u;
}

// Fill a register operand of a caller-chosen width (single / pair / quad).
static void op_by_kind(C6xOperand *o, ut8 kind, ut8 side, ut8 num) {
	if (kind == C6X_OP_REGQUAD) {
		op_regquad(o, side, num);
	} else if (kind == C6X_OP_REGPAIR) {
		op_regpair(o, side, num);
	} else {
		op_reg(o, side, num);
	}
}

static void op_imm(C6xOperand *o, st64 v) {
	o->kind = C6X_OP_IMM;
	o->v.imm.value = v;
}

static void op_ctrlreg(C6xOperand *o, const char *name) {
	o->kind = C6X_OP_CTRLREG;
	o->v.ctrl = name;
}

// Field values that select a top-level format of a 32-bit instruction word.
typedef enum {
	C6X_DFMT_LDST = 0x1, ///< .D load/store, bits 3:2
	C6X_DFMT_LDST_LONG = 0x3, ///< .D long-immediate load/store off B14/B15, bits 3:2
	C6X_DFMT_MVK = 0x0, ///< MVK on the .D unit (C64x+), bits 12:7
	C6X_LFMT_1OR2SRC = 0x6, ///< .L one- or two-source, bits 4:2
	C6X_MOP_ABS = 0x05, ///< ABS, the unary form of the 5-bit constant move, bits 17:13
	C6X_MOP_MVK5 = 0x1a, ///< the 5-bit signed constant move, bits 11:5
	C6X_UNARY_SIG = 0x07, ///< unary forms carrying the creg = 0, z = 1 signature, bits 11:5
	C6X_UNARY_SIG_ALT = 0x03,
	C6X_DFMT_ADDA = 0x1, ///< the ADDAB/ADDAH/ADDAW address forms, bits 31:28
} C6xWordFormat;

/** The no-unit NOP: thirteen fixed low bits, with (count - 1) in bits 15:13. */
#define C6X_COMPACT_NOP 0x0c6e

/** A two-bit field set to both ones, used to widen a compact form. */
#define C6X_CFMT_BOTH_SET 0x3

// Compact-instruction format signatures. Which format a 16-bit opcode uses is
// spread over several fields rather than one, so each is picked out by the bits
// TI's figure for it fixes; the names follow those figures.
typedef enum {
	C6X_CFMT_MPY = 0xf, ///< compact .M multiply, bits 4:1
	C6X_CFMT_SX1_3REG = 0x5, ///< Sx1 three-register add/subtract, bits 3:1
	C6X_CFMT_LSX1_1REG = 0x6, ///< Lx1/Sx1 one-register form, bits 6:4
	C6X_CFMT_DX1_1REG = 0x7, ///< the .D-unit spelling of the same, bits 6:4
	C6X_CFMT_DX2 = 0x17, ///< Dx2 byte/halfword load-store, bits 6:1
	C6X_CFMT_DX5P = 0x1b, ///< Dx5p stack access, bits 6:1
	C6X_CFMT_LOOP = 0x33, ///< loop-buffer group (SPLOOP/SPMASK), bits 6:1
	C6X_CFMT_DX5 = 0x3b, ///< Dx5 stack-adjust pair, bits 6:1
} C6xCompactFormat;

// The .S one-or-two-source sub-opcode, bits 11:6 of the instruction word.
typedef enum {
	C6X_SOP_BDEC = 0x00, ///< BDEC/BPOS, register-conditional loop branch (C64x+)
	C6X_SOP_B_IRP = 0x03, ///< B IRP/NRP, return from a (non)maskable interrupt
	C6X_SOP_BNOP_DISP = 0x04, ///< BNOP with a displacement (Figure F-10)
	C6X_SOP_ADDKPC = 0x05, ///< ADDKPC, PC-relative address form (.S2, C64x+)
	C6X_SOP_B_REG = 0x0d, ///< B src2, register branch (.S2 only)
	C6X_SOP_MVC_LO = 0x0e, ///< MVC, control-register move
	C6X_SOP_MVC_HI = 0x0f,
} C6xSUnitSubOp;

// The unit-selecting signature of a 32-bit instruction word, bits 6:2: which
// functional unit and top-level form the rest of the word encodes.
typedef enum {
	C6X_SIG_M = 0x00, ///< .M unit
	C6X_SIG_S_BRANCH = 0x04, ///< .S branch with a displacement
	C6X_SIG_D = 0x10, ///< .D arithmetic and address forms
	C6X_SIG_S_ADDK = 0x14, ///< .S ADDK
} C6xUnitSig;

// The bits 5:2 opcode group of a 32-bit instruction word: which family of
// forms the rest of the word is decoded as (SPRUFE8 Figures F-1 onwards).
typedef enum {
	C6X_OPGRP_FIELD = 0x2, ///< EXTU/EXT/SET/CLR, constant field form
	C6X_OPGRP_1OR2SRC = 0x8, ///< .S one- or two-source, 6-bit op field
	C6X_OPGRP_MVK = 0xa, ///< .S MVK/MVKH, bit 6 selects high
	C6X_OPGRP_EXT = 0xc, ///< .D and .L extended forms added by C64x+
} C6xOpGroup;

// Control registers by crlo field (SPRUFE8 Table 3-27).
static const char *const c6x_ctrlregs_by_crlo[32] = {
	"amr", "csr", NULL, "icr", "ier", "istp", "irp", "nrp",
	NULL, NULL, "tscl", "tsch", NULL, "ilc", "rilc", "rep",
	"pce1", "dnum", "fadcr", "faucr", "fmcr", "ssr", "gplya", "gplyb",
	"gfpgfr", "dier", "tsr", "itsr", "ntsr", NULL, NULL, "ierr"
};

// crlo 2 and 29 name a different register per direction, disambiguated by \p read.
static const char *ctrlreg_name(ut8 crlo, bool read) {
	if (crlo == 2) {
		return read ? "ifr" : "isr";
	}
	if (crlo == 29) {
		return read ? "efr" : "ecr";
	}
	return c6x_ctrlregs_by_crlo[crlo];
}

// Sign-extend the low \p bits of \p v. The cast goes through st32 so the sign
// bit propagates: without it the ut32 subtraction wraps and widens to a large
// positive st64 (which broke backward branches and negative constants).
static st64 sext(ut32 v, ut8 bits) {
	ut32 m = 1u << (bits - 1);
	return (st64)(st32)((v ^ m) - m);
}

// Fill src1 (bits 17:13) as register or short constant per the row's kind.
static void fill_src1(C6xOperand *o, ut32 w, ut8 side, C6xSrc1Kind kind) {
	ut8 f = BITS(w, 17, 13);
	switch (kind) {
	case SRC1_REG:
		op_reg(o, side, f);
		break;
	case SRC1_SCST5:
		op_imm(o, sext(f, 5));
		break;
	case SRC1_UCST5:
		op_imm(o, f);
		break;
	default:
		o->kind = C6X_OP_NONE;
		break;
	}
}

// .L/.S/.M 3-operand form: dst, src2 (cross-pathable), src1 (reg or const).
// Double-precision rows read and write 64-bit register pairs instead of scalars.
static void decode_3op(C6xInsn *insn, const C6xRow *row) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 x = BIT(w, 12);
	set_ins(insn, row->id);
	insn->op_type = row->type;
	insn->is_fp = row->feat == FEAT_FP;
	insn->unit_side = s;
	insn->cross = x != 0;
	// The cross-path (x) bit moves one source operand to the opposite register
	// side. It normally selects src2; src1-cross variants (non-commutative ops
	// such as SUBSP/SUBDP) apply it to src1 instead.
	ut8 src1_side = (row->src1_cross && x) ? !s : s;
	ut8 src2_side = (!row->src1_cross && x) ? !s : s;
	ut8 nops = 0;
	if (row->src1 != SRC1_NONE) {
		if (row->pair && row->src1 == SRC1_REG) {
			op_regpair(&OP(nops++), src1_side, BITS(w, 17, 13));
		} else {
			fill_src1(&OP(nops++), w, src1_side, row->src1);
		}
	}
	bool src2_pair = row->pair;
	bool dst_pair = row->pair;
	if (row->oshape == OSHAPE_CMP_DP) {
		dst_pair = false; // DP compare result is a single sint
	} else if (row->oshape == OSHAPE_TO_DP) {
		src2_pair = false; // a single src2 widened into a pair dst
		dst_pair = true;
	} else if (row->oshape == OSHAPE_CMP_LONG) {
		src2_pair = true; // a 40-bit long src2 compared against a single/const
		dst_pair = false;
	} else if (row->oshape == OSHAPE_LONG_DST) {
		src2_pair = true; // long ADD: single src1 + long src2 -> long dst
		dst_pair = true;
	}
	if (src2_pair) {
		op_regpair(&OP(nops++), src2_side, BITS(w, 22, 18)); // src2
	} else {
		op_reg(&OP(nops++), src2_side, BITS(w, 22, 18)); // src2
	}
	// Shifts print value (src2) before count (src1); swap the two sources
	// that were emitted in the fixed src1, src2 order above.
	bool is_shift = row->type == RZ_ANALYSIS_OP_TYPE_SHL ||
		row->type == RZ_ANALYSIS_OP_TYPE_SHR || row->type == RZ_ANALYSIS_OP_TYPE_SAR;
	if (is_shift && nops == 2 && !row->no_operand_swap) {
		C6xOperand tmp = OP(0);
		OP(0) = OP(1);
		OP(1) = tmp;
	}
	if (dst_pair) {
		op_regpair(&OP(nops++), s, BITS(w, 27, 23)); // dst
	} else {
		op_reg(&OP(nops++), s, BITS(w, 27, 23)); // dst
	}
	insn->nops = nops;
	// Render the .S/.L assembler idioms the way the TI tools do so the output
	// matches the reference disassembler:
	//   MV   dst = 0 | src   or   0 + src        (OR/ADD against 0)
	//   NEG  dst = 0 - src                        (SUB from 0)
	//   ZERO dst = src - src                      (SUB of a register from itself)
	//   SUB  src2, k, dst  for  ADD -k, src2, dst (negative-constant ADD)
	bool is_add = row->id == C6X_INS_ADD;
	bool is_sub = row->id == C6X_INS_SUB;
	bool is_or = row->id == C6X_INS_OR;
	bool is_xor = row->id == C6X_INS_XOR;
	if (nops == 3 && OP(0).kind == C6X_OP_IMM && OP(0).v.imm.value == 0 &&
		(is_or || is_add || is_sub)) {
		set_ins(insn, is_sub ? C6X_INS_NEG : C6X_INS_MV);
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		OP(0) = OP(1);
		OP(1) = OP(2);
		insn->nops = 2;
	} else if (nops == 3 && is_xor && OP(0).kind == C6X_OP_IMM &&
		OP(0).v.imm.value == -1) {
		set_ins(insn, C6X_INS_NOT); // XOR -1, src, dst  ==  NOT src, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOT;
		OP(0) = OP(1);
		OP(1) = OP(2);
		insn->nops = 2;
	} else if (nops == 3 && is_add && OP(0).kind == C6X_OP_IMM &&
		OP(0).v.imm.value < 0) {
		set_ins(insn, C6X_INS_SUB); // ADD -k, src2, dst  ==  SUB src2, k, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_SUB;
		st64 k = -OP(0).v.imm.value;
		OP(0) = OP(1);
		op_imm(&OP(1), k);
	} else if (nops == 3 && is_sub && OP(0).kind == C6X_OP_REG &&
		OP(1).kind == C6X_OP_REG && OP(0).v.reg.num == OP(1).v.reg.num &&
		OP(0).v.reg.side == OP(1).v.reg.side) {
		set_ins(insn, C6X_INS_ZERO); // SUB src, src, dst  ==  ZERO dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		OP(0) = OP(2);
		insn->nops = 1;
	}
}

// .D arithmetic/address form, all on side s with no cross path. The .D
// encoding places the base/src2 register at bits 22:18 and src1 (register or
// short constant) at bits 17:13, and the assembler prints them in that order
// -- src2, src1, dst -- for both plain ADD/SUB and the ADDA*/SUBA* address
// ops, unlike the .L/.S forms that print src1 first.
static void decode_darith(C6xInsn *insn, const C6xRow *row) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	set_ins(insn, row->id);
	insn->op_type = row->type;
	insn->unit_side = s;
	op_reg(&OP(0), s, BITS(w, 22, 18)); // src2 (base)
	fill_src1(&OP(1), w, s, row->src1); // src1 (offset/operand)
	op_reg(&OP(2), s, BITS(w, 27, 23)); // dst
	insn->nops = 3;
	// The .D unit shares the same assembler idioms as .L/.S: MV/NEG (ADD/SUB
	// against 0), NOT (XOR -1), ZERO (SUB of a register from itself), and the
	// negative-constant SUB spelled as ADD. In the .D operand order src2 comes
	// first, so the constant (when present) is src1 at ops[1].
	bool d_add = row->id == C6X_INS_ADD;
	bool d_sub = row->id == C6X_INS_SUB;
	bool d_xor = row->id == C6X_INS_XOR;
	if (OP(1).kind == C6X_OP_IMM && OP(1).v.imm.value == 0 && (d_add || d_sub)) {
		set_ins(insn, d_sub ? C6X_INS_NEG : C6X_INS_MV);
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		OP(1) = OP(2); // dst follows src
		insn->nops = 2;
	} else if (OP(1).kind == C6X_OP_IMM && OP(1).v.imm.value == -1 && d_xor) {
		set_ins(insn, C6X_INS_NOT); // XOR src, -1, dst  ==  NOT src, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOT;
		OP(1) = OP(2);
		insn->nops = 2;
	} else if (d_add && OP(1).kind == C6X_OP_IMM && OP(1).v.imm.value < 0) {
		set_ins(insn, C6X_INS_SUB); // ADD src2, -k, dst  ==  SUB src2, k, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_SUB;
		op_imm(&OP(1), -OP(1).v.imm.value);
	} else if (d_sub && OP(0).kind == C6X_OP_REG && OP(1).kind == C6X_OP_REG &&
		OP(0).v.reg.num == OP(1).v.reg.num && OP(0).v.reg.side == OP(1).v.reg.side) {
		set_ins(insn, C6X_INS_ZERO); // SUB src, src, dst  ==  ZERO dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		OP(0) = OP(2);
		insn->nops = 1;
	}
}

// .D long-immediate load/store: *+B14/B15[ucst15] (SPRU733 LDW 15-bit offset).
// Base is B14 (y=0) or B15 (y=1); the 15-bit unsigned offset sits at bits 22:8.
static void decode_ldst_long(C6xInsn *insn, C6xInsnId id, bool store) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 y = BIT(w, 7);
	C6xOperand mem = { 0 };
	C6xOperand reg = { 0 };
	set_ins(insn, id);
	insn->op_type = store ? RZ_ANALYSIS_OP_TYPE_STORE : RZ_ANALYSIS_OP_TYPE_LOAD;
	insn->unit = C6X_UNIT_D;
	insn->unit_side = C6X_SIDE_B; // B14/B15 are on the B side; .D2 only
	mem.kind = C6X_OP_MEM;
	mem.v.mem.mode = C6X_AM_POS_CST;
	mem.v.mem.base = y ? 15 : 14;
	mem.v.mem.base_side = 1;
	mem.v.mem.off_cst = BITS(w, 22, 8);
	mem.v.mem.scaled = true;
	op_reg(&reg, s, BITS(w, 27, 23));
	OP(0) = store ? reg : mem;
	OP(1) = store ? mem : reg;
	insn->nops = 2;
}

// .D address arithmetic with a 15-bit constant: B14/B15 + ucst15 -> dst. The
// family reuses the 15-bit-offset store slots -- ADDAB the STB one, ADDAH the
// STH one, ADDAW the STW one -- and is marked by the otherwise-reserved
// creg=0/z=1 pattern (bits 31:28 == 0001), so a real (predicated or plain)
// store there stays a store. The constant counts elements of the named width.
static void decode_addaw_long(C6xInsn *insn, C6xInsnId id) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 y = BIT(w, 7);
	set_ins(insn, id);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
	insn->unit = C6X_UNIT_D;
	insn->unit_side = s;
	// the base is always B14/B15, so an A-side destination reads across
	insn->cross = s == 0;
	op_reg(&OP(0), 1, y ? 15 : 14); // base B14/B15
	op_imm(&OP(1), BITS(w, 22, 8)); // ucst15
	OP(1).v.imm.decimal = true;
	op_reg(&OP(2), s, BITS(w, 27, 23)); // dst
	insn->nops = 3;
}

// .D load/store addressing mode (bits 12:9), Table 3-11.
static const C6xAddrMode c6x_ldst_modes[16] = {
	C6X_AM_NEG_CST, C6X_AM_POS_CST, C6X_AM_NEG_CST, C6X_AM_POS_CST,
	C6X_AM_NEG_REG, C6X_AM_POS_REG, C6X_AM_NEG_REG, C6X_AM_POS_REG,
	C6X_AM_PREDEC_CST, C6X_AM_PREINC_CST, C6X_AM_POSTDEC_CST, C6X_AM_POSTINC_CST,
	C6X_AM_PREDEC_REG, C6X_AM_PREINC_REG, C6X_AM_POSTDEC_REG, C6X_AM_POSTINC_REG
};

static C6xAddrMode ldst_mode(ut8 field, bool *reg_offset) {
	*reg_offset = (field & 0x4) != 0;
	return c6x_ldst_modes[field & 0xf];
}

static void decode_ldst(C6xInsn *insn, C6xInsnId id, bool store, bool dword) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 y = BIT(w, 7);
	bool reg_off = false;
	C6xOperand mem = { 0 };
	C6xOperand reg = { 0 };
	set_ins(insn, id);
	insn->op_type = store ? RZ_ANALYSIS_OP_TYPE_STORE : RZ_ANALYSIS_OP_TYPE_LOAD;
	insn->unit_side = y;
	mem.kind = C6X_OP_MEM;
	mem.v.mem.mode = ldst_mode(BITS(w, 12, 9), &reg_off);
	mem.v.mem.base = BITS(w, 22, 18);
	mem.v.mem.base_side = y;
	mem.v.mem.scaled = true; // [] bracket scaling by access size
	if (reg_off) {
		mem.v.mem.off_reg = BITS(w, 17, 13);
	} else {
		mem.v.mem.off_cst = BITS(w, 17, 13);
	}
	if (dword) {
		reg.kind = C6X_OP_REGPAIR;
		reg.v.reg.side = s;
		reg.v.reg.num = BITS(w, 27, 23) & ~1u;
	} else {
		op_reg(&reg, s, BITS(w, 27, 23));
	}
	// TI syntax: loads read "*mem, dst"; stores read "src, *mem".
	OP(0) = store ? reg : mem;
	OP(1) = store ? mem : reg;
	insn->nops = 2;
}

// .S branch to a register: B/BNOP (.S2) src2 (SPRU733 "Branch Using a
// Register"). src2 holds the target; a return is BNOP .S2 B3, 5. The 3-bit
// field at 15:13 is the NOP count -- when non-zero the assembler spells it
// BNOP; the C64x+ compiler uses BNOP B3, 5 as the return idiom.
static void decode_branch_reg(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 x = BIT(w, 12);
	ut8 n = BITS(w, 15, 13);
	set_ins(insn, n ? C6X_INS_BNOP : C6X_INS_B);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_RJMP;
	insn->unit_side = C6X_SIDE_B; // .S2 only
	insn->cross = x != 0;
	// src2 is read from the B side, or the A side when the cross path is used
	op_reg(&OP(0), x ? 0 : 1, BITS(w, 22, 18));
	insn->nops = 1;
	if (n) {
		op_imm(&OP(insn->nops++), n);
	}
}

// .S branch, 21-bit signed PC-relative displacement (scaled by 4), Figure F-5.
static void decode_branch(C6xInsn *insn) {
	ut32 w = insn->word;
	st64 disp = sext(BITS(w, 27, 7), 21) * 4;
	insn->unit_side = BIT(w, 1);
	OP(0).kind = C6X_OP_PCREL;
	OP(0).v.imm.value = disp; // absolute target resolved by the analysis filler
	insn->nops = 1;
	// CALLP is encoded as an otherwise-meaningless unconditional branch with the
	// z bit set; the return address is placed in A3 (.S1) or B3 (.S2).
	if (insn->creg == 0 && insn->z) {
		set_ins(insn, C6X_INS_CALLP);
		insn->op_type = RZ_ANALYSIS_OP_TYPE_CALL;
		op_reg(&OP(1), insn->unit_side, 3); // A3 on .S1, B3 on .S2
		insn->nops = 2;
		return;
	}
	set_ins(insn, C6X_INS_B);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_JMP;
}

// .S BNOP with a displacement (SPRUFE8 Figure F-10): a 12-bit signed
// displacement plus a NOP count. The displacement is word-scaled like the plain
// B -- asm6x encodes BNOP .S1 $+8 as 0x00028120, a field of 2 -- and stays
// packet-relative, so the analysis filler resolves it against PCE1. Only the
// compact branches are half-word-scaled, so that they can reach compact code.
static void decode_branch_nop(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 n = BITS(w, 15, 13);
	set_ins(insn, C6X_INS_BNOP);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_JMP;
	insn->unit_side = BIT(w, 1);
	OP(0).kind = C6X_OP_PCREL;
	OP(0).v.imm.value = sext(BITS(w, 27, 16), 12) * 4;
	op_imm(&OP(1), n);
	insn->nops = 2;
}
static void decode_mvk(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 h = BIT(w, 6);
	set_ins(insn, h ? C6X_INS_MVKH : C6X_INS_MVK);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
	insn->unit_side = s;
	op_imm(&OP(0), h ? (st64)BITS(w, 22, 7) : sext(BITS(w, 22, 7), 16));
	op_reg(&OP(1), s, BITS(w, 27, 23));
	insn->nops = 2;
}

// .S ADDK, 16-bit signed constant, Figure (ADDK opcode row bits 6:2 == 10100).
static void decode_addk(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	set_ins(insn, C6X_INS_ADDK);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
	insn->unit_side = s;
	op_imm(&OP(0), sext(BITS(w, 22, 7), 16));
	op_reg(&OP(1), s, BITS(w, 27, 23));
	insn->nops = 2;
}

// .S2 ADDKPC (C64x+): forms a PC-relative address, dst = PCE1 + scst7 * 4,
// and skips a following count (bits 15:13) of parallel NOP cycles. The target
// is rendered like a branch so it reads as an absolute address.
static void decode_addkpc(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	set_ins(insn, C6X_INS_ADDKPC);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
	insn->unit_side = s;
	OP(0).kind = C6X_OP_PCREL;
	OP(0).v.imm.value = sext(BITS(w, 22, 16), 7) * 4;
	op_reg(&OP(1), s, BITS(w, 27, 23)); // dst
	op_imm(&OP(2), BITS(w, 15, 13)); // parallel NOP count
	OP(2).v.imm.decimal = true;
	insn->nops = 3;
}

// .S BDEC/BPOS (C64x+ loop control): branch to PCE1 + scst10 * 4 while the
// named register is non-negative; BDEC also predecrements it. Bit 12 selects
// the decrementing form (1) over the plain positive test (0).
static void decode_bdec(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	set_ins(insn, BIT(w, 12) ? C6X_INS_BDEC : C6X_INS_BPOS);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_CJMP;
	insn->unit_side = s;
	OP(0).kind = C6X_OP_PCREL;
	OP(0).v.imm.value = sext(BITS(w, 22, 13), 10) * 4;
	op_reg(&OP(1), s, BITS(w, 27, 23)); // counter register
	insn->nops = 2;
}

// No-unit NOP (SPRU733 Appendix G): the word is all zero except the parallel bit
// and a 1..8 cycle count in bits 16:13 (count = field + 1). IDLE is a dedicated
// control opcode handled by the emulation format.
// No-unit formats spend on opcode the bits every other format spends on the
// predicate, so they carry neither a functional unit nor a creg/z guard. Each
// one keys its own table on the selector field named here.
#define C6X_NOUNIT_PARALLEL 1u ///< parallel bit, bit 0
#define C6X_NOUNIT_CNT      (0xfu << 13) ///< NOP count / interrupt op, bits 16:13
#define C6X_NOUNIT_SEL      (0x1fu << 13) ///< loop-buffer selector, bits 17:13
#define C6X_NOUNIT_II       (0x1fu << 23) ///< loop iteration interval, bits 27:23
#define C6X_NOUNIT_STGCYC   (0x3fu << 22) ///< SPKERNEL fstg/fcyc, bits 27:22
#define C6X_NOUNIT_UNITS    (0xffu << 18) ///< SPMASK unit list, bits 25:18
#define C6X_NOUNIT_PRED     0xf0000000u ///< creg/z, where the format is predicable
#define C6X_NOUNIT_INT      0x10000000u ///< the 0001 prefix marking DINT/RINT
#define C6X_NOP_IDLE_CNT    16 ///< the NOP count slot the IDLE opcode occupies

// What the loop-buffer formats spend their upper bits on.
typedef enum {
	NOUNIT_NO_OPERAND = 0, ///< no operand
	NOUNIT_II, ///< loop iteration interval, bits 27:23 plus one
	NOUNIT_STGCYC, ///< SPKERNEL fstg/fcyc boundary, bits 27:22
	NOUNIT_UNITS, ///< SPMASK functional-unit list, bits 25:18
} C6xNoUnitOperand;

typedef struct {
	ut8 sel; ///< selector value within the format
	C6xInsnId id; ///< opcode identity
	_RzAnalysisOpType type; ///< analysis classification
	ut8 operand; ///< C6xNoUnitOperand
	bool pred; ///< creg/z are a predicate here, not opcode
	ut8 feat; ///< C6xFeat gate
} C6xNoUnitRow;

// C64x+ software-pipelined loop buffer. SPLOOP and SPLOOPD carry the loop
// iteration interval; SPMASK does not.
static const C6xNoUnitRow c6x_sploop_rows[] = {
	{ 24, C6X_INS_SPMASK, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_UNITS, false, FEAT_SIMD },
	{ 25, C6X_INS_SPMASKR, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_UNITS, false, FEAT_SIMD },
	{ 26, C6X_INS_SPKERNEL, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_STGCYC, false, FEAT_SIMD },
	{ 27, C6X_INS_SPKERNELR, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_STGCYC, false, FEAT_SIMD },
	{ 28, C6X_INS_SPLOOP, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_II, true, FEAT_SIMD },
	{ 29, C6X_INS_SPLOOPD, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_II, true, FEAT_SIMD },
	{ 31, C6X_INS_SPLOOPW, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_II, true, FEAT_SIMD },
};

// Interrupt-enable control (SPRUFE8 Figure H-1).
static const C6xNoUnitRow c6x_int_rows[] = {
	{ 2, C6X_INS_DINT, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_NO_OPERAND, false, FEAT_SIMD },
	{ 3, C6X_INS_RINT, RZ_ANALYSIS_OP_TYPE_NULL, NOUNIT_NO_OPERAND, false, FEAT_SIMD },
};

static const C6xNoUnitRow *nounit_find(const C6xNoUnitRow *rows, size_t n, ut8 sel, const C6xArchDesc *d) {
	for (size_t i = 0; i < n; i++) {
		if (rows[i].sel == sel && feat_ok(d, rows[i].feat)) {
			return &rows[i];
		}
	}
	return NULL;
}

// Apply a matched no-unit row. Each format spends its upper bits differently, so
// the operand is taken from the field the row names.
static bool nounit_apply(C6xInsn *insn, const C6xNoUnitRow *r, ut32 w) {
	set_ins(insn, r->id);
	insn->op_type = r->type;
	insn->unit = C6X_UNIT_NONE;
	if (!r->pred) {
		// creg/z are opcode in these formats, not a guard
		insn->creg = 0;
		insn->z = 0;
	}
	switch (r->operand) {
	case NOUNIT_II:
		op_imm(&OP(0), BITS(w, 27, 23) + 1);
		insn->nops = 1;
		break;
	case NOUNIT_STGCYC:
		op_imm(&OP(0), BITS(w, 27, 22));
		insn->nops = 1;
		break;
	case NOUNIT_UNITS:
		OP(0).kind = C6X_OP_UNITMASK;
		OP(0).v.units = BITS(w, 25, 18);
		insn->nops = 1;
		break;
	default:
		break;
	}
	return true;
}

static bool decode_nounit(C6xInsn *insn, const C6xArchDesc *d) {
	ut32 w = insn->word;
	// only the count field (16:13) and the parallel bit (0) may be set
	if ((w & ~(C6X_NOUNIT_CNT | C6X_NOUNIT_PARALLEL)) == 0) {
		ut8 cnt = BITS(w, 16, 13) + 1;
		// a 16-cycle delay is not a real NOP; that slot is the IDLE opcode
		if (cnt == C6X_NOP_IDLE_CNT) {
			set_ins(insn, C6X_INS_IDLE);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
			insn->unit = C6X_UNIT_NONE;
			return true;
		}
		set_ins(insn, C6X_INS_NOP);
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
		insn->unit = C6X_UNIT_NONE;
		if (cnt > 1) {
			op_imm(&OP(0), cnt);
			insn->nops = 1;
		}
		return true;
	}
	// SPLOOP/SPLOOPD/SPMASK (C64x+ software-pipelined loop buffer): bit 17 marks
	// this class, bits 17:13 pick the op, and SPLOOP(D) carry the loop iteration
	// interval (ii = field + 1) in bits 27:23.
	if (BIT(w, 17)) {
		const C6xNoUnitRow *r = nounit_find(c6x_sploop_rows, RZ_ARRAY_SIZE(c6x_sploop_rows), BITS(w, 17, 13), d);
		// Everything outside the selector, this row's operand field, the
		// parallel bit and (where the row allows it) the predicate must be zero.
		ut32 allowed = C6X_NOUNIT_SEL | C6X_NOUNIT_PARALLEL;
		if (r) {
			allowed |= r->operand == NOUNIT_II    ? C6X_NOUNIT_II
				: r->operand == NOUNIT_STGCYC ? C6X_NOUNIT_STGCYC
				: r->operand == NOUNIT_UNITS  ? C6X_NOUNIT_UNITS
							      : 0;
			if (r->pred) {
				allowed |= C6X_NOUNIT_PRED;
			}
			if ((w & ~allowed) == 0) {
				return nounit_apply(insn, r, w);
			}
		}
	}
	// DINT/RINT: no-unit interrupt-enable control (SPRUFE8 Figure H-1). The
	// 0001 prefix at bits 31:28 is opcode, not a predicate, so it must not be
	// read as creg/z. op (bits 16:13) selects the mnemonic; only the op field
	// and the parallel bit may otherwise be set.
	if ((w & ~(C6X_NOUNIT_CNT | C6X_NOUNIT_PARALLEL)) == C6X_NOUNIT_INT) {
		const C6xNoUnitRow *r = nounit_find(c6x_int_rows, RZ_ARRAY_SIZE(c6x_int_rows), BITS(w, 16, 13), d);
		if (r) {
			return nounit_apply(insn, r, w);
		}
	}
	return false;
}

// MVC: move between a control register and a general register (.S2 only).
// bit 6 selects direction; the control register is named by its crlo field
// (crhi is 0 for register access, so it is not rendered).
static bool decode_mvc(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	bool read = BIT(w, 6); // 1: control -> register; 0: register -> control
	ut8 crlo = read ? BITS(w, 22, 18) : BITS(w, 27, 23);
	ut8 reg = read ? BITS(w, 27, 23) : BITS(w, 22, 18);
	const char *cr = ctrlreg_name(crlo, read);
	set_ins(insn, C6X_INS_MVC);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
	insn->unit = C6X_UNIT_S;
	insn->unit_side = s;
	if (read) {
		op_ctrlreg(&OP(0), cr);
		op_reg(&OP(1), s, reg);
	} else {
		op_reg(&OP(0), s, reg);
		op_ctrlreg(&OP(1), cr);
	}
	insn->nops = 2;
	return cr != NULL;
}

// EXTU/EXT/SET/CLR, constant form (SPRUFE8 field-op format): csta and cstb
// give the bit-field bounds as 5-bit constants; the op is bits 7:6.
static bool decode_field(C6xInsn *insn) {
	ut32 w = insn->word;
	static const C6xInsnId names[4] = { C6X_INS_EXTU, C6X_INS_EXT, C6X_INS_SET, C6X_INS_CLR };
	static const _RzAnalysisOpType types[4] = {
		RZ_ANALYSIS_OP_TYPE_SHR, RZ_ANALYSIS_OP_TYPE_SHR,
		RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_AND
	};
	ut8 op = BITS(w, 7, 6);
	ut8 s = BIT(w, 1);
	set_ins(insn, names[op]);
	insn->op_type = types[op];
	insn->unit = C6X_UNIT_S;
	insn->unit_side = s;
	op_reg(&OP(0), s, BITS(w, 22, 18)); // src2
	op_imm(&OP(1), BITS(w, 17, 13)); // csta
	op_imm(&OP(2), BITS(w, 12, 8)); // cstb
	OP(1).v.imm.decimal = true;
	OP(2).v.imm.decimal = true;
	op_reg(&OP(3), s, BITS(w, 27, 23)); // dst
	insn->nops = 4;
	return true;
}

// Decode a functional-unit instruction from its low-bit signature.
static bool decode_unit(const C6xArchDesc *d, C6xInsn *insn) {
	ut32 w = insn->word;
	// .D loads/stores: bits 3:2 == 01
	if (BITS(w, 3, 2) == C6X_DFMT_LDST) {
		// Doubleword variants (register pair) are marked by bit 8; the op
		// field then selects among them. Available on C64x+ (SIMD) and C67x
		// (FP), not plain C62x.
		if (BIT(w, 8)) {
			C6xInsnId mn = C6X_INS_INVALID;
			bool store = false, dword = true;
			switch (BITS(w, 6, 4)) {
			case 0x2: mn = C6X_INS_LDNDW; break;
			case 0x3:
				mn = C6X_INS_LDNW, dword = false;
				break; // non-aligned word load (C64x+)
			case 0x4: mn = C6X_INS_STDW, store = true; break;
			case 0x5:
				mn = C6X_INS_STNW, store = true, dword = false;
				break; // non-aligned word store (C64x+)
			case 0x6: mn = C6X_INS_LDDW; break;
			case 0x7: mn = C6X_INS_STNDW, store = true; break;
			}
			if (mn) {
				decode_ldst(insn, mn, store, dword);
				insn->unit = C6X_UNIT_D;
				return feat_ok(d, FEAT_FP) || feat_ok(d, FEAT_SIMD);
			}
		}
		ut8 op = BITS(w, 6, 4);
		decode_ldst(insn, c6x_mem_rows[op].id, c6x_mem_rows[op].store, false);
		insn->unit = C6X_UNIT_D;
		return true;
	}
	// .D long-immediate loads/stores (*+B14/B15[ucst15]): bits 3:2 == 11
	if (BITS(w, 3, 2) == C6X_DFMT_LDST_LONG) {
		ut8 op = BITS(w, 6, 4);
		// The ADDAB/ADDAH/ADDAW address forms share the byte/halfword/word
		// store slots; bits 31:28 == 0001 selects them.
		if (BITS(w, 31, 28) == C6X_DFMT_ADDA) {
			C6xInsnId addr_id = op == 0x3 ? C6X_INS_ADDAB
				: op == 0x5           ? C6X_INS_ADDAH
				: op == 0x7           ? C6X_INS_ADDAW
						      : C6X_INS_INVALID;
			if (addr_id != C6X_INS_INVALID) {
				decode_addaw_long(insn, addr_id);
				return true;
			}
		}
		decode_ldst_long(insn, c6x_mem_rows[op].id, c6x_mem_rows[op].store);
		return true;
	}
	// .L 1-or-2-source: bits 4:2 == 110
	if (BITS(w, 4, 2) == C6X_LFMT_1OR2SRC) {
		// FP add/sub on .S issue in this same format; their opfields select
		// the .S unit, so match them before the .L table.
		const C6xRow *sf = row_find(c6x_s_fp_rows, RZ_ARRAY_SIZE(c6x_s_fp_rows), BITS(w, 11, 5), d);
		if (sf) {
			decode_3op(insn, sf);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		// MVK.L (LSDx1 overlay, C64x+): the ABS opfield 0x1a is reused for
		// a 5-bit signed constant move; ABS's unary form fixes src1 = 0,
		// so a src1 field of 0x05 means MVK instead.
		if (BITS(w, 11, 5) == C6X_MOP_MVK5 && BITS(w, 17, 13) == C6X_MOP_ABS) {
			ut8 s = BIT(w, 1);
			set_ins(insn, C6X_INS_MVK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_L;
			insn->unit_side = s;
			op_imm(&OP(0), sext(BITS(w, 22, 18), 5));
			OP(0).v.imm.decimal = true;
			op_reg(&OP(1), s, BITS(w, 27, 23));
			insn->nops = 2;
			return true;
		}
		// The ABS opfield also carries the C64x+ unary byte reshuffles, chosen
		// by src1; src1 == 0 is the ABS itself and falls through to the table.
		if (feat_ok(d, FEAT_SIMD) && BITS(w, 11, 5) == C6X_MOP_MVK5) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_l_unary_rows); i++) {
				if (c6x_l_unary_rows[i].src1 != BITS(w, 17, 13)) {
					continue;
				}
				ut8 s = BIT(w, 1);
				ut8 x = BIT(w, 12);
				set_ins(insn, c6x_l_unary_rows[i].id);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = C6X_UNIT_L;
				insn->unit_side = s;
				insn->cross = x;
				op_reg(&OP(0), x ? !s : s, BITS(w, 22, 18)); // src2
				op_reg(&OP(1), s, BITS(w, 27, 23)); // dst
				insn->nops = 2;
				return true;
			}
		}
		// C66x promotes the .L reg-reg ADD/SUB to a 64-bit DADD/DSUB on
		// register pairs. It reuses the same opfield but takes the reserved
		// creg = 0, z = 1 signature (bits 31:29 == 0, bit 28 == 1) that a real
		// predicated instruction cannot have, so the scalar form is untouched.
		if (BITS(w, 31, 29) == 0 && BIT(w, 28) == 1 && feat_ok(d, FEAT_C66X) && (BITS(w, 11, 5) == C6X_UNARY_SIG_ALT || BITS(w, 11, 5) == C6X_UNARY_SIG)) {
			bool is_sub = BITS(w, 11, 5) == C6X_UNARY_SIG;
			ut8 s = BIT(w, 1);
			ut8 x = BIT(w, 12);
			set_ins(insn, is_sub ? C6X_INS_DSUB : C6X_INS_DADD);
			insn->op_type = is_sub ? RZ_ANALYSIS_OP_TYPE_SUB : RZ_ANALYSIS_OP_TYPE_ADD;
			insn->unit = C6X_UNIT_L;
			insn->unit_side = s;
			insn->cross = x != 0;
			op_regpair(&OP(0), s, BITS(w, 17, 13)); // src1
			op_regpair(&OP(1), x ? !s : s, BITS(w, 22, 18)); // src2 (cross-path)
			op_regpair(&OP(2), s, BITS(w, 27, 23)); // dst
			insn->nops = 3;
			return true;
		}
		const C6xRow *r = row_find(c6x_l_rows, RZ_ARRAY_SIZE(c6x_l_rows), BITS(w, 11, 5), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_L;
			return true;
		}
		return false;
	}
	if (BITS(w, 5, 2) == C6X_OPGRP_FIELD) {
		return decode_field(insn);
	}
	// .D-unit extended logic/arith, selected by bits 11:10 == 10.
	if (BITS(w, 5, 2) == C6X_OPGRP_EXT && BITS(w, 11, 10) == 0x2) {
		const C6xRow *r = row_find(c6x_d_ext_rows, RZ_ARRAY_SIZE(c6x_d_ext_rows), BITS(w, 9, 6), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_D;
			return true;
		}
	}
	// Extended .M (C64x+): bits 5:2 == 1100 with bits 11:10 in {0,1}. The
	// unary moves/shuffles share the bits 9:6 == 3 slot and are told apart by
	// the src1 field; every other slot is a two-source (packed) multiply.
	if (feat_ok(d, FEAT_SIMD) && BITS(w, 5, 2) == C6X_OPGRP_EXT && BITS(w, 11, 10) <= 1) {
		ut8 s = BIT(w, 1);
		ut8 x = BIT(w, 12);
		// C66x complex/matrix ops occupy this space with z = 1, creg = 0 (they
		// are always unconditional); that signature reserves the slot from the
		// C64x+ op below, which is either unconditional (z = 0) or predicated
		// (creg != 0).
		if (BITS(w, 31, 29) == 0 && BIT(w, 28) == 1) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_cplx_rows); i++) {
				const C6xMCplxRow *r = &c6x_m_cplx_rows[i];
				if (r->sub != BITS(w, 11, 10) || r->op != BITS(w, 9, 6) || !feat_ok(d, r->feat)) {
					continue;
				}
				set_ins(insn, r->id);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MUL;
				insn->unit = C6X_UNIT_M;
				insn->unit_side = s;
				insn->cross = x;
				op_by_kind(&OP(0), r->k1, s, BITS(w, 17, 13)); // src1
				op_by_kind(&OP(1), r->k2, x ? !s : s, BITS(w, 22, 18)); // src2 (cross)
				op_by_kind(&OP(2), r->k3, s, BITS(w, 27, 23)); // dst
				insn->nops = 3;
				return true;
			}
			return false;
		}
		if (BITS(w, 11, 10) == 0 && BITS(w, 9, 6) == 3) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_unary_rows); i++) {
				if (c6x_m_unary_rows[i].src1 != BITS(w, 17, 13)) {
					continue;
				}
				set_ins(insn, c6x_m_unary_rows[i].id);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = C6X_UNIT_M;
				insn->unit_side = s;
				insn->cross = x;
				op_reg(&OP(0), x ? !s : s, BITS(w, 22, 18)); // src2
				op_reg(&OP(1), s, BITS(w, 27, 23)); // dst
				insn->nops = 2;
				return true;
			}
			return false;
		}
		for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_ext_rows); i++) {
			const C6xMExtRow *r = &c6x_m_ext_rows[i];
			if (r->sub != BITS(w, 11, 10) || r->op != BITS(w, 9, 6) || !feat_ok(d, r->feat)) {
				continue;
			}
			set_ins(insn, r->id);
			insn->op_type = r->type;
			insn->is_fp = r->feat == FEAT_FP;
			insn->unit = C6X_UNIT_M;
			insn->unit_side = s;
			insn->cross = x;
			// the x bit normally crosses src2; mpyspdp crosses src1 (the SP
			// value) instead, its DP-pair src2 staying on the unit side
			ut8 src1_side = r->src1_cross && x ? !s : s;
			ut8 src2_side = !r->src1_cross && x ? !s : s;
			if (r->swap) {
				// reversed syntax (src2, src1, dst): the shift-count and
				// rotate ops print the value (src2) before the amount (src1)
				op_reg(&OP(0), src2_side, BITS(w, 22, 18)); // src2
				if (r->src1_cst) {
					op_imm(&OP(1), BITS(w, 17, 13));
				} else {
					op_reg(&OP(1), src1_side, BITS(w, 17, 13)); // src1
				}
			} else {
				op_reg(&OP(0), src1_side, BITS(w, 17, 13)); // src1
				if (r->src2_pair) {
					op_regpair(&OP(1), src2_side, BITS(w, 22, 18));
				} else {
					op_reg(&OP(1), src2_side, BITS(w, 22, 18));
				}
			}
			if (r->dst_pair) {
				op_regpair(&OP(2), s, BITS(w, 27, 23));
			} else {
				op_reg(&OP(2), s, BITS(w, 27, 23));
			}
			insn->nops = 3;
			return true;
		}
		return false;
	}
	// Extended .S (C64x+): bits 5:2 == 1100, bits 11:10 == 11. Packed shifts,
	// saturating add/pack and andn share this space, keyed by bits 9:6.
	if (feat_ok(d, FEAT_SIMD) && BITS(w, 5, 2) == C6X_OPGRP_EXT && BITS(w, 11, 10) == 0x3) {
		for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_s_ext_rows); i++) {
			if (c6x_s_ext_rows[i].op != BITS(w, 9, 6)) {
				continue;
			}
			ut8 s = BIT(w, 1);
			ut8 x = BIT(w, 12);
			ut8 src2_side = x ? !s : s;
			set_ins(insn, c6x_s_ext_rows[i].id);
			insn->op_type = c6x_s_ext_rows[i].type;
			insn->unit = C6X_UNIT_S;
			insn->unit_side = s;
			insn->cross = x;
			if (c6x_s_ext_rows[i].swap) {
				// packed shifts print value (src2) then count (src1)
				op_reg(&OP(0), src2_side, BITS(w, 22, 18));
				op_reg(&OP(1), s, BITS(w, 17, 13));
			} else {
				op_reg(&OP(0), s, BITS(w, 17, 13)); // src1
				op_reg(&OP(1), src2_side, BITS(w, 22, 18)); // src2
			}
			op_reg(&OP(2), s, BITS(w, 27, 23)); // dst
			insn->nops = 3;
			return true;
		}
		return false;
	}
	// .D extended logical/arith, selected by bits 11:10 == 10.
	if (BITS(w, 5, 2) == C6X_OPGRP_EXT && BITS(w, 11, 10) == 0x2) {
		const C6xRow *r = row_find(c6x_dext_rows, RZ_ARRAY_SIZE(c6x_dext_rows), BITS(w, 9, 6), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_D;
			return true;
		}
		return false;
	}
	// remaining formats have bits 4:2 == 000, 100 or 010; refine by higher bits
	ut8 sig = BITS(w, 6, 2);
	if (sig == C6X_SIG_M) {
		// C66x quad/matrix multiplies share this format but are unconditional
		// with z = 1, creg = 0 -- that reserves the slot from the z = 0 scalar
		// multiply at the same opcode.
		if (BITS(w, 31, 29) == 0 && BIT(w, 28) == 1 && feat_ok(d, FEAT_C66X)) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_wide_rows); i++) {
				const C6xMWideRow *r = &c6x_m_wide_rows[i];
				if (r->op != BITS(w, 11, 7)) {
					continue;
				}
				ut8 s = BIT(w, 1);
				set_ins(insn, r->id);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MUL;
				insn->unit = C6X_UNIT_M;
				insn->unit_side = s;
				// cmatmpy swaps the src1/src2 register fields
				ut8 f1 = r->swap ? BITS(w, 22, 18) : BITS(w, 17, 13);
				ut8 f2 = r->swap ? BITS(w, 17, 13) : BITS(w, 22, 18);
				op_by_kind(&OP(0), r->k1, s, f1);
				op_by_kind(&OP(1), r->k2, s, f2);
				op_by_kind(&OP(2), r->k3, s, BITS(w, 27, 23));
				insn->nops = 3;
				return true;
			}
			return false;
		}
		const C6xRow *r = row_find(c6x_m_rows, RZ_ARRAY_SIZE(c6x_m_rows), BITS(w, 11, 7), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_M;
			return true;
		}
		return false;
	}
	if (sig == C6X_SIG_D) {
		// MVK on the .D unit (C64x+) reuses the op-0 slot: a 5-bit signed
		// constant move, dst on side s. cst5 sits at bits 17:13.
		if (BITS(w, 12, 7) == C6X_DFMT_MVK) {
			ut8 s = BIT(w, 1);
			set_ins(insn, C6X_INS_MVK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_D;
			insn->unit_side = s;
			op_imm(&OP(0), sext(BITS(w, 17, 13), 5));
			OP(0).v.imm.decimal = true;
			op_reg(&OP(1), s, BITS(w, 27, 23));
			insn->nops = 2;
			return true;
		}
		const C6xRow *r = row_find(c6x_d_rows, RZ_ARRAY_SIZE(c6x_d_rows), BITS(w, 12, 7), d);
		if (r) {
			decode_darith(insn, r);
			insn->unit = C6X_UNIT_D;
			return true;
		}
		return false;
	}
	if (BITS(w, 5, 2) == C6X_OPGRP_1OR2SRC) {
		ut16 sop = BITS(w, 11, 6);
		if (sop == C6X_SOP_B_REG) {
			decode_branch_reg(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == C6X_SOP_BNOP_DISP) {
			decode_branch_nop(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == C6X_SOP_MVC_LO || sop == C6X_SOP_MVC_HI) {
			return decode_mvc(insn);
		}
		if (sop == C6X_SOP_ADDKPC) {
			decode_addkpc(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == C6X_SOP_BDEC) {
			decode_bdec(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == C6X_SOP_B_IRP) {
			ut8 n = BITS(w, 15, 13);
			set_ins(insn, n ? C6X_INS_BNOP : C6X_INS_B);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_RJMP;
			insn->unit_side = C6X_SIDE_B;
			op_ctrlreg(&OP(0), ctrlreg_name(BITS(w, 22, 18), true));
			insn->nops = 1;
			if (n) {
				op_imm(&OP(insn->nops++), n);
			}
			insn->unit = C6X_UNIT_S;
			return true;
		}
		const C6xRow *r = row_find(c6x_s_rows, RZ_ARRAY_SIZE(c6x_s_rows), sop, d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		return false;
	}
	if (sig == C6X_SIG_S_BRANCH) {
		decode_branch(insn);
		insn->unit = C6X_UNIT_S;
		return true;
	}
	if (sig == C6X_SIG_S_ADDK) {
		decode_addk(insn);
		insn->unit = C6X_UNIT_S;
		return true;
	}
	if (BITS(w, 5, 2) == C6X_OPGRP_MVK) { // bit 6 selects MVKH
		decode_mvk(insn);
		insn->unit = C6X_UNIT_S;
		return true;
	}
	return false;
}

// Map a 3-bit compact register field to a register operand. The header RS bit
// selects the low (A0-A7 / B0-B7) or high (A16-A23 / B16-B23) register set.
static void compact_reg(C6xOperand *o, ut8 field, ut8 side, bool rs) {
	op_reg(o, side, (rs ? 16 : 0) + (field & 0x7));
}

// The .L L3i short constant (SPRUFE8 Figure D-5): sn:cst3 encode a 5-bit signed
// value where cst3 == 0 means +-8 rather than 0.
static st64 l3i_const(ut8 sn, ut8 cst3) {
	ut8 raw = (sn << 3) | cst3;
	return raw == 0 ? 8 : (raw < 8 ? (st64)raw : (st64)raw - 16);
}

// Decode a 16-bit compact instruction (SPRUFE8 3.10, Appendices D and G). \p rs
// and \p sat come from the fetch-packet header expansion field. Only the common
// subset is handled (NOP; MV; predicated MVK; and the .L ALU/compare/MVK forms);
// unhandled encodings leave the mnemonic NULL but keep the 2-byte size so the
// packet stays aligned. bit 0 is the side selector (s); the parallel bit comes
// from the header p-bits and is set by the caller.
static void decode_compact(C6xInsn *insn, ut16 w, bool rs, bool sat, ut8 dsz, bool br) {
	insn->size = C6X_COMPACT_SIZE;
	ut8 s = w & 1; // 0 = A side (.x1), 1 = B side (.x2)
	insn->unit_side = s;

	// no-unit NOP: 13 fixed low bits, (count - 1) in bits 15:13.
	if ((w & 0x1fff) == C6X_COMPACT_NOP) {
		set_ins(insn, C6X_INS_NOP);
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
		insn->unit_side = 0;
		op_imm(&OP(0), ((w >> 13) & 0x7) + 1);
		insn->nops = 1;
		return;
	}

	if ((w & 0x6) == C6X_CSPACE_SHARED) {
		// Compact .M multiply: bits 4:1 == 1111. Bits 6:5 pick the halfword
		// halves (11 high*low, 10 low*high, 01 high*high, 00 the plain
		// multiply), bit 12 the cross path, and the destination field is two
		// bits scaled by two, so only even-numbered registers are encodable.
		if (((w >> 1) & 0xf) == C6X_CFMT_MPY) {
			static const C6xInsnId mpy_by_halves[4] = {
				C6X_INS_MPY, C6X_INS_MPYH, C6X_INS_MPYLH, C6X_INS_MPYHL
			};
			bool x = (w >> 12) & 1;
			set_ins(insn, mpy_by_halves[(w >> 5) & 0x3]);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MUL;
			insn->unit = C6X_UNIT_M;
			insn->cross = x;
			compact_reg(&OP(0), (w >> 13) & 0x7, s, rs);
			compact_reg(&OP(1), (w >> 7) & 0x7, x ? !s : s, rs);
			compact_reg(&OP(2), (ut8)(((w >> 10) & 0x3) * 2), s, rs);
			insn->nops = 3;
			return;
		}
		// Lx1/Sx1 one-register format: a single register operand with an
		// implied small constant, the operation chosen by bits 15:13 and the
		// unit by bit 3. Selector 4 is reserved, and 6 (MVC to ILC) exists only
		// on the .S unit.
		if ((((w >> 4) & 0x7) == C6X_CFMT_LSX1_1REG || ((w >> 4) & 0x7) == C6X_CFMT_DX1_1REG) && ((w >> 10) & 0x7) == 0x6) {
			ut8 sel = (w >> 13) & 0x7;
			// bits 6:4 pick the unit: 111 is the .D form, 110 leaves bit 3 to
			// choose between .S and .L.
			bool dunit = ((w >> 4) & 0x7) == C6X_CFMT_DX1_1REG;
			bool sunit = !dunit && ((w >> 3) & 1);
			C6xOperand reg;
			compact_reg(&reg, (w >> 7) & 0x7, s, rs);
			insn->unit = dunit ? C6X_UNIT_D : sunit ? C6X_UNIT_S
								: C6X_UNIT_L;
			switch (sel) {
			case 0:
			case 1: // MVK of the selector's low bit
				set_ins(insn, C6X_INS_MVK);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				op_imm(&OP(0), sel);
				OP(1) = reg;
				insn->nops = 2;
				return;
			case 2: // NEG dst, dst -- not available on the .D unit
				if (dunit) {
					break;
				}
				set_ins(insn, C6X_INS_NEG);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_NOT;
				OP(0) = reg;
				OP(1) = reg;
				insn->nops = 2;
				return;
			case 3:
			case 5:
			case 7: {
				C6xInsnId id = sel == 3 ? C6X_INS_SUB : sel == 5 ? C6X_INS_ADD
										 : C6X_INS_XOR;
				set_ins(insn, id);
				insn->op_type = sel == 3 ? RZ_ANALYSIS_OP_TYPE_SUB : sel == 5 ? RZ_ANALYSIS_OP_TYPE_ADD
											      : RZ_ANALYSIS_OP_TYPE_XOR;
				OP(0) = reg;
				op_imm(&OP(1), 1);
				OP(2) = reg;
				insn->nops = 3;
				return;
			}
			case 6:
				if (!sunit) {
					break; // reserved on the .L unit
				}
				set_ins(insn, C6X_INS_MVC);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				OP(0) = reg;
				OP(1).kind = C6X_OP_CTRLREG;
				OP(1).v.ctrl = "ilc";
				insn->nops = 2;
				return;
			default:
				break; // selector 4 is reserved
			}
			insn->unit = C6X_UNIT_NONE;
		}
		// Compact loop-buffer group: bits 6:1 == 110011 with bits 11:10 == 11.
		// Bit 13 picks the SPMASK pair over the SPLOOP forms and bit 12 the
		// rounding variant. The protected units are a scattered bitmap rather
		// than a contiguous field, so each unit is picked out by name.
		if (((w >> 1) & 0x3f) == C6X_CFMT_LOOP && ((w >> 10) & 0x3) == 0x3 && !((w >> 13) & 1) && ((w >> 12) & 1)) {
			// SPKERNEL: the fstg/fcyc boundary is one scattered six-bit field,
			// reported as the combined value the way the 32-bit form is.
			set_ins(insn, C6X_INS_SPKERNEL);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
			insn->unit = C6X_UNIT_NONE;
			insn->unit_side = 0;
			op_imm(&OP(0), (((w >> 7) & 1)) | (((w >> 8) & 1) << 1) | (((w >> 9) & 1) << 2) | (((w >> 14) & 1) << 3) | (((w >> 15) & 1) << 4) | ((w & 1) << 5));
			insn->nops = 1;
			return;
		}
		if (((w >> 1) & 0x3f) == C6X_CFMT_LOOP && ((w >> 10) & 0x3) == 0x3 && !((w >> 13) & 1) && !((w >> 12) & 1)) {
			// SPLOOP/SPLOOPD: bit 0 picks the delayed form, bit 15 predicates
			// on B0, and the iteration interval is a scattered field.
			set_ins(insn, (w & 1) ? C6X_INS_SPLOOPD : C6X_INS_SPLOOP);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
			insn->unit = C6X_UNIT_NONE;
			insn->unit_side = 0;
			if ((w >> 15) & 1) {
				insn->creg = 1; // B0
				insn->z = 0;
			}
			op_imm(&OP(0), 1 + (((w >> 7) & 1) | (((w >> 8) & 1) << 1) | (((w >> 9) & 1) << 2) | (((w >> 14) & 1) << 3)));
			insn->nops = 1;
			return;
		}
		if (((w >> 1) & 0x3f) == C6X_CFMT_LOOP && ((w >> 10) & 0x3) == 0x3 && ((w >> 13) & 1)) {
			set_ins(insn, ((w >> 12) & 1) ? C6X_INS_SPMASKR : C6X_INS_SPMASK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
			insn->unit = C6X_UNIT_NONE;
			insn->unit_side = 0;
			OP(0).kind = C6X_OP_UNITMASK;
			OP(0).v.units = (ut8)((w & 1) | (((w >> 7) & 1) << 1) | (((w >> 8) & 1) << 2) |
				(((w >> 9) & 1) << 3) | (((w >> 14) & 1) << 4) | (((w >> 15) & 1) << 5));
			insn->nops = 1;
			return;
		}
		// Shared .L/.S/.D forms (Appendix G): bits 2:1 == 11, unit at bits 4:3.
		// Dx5p (Figure C-19): ADDAW from the stack pointer, dst = B15 + ucst5
		// words. The constant is split across bits 12:11 and 15:13, and bit 0
		// picks the destination side -- an A-side destination reads B15 across
		// the datapath, which is why TI prints it as .D1X.
		// Sx5 (Figure C-6): ADDK with a 5-bit unsigned constant, destination in
		// bits 9:7 and the constant scattered across bits 15:11.
		if (((w >> 1) & 0x3f) == C6X_CFMT_DX2 && ((w >> 10) & 1)) {
			set_ins(insn, C6X_INS_ADDK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
			insn->unit = C6X_UNIT_S;
			op_imm(&OP(0), (((w >> 13) & 1)) | (((w >> 14) & 1) << 1) | (((w >> 15) & 1) << 2) | (((w >> 11) & 1) << 3) | (((w >> 12) & 1) << 4));
			compact_reg(&OP(1), (w >> 7) & 0x7, s, rs);
			insn->nops = 2;
			return;
		}
		// Dx5 (Figure C-18): the stack-adjust pair, where source and destination
		// are both B15 and bit 7 picks add over subtract. Same scattered
		// constant as Dx5p but shifted into bits 9:8.
		if (((w >> 1) & 0x3f) == C6X_CFMT_DX5 && ((w >> 10) & 0x3) == 0x3) {
			set_ins(insn, ((w >> 7) & 1) ? C6X_INS_SUBAW : C6X_INS_ADDAW);
			insn->op_type = ((w >> 7) & 1) ? RZ_ANALYSIS_OP_TYPE_SUB : RZ_ANALYSIS_OP_TYPE_ADD;
			insn->unit = C6X_UNIT_D;
			insn->unit_side = s;
			op_reg(&OP(0), 1, 15); // B15
			op_imm(&OP(1), (((w >> 13) & 1)) | (((w >> 14) & 1) << 1) | (((w >> 15) & 1) << 2) | (((w >> 8) & 1) << 3) | (((w >> 9) & 1) << 4));
			op_reg(&OP(2), 1, 15); // B15
			insn->nops = 3;
			return;
		}
		if (((w >> 1) & 0x3f) == C6X_CFMT_DX5P) {
			set_ins(insn, C6X_INS_ADDAW);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
			insn->unit = C6X_UNIT_D;
			insn->cross = s == 0;
			op_reg(&OP(0), 1, 15); // B15
			op_imm(&OP(1), (((w >> 13) & 0x1) << 0) | (((w >> 14) & 0x1) << 1) | (((w >> 15) & 0x1) << 2) | (((w >> 11) & 0x1) << 3) | (((w >> 12) & 0x1) << 4));
			compact_reg(&OP(2), (w >> 7) & 0x7, s, rs);
			insn->nops = 3;
			return;
		}
		ut8 unit_f = (w >> 3) & 0x3;
		C6xUnit unit = unit_f == 0 ? C6X_UNIT_L : unit_f == 1 ? C6X_UNIT_S
			: unit_f == 2                                 ? C6X_UNIT_D
								      : C6X_UNIT_NONE;
		ut8 b5 = (w >> 5) & 1, b6 = (w >> 6) & 1;
		ut8 b10 = (w >> 10) & 1, b11 = (w >> 11) & 1, b12 = (w >> 12) & 1;
		ut8 x = b12;
		if (unit == C6X_UNIT_D && b5 == 1 && b6 == 1 && b11 == 0) {
			// Dpp (Figure C-21): B15 stack load/store, word or doubleword.
			// The pointer is always B15; stores post-decrement and loads
			// pre-increment by ucst2. src/dst is a full 4-bit register on the
			// side named by t (bit 12); the RS header bit does not apply here.
			bool dw = (w >> 15) & 1;
			bool ld = (w >> 14) & 1;
			ut8 t = (w >> 12) & 1;
			ut8 rnum = (w >> 7) & 0xf;
			set_ins(insn, dw ? (ld ? C6X_INS_LDDW : C6X_INS_STDW) : (ld ? C6X_INS_LDW : C6X_INS_STW));
			insn->op_type = ld ? RZ_ANALYSIS_OP_TYPE_LOAD : RZ_ANALYSIS_OP_TYPE_STORE;
			insn->unit = C6X_UNIT_D;
			C6xOperand mem = { 0 };
			mem.kind = C6X_OP_MEM;
			mem.v.mem.base = 15;
			mem.v.mem.base_side = 1; // B15
			mem.v.mem.scaled = true;
			mem.v.mem.mode = ld ? C6X_AM_PREINC_CST : C6X_AM_POSTDEC_CST;
			mem.v.mem.off_cst = ((w >> 13) & 1) + 1; // ucst2 = ucst0 + 1
			C6xOperand reg = { 0 };
			if (dw) {
				op_regpair(&reg, t, rnum);
			} else {
				op_reg(&reg, t, rnum);
			}
			OP(0) = ld ? mem : reg;
			OP(1) = ld ? reg : mem;
			insn->nops = 2;
			return;
		}
		if (b5 == 0) { // G-1 / G-2: MV (mvto has bit6 = 0, mvfr has bit6 = 1)
			set_ins(insn, C6X_INS_MV);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = unit;
			insn->cross = x;
			compact_reg(&OP(0), (w >> 7) & 0x7, x ? !s : s, rs); // src2
			compact_reg(&OP(1), (w >> 13) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (b6 == 1 && b12 == 0 && b11 == 1 && b10 == 0) { // G-3: predicated MVK ucst1
			ut8 cc = (w >> 14) & 0x3;
			set_ins(insn, C6X_INS_MVK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = unit;
			insn->creg = (cc & 2) ? 0x1 : 0x6; // 10x -> B0, 0x -> A0
			insn->z = cc & 1; // odd CC is the negated ([!A0]/[!B0]) sense
			op_imm(&OP(0), (w >> 13) & 0x1); // ucst1
			compact_reg(&OP(1), (w >> 7) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (unit == C6X_UNIT_L && b6 == 0 && b5 == 1 && b10 == 1) { // Lx5: MVK scst5 (.L)
			set_ins(insn, C6X_INS_MVK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_L;
			ut8 scst5 = (((w >> 11) & 0x3) << 3) | ((w >> 13) & 0x7);
			op_imm(&OP(0), sext(scst5, 5));
			compact_reg(&OP(1), (w >> 7) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (unit == C6X_UNIT_L && b6 == 0 && b5 == 1 && b10 == 0) {
			// Lx3c/Lx1c: .L compare against a small constant. bit 12 == 0 is
			// CMPEQ with a ucst3 (Lx3c); bit 12 == 1 selects CMPLT/CMPGT/
			// CMPLTU/CMPGTU with a ucst1 (Lx1c). dst is A0/A1 or B0/B1.
			ut8 dstlo = (w >> 11) & 1;
			insn->unit = C6X_UNIT_L;
			if (b12 == 0) {
				set_ins(insn, C6X_INS_CMPEQ);
				op_imm(&OP(0), (w >> 13) & 0x7); // ucst3
			} else {
				static const C6xInsnId mn[4] = { C6X_INS_CMPLT, C6X_INS_CMPGT, C6X_INS_CMPLTU, C6X_INS_CMPGTU };
				set_ins(insn, mn[(w >> 14) & 0x3]);
				op_imm(&OP(0), (w >> 13) & 0x1); // ucst1
			}
			insn->op_type = RZ_ANALYSIS_OP_TYPE_CMP;
			compact_reg(&OP(1), (w >> 7) & 0x7, s, rs); // src2
			op_reg(&OP(2), s, dstlo); // dst A0/A1 or B0/B1
			insn->nops = 3;
			return;
		}
		if (b6 == 1 && b5 == 1 && b12 == 1 && b11 == 1 && b10 == 0) {
			// G-4 LSDx1: op field selects MVK 0/1 or ADD/XOR src,1 (src == dst).
			ut8 op = (w >> 13) & 0x7;
			if (op < 2) { // MVK 0 or MVK 1
				set_ins(insn, C6X_INS_MVK);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = unit;
				op_imm(&OP(0), op);
				compact_reg(&OP(1), (w >> 7) & 0x7, s, rs);
				insn->nops = 2;
				return;
			}
			if (op == 5 || op == 7) { // ADD src,1,dst or XOR src,1,dst
				set_ins(insn, op == 5 ? C6X_INS_ADD : C6X_INS_XOR);
				insn->op_type = op == 5 ? RZ_ANALYSIS_OP_TYPE_ADD : RZ_ANALYSIS_OP_TYPE_XOR;
				insn->unit = unit;
				compact_reg(&OP(0), (w >> 7) & 0x7, s, rs); // src (== dst)
				op_imm(&OP(1), 1);
				compact_reg(&OP(2), (w >> 7) & 0x7, s, rs); // dst
				insn->nops = 3;
				return;
			}
			if (unit == C6X_UNIT_S && op == 6) {
				// Sx1: MVC src, ILC -- move a general register into the
				// inner-loop-count control register (encoded with s = 1).
				set_ins(insn, C6X_INS_MVC);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = C6X_UNIT_S;
				compact_reg(&OP(0), (w >> 7) & 0x7, s, rs); // src
				op_ctrlreg(&OP(1), "ilc");
				insn->nops = 2;
				return;
			}
			return; // remaining op 2/3/4 per-unit Dx1/Lx1/Sx1 forms not decoded
		}
		if (unit == C6X_UNIT_S && b6 == 1 && b5 == 1 && b12 == 0 && b11 == 0) {
			// Sx1b: BNOP src2, N3 -- a branch to a B-side register (B0-B15).
			// This is the C64x+ compact form of the ABI return B .S2 B3; the
			// encoding is always BNOP, even when the NOP count is zero.
			ut8 n3 = (w >> 13) & 0x7;
			set_ins(insn, C6X_INS_BNOP);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_RJMP;
			insn->unit = C6X_UNIT_S;
			op_reg(&OP(0), 1, (w >> 7) & 0xf); // src2 on the B side
			op_imm(&OP(1), n3);
			insn->nops = 2;
			return;
		}
		return; // other shared forms not decoded yet
	}

	if ((w & 0x6) == C6X_CSPACE_L) {
		// .L-only forms (Appendix D): bits 2:1 == 00, distinguished by bits 3,10.
		ut8 b3 = (w >> 3) & 1, b10 = (w >> 10) & 1, x = (w >> 12) & 1;
		insn->unit = C6X_UNIT_L;
		insn->cross = x;
		if (b3 == 0 && b10 == 0) { // L3: ADD/SUB (+ SADD/SSUB under header SAT)
			ut8 op = (w >> 11) & 1;
			set_ins(insn, op ? (sat ? C6X_INS_SSUB : C6X_INS_SUB) : (sat ? C6X_INS_SADD : C6X_INS_ADD));
			insn->op_type = op ? RZ_ANALYSIS_OP_TYPE_SUB : RZ_ANALYSIS_OP_TYPE_ADD;
			compact_reg(&OP(0), (w >> 13) & 0x7, s, rs); // src1
			compact_reg(&OP(1), (w >> 7) & 0x7, x ? !s : s, rs); // src2
			compact_reg(&OP(2), (w >> 4) & 0x7, s, rs); // dst
			insn->nops = 3;
			return;
		}
		if (b3 == 0 && b10 == 1) { // L3i: ADD scst5, src2, dst
			set_ins(insn, C6X_INS_ADD);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
			op_imm(&OP(0), l3i_const((w >> 11) & 1, (w >> 13) & 0x7));
			compact_reg(&OP(1), (w >> 7) & 0x7, x ? !s : s, rs); // src2
			compact_reg(&OP(2), (w >> 4) & 0x7, s, rs); // dst
			insn->nops = 3;
			return;
		}
		if (b3 == 1 && b10 == 1) { // L2c: AND/OR/XOR/CMPEQ/CMPLT/CMPGT(U)
			static const C6xInsnId ops[8] = { C6X_INS_AND, C6X_INS_OR, C6X_INS_XOR, C6X_INS_CMPEQ,
				C6X_INS_CMPLT, C6X_INS_CMPGT, C6X_INS_CMPLTU, C6X_INS_CMPGTU };
			static const _RzAnalysisOpType types[8] = { RZ_ANALYSIS_OP_TYPE_AND,
				RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_XOR,
				RZ_ANALYSIS_OP_TYPE_CMP, RZ_ANALYSIS_OP_TYPE_CMP,
				RZ_ANALYSIS_OP_TYPE_CMP, RZ_ANALYSIS_OP_TYPE_CMP,
				RZ_ANALYSIS_OP_TYPE_CMP };
			ut8 op = ((w >> 11) & 1) << 2 | ((w >> 5) & 0x3); // op2 : op1-0
			set_ins(insn, ops[op]);
			insn->op_type = types[op];
			compact_reg(&OP(0), (w >> 13) & 0x7, s, rs); // src1
			compact_reg(&OP(1), (w >> 7) & 0x7, x ? !s : s, rs); // src2
			op_reg(&OP(2), s, (w >> 4) & 0x1); // dst: A0/A1 or B0/B1
			insn->nops = 3;
			return;
		}
		return; // Ltbd and other .L forms not decoded yet
	}
	if ((w & 0x6) == C6X_CSPACE_D) {
		// .D-unit loads/stores (Appendix C): bits 2:1 == 10. Data size comes
		// from the header DSZ combined with the opcode sz bit; the addressing
		// form (offset const, offset reg, post-inc, pre-dec) from bits 11:10.
		ut8 t = (w >> 12) & 1; // T datapath (data register) side
		// Dstk spends bit 9 on the offset, so it carries no sz bit: the stack
		// access is a word whatever the header DSZ says (checked against TI
		// dis6x in doubleword-primary packets, where it stays LDW/STW).
		bool dstk = ((w >> 10) & 0x3) == C6X_CFMT_BOTH_SET && (w & 0x8000);
		ut8 sz = dstk ? 0 : (w >> 9) & 1;
		bool ld = (w >> 3) & 1;
		ut8 prim = (dsz >> 2) & 1, sec = dsz & 0x3;
		C6xInsnId mn;
		bool dwpair = false;
		if (sz == 0 && prim == 1) {
			// Doubleword-primary access (Doff4DW/DindDW/DincDW/DdecDW): the
			// register is an even pair encoded at bits 6:5, and na (bit 4)
			// selects aligned (DW) versus nonaligned (NDW).
			ut8 na = (w >> 4) & 1;
			mn = na ? (ld ? C6X_INS_LDNDW : C6X_INS_STNDW) : (ld ? C6X_INS_LDDW : C6X_INS_STDW);
			dwpair = true;
		} else if (sz == 0) {
			mn = ld ? C6X_INS_LDW : C6X_INS_STW; // word-primary access
		} else if (prim == 0) { // word-primary packet: secondary byte/half sizes
			static const C6xInsnId l[4] = { C6X_INS_LDBU, C6X_INS_LDB, C6X_INS_LDHU, C6X_INS_LDH };
			static const C6xInsnId st[4] = { C6X_INS_STB, C6X_INS_STB, C6X_INS_STH, C6X_INS_STH };
			mn = ld ? l[sec] : st[sec];
		} else { // doubleword-primary packet: secondary word/byte/half sizes
			static const C6xInsnId l[4] = { C6X_INS_LDW, C6X_INS_LDB, C6X_INS_LDNW, C6X_INS_LDH };
			static const C6xInsnId st[4] = { C6X_INS_STW, C6X_INS_STB, C6X_INS_STNW, C6X_INS_STH };
			mn = ld ? l[sec] : st[sec];
		}
		if (dstk) {
			mn = ld ? C6X_INS_LDW : C6X_INS_STW;
			dwpair = false;
		}
		set_ins(insn, mn);
		insn->op_type = ld ? RZ_ANALYSIS_OP_TYPE_LOAD : RZ_ANALYSIS_OP_TYPE_STORE;
		insn->unit = C6X_UNIT_D;
		C6xOperand mem = { 0 };
		mem.kind = C6X_OP_MEM;
		mem.v.mem.base = (rs ? 16 : 0) + 4 + ((w >> 7) & 0x3); // pointer is R4-R7
		mem.v.mem.base_side = s;
		mem.v.mem.scaled = true;
		ut8 b11 = (w >> 11) & 1, b10 = (w >> 10) & 1;
		if (b10 == 0) { // Doff4: *+ptr[ucst4]
			mem.v.mem.mode = C6X_AM_POS_CST;
			mem.v.mem.off_cst = (b11 << 3) | ((w >> 13) & 0x7);
		} else if (b11 == 0) { // Dind: *+ptr[src1]
			mem.v.mem.mode = C6X_AM_POS_REG;
			mem.v.mem.off_reg = (rs ? 16 : 0) + ((w >> 13) & 0x7);
		} else if (w & 0x8000) {
			// Dstk (Figure C-16): the pointer is the stack pointer B15 rather
			// than one of R4-R7, and the offset widens to a ucst5 split across
			// bits 9:7 and 14:13. Bit 15 selects this form, so it has to be
			// tested before Dinc/Ddec, which otherwise claim the same bits.
			mem.v.mem.base = 15;
			mem.v.mem.base_side = 1; // B15
			mem.v.mem.mode = C6X_AM_POS_CST;
			mem.v.mem.off_cst = (((w >> 7) & 0x7) << 2) | ((w >> 13) & 0x3);
		} else if (((w >> 14) & 1) == 0) { // Dinc: *ptr++[ucst2]
			mem.v.mem.mode = C6X_AM_POSTINC_CST;
			mem.v.mem.off_cst = ((w >> 13) & 1) + 1;
		} else { // Ddec: *--ptr[ucst2]
			mem.v.mem.mode = C6X_AM_PREDEC_CST;
			mem.v.mem.off_cst = ((w >> 13) & 1) + 1;
		}
		C6xOperand reg = { 0 };
		if (dwpair) {
			// even register pair, address formed as op6:op5:0
			op_regpair(&reg, t, (rs ? 16 : 0) + (((w >> 5) & 0x3) << 1));
		} else {
			op_reg(&reg, t, (rs ? 16 : 0) + ((w >> 4) & 0x7));
		}
		OP(0) = ld ? mem : reg; // loads: *mem, dst; stores: src, *mem
		OP(1) = ld ? reg : mem;
		insn->nops = 2;
		return;
	}
	if ((w & 0x6) == C6X_CSPACE_S) {
		// Sx1 three-register ADD/SUB: the same bits 3:1 == 101 group as the
		// shift below, with bit 10 clear. Bit 11 picks subtract and bit 12 the
		// cross path, which feeds src2 from the opposite register file.
		if (!br && ((w >> 1) & 0x7) == C6X_CFMT_SX1_3REG && !((w >> 10) & 1)) {
			bool x = (w >> 12) & 1;
			set_ins(insn, ((w >> 11) & 1) ? C6X_INS_SUB : C6X_INS_ADD);
			insn->op_type = ((w >> 11) & 1) ? RZ_ANALYSIS_OP_TYPE_SUB : RZ_ANALYSIS_OP_TYPE_ADD;
			insn->unit = C6X_UNIT_S;
			insn->cross = x;
			compact_reg(&OP(0), (w >> 13) & 0x7, s, rs);
			compact_reg(&OP(1), (w >> 7) & 0x7, x ? !s : s, rs);
			compact_reg(&OP(2), (w >> 4) & 0x7, s, rs);
			insn->nops = 3;
			return;
		}
		// Sx2 shift-by-constant (Appendix F): bits 3:1 == 101 with bit 10 set.
		// The count is a 3-bit field whose zero encoding means 16, since a
		// shift by zero would be a no-op and needs no encoding. A header BR
		// bit re-purposes the bit-3 forms as branches, so this only applies
		// when the packet is not a branch packet.
		if (!br && ((w >> 1) & 0x7) == C6X_CFMT_SX1_3REG && ((w >> 10) & 1)) {
			ut8 cnt = (w >> 13) & 0x7;
			bool x = (w >> 12) & 1;
			set_ins(insn, ((w >> 11) & 1) ? C6X_INS_SHR : C6X_INS_SHL);
			insn->op_type = ((w >> 11) & 1) ? RZ_ANALYSIS_OP_TYPE_SHR : RZ_ANALYSIS_OP_TYPE_SHL;
			insn->unit = C6X_UNIT_S;
			insn->cross = x;
			compact_reg(&OP(0), (w >> 7) & 0x7, x ? !s : s, rs); // src2
			op_imm(&OP(1), cnt ? cnt : 16);
			compact_reg(&OP(2), (w >> 4) & 0x7, s, rs); // dst
			insn->nops = 3;
			return;
		}
		// .S-unit compact formats (Appendix F): bits 2:1 == 01. Under a header
		// BR bit the bit-3 forms are branches; otherwise they are ALU/shift ops
		// (still to do). The MVK form (Smvk8) is BR-independent.
		if (((w >> 4) & 1) && !((w >> 3) & 1)) {
			// Smvk8 MVK: ucst8 is scattered across the word.
			ut16 imm = ((w >> 13) & 0x7) | (((w >> 11) & 0x3) << 3) |
				(((w >> 5) & 0x3) << 5) | (((w >> 10) & 0x1) << 7);
			set_ins(insn, C6X_INS_MVK);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_S;
			op_imm(&OP(0), imm);
			compact_reg(&OP(1), (w >> 7) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (!((w >> 3) & 1) && !((w >> 4) & 1)) {
			// .S ALU: shifts (Ssh5/S2sh, bit 10 == 1) and field operations
			// (Sc5/S2ext, bit 10 == 0). The op at bits 6:5 selects the form;
			// op == 3 escapes to the register-count (S2sh) or fixed-width
			// (S2ext) variant, which carries its own op at bits 12:11.
			insn->unit = C6X_UNIT_S;
			ut8 b10 = (w >> 10) & 1;
			ut8 op = (w >> 5) & 0x3;
			ut8 ucst5 = (((w >> 11) & 0x3) << 3) | ((w >> 13) & 0x7);
			if (b10 && op != 3) { // Ssh5: SHL/SHR/SHRU (SSHL when header SAT)
				static const C6xInsnId mn[3] = { C6X_INS_SHL, C6X_INS_SHR, C6X_INS_SHRU };
				set_ins(insn, (op == 2 && sat) ? C6X_INS_SSHL : mn[op]);
				insn->op_type = op ? RZ_ANALYSIS_OP_TYPE_SHR : RZ_ANALYSIS_OP_TYPE_SHL;
				compact_reg(&OP(0), (w >> 7) & 0x7, s, rs); // src2 (= dst)
				op_imm(&OP(1), ucst5);
				compact_reg(&OP(2), (w >> 7) & 0x7, s, rs); // dst
				insn->nops = 3;
				return;
			}
			if (b10) { // S2sh: register-count shift, src1 (count) at bits 15:13
				static const C6xInsnId mn[4] = { C6X_INS_SHL, C6X_INS_SHR, C6X_INS_SHRU, C6X_INS_SSHL };
				ut8 op2 = (w >> 11) & 0x3;
				set_ins(insn, mn[op2]);
				insn->op_type = op2 == 1 ? RZ_ANALYSIS_OP_TYPE_SHR : RZ_ANALYSIS_OP_TYPE_SHL;
				compact_reg(&OP(0), (w >> 7) & 0x7, s, rs); // src2 (= dst)
				compact_reg(&OP(1), (w >> 13) & 0x7, s, rs); // src1 (count)
				compact_reg(&OP(2), (w >> 7) & 0x7, s, rs); // dst
				insn->nops = 3;
				return;
			}
			if (op != 3) { // Sc5: EXTU/SET/CLR with a ucst5 field (dst is A0/B0)
				static const C6xInsnId mn[3] = { C6X_INS_EXTU, C6X_INS_SET, C6X_INS_CLR };
				static const _RzAnalysisOpType ty[3] = { RZ_ANALYSIS_OP_TYPE_SHR,
					RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_AND };
				set_ins(insn, mn[op]);
				insn->op_type = ty[op];
				compact_reg(&OP(0), (w >> 7) & 0x7, s, rs); // src2
				op_imm(&OP(1), ucst5);
				op_imm(&OP(2), op == 0 ? 31 : ucst5); // EXTU pairs with 31
				op_reg(&OP(3), s, 0); // dst A0/B0
				insn->nops = 4;
				return;
			}
			// S2ext: EXT/EXTU with a fixed 16- or 24-bit field width.
			static const C6xInsnId mn[4] = { C6X_INS_EXT, C6X_INS_EXT, C6X_INS_EXTU, C6X_INS_EXTU };
			ut8 op2 = (w >> 11) & 0x3;
			ut8 width = (op2 & 1) ? 24 : 16;
			set_ins(insn, mn[op2]);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_SHR;
			compact_reg(&OP(0), (w >> 7) & 0x7, s, rs); // src2
			op_imm(&OP(1), width);
			op_imm(&OP(2), width);
			compact_reg(&OP(3), (w >> 13) & 0x7, s, rs); // dst
			insn->nops = 4;
			return;
		}
		if (br && ((w >> 3) & 1)) {
			// Branch forms (Sbs7/Sbu8/Scs10 and their conditional variants). The
			// displacement is packet-relative and scaled to the 16-bit slot, so
			// the analysis filler resolves it against the fetch-packet base.
			insn->unit = C6X_UNIT_S;
			ut8 b4 = (w >> 4) & 1, b5 = (w >> 5) & 1;
			if (b5 == 0 && b4 == 1) { // Scs10: CALLP scst10, 5
				set_ins(insn, C6X_INS_CALLP);
				insn->op_type = RZ_ANALYSIS_OP_TYPE_CALL;
				OP(0).kind = C6X_OP_PCREL;
				OP(0).v.imm.value = sext((w >> 6) & 0x3ff, 10) * 2;
				insn->nops = 1;
				return;
			}
			// Sbu8/Sbu8c carry an 8-bit unsigned constant instead of a signed 7-bit one
			bool wide = ((w >> 14) & 0x3) == C6X_CFMT_BOTH_SET;
			st64 disp = wide ? (st64)(((w >> 6) & 0xff) * 2) // ucst8 (unsigned)
					 : sext((w >> 6) & 0x7f, 7) * 2; // scst7 (signed)
			ut8 n3 = wide ? 5 : ((w >> 13) & 0x7); // NOP count (Sbu8 implies 5)
			if (b5) { // conditional variants carry a predicate in s and bit 4
				insn->creg = (w & 1) ? 0x1 : 0x6; // s selects B0 / A0
				insn->z = b4; // bit 4 is the z (negate) sense
			}
			set_ins(insn, C6X_INS_BNOP);
			insn->op_type = RZ_ANALYSIS_OP_TYPE_JMP;
			OP(0).kind = C6X_OP_PCREL;
			OP(0).v.imm.value = disp;
			op_imm(&OP(1), n3);
			insn->nops = 2;
			return;
		}
		return;
	}
}

/**
 * Decode one 32-bit C6000 opcode.
 * \param desc variant descriptor (feature gate)
 * \param buf input bytes (>= 4)
 * \param len available bytes
 * \param big_endian byte order of \p buf
 * \param insn output, filled on success
 * \return true if a 4-byte opcode was consumed (even when unrecognised, in
 *         which case \ref C6xInsn::mnemonic is NULL)
 */
RZ_IPI bool c6x_decode(const C6xArchDesc *desc, const ut8 *buf, int len, ut64 pc, bool big_endian, RZ_OUT C6xInsn *insn) {
	rz_return_val_if_fail(desc && buf && insn, false);
	if (len < 2) {
		return false;
	}
	memset(insn, 0, sizeof(*insn));
	// C64x+ compact fetch packets (SPRUFE8 3.10): the eighth word of a 32-byte
	// fetch packet is a header (top nibble 1110) whose layout field marks which
	// of the other seven words hold two 16-bit compact instructions. Look for
	// that header ahead of the current word; if this slot is compact, decode a
	// 16-bit instruction and take the parallel bit from the header p-bit field.
	// Only families with the compact set are probed, so C62x/C67x are untouched;
	// when the header is not reachable (an isolated single-word decode) the
	// 32-bit path runs and still recognises a header word on its own.
	if (desc->features & C6X_FEAT_SIMD) {
		ut32 fp_off = (ut32)(pc & 0x1f);
		int hdr_off = 0x1c - (int)fp_off; // header lives at packet offset 0x1c
		if (fp_off < 0x1c && hdr_off + 4 <= len) {
			ut32 hdr = big_endian ? rz_read_be32(buf + hdr_off) : rz_read_le32(buf + hdr_off);
			ut8 slot = fp_off >> 2;
			if ((hdr >> 28) == C6X_FP_HEADER_TAG && ((hdr >> (21 + slot)) & 1)) {
				ut16 w16 = big_endian ? rz_read_be16(buf) : rz_read_le16(buf);
				ut8 half = (fp_off >> 1) & 1;
				insn->word = w16;
				insn->parallel = (hdr >> (slot * 2 + half)) & 1;
				decode_compact(insn, w16, (hdr >> 19) & 1, (hdr >> 14) & 1,
					(hdr >> 16) & 0x7, (hdr >> 15) & 1);
				return true;
			}
		}
	}
	if (len < 4) {
		return false;
	}
	insn->word = big_endian ? rz_read_be32(buf) : rz_read_le32(buf);
	insn->size = C6X_WORD_SIZE;
	ut32 w = insn->word;
	// A C64x+ compact fetch packet replaces its eighth word with a header
	// (SPRUFE8 3.10.2): top nibble 1110, i.e. creg=111/z=0, which is the
	// reserved predicate no real instruction uses. The header repacks the
	// other slots as 16-bit compact instructions; decoding those is future
	// work, but the header itself is recognised so it is not mis-read as a
	// 32-bit opcode and to flag the packet as compact.
	if ((w >> 28) == C6X_FP_HEADER_TAG) {
		insn->is_header = true;
		set_ins(insn, C6X_INS_FPHEAD);
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
		return true;
	}
	insn->parallel = BIT(w, 0) != 0;
	insn->creg = BITS(w, 31, 29);
	insn->z = BIT(w, 28);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ILL;
	if (decode_nounit(insn, desc)) {
		return true;
	}
	if (!decode_unit(desc, insn)) {
		set_ins(insn, C6X_INS_INVALID); // unrecognised, still 4 bytes
		insn->op_type = RZ_ANALYSIS_OP_TYPE_ILL;
	}
	return true;
}
