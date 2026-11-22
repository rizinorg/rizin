// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file vax.h
 * Clean-room VAX-11 disassembler core.
 *
 * This decoder is written from the publicly documented VAX instruction
 * encoding (1-or-2 byte opcode followed by uniform operand specifiers) and
 * does not derive from any GPL-licensed VAX disassembler.
 */

#ifndef RZ_VAX_H
#define RZ_VAX_H

#include <rz_types.h>
#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of explicit operands a single VAX instruction can carry. */
#define VAX_MAX_OPS 6
/** Safe upper bound used by the analysis layer for non-CASE instructions. */
#define VAX_MAX_OP_SIZE 56

/** General-purpose register indices (PC-relative addressing keys off PC). */
enum {
	VAX_REG_AP = 12, ///< argument pointer
	VAX_REG_FP = 13, ///< frame pointer
	VAX_REG_SP = 14, ///< stack pointer
	VAX_REG_PC = 15, ///< program counter
};

/**
 * Named opcodes used by the control-flow and data classification logic.
 * Only the opcodes that are referred to by name elsewhere are listed; the
 * disassembler itself indexes a full 256-entry table and does not need them.
 * The four float opcodes mark the bounds of the contiguous F_ and D_ ranges.
 */
typedef enum {
	VAX_OP_HALT = 0x00,
	VAX_OP_NOP = 0x01,
	VAX_OP_REI = 0x02,
	VAX_OP_BPT = 0x03,
	VAX_OP_RET = 0x04,
	VAX_OP_RSB = 0x05,
	VAX_OP_LDPCTX = 0x06,
	VAX_OP_SVPCTX = 0x07,
	VAX_OP_PROBER = 0x0c,
	VAX_OP_PROBEW = 0x0d,
	VAX_OP_BSBB = 0x10,
	VAX_OP_BRB = 0x11,
	VAX_OP_BNEQ = 0x12,
	VAX_OP_BEQL = 0x13,
	VAX_OP_BGTR = 0x14,
	VAX_OP_BLEQ = 0x15,
	VAX_OP_JSB = 0x16,
	VAX_OP_JMP = 0x17,
	VAX_OP_BGEQ = 0x18,
	VAX_OP_BLSS = 0x19,
	VAX_OP_BGTRU = 0x1a,
	VAX_OP_BLEQU = 0x1b,
	VAX_OP_BVC = 0x1c,
	VAX_OP_BVS = 0x1d,
	VAX_OP_BGEQU = 0x1e,
	VAX_OP_BLSSU = 0x1f,
	VAX_OP_BSBW = 0x30,
	VAX_OP_BRW = 0x31,
	VAX_OP_ACBW = 0x3d,
	VAX_OP_PUSHAW = 0x3f,
	VAX_OP_ADDF2 = 0x40, ///< first F_floating opcode
	VAX_OP_ACBF = 0x4f,
	VAX_OP_CVTFD = 0x56, ///< last F_floating opcode
	VAX_OP_ADDD2 = 0x60, ///< first D_floating opcode
	VAX_OP_ACBD = 0x6f,
	VAX_OP_CVTDF = 0x76, ///< last D_floating opcode
	VAX_OP_PUSHAQ = 0x7f,
	VAX_OP_CASEB = 0x8f,
	VAX_OP_ACBB = 0x9d,
	VAX_OP_PUSHAB = 0x9f,
	VAX_OP_CASEW = 0xaf,
	VAX_OP_CHMK = 0xbc,
	VAX_OP_CHME = 0xbd,
	VAX_OP_CHMS = 0xbe,
	VAX_OP_CHMU = 0xbf,
	VAX_OP_CASEL = 0xcf,
	VAX_OP_MTPR = 0xda,
	VAX_OP_MFPR = 0xdb,
	VAX_OP_PUSHL = 0xdd,
	VAX_OP_PUSHAL = 0xdf,
	VAX_OP_BBS = 0xe0,
	VAX_OP_BBC = 0xe1,
	VAX_OP_BBSS = 0xe2,
	VAX_OP_BBCS = 0xe3,
	VAX_OP_BBSC = 0xe4,
	VAX_OP_BBCC = 0xe5,
	VAX_OP_BBSSI = 0xe6,
	VAX_OP_BBCCI = 0xe7,
	VAX_OP_BLBS = 0xe8,
	VAX_OP_BLBC = 0xe9,
	VAX_OP_ACBL = 0xf1,
	VAX_OP_AOBLSS = 0xf2,
	VAX_OP_AOBLEQ = 0xf3,
	VAX_OP_SOBGEQ = 0xf4,
	VAX_OP_SOBGTR = 0xf5,
	VAX_OP_CALLG = 0xfa,
	VAX_OP_CALLS = 0xfb,
	VAX_OP_XFC = 0xfc,
} VaxOpcode;

/** Operand access class as defined by the instruction template. */
typedef enum {
	VAX_AC_NONE = 0,
	VAX_AC_R, ///< read
	VAX_AC_W, ///< write
	VAX_AC_M, ///< modify (read + write)
	VAX_AC_A, ///< address
	VAX_AC_B, ///< branch displacement (implicit, PC relative)
	VAX_AC_V, ///< variable bit-field base
} VaxAccess;

/** Operand data type; determines immediate size and autoincrement stride. */
typedef enum {
	VAX_DT_NONE = 0,
	VAX_DT_B, ///< byte (1)
	VAX_DT_W, ///< word (2)
	VAX_DT_L, ///< longword (4)
	VAX_DT_Q, ///< quadword (8)
	VAX_DT_O, ///< octaword (16)
	VAX_DT_F, ///< F_floating (4)
	VAX_DT_D, ///< D_floating (8)
	VAX_DT_G, ///< G_floating (8)
	VAX_DT_H, ///< H_floating (16)
} VaxDataType;

/** Decoded addressing mode of a single operand. */
typedef enum {
	VAX_AM_INVALID = 0,
	VAX_AM_LITERAL, ///< short literal $const (0..63)
	VAX_AM_REG, ///< Rn
	VAX_AM_REGDEF, ///< (Rn)
	VAX_AM_AUTODEC, ///< -(Rn)
	VAX_AM_AUTOINC, ///< (Rn)+
	VAX_AM_AUTOINCDEF, ///< *(Rn)+
	VAX_AM_BYTEDISP, ///< d(Rn) with byte displacement
	VAX_AM_BYTEDISPDEF, ///< *d(Rn) with byte displacement
	VAX_AM_WORDDISP, ///< d(Rn) with word displacement
	VAX_AM_WORDDISPDEF, ///< *d(Rn) with word displacement
	VAX_AM_LONGDISP, ///< d(Rn) with longword displacement
	VAX_AM_LONGDISPDEF, ///< *d(Rn) with longword displacement
	VAX_AM_IMMEDIATE, ///< $imm (PC autoincrement)
	VAX_AM_ABSOLUTE, ///< *0xaddr (PC autoincrement deferred)
	VAX_AM_BYTEREL, ///< PC byte relative
	VAX_AM_BYTERELDEF, ///< PC byte relative deferred
	VAX_AM_WORDREL, ///< PC word relative
	VAX_AM_WORDRELDEF, ///< PC word relative deferred
	VAX_AM_LONGREL, ///< PC longword relative
	VAX_AM_LONGRELDEF, ///< PC longword relative deferred
	VAX_AM_BRANCH, ///< implicit branch displacement target
} VaxAddrMode;

/** One fully decoded operand. */
typedef struct {
	VaxAddrMode mode;
	VaxAccess access;
	VaxDataType dt;
	ut8 reg; ///< primary register (for register/displacement/deferred modes)
	bool indexed; ///< true when an index prefix [Rx] applies
	ut8 index_reg; ///< Rx for the index prefix
	st64 disp; ///< sign-extended displacement / short literal value
	ut64 imm; ///< raw immediate bit pattern (sized by dt)
	ut64 target; ///< resolved absolute address for PC-relative / absolute / branch
	bool has_target; ///< whether \p target carries a meaningful value
} VaxOperand;

/** A decoded VAX instruction. */
typedef struct {
	ut16 opcode; ///< 1-byte opcode, or 0xFDxx / 0xFExx / 0xFFxx for escaped opcodes
	const char *name; ///< canonical mnemonic, NULL when invalid
	int size; ///< total instruction length in bytes
	int n_ops; ///< number of decoded operands
	VaxOperand ops[VAX_MAX_OPS];
} VaxInst;

RZ_API int rz_vax_decode(RZ_NONNULL VaxInst *inst, RZ_NONNULL const ut8 *buf, int len, ut64 addr);
RZ_API void rz_vax_format(RZ_NONNULL const VaxInst *inst, RZ_NONNULL RzStrBuf *sb);
RZ_API int rz_vax_dt_size(VaxDataType dt);
RZ_API const char *rz_vax_reg_name(int reg);

#ifdef __cplusplus
}
#endif

#endif /* RZ_VAX_H */
