// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_SH_DISASSEMBLER_H
#define RZ_ASM_SH_DISASSEMBLER_H
#include <rz_types.h>
#include <rz_util.h>

typedef enum sh_addr_mode_t {
	SH_ADDR_INVALID = 0,
	SH_REG_DIRECT,
	SH_REG_INDIRECT,
	SH_REG_INDIRECT_I, ///< register indirect with post-increment
	SH_REG_INDIRECT_D, ///< register indirect with pre-decrement
	SH_REG_INDIRECT_DISP, ///< register indirect with displacement
	SH_REG_INDIRECT_INDEXED, ///< indexed register indirect
	SH_GBR_INDIRECT_DISP,
	SH_GBR_INDIRECT_INDEXED,
	SH_PC_RELATIVE_DISP,
	SH_PC_RELATIVE,
	SH_PC_RELATIVE_REG,
	SH_IMM_U, ///< 8-bit immediate value (zero-extended)
	SH_IMM_S, ///< 8-bit immediate value (sign-extended)
} SHAddrMode;

typedef enum sh_scaling_t {
	SH_SCALING_INVALID = 0,
	SH_SCALING_B, ///< byte
	SH_SCALING_W, ///< word
	SH_SCALING_L, ///< long word
	SH_SCALING_Q ///< quad word
} SHScaling;

const ut8 sh_scaling_size[] = { -1, 1, 2, 4, 8 };

/**
 * Enum for register indexes
 */
typedef enum sh_register_index_t {
	SH_REG_IND_R0,
	SH_REG_IND_R1,
	SH_REG_IND_R2,
	SH_REG_IND_R3,
	SH_REG_IND_R4,
	SH_REG_IND_R5,
	SH_REG_IND_R6,
	SH_REG_IND_R7,
	SH_REG_IND_R8,
	SH_REG_IND_R9,
	SH_REG_IND_R10,
	SH_REG_IND_R11,
	SH_REG_IND_R12,
	SH_REG_IND_R13,
	SH_REG_IND_R14,
	SH_REG_IND_R15,
	SH_REG_IND_PC,
	SH_REG_IND_SR,
	SH_REG_IND_GBR,
	SH_REG_IND_SSR,
	SH_REG_IND_SPC,
	SH_REG_IND_SGR,
	SH_REG_IND_DBR,
	SH_REG_IND_VBR,
	SH_REG_IND_MACH,
	SH_REG_IND_MACL,
	SH_REG_IND_PR,
	SH_REG_IND_FPUL,
	SH_REG_IND_FPSCR,
	SH_REG_IND_FR0,
	SH_REG_IND_FR1,
	SH_REG_IND_FR2,
	SH_REG_IND_FR3,
	SH_REG_IND_FR4,
	SH_REG_IND_FR5,
	SH_REG_IND_FR6,
	SH_REG_IND_FR7,
	SH_REG_IND_FR8,
	SH_REG_IND_FR9,
	SH_REG_IND_FR10,
	SH_REG_IND_FR11,
	SH_REG_IND_FR12,
	SH_REG_IND_FR13,
	SH_REG_IND_FR14,
	SH_REG_IND_FR15,
	SH_REG_IND_XF0,
	SH_REG_IND_XF1,
	SH_REG_IND_XF2,
	SH_REG_IND_XF3,
	SH_REG_IND_XF4,
	SH_REG_IND_XF5,
	SH_REG_IND_XF6,
	SH_REG_IND_XF7,
	SH_REG_IND_XF8,
	SH_REG_IND_XF9,
	SH_REG_IND_XF10,
	SH_REG_IND_XF11,
	SH_REG_IND_XF12,
	SH_REG_IND_XF13,
	SH_REG_IND_XF14,
	SH_REG_IND_XF15
} SHRegisterIndex;

typedef enum {
	SH_OP_INVALID = 0,
	SH_OP_MOV,
	SH_OP_MOVT,
	SH_OP_SWAP,
	SH_OP_XTRCT,
	SH_OP_ADD,
	SH_OP_ADDC,
	SH_OP_ADDV,
	SH_OP_CMP_EQ,
	SH_OP_CMP_HS,
	SH_OP_CMP_GE,
	SH_OP_CMP_HI,
	SH_OP_CMP_GT,
	SH_OP_CMP_PZ,
	SH_OP_CMP_PL,
	SH_OP_CMP_STR,
	SH_OP_DIV1,
	SH_OP_DIV0S,
	SH_OP_DIV0U,
	SH_OP_DMULS,
	SH_OP_DMULU,
	SH_OP_DT,
	SH_OP_EXTS,
	SH_OP_EXTU,
	SH_OP_MAC,
	SH_OP_MUL,
	SH_OP_MULS,
	SH_OP_MULU,
	SH_OP_NEG,
	SH_OP_NEGC,
	SH_OP_SUB,
	SH_OP_SUBC,
	SH_OP_SUBV,
	SH_OP_AND,
	SH_OP_NOT,
	SH_OP_OR,
	SH_OP_TAS,
	SH_OP_TST,
	SH_OP_XOR,
	SH_OP_ROTL,
	SH_OP_ROTR,
	SH_OP_ROTCL,
	SH_OP_ROTCR,
	SH_OP_SHAD,
	SH_OP_SHAL,
	SH_OP_SHLD,
	SH_OP_SHLL,
	SH_OP_SHLR,
	SH_OP_SHLL2,
	SH_OP_SHLR2,
	SH_OP_SHLL8,
	SH_OP_SHLR8,
	SH_OP_SHLL16,
	SH_OP_SHLR16,
	SH_OP_CLRMAC,
	SH_OP_CLRS,
	SH_OP_CLRT,
	SH_OP_LDC,
	SH_OP_LDS,
	SH_OP_NOP,
	/* end */
	SH_OP_SIZE
} SHOpMnem;

typedef struct sh_param_t {
	ut16 param[2];
	SHAddrMode mode;
} SHParam;

typedef struct sh_opcode_t {
	SHOpMnem mnemonic;
	SHParam param[2];
	SHScaling scaling;
} SHOp;

ut32 sh_disassembler(const ut8 *buffer, const ut32 size, ut64 pc, bool be, SHOp *aop, RzStrBuf *sb);

#endif /* RZ_ASM_SH_DISASSEMBLER_H */
