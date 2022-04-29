// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_SH_DISASSEMBLER_H
#define RZ_ASM_SH_DISASSEMBLER_H
#include <rz_types.h>
#include <rz_util.h>

typedef enum {
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

typedef enum {
	SH_SCALING_INVALID = 0,
	SH_SCALING_B, ///< byte
	SH_SCALING_W, ///< word
	SH_SCALING_L, ///< long word
	SH_SCALING_Q ///< quad word
} SHScaling;

const ut8 sh_scaling_size[] = { -1, 1, 2, 4, 8 };

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
