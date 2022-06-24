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
	SH_PC_RELATIVE8,
	SH_PC_RELATIVE12,
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

static const ut8 sh_scaling_size[] = { -1, 1, 2, 4, 8 };

// SR register in SH
// SR = x|D|R|B|xxxxxxxxxxxx|F|xxxxx|M|Q|IIII|xx|S|T
// x are the reserved bits
#define SH_SR_T_BIT 1u << 0
#define SH_SR_T     "sr_t" ///< SR.T: True/False condition or carry/borrow bit
#define SH_SR_S_BIT 1u << 1
#define SH_SR_S     "sr_s" ///< SR.S: Specifies a saturation operation for a MAC instruction
#define SH_SR_I_BIT 1u << 4
#define SH_SR_I     "sr_i" ///< SR.I: Interrupt mask level: External interrupts of a lower level than IMASK are masked.
#define SH_SR_Q_BIT 1u << 8
#define SH_SR_Q     "sr_q" ///< SR.Q: State for divide step (Used by the DIV0S, DIV0U and DIV1 instructions)
#define SH_SR_M_BIT 1u << 9
#define SH_SR_M     "sr_m" ///< SR.M: State for divide step (Used by the DIV0S, DIV0U and DIV1 instructions)
#define SH_SR_F_BIT 1u << 15
#define SH_SR_F     "sr_f" ///< SR.FD: FPU disable bit (cleared to 0 by a reset)
#define SH_SR_B_BIT 1u << 28
#define SH_SR_B     "sr_b" ///< SR.BL: Exception/interrupt block bit (set to 1 by a reset, exception, or interrupt)
#define SH_SR_R_BIT 1u << 29
#define SH_SR_R     "sr_r" ///< SR.RB: General register bank specifier in privileged mode (set to 1 by a reset, exception or interrupt)
#define SH_SR_D_BIT 1u << 30
#define SH_SR_D     "sr_d" ///< SR.MD: Processor mode

/**
 * Registers available as global variables in the IL
 */
static const char *sh_global_registers[] = {
	"r0b0", "r1b0", "r2b0", "r3b0", "r4b0", "r5b0", "r6b0", "r7b0", ///< bank 0 registers
	"r0b1", "r1b1", "r2b1", "r3b1", "r4b1", "r5b1", "r6b1", "r7b1", ///< bank 1 registers
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15"
};

/**
 * All registers
 */
static const char *sh_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"sr", "gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15"
};

/**
 * Status bit registers
 */
static const char *sh_status_bit_registers[] = {
	SH_SR_T, SH_SR_S, SH_SR_Q, SH_SR_M, SH_SR_F, SH_SR_B, SH_SR_R, SH_SR_D
};

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
	SH_OP_SHAR,
	SH_OP_SHLD,
	SH_OP_SHLL,
	SH_OP_SHLR,
	SH_OP_SHLL2,
	SH_OP_SHLR2,
	SH_OP_SHLL8,
	SH_OP_SHLR8,
	SH_OP_SHLL16,
	SH_OP_SHLR16,
	SH_OP_BF,
	SH_OP_BFS,
	SH_OP_BT,
	SH_OP_BTS,
	SH_OP_BRA,
	SH_OP_BRAF,
	SH_OP_BSR,
	SH_OP_BSRF,
	SH_OP_JMP,
	SH_OP_JSR,
	SH_OP_RTS,
	SH_OP_CLRMAC,
	SH_OP_CLRS,
	SH_OP_CLRT,
	SH_OP_LDC,
	SH_OP_LDS,
	SH_OP_MOVCA,
	SH_OP_NOP,
	SH_OP_RTE,
	SH_OP_SETS,
	SH_OP_SETT,
	SH_OP_SLEEP,
	SH_OP_STC,
	SH_OP_STS,
	SH_OP_UNIMPL,
	/* end */
	SH_OP_SIZE
} SHOpMnem;

typedef struct sh_param_t {
	ut16 param[2];
	SHAddrMode mode;
} SHParam;

typedef struct sh_opcode_t {
	ut16 opcode;
	const char *str_mnem;
	SHOpMnem mnemonic;
	SHParam param[2];
	SHScaling scaling;
} SHOp;

SHOp *sh_disassembler(ut16 opcode);

RZ_API RZ_OWN char *sh_op_param_to_str(SHParam param, SHScaling scaling, ut64 pc);
RZ_API RZ_OWN char *sh_op_to_str(const SHOp *op, ut64 pc);

#endif /* RZ_ASM_SH_DISASSEMBLER_H */
