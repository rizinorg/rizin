// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RX_OPCODE_DETAIL_H
#define RX_OPCODE_DETAIL_H

#include <rz_util.h>

typedef enum {
	RX_OP_INVALID,
	RX_OP_ABS,
	RX_OP_ADC,
	RX_OP_ADD,
	RX_OP_ADD_UB,
	RX_OP_AND,
	RX_OP_AND_UB,
	RX_OP_BCLR,
	RX_OP_BCND_S,
	RX_OP_BCND_B,
	RX_OP_BCND_W,
	RX_OP_BMCND,
	RX_OP_BNOT,
	RX_OP_BRA_S,
	RX_OP_BRA_B,
	RX_OP_BRA_W,
	RX_OP_BRA_A,
	RX_OP_BRA_L,
	RX_OP_BRK,
	RX_OP_BSET,
	RX_OP_BSR_W,
	RX_OP_BSR_A,
	RX_OP_BSR_L,
	RX_OP_BTST,
	RX_OP_CLRPSW,
	RX_OP_CMP,
	RX_OP_CMP_UB,
	RX_OP_DIV,
	RX_OP_DIV_UB,
	RX_OP_DIVU,
	RX_OP_DIVU_UB,
	RX_OP_EMUL,
	RX_OP_EMUL_UB,
	RX_OP_EMULU,
	RX_OP_EMULU_UB,
	RX_OP_FADD,
	RX_OP_FCMP,
	RX_OP_FDIV,
	RX_OP_FMUL,
	RX_OP_FSUB,
	RX_OP_FTOI,
	RX_OP_INT,
	RX_OP_ITOF,
	RX_OP_ITOF_UB,
	RX_OP_JMP,
	RX_OP_JSR,
	RX_OP_MACHI,
	RX_OP_MACLO,
	RX_OP_MAX,
	RX_OP_MAX_UB,
	RX_OP_MIN,
	RX_OP_MIN_UB,
	RX_OP_MOV,
	RX_OP_MOVU,
	RX_OP_MUL,
	RX_OP_MUL_UB,
	RX_OP_MULHI,
	RX_OP_MULLO,
	RX_OP_MVFACHI,
	RX_OP_MVFACMI,
	RX_OP_MVFC,
	RX_OP_MVTACHI,
	RX_OP_MVTACLO,
	RX_OP_MVTC,
	RX_OP_MVTIPL,
	RX_OP_NEG,
	RX_OP_NOP,
	RX_OP_NOT,
	RX_OP_OR,
	RX_OP_OR_UB,
	RX_OP_POP,
	RX_OP_POPC,
	RX_OP_POPM,
	RX_OP_PUSH,
	RX_OP_PUSHC,
	RX_OP_PUSHM,
	RX_OP_RACW,
	RX_OP_REVL,
	RX_OP_REVW,
	RX_OP_RMPA,
	RX_OP_ROLC,
	RX_OP_RORC,
	RX_OP_ROTL,
	RX_OP_ROTR,
	RX_OP_ROUND,
	RX_OP_RTE,
	RX_OP_RTFI,
	RX_OP_RTS,
	RX_OP_RTSD,
	RX_OP_SAT,
	RX_OP_SATR,
	RX_OP_SBB,
	RX_OP_SCCOND,
	RX_OP_SCMPU,
	RX_OP_SETPSW,
	RX_OP_SHAR,
	RX_OP_SHLL,
	RX_OP_SHLR,
	RX_OP_SMOVB,
	RX_OP_SMOVF,
	RX_OP_SMOVU,
	RX_OP_SSTR,
	RX_OP_STNZ,
	RX_OP_STZ,
	RX_OP_SUB,
	RX_OP_SUB_UB,
	RX_OP_SUNTIL,
	RX_OP_SWHILE,
	RX_OP_TST,
	RX_OP_TST_UB,
	RX_OP_WAIT,
	RX_OP_XCHG,
	RX_OP_XCHG_UB,
	RX_OP_XOR,
	RX_OP_XOR_UB,
	_RX_OP_COUNT,
} RxOpCode;

typedef enum {
	// General Purpose Register
	// R0 as SP
	RX_REG_R0,
	RX_REG_R1,
	RX_REG_R2,
	RX_REG_R3,
	RX_REG_R4,
	RX_REG_R5,
	RX_REG_R6,
	RX_REG_R7,
	RX_REG_R8,
	RX_REG_R9,
	RX_REG_R10,
	RX_REG_R11,
	RX_REG_R12,
	RX_REG_R13,
	RX_REG_R14,
	RX_REG_R15,
	// Control Register
	RX_REG_ISP,
	RX_REG_USP,
	RX_REG_INTB,
	RX_REG_PC,
	RX_REG_PSW,
	RX_REG_BPC,
	RX_REG_BPSW,
	RX_REG_FINTV,
	RX_REG_FPSW,
	RX_REG_ACC, // dsp
	RX_REG_RESERVED
} RxReg;

typedef enum {
	RX_EXT_NON,
	RX_EXT_UB,
	RX_EXT_B,
	RX_EXT_W,
	RX_EXT_L,
	RX_EXT_UW,
	_RX_EXT_COUNT,
} RxOpExtMark;

typedef enum {
	RX_TOKEN_NON,
	RX_TOKEN_INST,
	RX_TOKEN_LD,
	RX_TOKEN_LI,
	RX_TOKEN_LD_PART,
	RX_TOKEN_MI,
	RX_TOKEN_IMM,
	RX_TOKEN_REG,
	RX_TOKEN_COND,
	RX_TOKEN_DSP,
	RX_TOKEN_DSP_SPLIT,
	RX_TOKEN_IGNORE,
	RX_TOKEN_SZ,
	RX_TOKEN_AD,
	RX_TOKEN_CR,
	RX_TOKEN_CB,
	RX_TOKEN_JMP,
	RX_TOKEN_DATA,
	RX_TOKEN_RI,
	RX_TOKEN_REG_LIMIT,
	RX_TOKEN_HOOK, // for validation at the end of token
} RxTokenType;

struct rx_inst_token_t {
	ut8 tk_len;
	ut32 detail;
};
typedef struct rx_inst_token_t RxInstToken;

struct rx_oprand_related_token_t {
	ut8 tk_len;
	ut8 vid;
};
typedef struct rx_oprand_related_token_t RxDispLenToken;
typedef struct rx_oprand_related_token_t RxImmLenToken;
typedef struct rx_oprand_related_token_t RxVarDispLenToken;
typedef struct rx_oprand_related_token_t RxRegToken;
typedef struct rx_oprand_related_token_t RxImmToken;
typedef struct rx_oprand_related_token_t RxControlRegToken;
typedef struct rx_oprand_related_token_t RxCondToken;

typedef struct {
	ut8 fixed_len;
	ut8 vid;
	ut8 data_type;
} RxDataToken;

typedef struct {
	ut8 tk_len;
	ut8 vid;
	ut8 interval;
	ut8 tk_len_more;
} RxDspSplitToken;

struct rx_simple_token_t {
	ut8 tk_len;
};
typedef struct rx_simple_token_t RxMemexToken;
typedef struct rx_simple_token_t RxSizeToken;
typedef struct rx_simple_token_t RxFlagToken;
typedef struct rx_simple_token_t RxAddrToken;
typedef struct rx_simple_token_t RxSimpleToken;
typedef struct rx_simple_token_t RxDispToken;

typedef union rx_token_union {
	RxInstToken inst;
	RxDispLenToken ld;
	RxImmLenToken li;
	RxVarDispLenToken ld_part; // ld for partial valid bits range
	RxMemexToken mi;
	RxImmToken imm;
	RxRegToken reg;
	RxRegToken reg_li; // reg for limited range
	RxRegToken ri;
	RxCondToken cond;
	RxDispToken dsp;
	RxDspSplitToken dsp_sp;
	RxSizeToken sz;
	RxAddrToken ad;
	RxControlRegToken cr;
	RxFlagToken cb;
	RxSimpleToken jmp;
	RxDataToken data;
	RxSimpleToken reserved;
} RxTokenUnion;

struct rx_token_t {
	RxTokenType type;
	RxTokenUnion tk;
};
typedef struct rx_token_t RxToken;

#define MAX_TOKEN    10
#define RX_SET_V1_SZ 90
#define RX_SET_V2_SZ (RX_SET_V1_SZ + 19)
#define RX_SET_V3_SZ (RX_SET_V2_SZ + 4)
#define RX_SET_SIZE  RX_SET_V3_SZ

// todo: accurate num
#define RX_DESC_SIZE (RX_SET_SIZE * 3)

struct rx_desc_t {
	RxOpCode op;
	RxToken tks[MAX_TOKEN];
};
typedef struct rx_desc_t RxDesc;

extern RxDesc rx_inst_descs[RX_DESC_SIZE];

#endif