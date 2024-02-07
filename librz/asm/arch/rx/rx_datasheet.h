#ifndef RX_DATASHEET_H
#define RX_DATASHEET_H

#include <rz_util.h>

typedef enum {
	RX_OP_INVALID
		RX_OP_ABS,
	RX_OP_ADC,
	RX_OP_ADD,
} RxOpCode;

typedef enum {
	// General Purpose Register
	RX_REG_R0, // SP
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
	RX_EXT_UB,
	RX_EXT_B,
	RX_EXT_W,
	RX_EXT_UW,
	RX_EXT_L
} RxOpExtMark;

typedef enum {
	RX_TOKEN_NON,
	RX_TOKEN_INST,
	RX_TOKEN_LD,
	RX_TOKEN_LI,
	RX_TOKEN_LDR,
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
typedef struct rx_oprand_related_token_t RxDataToken;

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
	RxVarDispLenToken ldr; // lds (ld for src) and ldd (ld for dest)
	RxMemexToken mi;
	RxImmToken imm;
	RxRegToken reg;
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
#define RX_DESC_SIZE (RX_SET_SIZE * 4)

struct rx_desc_t {
	RxOpCode op;
	RxToken tks[MAX_TOKEN];
};
typedef struct rx_desc_t RxDesc;

#define RxCode(x, y) \
	{ \
		.type = RX_TOKEN_INST, .tk.inst = {.tk_len = (x), \
			.detail = (y) } \
	}
#define RxReg(x, v) \
	{ .type = RX_TOKEN_REG, .tk.reg.tk_len = (x), .tk.reg.vid = (v) }
#define RxLi(x, v) \
	{ .type = RX_TOKEN_LI, .tk.li.tk_len = (x), .tk.li.vid = (v) }
#define RxImm(x, v) \
	{ .type = RX_TOKEN_IMM, .tk.imm.tk_len = (x), .tk.imm.vid = (v) }
#define RxMi(x) \
	{ .type = RX_TOKEN_MI, .tk.mi.tk_len = (x) }
#define RxLd(x, v) \
	{ .type = RX_TOKEN_LD, .tk.ld.tk_len = (x), .tk.ld.vid = (v) }
#define RxLds(x, v) \
	{ .type = RX_TOKEN_LDR, .tk.ldr.tk_len = (x), .tk.ldr.vid = (v) }
#define RxLdd(x, v) \
	{ .type = RX_TOKEN_LDR, .tk.ldr.tk_len = (x), .tk.ldr.vid = (v) }
#define RxCond(x, v) \
	{ .type = RX_TOKEN_COND, .tk.cond.tk_len = (x), .tk.cond.vid = (v) }
#define RxDsp(x) \
	{ .type = RX_TOKEN_DSP, .tk.dsp.tk_len = (x) }
#define RxSz(x) \
	{ .type = RX_TOKEN_SZ, .tk.sz.tk_len = (x) }
#define RxAd(x) \
	{ .type = RX_TOKEN_AD, .tk.ad.tk_len = (x) }
#define RxCr(x, v) \
	{ .type = RX_TOKEN_CR, .tk.cr.tk_len = (x), .tk.cr.vid = (v) }
#define RxCb(x) \
	{ .type = RX_TOKEN_CB, .tk.cb.tk_len = (x) }
#define RxDspSplit(x, v, interval, xx) \
	{ .type = RX_TOKEN_DSP_SPLIT, \
	  .tk.dsp_sp.tk_len = (x), .tk.dsp_sp.vid = (v).tk.dsp_sp.tk_len_more = (xx), .tk.dsp_sp.interval = (interval) }
#define RxIgnore(x) \
	{ .type = RX_TOKEN_IGNORE, .tk.reserved.tk_len = (x) }
#define RxJmp(w) \
	{ .type = RX_TOKEN_JMP, .tk.jmp.tk_len = (w) }

#define ImmData(vid) \
	{ .type = RX_TOKEN_DATA, .tk.reserved.tk_len = (vid) }
#define DspData(vid) \
	{ .type = RX_TOKEN_DATA, .tk.reserved.tk_len = (vid) }
#define PcDspData(vid) \
	{ .type = RX_TOKEN_DATA, .tk.reserved.tk_len = (vid) }

#define RxEnd \
	{ .type = RX_TOKEN_NON }

#define V0 0
#define V1 1
#define V2 2

RxDesc rx_inst_descs[RX_DESC_SIZE] = {
	{ .op = RX_OP_ABS, .tks = { RxCode(12, 0x7e2), RxReg(4), RxEnd } },
	{ .op = RX_OP_ABS, .tks = { RxCode(16, 0xfcf), RxReg(4), RxReg(4), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(12, 0xfd7), RxLi(2, 0), RxCode(6, 0x02), RxReg(4), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(8, 0x62), RxImm(4), RxReg(4), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x3), RxLd(2, 0), RxReg(4), RxReg(4), RxEnd } },
};

#undef RxCode
#undef RxReg
#undef RxLi
#undef RxIm
#undef RxMi
#undef RxLd
#undef RxLds
#undef RxLdd
#undef RxCond
#undef RxDsp
#undef RxSz
#undef RxAd
#undef RxCr
#undef RxCb
#undef RxDspSplit
#undef RxIgnore
#undef RxJmp
#undef RxEnd
#undef ImmData
#undef DspData
#undef PcDspData
#undef V0
#undef V1
#undef V2

#endif