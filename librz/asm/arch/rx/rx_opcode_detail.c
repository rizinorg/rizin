// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rx_opcode_detail.h"
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
#define RxLdPart(x, v) \
	{ .type = RX_TOKEN_LD_PART, .tk.ld_part.tk_len = (x), .tk.ld_part.vid = (v) }
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
#define RxDspSplit(x, v, it, xx) \
	{ .type = RX_TOKEN_DSP_SPLIT, \
	  .tk.dsp_sp.tk_len = (x), .tk.dsp_sp.vid = (v), .tk.dsp_sp.tk_len_more = (xx), .tk.dsp_sp.interval = (it) }
#define RxIgnore(x) \
	{ .type = RX_TOKEN_IGNORE, .tk.reserved.tk_len = (x) }

#define RxRi(x, bind_v) \
	{ .type = RX_TOKEN_RI, .tk.reg.tk_len = (x), .tk.reg.vid = (bind_v) }

// TODO: Jmp maybe removed or an empty mark
#define RxJmp \
	{ .type = RX_TOKEN_JMP }

#define RxRegLimit(x, v) \
	{ .type = RX_TOKEN_REG_LIMIT, .tk.reg_li.tk_len = (x), .tk.reg_li.vid = (v) }

#define ImmData(v) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v), .tk.data.data_type = 1 }
#define DspData(v) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v), .tk.data.data_type = 2 }
#define PcDspData(v, l) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v), .tk.data.fixed_len = (l), .tk.data.data_type = 3 }
#define ImmFixedData(v, l) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v), .tk.data.fixed_len = (l), .tk.data.data_type = 1 }
#define RxHook \
	{ .type = RX_TOKEN_HOOK }
#define RxEnd \
	{ .type = RX_TOKEN_NON }

#define V0 0
#define V1 1
#define V2 2

RxDesc rx_inst_descs[RX_DESC_SIZE] = {
	{ .op = RX_OP_ABS, .tks = { RxCode(12, 0x07e2), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_ABS, .tks = { RxCode(16, 0xfc0f), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(12, 0x0fd7), RxLi(2, V0), RxCode(6, 0x02), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(16, 0xfc0b), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x08), RxLdPart(2, V0), RxCode(8, 0x02), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(8, 0x62), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	// { .op = RX_OP_ADD, .tks = { RxCode(6, 0x1c), RxLi(2, V0), RxReg(4, V1), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_ADD_UB, .tks = { RxCode(6, 0x12), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x02), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(6, 0x1c), RxLi(2, V0), RxReg(4, V1), RxReg(4, V2), ImmData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(12, 0x0ff2), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(8, 0x64), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(6, 0x1d), RxLi(2, V0), RxCode(4, 0x02), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_AND_UB, .tks = { RxCode(6, 0x14), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x04), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(12, 0xff4), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(6, 0x3c), RxLdPart(2, V1), RxReg(4, V1), RxCode(1, 0x1), RxImm(3, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(14, 0x3f19), RxLdPart(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(7, 0x3d), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(16, 0xfc67), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BCND_S, .tks = { RxCode(4, 0x1), RxCond(1, V0), RxDsp(3), RxEnd } },
	{ .op = RX_OP_BCND_B, .tks = { RxCode(4, 0x2), RxCond(4, V0), PcDspData(V0, 8), RxEnd } },
	{ .op = RX_OP_BCND_W, .tks = { RxCode(7, 0x1d), RxCond(1, V0), PcDspData(V0, 16), RxEnd } },
	{ .op = RX_OP_BMCND, .tks = { RxCode(11, 0x7e7), RxImm(3, V1), RxLdPart(2, V2), RxReg(4, V2), RxCond(4, V0), DspData(V2), RxEnd } },
	{ .op = RX_OP_BMCND, .tks = { RxCode(11, 0x7ef), RxImm(5, V1), RxCond(4, V0), RxReg(4, V2), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(11, 0x7e7), RxImm(3, V0), RxLdPart(2, V1), RxReg(4, V1), RxCode(4, 0xf), DspData(V1), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(14, 0x3f1b), RxLdPart(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(11, 0x7ef), RxImm(5, V0), RxCode(4, 0xf), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(16, 0xfc6f), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BRA_S, .tks = { RxCode(5, 0x1), RxJmp, RxDsp(3), RxEnd } },
	{ .op = RX_OP_BRA_B, .tks = { RxCode(8, 0x2e), RxJmp, PcDspData(V0, 8), RxEnd } },
	{ .op = RX_OP_BRA_W, .tks = { RxCode(8, 0x38), RxJmp, PcDspData(V0, 16), RxEnd } },
	{ .op = RX_OP_BRA_A, .tks = { RxCode(8, 0x04), RxJmp, PcDspData(V0, 24), RxEnd } },
	{ .op = RX_OP_BRA_L, .tks = { RxCode(12, 0x7f4), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BRK, .tks = { RxCode(8, 0x0), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(6, 0x3c), RxLdPart(2, V1), RxReg(4, V1), RxCode(1, 0x0), RxImm(3, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(14, 0x3f18), RxLdPart(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(7, 0x3c), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(16, 0xfc63), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BSR_W, .tks = { RxCode(8, 0x39), RxJmp, PcDspData(V0, 16), RxEnd } },
	{ .op = RX_OP_BSR_A, .tks = { RxCode(8, 0x05), RxJmp, PcDspData(V0, 24), RxEnd } },
	{ .op = RX_OP_BSR_L, .tks = { RxCode(12, 0x07f5), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(6, 0x3d), RxLdPart(2, V1), RxReg(4, V1), RxCode(1, 0x0), RxImm(3, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(14, 0x3f1a), RxLdPart(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(7, 0x3e), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(16, 0xfc6b), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_CLRPSW, .tks = { RxCode(12, 0x07fb), RxCb(4), RxEnd } },

	{ .op = RX_OP_CMP, .tks = { RxCode(8, 0x61), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_CMP, .tks = { RxCode(12, 0x0755), RxReg(4, V1), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_CMP, .tks = { RxCode(6, 0x1d), RxLi(2, V0), RxCode(4, 0x0), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_CMP_UB, .tks = { RxCode(6, 0x11), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_CMP, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x1), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },

	{ .op = RX_OP_DIV, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x08), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_DIV_UB, .tks = { RxCode(14, 0x3f08), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_DIV, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x08), RxLd(2, V0), RxCode(8, 0x08), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_DIVU, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x9), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_DIVU_UB, .tks = { RxCode(14, 0x3f09), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_DIVU, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x09), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	// EMUL family special Rd Range
	{ .op = RX_OP_EMUL, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x06), RxRegLimit(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_EMUL_UB, .tks = { RxCode(14, 0x3f06), RxLd(2, V0), RxReg(4, V0), RxRegLimit(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_EMUL, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x08), RxLd(2, V0), RxCode(8, 0x06), RxReg(4, V0), RxRegLimit(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_EMULU, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x07), RxRegLimit(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_EMULU_UB, .tks = { RxCode(14, 0x3f07), RxLd(2, V0), RxReg(4, V0), RxRegLimit(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_EMULU, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x07), RxReg(4, V0), RxRegLimit(4, V1), DspData(V0), RxEnd } },

	{ .op = RX_OP_FADD, .tks = { RxCode(20, 0xfd722), RxReg(4, V1), ImmFixedData(V0, 32), RxEnd } },
	{ .op = RX_OP_FADD, .tks = { RxCode(14, 0x3f22), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_FCMP, .tks = { RxCode(20, 0xfd721), RxReg(4, V1), ImmFixedData(V0, 32), RxEnd } },
	{ .op = RX_OP_FCMP, .tks = { RxCode(14, 0x3f21), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_FDIV, .tks = { RxCode(20, 0xfd724), RxReg(4, V1), ImmFixedData(V0, 32), RxEnd } },
	{ .op = RX_OP_FDIV, .tks = { RxCode(14, 0x3f24), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_FMUL, .tks = { RxCode(20, 0xfd723), RxReg(4, V1), ImmFixedData(V0, 32), RxEnd } },
	{ .op = RX_OP_FMUL, .tks = { RxCode(14, 0x3f23), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_FSUB, .tks = { RxCode(20, 0xfd720), RxReg(4, V1), ImmFixedData(V0, 32), RxEnd } },
	{ .op = RX_OP_FSUB, .tks = { RxCode(14, 0x3f20), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },

	{ .op = RX_OP_FTOI, .tks = { RxCode(14, 0x3f25), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_INT, .tks = { RxCode(16, 0x7560), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_ITOF_UB, .tks = { RxCode(14, 0x3f11), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ITOF, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x11), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_JMP, .tks = { RxCode(12, 0x07f0), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_JSR, .tks = { RxCode(12, 0x07f1), RxReg(4, V0), RxEnd } },

	// Mov family
	{ .op = RX_OP_MOV, .tks = { RxCode(2, 0x2), RxSz(2), RxCode(1, 0x0), RxDspSplit(4, V1, 3, 1), RxReg(3, V1), RxIgnore(1), RxReg(3, V0), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(2, 0x2), RxSz(2), RxCode(1, 0x1), RxDspSplit(4, V0, 3, 1), RxReg(3, V0), RxIgnore(1), RxReg(3, V1), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(8, 0x66), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(6, 0x0f), RxSz(2), RxDspSplit(1, V1, 3, 4), RxReg(3, V1), RxIgnore(4), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(12, 0x0754), RxReg(4, V1), ImmFixedData(V0, 8) } },
	{ .op = RX_OP_MOV, .tks = { RxCode(8, 0xfb), RxReg(4, V1), RxLi(2, V0), RxCode(2, 0x02), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(2, 0x3), RxSz(2), RxCode(4, 0xf), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	// ld are limited to 0-2
	{ .op = RX_OP_MOV, .tks = { RxCode(6, 0x3e), RxLdPart(2, V1), RxReg(4, V1), RxLi(2, V0), RxSz(2), DspData(V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(2, 0x3), RxSz(2), RxCode(2, 0x3), RxLdPart(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(10, 0x03f9), RxSz(2), RxRi(4, V0), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(2, 0x3), RxSz(2), RxLdPart(2, V1), RxCode(2, 0x3), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(10, 0x03f8), RxSz(2), RxRi(4, V1), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(2, 0x3), RxSz(2), RxLdPart(2, V1), RxLdPart(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(12, 0xfd2), RxAd(2), RxSz(2), RxReg(4, V1), RxHook, RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MOV, .tks = { RxCode(12, 0xfd2), RxAd(2), RxSz(2), RxReg(4, V0), RxHook, RxReg(4, V1), RxEnd } },

	{ .op = RX_OP_MOVU, .tks = { RxCode(4, 0xb), RxSz(1), RxDspSplit(4, V0, 3, 1), RxReg(3, V0), RxIgnore(1), RxReg(3, V1), RxEnd } },
	{ .op = RX_OP_MOVU, .tks = { RxCode(5, 0x0b), RxSz(1), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MOVU, .tks = { RxCode(11, 0x07f6), RxSz(1), RxRi(4, V0), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MOVU, .tks = { RxCode(12, 0x0fd3), RxAd(2), RxCode(1, 0x0), RxSz(1), RxReg(4, V0), RxReg(4, V1), RxEnd } },

	{ .op = RX_OP_MACHI, .tks = { RxCode(16, 0xfd04), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MACLO, .tks = { RxCode(16, 0xfd05), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MAX, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x4), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MAX_UB, .tks = { RxCode(14, 0x3f04), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MAX, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x04), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MIN, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x5), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MIN_UB, .tks = { RxCode(14, 0x3f05), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MIN, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x05), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MUL, .tks = { RxCode(8, 0x63), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MUL, .tks = { RxCode(6, 0x1d), RxLi(2, V0), RxCode(4, 0x01), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MUL_UB, .tks = { RxCode(6, 0x13), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MUL, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x3), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_MUL, .tks = { RxCode(12, 0xff3), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MULHI, .tks = { RxCode(16, 0xfd00), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MULLO, .tks = { RxCode(16, 0xfd01), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_NOP, .tks = { RxCode(8, 0x03), RxEnd } },
	{ .op = RX_OP_NEG, .tks = { RxCode(12, 0x07e1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_NEG, .tks = { RxCode(16, 0xfc07), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_NOT, .tks = { RxCode(12, 0x07e0), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_NOT, .tks = { RxCode(16, 0xfc3b), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_OR, .tks = { RxCode(8, 0x65), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_OR, .tks = { RxCode(6, 0x1d), RxLi(2, V0), RxCode(4, 0x03), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_OR_UB, .tks = { RxCode(6, 0x15), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_OR, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x5), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_OR, .tks = { RxCode(12, 0xff5), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MVFACHI, .tks = { RxCode(20, 0xfd1f0), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVFACMI, .tks = { RxCode(20, 0xfd1f2), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVFC, .tks = { RxCode(16, 0xfd6a), RxCr(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MVTACHI, .tks = { RxCode(20, 0xfd170), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVTACLO, .tks = { RxCode(20, 0xfd171), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVTC, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x30), RxCr(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MVTC, .tks = { RxCode(16, 0xfd68), RxReg(4, V0), RxCr(4, V1), RxEnd } },
	{ .op = RX_OP_MVTIPL, .tks = { RxCode(20, 0x75700), RxImm(4, V0), RxEnd } },
	{ .op = RX_OP_POP, .tks = { RxCode(12, 0x7eb), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_POPC, .tks = { RxCode(12, 0x7ee), RxCr(4, V0), RxEnd } },
	{ .op = RX_OP_POPM, .tks = { RxCode(8, 0x6f), RxRegLimit(4, V0), RxRegLimit(4, V1), RxEnd } }, // special rn
	{ .op = RX_OP_PUSH, .tks = { RxCode(10, 0x1fa), RxSz(2), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_PUSH, .tks = { RxCode(6, 0x3d), RxLdPart(2, V0), RxReg(4, V0), RxCode(2, 0x2), RxSz(2), DspData(V0), RxEnd } },
	{ .op = RX_OP_PUSHC, .tks = { RxCode(12, 0x7ec), RxCr(4, V0), RxEnd } },
	{ .op = RX_OP_PUSHM, .tks = { RxCode(8, 0x6e), RxRegLimit(4, V0), RxRegLimit(4, V1), RxEnd } }, // special rn
	{ .op = RX_OP_RACW, .tks = { RxCode(19, 0x7e8c0), RxImm(1, V0), RxCode(4, 0x0), RxEnd } },
	{ .op = RX_OP_REVL, .tks = { RxCode(16, 0xfd67), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_REVW, .tks = { RxCode(16, 0xfd65), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_RMPA, .tks = { RxCode(14, 0x1fe3), RxSz(2), RxEnd } },
	{ .op = RX_OP_ROLC, .tks = { RxCode(12, 0x7e5), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_RORC, .tks = { RxCode(12, 0x7e4), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_ROTL, .tks = { RxCode(15, 0x7eb7), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ROTL, .tks = { RxCode(16, 0xfd66), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ROTR, .tks = { RxCode(15, 0x7eb6), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ROTR, .tks = { RxCode(16, 0xfd64), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ROUND, .tks = { RxCode(14, 0x3f26), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_RTE, .tks = { RxCode(16, 0x7f95), RxEnd } },
	{ .op = RX_OP_RTFI, .tks = { RxCode(16, 0x7f94), RxEnd } },
	{ .op = RX_OP_RTS, .tks = { RxCode(8, 0x02), RxEnd } },
	{ .op = RX_OP_RTE, .tks = { RxCode(16, 0x7f94), RxEnd } },
	{ .op = RX_OP_RTSD, .tks = { RxCode(8, 0x67), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_RTSD, .tks = { RxCode(8, 0x3f), RxRegLimit(4, V0), RxRegLimit(4, V1), ImmFixedData(V0, 8), RxEnd } }, // special rn
	{ .op = RX_OP_SAT, .tks = { RxCode(12, 0x7e3), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_SATR, .tks = { RxCode(16, 0x7f93), RxEnd } },
	{ .op = RX_OP_WAIT, .tks = { RxCode(16, 0x7f96), RxEnd } },
	{ .op = RX_OP_SCCOND, .tks = { RxCode(12, 0xfcd), RxSz(2), RxLd(2, V1), RxReg(4, V1), RxCond(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_SCMPU, .tks = { RxCode(16, 0x7f83), RxEnd } },
	{ .op = RX_OP_SETPSW, .tks = { RxCode(12, 0x7fa), RxCb(4), RxEnd } },
	{ .op = RX_OP_SHAR, .tks = { RxCode(7, 0x35), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SHAR, .tks = { RxCode(16, 0xfd61), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SHAR, .tks = { RxCode(11, 0x07ed), RxImm(5, V0), RxReg(4, V1), RxReg(4, V2), RxEnd } },

	{ .op = RX_OP_SHLL, .tks = { RxCode(7, 0x36), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SHLL, .tks = { RxCode(16, 0xfd62), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SHLL, .tks = { RxCode(11, 0x07ee), RxImm(5, V0), RxReg(4, V1), RxReg(4, V2), RxEnd } },

	{ .op = RX_OP_SHLR, .tks = { RxCode(7, 0x34), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SHLR, .tks = { RxCode(16, 0xfd60), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SHLR, .tks = { RxCode(11, 0x07ec), RxImm(5, V0), RxReg(4, V1), RxReg(4, V2), RxEnd } },

	{ .op = RX_OP_SBB, .tks = { RxCode(16, 0xfc03), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SBB, .tks = { RxCode(14, 0x01a8), RxLdPart(2, V0), RxCode(8, 0x00), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },

	{ .op = RX_OP_SUB, .tks = { RxCode(8, 0x60), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_SUB_UB, .tks = { RxCode(6, 0x10), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_SUB, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x0), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_SUB, .tks = { RxCode(12, 0xff0), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },

	{ .op = RX_OP_SMOVB, .tks = { RxCode(16, 0x7f8b), RxEnd } },
	{ .op = RX_OP_SMOVF, .tks = { RxCode(16, 0x7f8f), RxEnd } },
	{ .op = RX_OP_SMOVU, .tks = { RxCode(16, 0x7f87), RxEnd } },
	{ .op = RX_OP_SSTR, .tks = { RxCode(14, 0x1fe2), RxSz(2), RxEnd } },
	{ .op = RX_OP_STNZ, .tks = { RxCode(12, 0x0fd7), RxLi(2, V0), RxCode(6, 0x0f), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_STZ, .tks = { RxCode(12, 0x0fd7), RxLi(2, V0), RxCode(6, 0x0e), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_SUNTIL, .tks = { RxCode(14, 0x1fe0), RxSz(2), RxEnd } },
	{ .op = RX_OP_SWHILE, .tks = { RxCode(14, 0x1fe1), RxSz(2), RxEnd } },

	{ .op = RX_OP_TST, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x0c), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_TST_UB, .tks = { RxCode(14, 0x3f0c), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_TST, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x0c), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },

	{ .op = RX_OP_XCHG_UB, .tks = { RxCode(14, 0x3f10), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_XCHG, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x10), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_XOR, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x0d), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_XOR, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x08), RxLd(2, V0), RxCode(8, 0x0d), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_XOR_UB, .tks = { RxCode(14, 0x3f0d), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
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
#undef RxHook
#undef RxEnd
#undef ImmData
#undef DspData
#undef PcDspData
#undef ImmFixedData
#undef RxRi

#undef V0
#undef V1
#undef V2