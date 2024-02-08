#include "rx_datasheet.h"
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

// TODO: Jmp maybe removed or an empty mark
#define RxJmp(w) \
	{ .type = RX_TOKEN_JMP, .tk.jmp.tk_len = (w) }

#define ImmData(v) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v) }
#define DspData(v) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v) }
#define PcDspData(v, l) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v), .tk.data.fixed_len = (l) }
#define ImmFixedData(v, l) \
	{ .type = RX_TOKEN_DATA, .tk.data.vid = (v), .tk.data.fixed_len = (l) }
#define RxEnd \
	{ .type = RX_TOKEN_NON }

#define V0 0
#define V1 1
#define V2 2

RxDesc rx_inst_descs[RX_DESC_SIZE] = {
	{ .op = RX_OP_ABS, .tks = { RxCode(12, 0x7e20), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_ABS, .tks = { RxCode(16, 0xfcf0), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(12, 0xfd70), RxLi(2, V0), RxCode(6, 0x02), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(16, 0xfc0b), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ADC, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x08), RxLd(2, V0), RxCode(8, 0x02), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(8, 0x62), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(6, 0x1c), RxLi(2, V0), RxReg(4, V1), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_ADD_UB, .tks = { RxCode(6, 0x12), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x02), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(6, 0x1c), RxLi(2, V0), RxReg(4, V1), RxReg(4, V2), ImmData(V0), RxEnd } },
	{ .op = RX_OP_ADD, .tks = { RxCode(16, 0xff20), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(8, 0x64), RxImm(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(6, 0x1d), RxLi(2, V0), RxCode(4, 0x02), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_AND_UB, .tks = { RxCode(6, 0x14), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x04), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_AND, .tks = { RxCode(12, 0xff4), RxReg(4, V2), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(6, 0x3c), RxLd(2, V1), RxReg(4, V1), RxCode(1, 0x1), RxImm(3, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(14, 0x3f19), RxLd(2, V1), RxReg(4, V1), RxReg(4, V0), RxDsp(V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(7, 0x3d), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BCLR, .tks = { RxCode(16, 0xfc67), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BCND_S, .tks = { RxCode(4, 0x1), RxCond(1, V0), RxDsp(3), RxEnd } },
	{ .op = RX_OP_BCND_B, .tks = { RxCode(4, 0x2), RxCond(4, V0), PcDspData(V0, 8), RxEnd } },
	{ .op = RX_OP_BCND_W, .tks = { RxCond(7, 0x1d), RxCond(1, V0), PcDspData(V0, 16), RxEnd } },
	{ .op = RX_OP_BMCND, .tks = { RxCode(11, 0x7e7), RxImm(3, V1), RxLd(2, V2), RxReg(4, V2), RxCond(4, V0), DspData(V2), RxEnd } },
	{ .op = RX_OP_BMCND, .tks = { RxCode(11, 0x7ef), RxImm(5, V1), RxCond(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(11, 0x7e7), RxImm(3, V0), RxLd(2, V1), RxReg(4, V1), RxCode(4, 0xf), DspData(V1), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(14, 0x3f1b), RxLd(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(11, 0x7ef), RxImm(5, V0), RxCode(4, 0xf), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BNOT, .tks = { RxCode(16, 0xfc6f), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BRA_S, .tks = { RxCode(5, 0x1), RxJmp(3), RxDsp(3), RxEnd } },
	{ .op = RX_OP_BRA_B, .tks = { RxCode(8, 0x2e), RxJmp(8), PcDspData(V0, 8), RxEnd } },
	{ .op = RX_OP_BRA_W, .tks = { RxCode(8, 0x38), RxJmp(16), PcDspData(V0, 16), RxEnd } },
	{ .op = RX_OP_BRA_A, .tks = { RxCode(8, 0x04), RxJmp(24), PcDspData(V0, 24), RxEnd } },
	{ .op = RX_OP_BRA_L, .tks = { RxCode(12, 0x7f4), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BRK, .tks = { RxCode(8, 0x0), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(6, 0x3c), RxLd(2, V1), RxReg(4, V1), RxCode(1, 0x0), RxImm(3, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(14, 0x3f18), RxLd(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(7, 0x3c), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BSET, .tks = { RxCode(16, 0xfc63), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_BSR_W, .tks = { RxCode(8, 0x39), RxJmp(16), PcDspData(V0, 16), RxEnd } },
	{ .op = RX_OP_BSR_A, .tks = { RxCode(8, 0x05), RxJmp(24), PcDspData(V0, 24), RxEnd } },
	{ .op = RX_OP_BSR_L, .tks = { RxCode(12, 0x07f5), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_TST, .tks = { RxCode(6, 0x3d), RxLd(2, V1), RxReg(4, V1), RxCode(1, 0x0), RxImm(3, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(14, 0x3f1a), RxLd(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(7, 0x3e), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_BTST, .tks = { RxCode(16, 0xfc6b), RxReg(4, V1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_CLRPSW, .tks = { RxCode(12, 0x07fb), RxCb(4), RxEnd } },

	{ .op = RX_OP_CMP, .tks = { RxCode(8, 0x61), RxImm(5, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_CMP, .tks = { RxCode(12, 0x0755), RxReg(4, V1), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_CMP, .tks = { RxCode(6, 0x1d), RxLi(2, V0), RxCode(4, 0x0), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_CMP_UB, .tks = { RxCode(6, 0x11), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_CMP, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x1), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_DIV, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x08), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_DIV_UB, .tks = { RxCode(14, 0x3f08), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_DIV, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x08), RxLd(2, V0), RxCode(8, 0x08), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },

	{ .op = RX_OP_FTOI, .tks = { RxCode(14, 0x3f25), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_INT, .tks = { RxCode(16, 0x7560), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_ITOF_UB, .tks = { RxCode(14, 0x3f11), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_ITOF, .tks = { RxCode(8, 0x06), RxMi(2), RxCode(4, 0x8), RxLd(2, V0), RxCode(8, 0x11), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_JMP, .tks = { RxCode(12, 0x07f0), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_JSR, .tks = { RxCode(12, 0x07f1), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MACHI, .tks = { RxCode(16, 0xfd04), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MACLO, .tks = { RxCode(16, 0xfd05), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MVFACHI, .tks = { RxCode(20, 0xfd1f0), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVFACMI, .tks = { RxCode(20, 0xfd1f2), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVFC, .tks = { RxCode(16, 0xfd6a), RxCond(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_MVTACHI, .tks = { RxCode(20, 0xfd170), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVTACLO, .tks = { RxCode(20, 0xfd171), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_MVTC, .tks = { RxCode(12, 0xfd7), RxLi(2, V0), RxCode(6, 0x30), RxCr(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_MVTC, .tks = { RxCode(16, 0xfd68), RxReg(4, V0), RxCr(4, V1), RxEnd } },
	{ .op = RX_OP_MVTIPL, .tks = { RxCode(20, 0x75700), RxImm(4, V0), RxEnd } },
	{ .op = RX_OP_POP, .tks = { RxCode(12, 0x7eb), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_POPC, .tks = { RxCode(12, 0x7ee), RxCr(4, V0), RxEnd } },
	{ .op = RX_OP_POPM, .tks = { RxCode(8, 0x6f), RxReg(4, V0), RxReg(4, V1), RxEnd } }, // special rn
	{ .op = RX_OP_PUSH, .tks = { RxCode(10, 0x1fa), RxSz(2), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_PUSH, .tks = { RxCode(6, 0x3d), RxLd(2, V0), RxReg(4, V0), RxCode(2, 0x2), RxSz(2), DspData(V0), RxEnd } },
	{ .op = RX_OP_PUSHC, .tks = { RxCode(12, 0x7ec), RxCr(4, V0), RxEnd } },
	{ .op = RX_OP_PUSHM, .tks = { RxCode(8, 0x6e), RxReg(4, V0), RxReg(4, V1), RxEnd } }, // special rn
	{ .op = RX_OP_RACW, .tks = { RxCode(19, 0x7e8c0), RxImm(1, V0), RxCode(4, 0x0), RxEnd } },
	{ .op = RX_OP_REVL, .tks = { RxCode(16, 0xfd67), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_REVW, .tks = { RxCode(16, 0xfd65), RxReg(4, V0), RxReg(4, V1), RxEnd } },
	{ .op = RX_OP_RMPA, .tks = { RxCode(14, 0x1fe3), RxSz(2), RxEnd } },
	{ .op = RX_OP_ROLC, .tks = { RxCode(12, 0x7e5), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_RORC, .tks = { RxCode(12, 0x7e4), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_ROUND, .tks = { RxCode(14, 0x3f62), RxLd(2, V0), RxReg(4, V0), RxReg(4, V1), DspData(V0), RxEnd } },
	{ .op = RX_OP_RTE, .tks = { RxCode(16, 0x7f95), RxEnd } },
	{ .op = RX_OP_RTFI, .tks = { RxCode(16, 0x7f94), RxEnd } },
	{ .op = RX_OP_RTS, .tks = { RxCode(8, 0x02), RxEnd } },
	{ .op = RX_OP_RTE, .tks = { RxCode(16, 0x7f94), RxEnd } },
	{ .op = RX_OP_RTSD, .tks = { RxCode(8, 0x67), ImmFixedData(V0, 8), RxEnd } },
	{ .op = RX_OP_RTSD, .tks = { RxCode(8, 0x3f), RxReg(4, V0), RxReg(4, V1), ImmFixedData(V0, 8), RxEnd } }, // special rn
	{ .op = RX_OP_SAT, .tks = { RxCode(12, 0x7e3), RxReg(4, V0), RxEnd } },
	{ .op = RX_OP_SATR, .tks = { RxCode(16, 0x7f93), RxEnd } },
	{ .op = RX_OP_WAIT, .tks = { RxCode(16, 0x7f96), RxEnd } },
	{ .op = RX_OP_SCCOND, .tks = { RxCode(12, 0xfcd), RxSz(2), RxLd(2, V1), RxReg(4, V1), RxReg(4, V0), DspData(V1), RxEnd } },
	{ .op = RX_OP_SCMPU, .tks = { RxCode(16, 0x7f83), RxEnd } },
	{ .op = RX_OP_SETPSW, .tks = { RxCode(12, 0x7fa), RxCb(4), RxEnd } },
	{ .op = RX_OP_SMOVB, .tks = { RxCode(16, 0x7f8b), RxEnd } },
	{ .op = RX_OP_SMOVF, .tks = { RxCode(16, 0x7f8f), RxEnd } },
	{ .op = RX_OP_SMOVU, .tks = { RxCode(16, 0x7f87), RxEnd } },
	{ .op = RX_OP_SSTR, .tks = { RxCode(14, 0x1fe2), RxSz(2), RxEnd } },
	{ .op = RX_OP_STNZ, .tks = { RxCode(12, 0x0fd7), RxLi(2, V0), RxCode(6, 0x0f), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_STZ, .tks = { RxCode(12, 0x0fd7), RxLi(2, V0), RxCode(6, 0x0e), RxReg(4, V1), ImmData(V0), RxEnd } },
	{ .op = RX_OP_SUNTIL, .tks = { RxCode(14, 0x1fe0), RxSz(2), RxEnd } },
	{ .op = RX_OP_SWHILE, .tks = { RxCode(14, 0x1fe1), RxSz(2), RxEnd } },
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