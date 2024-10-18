// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone/capstone.h>

#include "arm_cs.h"
#include "arm_accessors64.h"

#define REG64(x)      rz_str_get_null(cs_reg_name(*handle, insn->detail->CS_aarch64_.operands[x].reg))
#define MEMBASE64(x)  rz_str_get_null(cs_reg_name(*handle, insn->detail->CS_aarch64_.operands[x].mem.base))
#define MEMINDEX64(x) rz_str_get_null(cs_reg_name(*handle, insn->detail->CS_aarch64_.operands[x].mem.index))

RZ_IPI const char *rz_arm64_cs_esil_prefix_cond(RzAnalysisOp *op, CS_aarch64_cc() cond_type) {
	const char *close_cond[2];
	close_cond[0] = "";
	close_cond[1] = ",}";
	int close_type = 0;
	switch (cond_type) {
	case CS_AARCH64CC(_EQ):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,?{,");
		break;
	case CS_AARCH64CC(_NE):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,!,?{,");
		break;
	case CS_AARCH64CC(_HS):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,?{,");
		break;
	case CS_AARCH64CC(_LO):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,!,?{,");
		break;
	case CS_AARCH64CC(_MI):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,?{,");
		break;
	case CS_AARCH64CC(_PL):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,!,?{,");
		break;
	case CS_AARCH64CC(_VS):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "vf,?{,");
		break;
	case CS_AARCH64CC(_VC):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "vf,!,?{,");
		break;
	case CS_AARCH64CC(_HI):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,zf,!,&,?{,");
		break;
	case CS_AARCH64CC(_LS):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,!,zf,|,?{,");
		break;
	case CS_AARCH64CC(_GE):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,vf,^,!,?{,");
		break;
	case CS_AARCH64CC(_LT):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,vf,^,?{,");
		break;
	case CS_AARCH64CC(_GT):
		// zf == 0 && nf == vf
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,!,nf,vf,^,!,&,?{,");
		break;
	case CS_AARCH64CC(_LE):
		// zf == 1 || nf != vf
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,nf,vf,^,|,?{,");
		break;
	case CS_AARCH64CC(_AL):
		// always executed
		break;
	default:
		break;
	}
	return close_cond[close_type];
}

static int arm64_reg_width(int reg) {
	switch (reg) {
	case CS_AARCH64(_REG_W0):
	case CS_AARCH64(_REG_W1):
	case CS_AARCH64(_REG_W2):
	case CS_AARCH64(_REG_W3):
	case CS_AARCH64(_REG_W4):
	case CS_AARCH64(_REG_W5):
	case CS_AARCH64(_REG_W6):
	case CS_AARCH64(_REG_W7):
	case CS_AARCH64(_REG_W8):
	case CS_AARCH64(_REG_W9):
	case CS_AARCH64(_REG_W10):
	case CS_AARCH64(_REG_W11):
	case CS_AARCH64(_REG_W12):
	case CS_AARCH64(_REG_W13):
	case CS_AARCH64(_REG_W14):
	case CS_AARCH64(_REG_W15):
	case CS_AARCH64(_REG_W16):
	case CS_AARCH64(_REG_W17):
	case CS_AARCH64(_REG_W18):
	case CS_AARCH64(_REG_W19):
	case CS_AARCH64(_REG_W20):
	case CS_AARCH64(_REG_W21):
	case CS_AARCH64(_REG_W22):
	case CS_AARCH64(_REG_W23):
	case CS_AARCH64(_REG_W24):
	case CS_AARCH64(_REG_W25):
	case CS_AARCH64(_REG_W26):
	case CS_AARCH64(_REG_W27):
	case CS_AARCH64(_REG_W28):
	case CS_AARCH64(_REG_W29):
	case CS_AARCH64(_REG_W30):
		return 32;
		break;
	default:
		break;
	}
	return 64;
}

static int decode_sign_ext(CS_aarch64_extender() extender) {
	switch (extender) {
	case CS_AARCH64(_EXT_UXTB):
	case CS_AARCH64(_EXT_UXTH):
	case CS_AARCH64(_EXT_UXTW):
	case CS_AARCH64(_EXT_UXTX):
		return 0; // nothing needs to be done for unsigned
	case CS_AARCH64(_EXT_SXTB):
		return 8;
	case CS_AARCH64(_EXT_SXTH):
		return 16;
	case CS_AARCH64(_EXT_SXTW):
		return 32;
	case CS_AARCH64(_EXT_SXTX):
		return 64;
	default:
		break;
	}

	return 0;
}

#define EXT64(x) decode_sign_ext(insn->detail->CS_aarch64_.operands[x].ext)

static const char *decode_shift_64(CS_aarch64_shifter() shift) {
	const char *E_OP_SR = ">>";
	const char *E_OP_SL = "<<";
	const char *E_OP_RR = ">>>";
	const char *E_OP_VOID = "";

	switch (shift) {
	case CS_AARCH64(_SFT_ASR):
	case CS_AARCH64(_SFT_LSR):
		return E_OP_SR;

	case CS_AARCH64(_SFT_LSL):
	case CS_AARCH64(_SFT_MSL):
		return E_OP_SL;

	case CS_AARCH64(_SFT_ROR):
		return E_OP_RR;

	default:
		break;
	}
	return E_OP_VOID;
}

#define DECODE_SHIFT64(x) decode_shift_64(insn->detail->CS_aarch64_.operands[x].shift.type)

static int regsize64(cs_insn *insn, int n) {
	unsigned int reg = insn->detail->CS_aarch64_.operands[n].reg;
	if ((reg >= CS_AARCH64(_REG_S0) && reg <= CS_AARCH64(_REG_S31)) ||
		(reg >= CS_AARCH64(_REG_W0) && reg <= CS_AARCH64(_REG_W30)) ||
		reg == CS_AARCH64(_REG_WZR)) {
		return 4;
	}
	if (reg >= CS_AARCH64(_REG_B0) && reg <= CS_AARCH64(_REG_B31)) {
		return 1;
	}
	if (reg >= CS_AARCH64(_REG_H0) && reg <= CS_AARCH64(_REG_H31)) {
		return 2;
	}
	if (reg >= CS_AARCH64(_REG_Q0) && reg <= CS_AARCH64(_REG_Q31)) {
		return 16;
	}
	return 8;
}

#define REGSIZE64(x) regsize64(insn, x)

#define SHIFTED_REG64_APPEND(sb, n) shifted_reg64_append(sb, handle, insn, n)

// do the sign extension here as well, but honestly this whole thing should maybe be redesigned
static void shifted_reg64_append(RzStrBuf *sb, csh *handle, cs_insn *insn, int n) {
	int signext = EXT64(n);
	const char *rn;

	if (HASMEMINDEX64(n)) {
		rn = MEMINDEX64(n);
	} else {
		rn = REG64(n);
	}

	if (LSHIFT2_64(n)) {
		if (insn->detail->CS_aarch64_.operands[n].shift.type != CS_AARCH64(_SFT_ASR)) {
			if (signext) {
				rz_strbuf_appendf(sb, "%d,%d,%s,~,%s", LSHIFT2_64(n), signext, rn, DECODE_SHIFT64(n));
			} else {
				rz_strbuf_appendf(sb, "%d,%s,%s", LSHIFT2_64(n), rn, DECODE_SHIFT64(n));
			}
		} else {
			/* ASR: add the missing ones if negative */
			ut8 index = LSHIFT2_64(n);
			if (!index) {
				return;
			}
			ut64 missing_ones = rz_num_bitmask(index) << (REGSIZE64(n) * 8 - LSHIFT2_64(n));
			if (signext) {
				rz_strbuf_appendf(sb, "%d,%d,%s,~,%s,1,%d,%s,~,<<<,1,&,?{,%" PFMT64u ",}{,0,},|",
					LSHIFT2_64(n), signext, rn, DECODE_SHIFT64(n), signext, REG64(n), (ut64)missing_ones);
			} else {
				rz_strbuf_appendf(sb, "%d,%s,%s,1,%s,<<<,1,&,?{,%" PFMT64u ",}{,0,},|",
					LSHIFT2_64(n), rn, DECODE_SHIFT64(n), rn, (ut64)missing_ones);
			}
		}
	} else if (signext) {
		rz_strbuf_appendf(sb, "%d,%s,~", signext, rn);
	} else {
		rz_strbuf_appendf(sb, "%s", rn);
	}
}

#define OPCALL(opchar)     arm64math(a, op, addr, buf, len, handle, insn, opchar, 0)
#define OPCALL_NEG(opchar) arm64math(a, op, addr, buf, len, handle, insn, opchar, 1)

// got rid of the opchar= pattern here because it caused missing operators to fail silently
// and makes things more complicated with very little benefit
static void arm64math(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, const char *opchar, int negate) {
	if (ISIMM64(0) || ISIMM64(1)) {
		return;
	}
	const char *r0 = REG64(0);
	const char *r1 = REG64(1);

	if (ISREG64(2)) {
		if (LSHIFT2_64(2) || EXT64(2)) {
			SHIFTED_REG64_APPEND(&op->esil, 2);
			if (negate) {
				rz_strbuf_appendf(&op->esil, ",-1,^");
			}
			rz_strbuf_appendf(&op->esil, ",%s,%s,%s,=", r1, opchar, r0);
		} else {
			const char *r2 = REG64(2);
			if (negate) {
				rz_strbuf_setf(&op->esil, "%s,-1,^,%s,%s,%s,=", r2, r1, opchar, r0);
			} else {
				rz_strbuf_setf(&op->esil, "%s,%s,%s,%s,=", r2, r1, opchar, r0);
			}
		}
	} else {
		ut64 i2 = IMM64(2) << LSHIFT2_64(2);
		if (negate) {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",-1,^,%s,%s,%s,=", i2, r1, opchar, r0);
		} else {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,%s,%s,=", i2, r1, opchar, r0);
		}
	}
}

#if CS_NEXT_VERSION >= 6
static void cmp(RzAnalysisOp *op, csh *handle, cs_insn *insn) {
	// update esil, cpu flags
	int bits = arm64_reg_width(REGID64(1));
	if (ISIMM64(2)) {
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=", IMM64(2) << LSHIFT2_64(2), REG64(1), bits - 1, bits, bits - 1);
	} else {
		// cmp w10, w11
		SHIFTED_REG64_APPEND(&op->esil, 2);
		rz_strbuf_appendf(&op->esil, ",%s,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=", REG64(1), bits - 1, bits, bits - 1);
	}
}

static void bfm(RzAnalysisOp *op, csh *handle, cs_insn *insn) {
	ut64 lsb = IMM64(2);
	ut64 width = IMM64(3);
	switch (insn->alias_id) {
	default:
		return;
	case AARCH64_INS_ALIAS_BFI: // bfi w8, w8, 2, 1
		width += 1;
		// TODO Mod depends on (sf && N) bits
		lsb = -lsb % 32;
		break;
	case AARCH64_INS_ALIAS_BFXIL:
		width = width - lsb + 1;
		break;
	}
	ut64 mask = rz_num_bitmask((ut8)width);
	ut64 shift = lsb;
	ut64 notmask = ~(mask << shift);
	// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
	rz_strbuf_setf(&op->esil, "%" PFMT64u ",%s,&,%" PFMT64u ",%" PFMT64u ",%s,&,<<,|,%s,=",
		notmask, REG64(0), shift, mask, REG64(1), REG64(0));
}

static void subfm(RzAnalysisOp *op, csh *handle, cs_insn *insn) {
	ut64 lsb = IMM64(2);
	ut64 width = IMM64(3);
	if (insn->alias_id == AARCH64_INS_ALIAS_SBFIZ) {
		width += 1;
		lsb = -lsb % 64;
		rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64u ",&,~,<<,%s,=",
			lsb, IMM64(3), REG64(1), rz_num_bitmask((ut8)width), REG64(0));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_UBFIZ) {
		width += 1;
		lsb = -lsb % 64;
		rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,%" PFMT64u ",&,<<,%s,=",
			lsb, REG64(1), rz_num_bitmask((ut8)width), REG64(0));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_SBFX) {
		width = width - lsb + 1;
		rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64d ",%" PFMT64u ",<<,&,>>,~,%s,=",
			IMM64(3), IMM64(2), REG64(1), IMM64(2), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_UBFX) {
		width = width - lsb + 1;
		rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,%" PFMT64d ",%" PFMT64u ",<<,&,>>,%s,=",
			lsb, REG64(1), lsb, rz_num_bitmask((ut8)width), REG64(0));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_LSL) {
		// imms != 0x1f => mod 32
		// imms != 0x3f => mod 64
		ut32 m = IMM64(3) != 0x1f ? 32 : 64;
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		const int size = REGSIZE64(0) * 8;

		if (ISREG64(2)) {
			if (LSHIFT2_64(2) || EXT64(2)) {
				SHIFTED_REG64_APPEND(&op->esil, 2);
				rz_strbuf_appendf(&op->esil, ",%d,%%,%s,<<,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64(2);
				rz_strbuf_setf(&op->esil, "%d,%s,%%,%s,<<,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64(2) % m;
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,<<,%s,=", i2 % (ut64)size, r1, r0);
		}
	} else if (insn->alias_id == AARCH64_INS_ALIAS_LSR) {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		const int size = REGSIZE64(0) * 8;

		if (ISREG64(2)) {
			if (LSHIFT2_64(2) || EXT64(2)) {
				SHIFTED_REG64_APPEND(&op->esil, 2);
				rz_strbuf_appendf(&op->esil, ",%d,%%,%s,>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64(2);
				rz_strbuf_setf(&op->esil, "%d,%s,%%,%s,>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64(2);
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,>>,%s,=", i2 % (ut64)size, r1, r0);
		}
	} else if (insn->alias_id == AARCH64_INS_ALIAS_ASR) {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		const int size = REGSIZE64(0) * 8;

		if (ISREG64(2)) {
			if (LSHIFT2_64(2)) {
				SHIFTED_REG64_APPEND(&op->esil, 2);
				rz_strbuf_appendf(&op->esil, ",%d,%%,%s,>>>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64(2);
				rz_strbuf_setf(&op->esil, "%d,%s,%%,%s,>>>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64(2);
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,>>>>,%s,=", i2 % (ut64)size, r1, r0);
		}
	}
	return;
}
#endif

RZ_IPI int rz_arm_cs_analysis_op_64_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	const char *postfix = NULL;

	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");

	postfix = rz_arm64_cs_esil_prefix_cond(op, insn->detail->CS_aarch64_.cc);

	switch (insn->id) {
	case CS_AARCH64(_INS_REV):
		// these REV* instructions were almost right, except in the cases like rev x0, x0
		// where the use of |= caused copies of the value to be erroneously present
		{
			const char *r0 = REG64(0);
			const char *r1 = REG64(1);
			int size = REGSIZE64(1);
#if 0
		rz_strbuf_setf (&op->esil,
			"0,%s,=,"                        // dst = 0
			"%d,"                            // initial counter = size
			"DUP,"                           // counter: size -> 0 (repeat here)
				"DUP,1,SWAP,-,8,*,"          // counter to bits in source
					"DUP,0xff,<<,%s,&,>>,"   // src byte moved to LSB
				"SWAP,%d,-,8,*,"             // invert counter, calc dst bit
				"SWAP,<<,%s,|=,"             // shift left to there and insert
			"4,REPEAT",                      // goto 5th instruction
			r0, size, r1, size, r0);
#endif
			if (size == 8) {
				rz_strbuf_setf(&op->esil,
					"56,0xff,%s,&,<<,tmp,=,"
					"48,0xff,8,%s,>>,&,<<,tmp,|=,"
					"40,0xff,16,%s,>>,&,<<,tmp,|=,"
					"32,0xff,24,%s,>>,&,<<,tmp,|=,"
					"24,0xff,32,%s,>>,&,<<,tmp,|=,"
					"16,0xff,40,%s,>>,&,<<,tmp,|=,"
					"8,0xff,48,%s,>>,&,<<,tmp,|=,"
					"0xff,56,%s,>>,&,tmp,|=,tmp,%s,=",
					r1, r1, r1, r1,
					r1, r1, r1, r1, r0);
			} else {
				rz_strbuf_setf(&op->esil,
					"24,0xff,%s,&,<<,tmp,=,"
					"16,0xff,8,%s,>>,&,<<,tmp,|=,"
					"8,0xff,16,%s,>>,&,<<,tmp,|=,"
					"0xff,24,%s,>>,&,tmp,|=,tmp,%s,=",
					r1, r1, r1, r1, r0);
			}
			break;
		}
	case CS_AARCH64(_INS_REV32): {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		rz_strbuf_setf(&op->esil,
			"24,0x000000ff000000ff,%s,&,<<,tmp,=,"
			"16,0x000000ff000000ff,8,%s,>>,&,<<,tmp,|=,"
			"8,0x000000ff000000ff,16,%s,>>,&,<<,tmp,|=,"
			"0x000000ff000000ff,24,%s,>>,&,tmp,|=,tmp,%s,=",
			r1, r1, r1, r1, r0);
		break;
	}
	case CS_AARCH64(_INS_REV16): {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		rz_strbuf_setf(&op->esil,
			"8,0xff00ff00ff00ff00,%s,&,>>,tmp,=,"
			"8,0x00ff00ff00ff00ff,%s,&,<<,tmp,|=,tmp,%s,=",
			r1, r1, r0);
		break;
	}
	case CS_AARCH64(_INS_ADR):
		// TODO: must be 21bit signed
		rz_strbuf_setf(&op->esil,
			"%" PFMT64d ",%s,=", IMM64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_SMADDL): {
		int size = REGSIZE64(1) * 8;
		rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,*,%s,+,%s,=",
			size, REG64(2), size, REG64(1), REG64(3), REG64(0));
		break;
	}
	case CS_AARCH64(_INS_UMADDL):
	case CS_AARCH64(_INS_FMADD):
	case CS_AARCH64(_INS_MADD):
		rz_strbuf_setf(&op->esil, "%s,%s,*,%s,+,%s,=",
			REG64(2), REG64(1), REG64(3), REG64(0));
		break;
	case CS_AARCH64(_INS_MSUB):
		rz_strbuf_setf(&op->esil, "%s,%s,*,%s,-,%s,=",
			REG64(2), REG64(1), REG64(3), REG64(0));
		break;
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_MNEG):
		rz_strbuf_setf(&op->esil, "%s,%s,*,0,-,%s,=",
			REG64(2), REG64(1), REG64(0));
		break;
#endif
	case CS_AARCH64(_INS_ADD):
	case CS_AARCH64(_INS_ADC): // Add with carry.
		// case CS_AARCH64(_INS_ADCS): // Add with carry.
		OPCALL("+");
		break;
	case CS_AARCH64(_INS_SUB):
		OPCALL("-");
		break;
	case CS_AARCH64(_INS_SBC):
		// TODO have to check this more, VEX does not work
		rz_strbuf_setf(&op->esil, "%s,cf,+,%s,-,%s,=",
			REG64(2), REG64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_SMULL): {
		int size = REGSIZE64(1) * 8;
		rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,*,%s,=",
			size, REG64(2), size, REG64(1), REG64(0));
		break;
	}
	case CS_AARCH64(_INS_MUL):
		OPCALL("*");
		break;
	case CS_AARCH64(_INS_AND):
		OPCALL("&");
		break;
	case CS_AARCH64(_INS_ORR):
		OPCALL("|");
		break;
	case CS_AARCH64(_INS_EOR):
		OPCALL("^");
		break;
	case CS_AARCH64(_INS_ORN):
		OPCALL_NEG("|");
		break;
	case CS_AARCH64(_INS_EON):
		OPCALL_NEG("^");
		break;
	case CS_AARCH64(_INS_LSR): {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		const int size = REGSIZE64(0) * 8;

		if (ISREG64(2)) {
			if (LSHIFT2_64(2) || EXT64(2)) {
				SHIFTED_REG64_APPEND(&op->esil, 2);
				rz_strbuf_appendf(&op->esil, ",%d,%%,%s,>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64(2);
				rz_strbuf_setf(&op->esil, "%d,%s,%%,%s,>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64(2);
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		break;
	}
	case CS_AARCH64(_INS_LSL): {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		const int size = REGSIZE64(0) * 8;

		if (ISREG64(2)) {
			if (LSHIFT2_64(2) || EXT64(2)) {
				SHIFTED_REG64_APPEND(&op->esil, 2);
				rz_strbuf_appendf(&op->esil, ",%d,%%,%s,<<,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64(2);
				rz_strbuf_setf(&op->esil, "%d,%s,%%,%s,<<,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64(2);
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,<<,%s,=", i2 % (ut64)size, r1, r0);
		}
		break;
	}
	case CS_AARCH64(_INS_ROR):
		OPCALL(">>>");
		break;
	case CS_AARCH64(_INS_HINT):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_NOP):
		rz_strbuf_setf(&op->esil, ",");
		break;
#endif
	case CS_AARCH64(_INS_FDIV):
		break;
	case CS_AARCH64(_INS_SDIV): {
		/* TODO: support WZR XZR to specify 32, 64bit op */
		int size = REGSIZE64(1) * 8;
		if (ISREG64(2)) {
			rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,~/,%s,=", size, REG64(2), size, REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,~/,%s,=", size, REG64(1), size, REG64(0), REG64(0));
		}
		break;
	}
	case CS_AARCH64(_INS_UDIV):
		/* TODO: support WZR XZR to specify 32, 64bit op */
		if ISREG64 (2) {
			rz_strbuf_setf(&op->esil, "%s,%s,/,%s,=", REG64(2), REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%s,%s,/=", REG64(1), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_BR):
		rz_strbuf_setf(&op->esil, "%s,pc,=", REG64(0));
		break;
	case CS_AARCH64(_INS_B):
		/* capstone precompute resulting address, using PC + IMM */
		rz_strbuf_appendf(&op->esil, "%" PFMT64d ",pc,=", IMM64(0));
		break;
	case CS_AARCH64(_INS_BL):
		rz_strbuf_setf(&op->esil, "pc,lr,=,%" PFMT64d ",pc,=", IMM64(0));
		break;
	case CS_AARCH64(_INS_BLR):
		rz_strbuf_setf(&op->esil, "pc,lr,=,%s,pc,=", REG64(0));
		break;
	case CS_AARCH64(_INS_CLZ):;
		int size = 8 * REGSIZE64(0);

		// expression is much more concise with GOTO, but GOTOs should be minimized
		// rz_strbuf_setf (&op->esil, "%s,%s,=,0,DUP,%d,1,<<,%s,&,%d,>,&,?{,%s,=,}{,1,%s,<<=,1,+,4,GOTO,}",
		//	REG64 (1), REG64 (0), size*8 - 1, REG64 (0), REG64 (0), REG64 (0));

		/*
		from https://en.wikipedia.org/wiki/Find_first_set modified for up to size 64
		function clz3 (x)
			if x = 0 return 32
			n ← 0
			if (x & 0xFFFF0000) = 0: n ← n + 16, x ← x << 16
			if (x & 0xFF000000) = 0: n ← n +  8, x ← x <<  8
			if (x & 0xF0000000) = 0: n ← n +  4, x ← x <<  4
			if (x & 0xC0000000) = 0: n ← n +  2, x ← x <<  2
			if (x & 0x80000000) = 0: n ← n +  1
			return n
		*/

		const char *r0 = REG64(0);
		const char *r1 = REG64(1);

		if (size == 32) {
			rz_strbuf_setf(&op->esil,
				"%s,tmp,=,0,"
				"tmp,0xffff0000,&,!,?{,16,tmp,<<=,16,+,},"
				"tmp,0xff000000,&,!,?{,8,tmp,<<=,8,+,},"
				"tmp,0xf0000000,&,!,?{,4,tmp,<<=,4,+,},"
				"tmp,0xc0000000,&,!,?{,2,tmp,<<=,2,+,},"
				"tmp,0x80000000,&,!,?{,1,+,},"
				"%s,!,?{,32,%s,=,}{,%s,=,}",
				r1, r1, r0, r0);
		} else {
			rz_strbuf_setf(&op->esil,
				"%s,tmp,=,0,"
				"tmp,0xffffffff00000000,&,!,?{,32,tmp,<<=,32,+,},"
				"tmp,0xffff000000000000,&,!,?{,16,tmp,<<=,16,+,},"
				"tmp,0xff00000000000000,&,!,?{,8,tmp,<<=,8,+,},"
				"tmp,0xf000000000000000,&,!,?{,4,tmp,<<=,4,+,},"
				"tmp,0xc000000000000000,&,!,?{,2,tmp,<<=,2,+,},"
				"tmp,0x8000000000000000,&,!,?{,1,+,},"
				"%s,!,?{,64,%s,=,}{,%s,=,}",
				r1, r1, r0, r0);
		}

		break;
	case CS_AARCH64(_INS_LDRH):
	case CS_AARCH64(_INS_LDUR):
	case CS_AARCH64(_INS_LDURB):
	case CS_AARCH64(_INS_LDURH):
	case CS_AARCH64(_INS_LDR):
	// case CS_AARCH64(_INS_LDRSB):
	// case CS_AARCH64(_INS_LDRSH):
	case CS_AARCH64(_INS_LDRB):
	// case CS_AARCH64(_INS_LDRSW):
	// case CS_AARCH64(_INS_LDURSW):
	case CS_AARCH64(_INS_LDXR):
	case CS_AARCH64(_INS_LDXRB):
	case CS_AARCH64(_INS_LDXRH):
	case CS_AARCH64(_INS_LDAXR):
	case CS_AARCH64(_INS_LDAXRB):
	case CS_AARCH64(_INS_LDAXRH):
	case CS_AARCH64(_INS_LDAR):
	case CS_AARCH64(_INS_LDARB):
	case CS_AARCH64(_INS_LDARH): {
		int size = REGSIZE64(0);
		switch (insn->id) {
		case CS_AARCH64(_INS_LDRB):
		case CS_AARCH64(_INS_LDARB):
		case CS_AARCH64(_INS_LDAXRB):
		case CS_AARCH64(_INS_LDXRB):
		case CS_AARCH64(_INS_LDURB):
			size = 1;
			break;
		case CS_AARCH64(_INS_LDRH):
		case CS_AARCH64(_INS_LDARH):
		case CS_AARCH64(_INS_LDXRH):
		case CS_AARCH64(_INS_LDAXRH):
		case CS_AARCH64(_INS_LDURH):
			size = 2;
			break;
		case CS_AARCH64(_INS_LDRSW):
		case CS_AARCH64(_INS_LDURSW):
			size = 4;
			break;
		default:
			break;
		}

		if (ISMEM64(1)) {
			if (HASMEMINDEX64(1)) {
				if (LSHIFT2_64(1) || EXT64(1)) {
					SHIFTED_REG64_APPEND(&op->esil, 1);
					rz_strbuf_appendf(&op->esil, ",%s,+,[%d],%s,=", MEMBASE64(1), size, REG64(0));
				} else {
					rz_strbuf_appendf(&op->esil, "%s,%s,+,[%d],%s,=",
						MEMBASE64(1), MEMINDEX64(1), size, REG64(0));
				}
			} else {
				// I really don't like the DUP / tmp approach but its better than doubling the calculation
				if (LSHIFT2_64(1)) {
					rz_strbuf_appendf(&op->esil, "%s,%d,%" PFMT64d ",%s,+",
						MEMBASE64(1), LSHIFT2_64(1), MEMDISP64(1), DECODE_SHIFT64(1));
				} else if ((int)MEMDISP64(1) < 0) {
					rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,-",
						-(st64)MEMDISP64(1), MEMBASE64(1));
				} else {
					rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,+",
						MEMDISP64(1), MEMBASE64(1));
				}

				rz_strbuf_append(&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64()) {
					rz_strbuf_appendf(&op->esil, ",tmp,%s,=", REG64(1));
				}

				rz_strbuf_appendf(&op->esil, ",[%d],%s,=", size, REG64(0));

				if (ISPOSTINDEX64()) {
					if (ISREG64(2)) { // not sure if register valued post indexing exists?
						rz_strbuf_appendf(&op->esil, ",tmp,%s,+,%s,=", REG64(2), REG64(1));
					} else {
#if CS_NEXT_VERSION < 6
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", IMM64(2), REG64(1));
#else
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", MEMDISP64(1), MEMBASE64(1));
#endif
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64(1)) {
				if (OPCOUNT64() == 2) {
					rz_strbuf_setf(&op->esil, "%s,[%d],%s,=",
						REG64(1), size, REG64(0));
				} else if (OPCOUNT64() == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as CS_AARCH64(_OP_MEM) type and
						fall in this case instead.
					*/
					if (ISREG64(2)) {
						rz_strbuf_setf(&op->esil, "%s,%s,+,[%d],%s,=",
							REG64(1), REG64(2), size, REG64(0));
					}
				}
			} else {
				rz_strbuf_setf(&op->esil, "%" PFMT64d ",[%d],%s,=",
					IMM64(1), size, REG64(0));
			}
		}
		break;
	}
	case CS_AARCH64(_INS_LDRSB):
	case CS_AARCH64(_INS_LDRSH):
	case CS_AARCH64(_INS_LDRSW):
	case CS_AARCH64(_INS_LDURSB):
	case CS_AARCH64(_INS_LDURSH):
	case CS_AARCH64(_INS_LDURSW): {
		// handle the sign extended instrs here
		int size = REGSIZE64(0);
		switch (insn->id) {
		case CS_AARCH64(_INS_LDRSB):
		case CS_AARCH64(_INS_LDURSB):
			size = 1;
			break;
		case CS_AARCH64(_INS_LDRSH):
		case CS_AARCH64(_INS_LDURSH):
			size = 2;
			break;
		case CS_AARCH64(_INS_LDRSW):
		case CS_AARCH64(_INS_LDURSW):
			size = 4;
			break;
		default:
			break;
		}

		if (ISMEM64(1)) {
			if (HASMEMINDEX64(1)) {
				if (LSHIFT2_64(1) || EXT64(1)) {
					rz_strbuf_appendf(&op->esil, "%d,%s,", size * 8, MEMBASE64(1));
					SHIFTED_REG64_APPEND(&op->esil, 1);
					rz_strbuf_appendf(&op->esil, ",+,[%d],~,%s,=", size, REG64(0));
				} else {
					rz_strbuf_appendf(&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
						size * 8, MEMBASE64(1), MEMINDEX64(1), size, REG64(0));
				}
			} else {
				if (LSHIFT2_64(1)) {
					rz_strbuf_appendf(&op->esil, "%d,%s,%d,%" PFMT64d ",%s",
						size * 8, MEMBASE64(1), LSHIFT2_64(1), MEMDISP64(1), DECODE_SHIFT64(1));
				} else if ((int)MEMDISP64(1) < 0) {
					rz_strbuf_appendf(&op->esil, "%d,%" PFMT64d ",%s,-",
						size * 8, -(st64)MEMDISP64(1), MEMBASE64(1));
				} else {
					rz_strbuf_appendf(&op->esil, "%d,%" PFMT64d ",%s,+",
						size * 8, MEMDISP64(1), MEMBASE64(1));
				}

				rz_strbuf_append(&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64()) {
					rz_strbuf_appendf(&op->esil, ",tmp,%s,=", REG64(1));
				}

				rz_strbuf_appendf(&op->esil, ",[%d],~,%s,=", size, REG64(0));

				if (ISPOSTINDEX64()) {
					if (ISREG64(2)) { // not sure if register valued post indexing exists?
						rz_strbuf_appendf(&op->esil, ",tmp,%s,+,%s,=", REG64(2), REG64(1));
					} else {
#if CS_NEXT_VERSION < 6
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", IMM64(2), REG64(1));
#else
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", MEMDISP64(1), MEMBASE64(1));
#endif
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64(1)) {
				if (OPCOUNT64() == 2) {
					rz_strbuf_setf(&op->esil, "%d,%s,[%d],~,%s,=",
						size * 8, REG64(1), size, REG64(0));
				} else if (OPCOUNT64() == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as CS_AARCH64(_OP_MEM) type and
						fall in this case instead.
					*/
					if (ISREG64(2)) {
						rz_strbuf_setf(&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
							size * 8, REG64(1), REG64(2), size, REG64(0));
					}
				}
			} else {
				rz_strbuf_setf(&op->esil, "%d,%" PFMT64d ",[%d],~,%s,=",
					size * 8, IMM64(1), size, REG64(0));
			}
		}
		break;
	}
	case CS_AARCH64(_INS_FCMP):
	case CS_AARCH64(_INS_CCMP):
	case CS_AARCH64(_INS_CCMN):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_TST): // cmp w8, 0xd
	case CS_AARCH64(_INS_CMP): // cmp w8, 0xd
	case CS_AARCH64(_INS_CMN): // cmp w8, 0xd
#endif
	{
		// update esil, cpu flags
		int bits = arm64_reg_width(REGID64(0));
		if (ISIMM64(1)) {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=", IMM64(1) << LSHIFT2_64(1), REG64(0), bits - 1, bits, bits - 1);
		} else {
			// cmp w10, w11
			SHIFTED_REG64_APPEND(&op->esil, 1);
			rz_strbuf_appendf(&op->esil, ",%s,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=", REG64(0), bits - 1, bits, bits - 1);
		}
		break;
	}
#if CS_NEXT_VERSION >= 6
	case AARCH64_INS_SUBS:
		if (insn->alias_id != AARCH64_INS_ALIAS_CMP &&
			insn->alias_id != AARCH64_INS_ALIAS_CMN) {
			cmp(op, handle, insn);
			break;
		}
		// update esil, cpu flags
		int bits = arm64_reg_width(REGID64(1));
		if (ISIMM64(2)) {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=", IMM64(2) << LSHIFT2_64(2), REG64(1), bits - 1, bits, bits - 1);
		} else {
			// cmp w10, w11
			SHIFTED_REG64_APPEND(&op->esil, 2);
			rz_strbuf_appendf(&op->esil, ",%s,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=", REG64(1), bits - 1, bits, bits - 1);
		}
		break;
#endif
	case CS_AARCH64(_INS_FCSEL):
	case CS_AARCH64(_INS_CSEL): // csel Wd, Wn, Wm --> Wd := (cond) ? Wn : Wm
		rz_strbuf_appendf(&op->esil, "%s,}{,%s,},%s,=", REG64(1), REG64(2), REG64(0));
		postfix = "";
		break;
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_CSET): // cset Wd --> Wd := (cond) ? 1 : 0
		rz_strbuf_appendf(&op->esil, "1,}{,0,},%s,=", REG64(0));
		postfix = "";
		break;
	case CS_AARCH64(_INS_CINC): // cinc Wd, Wn --> Wd := (cond) ? (Wn+1) : Wn
		rz_strbuf_appendf(&op->esil, "1,%s,+,}{,%s,},%s,=", REG64(1), REG64(1), REG64(0));
		postfix = "";
		break;
	case CS_AARCH64(_INS_CSINC): // csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
		rz_strbuf_appendf(&op->esil, "%s,}{,1,%s,+,},%s,=", REG64(1), REG64(2), REG64(0));
		postfix = "";
		break;
#else
	case CS_AARCH64(_INS_CSINC):
		switch (insn->alias_id) {
		default:
			// csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
			rz_strbuf_appendf(&op->esil, "%s,}{,1,%s,+,},%s,=", REG64(1), REG64(2), REG64(0));
			postfix = "";
			break;
		case AARCH64_INS_ALIAS_CSET: // cset Wd --> Wd := (cond) ? 1 : 0
			rz_strbuf_drain_nofree(&op->esil);
			rz_arm64_cs_esil_prefix_cond(op, AArch64CC_getInvertedCondCode(insn->detail->CS_aarch64_.cc));
			rz_strbuf_appendf(&op->esil, "1,}{,0,},%s,=", REG64(0));
			postfix = "";
			break;
		case AARCH64_INS_ALIAS_CINC: // cinc Wd, Wn --> Wd := (cond) ? (Wn+1) : Wn
			rz_strbuf_drain_nofree(&op->esil);
			rz_arm64_cs_esil_prefix_cond(op, AArch64CC_getInvertedCondCode(insn->detail->CS_aarch64_.cc));
			rz_strbuf_appendf(&op->esil, "1,%s,+,}{,%s,},%s,=", REG64(1), REG64(1), REG64(0));
			postfix = "";
			break;
		}
		break;
#endif
	case CS_AARCH64(_INS_STXRB):
	case CS_AARCH64(_INS_STXRH):
	case CS_AARCH64(_INS_STXR): {
		int size = REGSIZE64(1);
		if (insn->id == CS_AARCH64(_INS_STXRB)) {
			size = 1;
		} else if (insn->id == CS_AARCH64(_INS_STXRH)) {
			size = 2;
		}
		rz_strbuf_setf(&op->esil, "0,%s,=,%s,%s,%" PFMT64d ",+,=[%d]",
			REG64(0), REG64(1), MEMBASE64(1), MEMDISP64(1), size);
		break;
	}
	case CS_AARCH64(_INS_STRB):
	case CS_AARCH64(_INS_STRH):
	case CS_AARCH64(_INS_STUR):
	case CS_AARCH64(_INS_STURB):
	case CS_AARCH64(_INS_STURH):
	case CS_AARCH64(_INS_STR): // str x6, [x6,0xf90]
	{
		int size = REGSIZE64(0);
		if (insn->id == CS_AARCH64(_INS_STRB) || insn->id == CS_AARCH64(_INS_STURB)) {
			size = 1;
		} else if (insn->id == CS_AARCH64(_INS_STRH) || insn->id == CS_AARCH64(_INS_STURH)) {
			size = 2;
		}
		if (ISMEM64(1)) {
			if (HASMEMINDEX64(1)) {
				if (LSHIFT2_64(1) || EXT64(1)) {
					rz_strbuf_appendf(&op->esil, "%s,%s,", REG64(0), MEMBASE64(1));
					SHIFTED_REG64_APPEND(&op->esil, 1);
					rz_strbuf_appendf(&op->esil, ",+,=[%d]", size);
				} else {
					rz_strbuf_appendf(&op->esil, "%s,%s,%s,+,=[%d]",
						REG64(0), MEMBASE64(1), MEMINDEX64(1), size);
				}
			} else {
				if (LSHIFT2_64(1)) {
					rz_strbuf_appendf(&op->esil, "%s,%s,%d,%" PFMT64d ",%s,+",
						REG64(0), MEMBASE64(1), LSHIFT2_64(1), MEMDISP64(1), DECODE_SHIFT64(1));
				} else if ((int)MEMDISP64(1) < 0) {
					rz_strbuf_appendf(&op->esil, "%s,%" PFMT64d ",%s,-",
						REG64(0), -(st64)MEMDISP64(1), MEMBASE64(1));
				} else {
					rz_strbuf_appendf(&op->esil, "%s,%" PFMT64d ",%s,+",
						REG64(0), MEMDISP64(1), MEMBASE64(1));
				}

				rz_strbuf_append(&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64()) {
					rz_strbuf_appendf(&op->esil, ",tmp,%s,=", REG64(1));
				}

				rz_strbuf_appendf(&op->esil, ",=[%d]", size);

				if (ISPOSTINDEX64()) {
					if (ISREG64(2)) { // not sure if register valued post indexing exists?
						rz_strbuf_appendf(&op->esil, ",tmp,%s,+,%s,=", REG64(2), REG64(1));
					} else {
#if CS_NEXT_VERSION < 6
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", IMM64(2), REG64(1));
#else
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", MEMDISP64(1), MEMBASE64(1));
#endif
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64(1)) {
				if (OPCOUNT64() == 2) {
					rz_strbuf_setf(&op->esil, "%s,%s,=[%d]",
						REG64(0), REG64(1), size);
				} else if (OPCOUNT64() == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as CS_AARCH64(_OP_MEM) type and
						fall in this case instead.
					*/
					if (ISREG64(2)) {
						rz_strbuf_setf(&op->esil, "%s,%s,%s,+,=[%d]",
							REG64(0), REG64(1), REG64(2), size);
					}
				}
			} else {
				rz_strbuf_setf(&op->esil, "%s,%" PFMT64d ",=[%d]",
					REG64(0), IMM64(1), size);
			}
		}
		break;
	}
	case CS_AARCH64(_INS_BIC):
		if (OPCOUNT64() == 2) {
			if (REGSIZE64(0) == 4) {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffff,^,%s,&=", REG64(1), REG64(0));
			} else {
				if (ISREG64(1)) {
					rz_strbuf_appendf(&op->esil, "%s,0xffffffffffffffff,^,%s,&=", REG64(1), REG64(0));
				} else {
					rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",0xffffffffffffffff,^,%s,&=", IMM64(1), REG64(0));
				}
			}
		} else {
			if (REGSIZE64(0) == 4) {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffff,^,%s,&,%s,=", REG64(2), REG64(1), REG64(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffffffffffff,^,%s,&,%s,=", REG64(2), REG64(1), REG64(0));
			}
		}
		break;
	case CS_AARCH64(_INS_CBZ):
		rz_strbuf_setf(&op->esil, "%s,!,?{,%" PFMT64d ",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case CS_AARCH64(_INS_CBNZ):
		rz_strbuf_setf(&op->esil, "%s,?{,%" PFMT64d ",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case CS_AARCH64(_INS_TBZ):
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",1,<<,%s,&,!,?{,%" PFMT64d ",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case CS_AARCH64(_INS_TBNZ):
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",1,<<,%s,&,?{,%" PFMT64d ",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case CS_AARCH64(_INS_STNP):
	case CS_AARCH64(_INS_STP): // stp x6, x7, [x6,0xf90]
	{
		int disp = (int)MEMDISP64(2);
		char sign = disp >= 0 ? '+' : '-';
		ut64 abs = disp >= 0 ? MEMDISP64(2) : -MEMDISP64(2);
		int size = REGSIZE64(0);
		// Pre-index case
		if (ISPREINDEX64()) {
			// "stp x2, x3, [x8, 0x20]!
			// "32,x8,+=,x2,x8,=[8],x3,x8,8,+,=[8]",
			rz_strbuf_setf(&op->esil,
				"%" PFMT64d ",%s,%c=,%s,%s,=[%d],%s,%s,%d,+,=[%d]",
				abs, MEMBASE64(2), sign,
				REG64(0), MEMBASE64(2), size,
				REG64(1), MEMBASE64(2), size, size);
			// Post-index case
		} else if (ISPOSTINDEX64()) {
#if CS_NEXT_VERSION < 6
			int val = IMM64(3);
#else
			int val = MEMDISP64(2);
#endif
			sign = val >= 0 ? '+' : '-';
			abs = val >= 0 ? val : -val;
			// "stp x4, x5, [x8], 0x10"
			// "x4,x8,=[],x5,x8,8,+,=[],16,x8,+="
			rz_strbuf_setf(&op->esil,
				"%s,%s,=[%d],%s,%s,%d,+,=[%d],%" PFMT64d ",%s,%c=",
				REG64(0), MEMBASE64(2), size,
				REG64(1), MEMBASE64(2), size, size,
				abs, MEMBASE64(2), sign);
			// Everything else
		} else {
			rz_strbuf_setf(&op->esil,
				"%s,%s,%" PFMT64d ",%c,=[%d],"
				"%s,%s,%" PFMT64d ",%c,%d,+,=[%d]",
				REG64(0), MEMBASE64(2), abs, sign, size,
				REG64(1), MEMBASE64(2), abs, sign, size, size);
		}
	} break;
	case CS_AARCH64(_INS_LDP): // ldp x29, x30, [sp], 0x10
	{
		int disp = (int)MEMDISP64(2);
		char sign = disp >= 0 ? '+' : '-';
		ut64 abs = disp >= 0 ? MEMDISP64(2) : -MEMDISP64(2);
		int size = REGSIZE64(0);
		// Pre-index case
		// x2,x8,32,+,=[8],x3,x8,32,+,8,+,=[8]
		if (ISPREINDEX64()) {
			// "ldp x0, x1, [x8, -0x10]!"
			// 16,x8,-=,x8,[8],x0,=,x8,8,+,[8],x1,=
			rz_strbuf_setf(&op->esil,
				"%" PFMT64d ",%s,%c=,"
				"%s,[%d],%s,=,"
				"%d,%s,+,[%d],%s,=",
				abs, MEMBASE64(2), sign,
				MEMBASE64(2), size, REG64(0),
				size, MEMBASE64(2), size, REG64(1));
			// Post-index case
		} else if (ISPOSTINDEX64()) {
#if CS_NEXT_VERSION < 6
			int val = IMM64(3);
#else
			int val = MEMDISP64(2);
#endif
			sign = val >= 0 ? '+' : '-';
			abs = val >= 0 ? val : -val;
			// ldp x4, x5, [x8], -0x10
			// x8,[8],x4,=,x8,8,+,[8],x5,=,16,x8,+=
			rz_strbuf_setf(&op->esil,
				"%s,[%d],%s,=,"
				"%s,%d,+,[%d],%s,=,"
				"%" PFMT64d ",%s,%c=",
				MEMBASE64(2), size, REG64(0),
				MEMBASE64(2), size, size, REG64(1),
				abs, MEMBASE64(2), sign);
		} else {
			rz_strbuf_setf(&op->esil,
				"%" PFMT64d ",%s,%c,[%d],%s,=,"
				"%d,%" PFMT64d ",%s,%c,+,[%d],%s,=",
				abs, MEMBASE64(2), sign, size, REG64(0),
				size, abs, MEMBASE64(2), sign, size, REG64(1));
		}
	} break;
	case CS_AARCH64(_INS_ADRP):
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,=",
			IMM64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_MOV):
		if (ISREG64(1)) {
			rz_strbuf_setf(&op->esil, "%s,%s,=", REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,=", IMM64(1), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_EXTR):
		// from VEX
		/*
			01 | t0 = GET:I64(x4)
			02 | t1 = GET:I64(x0)
			03 | t4 = Shr64(t1,0x20)
			04 | t5 = Shl64(t0,0x20)
			05 | t3 = Or64(t5,t4)
			06 | PUT(x4) = t3
		*/
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,>>,%" PFMT64d ",%s,<<,|,%s,=",
			IMM64(3), REG64(2), IMM64(3), REG64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_RBIT):
		// this expression reverses the bits. it does. do not scroll right.
		// Derived from VEX
		rz_strbuf_setf(&op->esil, "0xffffffff00000000,0x20,0xffff0000ffff0000,0x10,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,<<,&,0x10,0xffff0000ffff0000,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,&,>>,|,<<,&,0x20,0xffffffff00000000,0xffff0000ffff0000,0x10,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,<<,&,0x10,0xffff0000ffff0000,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,&,>>,|,&,>>,|,%2$s,=",
			REG64(1), REG64(0));
		break;
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_MVN):
#endif
	case CS_AARCH64(_INS_MOVN):
		if (ISREG64(1)) {
			rz_strbuf_setf(&op->esil, "%d,%s,-1,^,<<,%s,=", LSHIFT2_64(1), REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%d,%" PFMT64d ",<<,-1,^,%s,=", LSHIFT2_64(1), IMM64(1), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_MOVK): // movk w8, 0x1290
	{
		ut64 shift = LSHIFT2_64(1);
		if (shift < 0) {
			shift = 0;
		} else if (shift > 48) {
			shift = 48;
		}
		ut64 shifted_imm = IMM64(1) << shift;
		ut64 mask = ~(0xffffULL << shift);

		rz_strbuf_setf(&op->esil, "0x%" PFMT64x ",%s,&,%" PFMT64u ",|,%s,=",
			mask,
			REG64(0),
			shifted_imm,
			REG64(0));

		break;
	}
	case CS_AARCH64(_INS_MOVZ):
		rz_strbuf_setf(&op->esil, "%" PFMT64u ",%s,=",
			IMM64(1) << LSHIFT2_64(1),
			REG64(0));
		break;
	/* ASR, SXTB, SXTH and SXTW are alias for SBFM */
	case CS_AARCH64(_INS_ASR): {
		// OPCALL(">>>>");
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		const int size = REGSIZE64(0) * 8;

		if (ISREG64(2)) {
			if (LSHIFT2_64(2)) {
				SHIFTED_REG64_APPEND(&op->esil, 2);
				rz_strbuf_appendf(&op->esil, ",%d,%%,%s,>>>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64(2);
				rz_strbuf_setf(&op->esil, "%d,%s,%%,%s,>>>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64(2);
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,>>>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		break;
	}
	case CS_AARCH64(_INS_SXTB):
		if (arm64_reg_width(REGID64(0)) == 32) {
			rz_strbuf_setf(&op->esil, "0xffffffff,8,0xff,%s,&,~,&,%s,=",
				REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "8,0xff,%s,&,~,%s,=",
				REG64(1), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_SXTH): /* halfword */
		if (arm64_reg_width(REGID64(0)) == 32) {
			rz_strbuf_setf(&op->esil, "0xffffffff,16,0xffff,%s,&,~,&,%s,=",
				REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "16,0xffff,%s,&,~,%s,=",
				REG64(1), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_SXTW): /* word */
		rz_strbuf_setf(&op->esil, "32,0xffffffff,%s,&,~,%s,=",
			REG64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_UXTB):
		rz_strbuf_setf(&op->esil, "%s,0xff,&,%s,=", REG64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_UMULL):
		rz_strbuf_setf(&op->esil, "%s,%s,*,%s,=", REG64(1), REG64(2), REG64(0));
		break;
	case CS_AARCH64(_INS_UXTH):
		rz_strbuf_setf(&op->esil, "%s,0xffff,&,%s,=", REG64(1), REG64(0));
		break;
	case CS_AARCH64(_INS_RET):
		rz_strbuf_setf(&op->esil, "lr,pc,=");
		break;
	case CS_AARCH64(_INS_ERET):
		rz_strbuf_setf(&op->esil, "lr,pc,=");
		break;
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_BFI): // bfi w8, w8, 2, 1
	case CS_AARCH64(_INS_BFXIL): {
		if (OPCOUNT64() >= 3 && ISIMM64(3) && IMM64(3) > 0) {
			ut64 mask = rz_num_bitmask((ut8)IMM64(3));
			ut64 shift = IMM64(2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			rz_strbuf_setf(&op->esil, "%" PFMT64u ",%s,&,%" PFMT64u ",%" PFMT64u ",%s,&,<<,|,%s,=",
				notmask, REG64(0), shift, mask, REG64(1), REG64(0));
		}
		break;
	}
	case CS_AARCH64(_INS_SBFIZ):
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64u ",&,~,<<,%s,=",
				IMM64(2), IMM64(3), REG64(1), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_UBFIZ):
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,%" PFMT64u ",&,<<,%s,=",
				IMM64(2), REG64(1), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_SBFX):
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64d ",%" PFMT64u ",<<,&,>>,~,%s,=",
				IMM64(3), IMM64(2), REG64(1), IMM64(2), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case CS_AARCH64(_INS_UBFX):
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,%" PFMT64d ",%" PFMT64u ",<<,&,>>,%s,=",
				IMM64(2), REG64(1), IMM64(2), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
#else
	case AARCH64_INS_BFM:
		bfm(op, handle, insn);
		break;
	case AARCH64_INS_UBFM:
	case AARCH64_INS_SBFM:
		subfm(op, handle, insn);
		break;
#endif
	case CS_AARCH64(_INS_NEG):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_NEGS):
#endif
		if (LSHIFT2_64(1)) {
			SHIFTED_REG64_APPEND(&op->esil, 1);
		} else {
			rz_strbuf_appendf(&op->esil, "%s", REG64(1));
		}
		rz_strbuf_appendf(&op->esil, ",0,-,%s,=", REG64(0));
		break;
	case CS_AARCH64(_INS_SVC):
		rz_strbuf_setf(&op->esil, "%" PFMT64u ",$", IMM64(0));
		break;
	}

	rz_strbuf_append(&op->esil, postfix);

	return 0;
}
