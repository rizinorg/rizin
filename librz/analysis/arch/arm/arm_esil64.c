// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone/capstone.h>

#include "arm_cs.h"
#include "arm_accessors64.h"

#define REG64(x)      rz_str_get_null(cs_reg_name(*handle, insn->detail->arm64.operands[x].reg))
#define MEMBASE64(x)  rz_str_get_null(cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.base))
#define MEMINDEX64(x) rz_str_get_null(cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.index))

static int arm64_reg_width(int reg) {
	switch (reg) {
	case ARM64_REG_W0:
	case ARM64_REG_W1:
	case ARM64_REG_W2:
	case ARM64_REG_W3:
	case ARM64_REG_W4:
	case ARM64_REG_W5:
	case ARM64_REG_W6:
	case ARM64_REG_W7:
	case ARM64_REG_W8:
	case ARM64_REG_W9:
	case ARM64_REG_W10:
	case ARM64_REG_W11:
	case ARM64_REG_W12:
	case ARM64_REG_W13:
	case ARM64_REG_W14:
	case ARM64_REG_W15:
	case ARM64_REG_W16:
	case ARM64_REG_W17:
	case ARM64_REG_W18:
	case ARM64_REG_W19:
	case ARM64_REG_W20:
	case ARM64_REG_W21:
	case ARM64_REG_W22:
	case ARM64_REG_W23:
	case ARM64_REG_W24:
	case ARM64_REG_W25:
	case ARM64_REG_W26:
	case ARM64_REG_W27:
	case ARM64_REG_W28:
	case ARM64_REG_W29:
	case ARM64_REG_W30:
		return 32;
		break;
	default:
		break;
	}
	return 64;
}

static int decode_sign_ext(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_UXTB:
	case ARM64_EXT_UXTH:
	case ARM64_EXT_UXTW:
	case ARM64_EXT_UXTX:
		return 0; // nothing needs to be done for unsigned
	case ARM64_EXT_SXTB:
		return 8;
	case ARM64_EXT_SXTH:
		return 16;
	case ARM64_EXT_SXTW:
		return 32;
	case ARM64_EXT_SXTX:
		return 64;
	default:
		break;
	}

	return 0;
}

#define EXT64(x) decode_sign_ext(insn->detail->arm64.operands[x].ext)

static const char *decode_shift_64(arm64_shifter shift) {
	const char *E_OP_SR = ">>";
	const char *E_OP_SL = "<<";
	const char *E_OP_RR = ">>>";
	const char *E_OP_VOID = "";

	switch (shift) {
	case ARM64_SFT_ASR:
	case ARM64_SFT_LSR:
		return E_OP_SR;

	case ARM64_SFT_LSL:
	case ARM64_SFT_MSL:
		return E_OP_SL;

	case ARM64_SFT_ROR:
		return E_OP_RR;

	default:
		break;
	}
	return E_OP_VOID;
}

#define DECODE_SHIFT64(x) decode_shift_64(insn->detail->arm64.operands[x].shift.type)

static int regsize64(cs_insn *insn, int n) {
	unsigned int reg = insn->detail->arm64.operands[n].reg;
	if ((reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) ||
		(reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
		reg == ARM64_REG_WZR) {
		return 4;
	}
	if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
		return 1;
	}
	if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
		return 2;
	}
	if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
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
		if (insn->detail->arm64.operands[n].shift.type != ARM64_SFT_ASR) {
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

RZ_IPI int rz_arm_cs_analysis_op_64_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	const char *postfix = NULL;

	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");

	postfix = rz_arm_cs_esil_prefix_cond(op, insn->detail->arm64.cc);

	switch (insn->id) {
	case ARM64_INS_REV:
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
	case ARM64_INS_REV32: {
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
	case ARM64_INS_REV16: {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		rz_strbuf_setf(&op->esil,
			"8,0xff00ff00ff00ff00,%s,&,>>,tmp,=,"
			"8,0x00ff00ff00ff00ff,%s,&,<<,tmp,|=,tmp,%s,=",
			r1, r1, r0);
		break;
	}
	case ARM64_INS_ADR:
		// TODO: must be 21bit signed
		rz_strbuf_setf(&op->esil,
			"%" PFMT64d ",%s,=", IMM64(1), REG64(0));
		break;
	case ARM64_INS_SMADDL: {
		int size = REGSIZE64(1) * 8;
		rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,*,%s,+,%s,=",
			size, REG64(2), size, REG64(1), REG64(3), REG64(0));
		break;
	}
	case ARM64_INS_UMADDL:
	case ARM64_INS_FMADD:
	case ARM64_INS_MADD:
		rz_strbuf_setf(&op->esil, "%s,%s,*,%s,+,%s,=",
			REG64(2), REG64(1), REG64(3), REG64(0));
		break;
	case ARM64_INS_MSUB:
		rz_strbuf_setf(&op->esil, "%s,%s,*,%s,-,%s,=",
			REG64(2), REG64(1), REG64(3), REG64(0));
		break;
	case ARM64_INS_MNEG:
		rz_strbuf_setf(&op->esil, "%s,%s,*,0,-,%s,=",
			REG64(2), REG64(1), REG64(0));
		break;
	case ARM64_INS_ADD:
	case ARM64_INS_ADC: // Add with carry.
		// case ARM64_INS_ADCS: // Add with carry.
		OPCALL("+");
		break;
	case ARM64_INS_SUB:
		OPCALL("-");
		break;
	case ARM64_INS_SBC:
		// TODO have to check this more, VEX does not work
		rz_strbuf_setf(&op->esil, "%s,cf,+,%s,-,%s,=",
			REG64(2), REG64(1), REG64(0));
		break;
	case ARM64_INS_SMULL: {
		int size = REGSIZE64(1) * 8;
		rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,*,%s,=",
			size, REG64(2), size, REG64(1), REG64(0));
		break;
	}
	case ARM64_INS_MUL:
		OPCALL("*");
		break;
	case ARM64_INS_AND:
		OPCALL("&");
		break;
	case ARM64_INS_ORR:
		OPCALL("|");
		break;
	case ARM64_INS_EOR:
		OPCALL("^");
		break;
	case ARM64_INS_ORN:
		OPCALL_NEG("|");
		break;
	case ARM64_INS_EON:
		OPCALL_NEG("^");
		break;
	case ARM64_INS_LSR: {
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
	case ARM64_INS_LSL: {
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
	case ARM64_INS_ROR:
		OPCALL(">>>");
		break;
	case ARM64_INS_NOP:
		rz_strbuf_setf(&op->esil, ",");
		break;
	case ARM64_INS_FDIV:
		break;
	case ARM64_INS_SDIV: {
		/* TODO: support WZR XZR to specify 32, 64bit op */
		int size = REGSIZE64(1) * 8;
		if (ISREG64(2)) {
			rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,~/,%s,=", size, REG64(2), size, REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%d,%s,~,%d,%s,~,~/,%s,=", size, REG64(1), size, REG64(0), REG64(0));
		}
		break;
	}
	case ARM64_INS_UDIV:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		if ISREG64 (2) {
			rz_strbuf_setf(&op->esil, "%s,%s,/,%s,=", REG64(2), REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%s,%s,/=", REG64(1), REG64(0));
		}
		break;
	case ARM64_INS_BR:
		rz_strbuf_setf(&op->esil, "%s,pc,=", REG64(0));
		break;
	case ARM64_INS_B:
		/* capstone precompute resulting address, using PC + IMM */
		rz_strbuf_appendf(&op->esil, "%" PFMT64d ",pc,=", IMM64(0));
		break;
	case ARM64_INS_BL:
		rz_strbuf_setf(&op->esil, "pc,lr,=,%" PFMT64d ",pc,=", IMM64(0));
		break;
	case ARM64_INS_BLR:
		rz_strbuf_setf(&op->esil, "pc,lr,=,%s,pc,=", REG64(0));
		break;
	case ARM64_INS_CLZ:;
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
	case ARM64_INS_LDRH:
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDURH:
	case ARM64_INS_LDR:
	// case ARM64_INS_LDRSB:
	// case ARM64_INS_LDRSH:
	case ARM64_INS_LDRB:
	// case ARM64_INS_LDRSW:
	// case ARM64_INS_LDURSW:
	case ARM64_INS_LDXR:
	case ARM64_INS_LDXRB:
	case ARM64_INS_LDXRH:
	case ARM64_INS_LDAXR:
	case ARM64_INS_LDAXRB:
	case ARM64_INS_LDAXRH:
	case ARM64_INS_LDAR:
	case ARM64_INS_LDARB:
	case ARM64_INS_LDARH: {
		int size = REGSIZE64(0);
		switch (insn->id) {
		case ARM64_INS_LDRB:
		case ARM64_INS_LDARB:
		case ARM64_INS_LDAXRB:
		case ARM64_INS_LDXRB:
		case ARM64_INS_LDURB:
			size = 1;
			break;
		case ARM64_INS_LDRH:
		case ARM64_INS_LDARH:
		case ARM64_INS_LDXRH:
		case ARM64_INS_LDAXRH:
		case ARM64_INS_LDURH:
			size = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
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
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", IMM64(2), REG64(1));
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
						are not detected as ARM64_OP_MEM type and
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
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDURSB:
	case ARM64_INS_LDURSH:
	case ARM64_INS_LDURSW: {
		// handle the sign extended instrs here
		int size = REGSIZE64(0);
		switch (insn->id) {
		case ARM64_INS_LDRSB:
		case ARM64_INS_LDURSB:
			size = 1;
			break;
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDURSH:
			size = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
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
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", IMM64(2), REG64(1));
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
						are not detected as ARM64_OP_MEM type and
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
	case ARM64_INS_FCMP:
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
	case ARM64_INS_TST: // cmp w8, 0xd
	case ARM64_INS_CMP: // cmp w8, 0xd
	case ARM64_INS_CMN: // cmp w8, 0xd
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
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSEL: // csel Wd, Wn, Wm --> Wd := (cond) ? Wn : Wm
		rz_strbuf_appendf(&op->esil, "%s,}{,%s,},%s,=", REG64(1), REG64(2), REG64(0));
		postfix = "";
		break;
	case ARM64_INS_CSET: // cset Wd --> Wd := (cond) ? 1 : 0
		rz_strbuf_appendf(&op->esil, "1,}{,0,},%s,=", REG64(0));
		postfix = "";
		break;
	case ARM64_INS_CINC: // cinc Wd, Wn --> Wd := (cond) ? (Wn+1) : Wn
		rz_strbuf_appendf(&op->esil, "1,%s,+,}{,%s,},%s,=", REG64(1), REG64(1), REG64(0));
		postfix = "";
		break;
	case ARM64_INS_CSINC: // csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
		rz_strbuf_appendf(&op->esil, "%s,}{,1,%s,+,},%s,=", REG64(1), REG64(2), REG64(0));
		postfix = "";
		break;
	case ARM64_INS_STXRB:
	case ARM64_INS_STXRH:
	case ARM64_INS_STXR: {
		int size = REGSIZE64(1);
		if (insn->id == ARM64_INS_STXRB) {
			size = 1;
		} else if (insn->id == ARM64_INS_STXRH) {
			size = 2;
		}
		rz_strbuf_setf(&op->esil, "0,%s,=,%s,%s,%" PFMT64d ",+,=[%d]",
			REG64(0), REG64(1), MEMBASE64(1), MEMDISP64(1), size);
		break;
	}
	case ARM64_INS_STRB:
	case ARM64_INS_STRH:
	case ARM64_INS_STUR:
	case ARM64_INS_STURB:
	case ARM64_INS_STURH:
	case ARM64_INS_STR: // str x6, [x6,0xf90]
	{
		int size = REGSIZE64(0);
		if (insn->id == ARM64_INS_STRB || insn->id == ARM64_INS_STURB) {
			size = 1;
		} else if (insn->id == ARM64_INS_STRH || insn->id == ARM64_INS_STURH) {
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
						rz_strbuf_appendf(&op->esil, ",tmp,%" PFMT64d ",+,%s,=", IMM64(2), REG64(1));
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
						are not detected as ARM64_OP_MEM type and
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
	case ARM64_INS_BIC:
		if (OPCOUNT64() == 2) {
			if (REGSIZE64(0) == 4) {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffff,^,%s,&=", REG64(1), REG64(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffffffffffff,^,%s,&=", REG64(1), REG64(0));
			}
		} else {
			if (REGSIZE64(0) == 4) {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffff,^,%s,&,%s,=", REG64(2), REG64(1), REG64(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,0xffffffffffffffff,^,%s,&,%s,=", REG64(2), REG64(1), REG64(0));
			}
		}
		break;
	case ARM64_INS_CBZ:
		rz_strbuf_setf(&op->esil, "%s,!,?{,%" PFMT64d ",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case ARM64_INS_CBNZ:
		rz_strbuf_setf(&op->esil, "%s,?{,%" PFMT64d ",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case ARM64_INS_TBZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",1,<<,%s,&,!,?{,%" PFMT64d ",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case ARM64_INS_TBNZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",1,<<,%s,&,?{,%" PFMT64d ",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case ARM64_INS_STNP:
	case ARM64_INS_STP: // stp x6, x7, [x6,0xf90]
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
			int val = IMM64(3);
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
	case ARM64_INS_LDP: // ldp x29, x30, [sp], 0x10
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
			int val = IMM64(3);
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
	case ARM64_INS_ADRP:
		rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,=",
			IMM64(1), REG64(0));
		break;
	case ARM64_INS_MOV:
		if (ISREG64(1)) {
			rz_strbuf_setf(&op->esil, "%s,%s,=", REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,=", IMM64(1), REG64(0));
		}
		break;
	case ARM64_INS_EXTR:
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
	case ARM64_INS_RBIT:
		// this expression reverses the bits. it does. do not scroll right.
		// Derived from VEX
		rz_strbuf_setf(&op->esil, "0xffffffff00000000,0x20,0xffff0000ffff0000,0x10,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,<<,&,0x10,0xffff0000ffff0000,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,&,>>,|,<<,&,0x20,0xffffffff00000000,0xffff0000ffff0000,0x10,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,<<,&,0x10,0xffff0000ffff0000,0xff00ff00ff00ff00,0x8,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,<<,&,0x8,0xff00ff00ff00ff00,0xf0f0f0f0f0f0f0f0,0x4,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,<<,&,0x4,0xf0f0f0f0f0f0f0f0,0xcccccccccccccccc,0x2,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,<<,&,0x2,0xcccccccccccccccc,0xaaaaaaaaaaaaaaaa,0x1,%1$s,<<,&,0x1,0xaaaaaaaaaaaaaaaa,%1$s,&,>>,|,&,>>,|,&,>>,|,&,>>,|,&,>>,|,&,>>,|,%2$s,=",
			REG64(1), REG64(0));
		break;
	case ARM64_INS_MVN:
	case ARM64_INS_MOVN:
		if (ISREG64(1)) {
			rz_strbuf_setf(&op->esil, "%d,%s,-1,^,<<,%s,=", LSHIFT2_64(1), REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "%d,%" PFMT64d ",<<,-1,^,%s,=", LSHIFT2_64(1), IMM64(1), REG64(0));
		}
		break;
	case ARM64_INS_MOVK: // movk w8, 0x1290
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
	case ARM64_INS_MOVZ:
		rz_strbuf_setf(&op->esil, "%" PFMT64u ",%s,=",
			IMM64(1) << LSHIFT2_64(1),
			REG64(0));
		break;
	/* ASR, SXTB, SXTH and SXTW are alias for SBFM */
	case ARM64_INS_ASR: {
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
	case ARM64_INS_SXTB:
		if (arm64_reg_width(REGID64(0)) == 32) {
			rz_strbuf_setf(&op->esil, "0xffffffff,8,0xff,%s,&,~,&,%s,=",
				REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "8,0xff,%s,&,~,%s,=",
				REG64(1), REG64(0));
		}
		break;
	case ARM64_INS_SXTH: /* halfword */
		if (arm64_reg_width(REGID64(0)) == 32) {
			rz_strbuf_setf(&op->esil, "0xffffffff,16,0xffff,%s,&,~,&,%s,=",
				REG64(1), REG64(0));
		} else {
			rz_strbuf_setf(&op->esil, "16,0xffff,%s,&,~,%s,=",
				REG64(1), REG64(0));
		}
		break;
	case ARM64_INS_SXTW: /* word */
		rz_strbuf_setf(&op->esil, "32,0xffffffff,%s,&,~,%s,=",
			REG64(1), REG64(0));
		break;
	case ARM64_INS_UXTB:
		rz_strbuf_setf(&op->esil, "%s,0xff,&,%s,=", REG64(1), REG64(0));
		break;
	case ARM64_INS_UMULL:
		rz_strbuf_setf(&op->esil, "%s,%s,*,%s,=", REG64(1), REG64(2), REG64(0));
		break;
	case ARM64_INS_UXTH:
		rz_strbuf_setf(&op->esil, "%s,0xffff,&,%s,=", REG64(1), REG64(0));
		break;
	case ARM64_INS_RET:
		rz_strbuf_setf(&op->esil, "lr,pc,=");
		break;
	case ARM64_INS_ERET:
		rz_strbuf_setf(&op->esil, "lr,pc,=");
		break;
	case ARM64_INS_BFI: // bfi w8, w8, 2, 1
	case ARM64_INS_BFXIL: {
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
	case ARM64_INS_SBFIZ:
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64u ",&,~,<<,%s,=",
				IMM64(2), IMM64(3), REG64(1), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case ARM64_INS_UBFIZ:
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,%" PFMT64u ",&,<<,%s,=",
				IMM64(2), REG64(1), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case ARM64_INS_SBFX:
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64d ",%" PFMT64u ",<<,&,>>,~,%s,=",
				IMM64(3), IMM64(2), REG64(1), IMM64(2), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case ARM64_INS_UBFX:
		if (IMM64(3) > 0 && IMM64(3) <= 64 - IMM64(2)) {
			rz_strbuf_appendf(&op->esil, "%" PFMT64d ",%s,%" PFMT64d ",%" PFMT64u ",<<,&,>>,%s,=",
				IMM64(2), REG64(1), IMM64(2), rz_num_bitmask((ut8)IMM64(3)), REG64(0));
		}
		break;
	case ARM64_INS_NEG:
#if CS_API_MAJOR > 3
	case ARM64_INS_NEGS:
#endif
		if (LSHIFT2_64(1)) {
			SHIFTED_REG64_APPEND(&op->esil, 1);
		} else {
			rz_strbuf_appendf(&op->esil, "%s", REG64(1));
		}
		rz_strbuf_appendf(&op->esil, ",0,-,%s,=", REG64(0));
		break;
	case ARM64_INS_SVC:
		rz_strbuf_setf(&op->esil, "%" PFMT64u ",$", IMM64(0));
		break;
	}

	rz_strbuf_append(&op->esil, postfix);

	return 0;
}
