// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone/capstone.h>

#include "arm_cs.h"
#include "arm_accessors32.h"

#define REG(x)      rz_str_get_null(cs_reg_name(*handle, insn->detail->arm.operands[x].reg))
#define MEMBASE(x)  rz_str_get_null(cs_reg_name(*handle, insn->detail->arm.operands[x].mem.base))
#define MEMINDEX(x) rz_str_get_null(cs_reg_name(*handle, insn->detail->arm.operands[x].mem.index))

static const char *decode_shift(arm_shifter shift) {
	const char *E_OP_SR = ">>";
	const char *E_OP_SL = "<<";
	const char *E_OP_RR = ">>>";
	const char *E_OP_ASR = ">>>>";
	const char *E_OP_VOID = "";

	switch (shift) {
	case ARM_SFT_ASR:
	case ARM_SFT_ASR_REG:
		return E_OP_ASR;

	case ARM_SFT_LSR:
	case ARM_SFT_LSR_REG:
		return E_OP_SR;

	case ARM_SFT_LSL:
	case ARM_SFT_LSL_REG:
		return E_OP_SL;

	case ARM_SFT_ROR:
	case ARM_SFT_RRX:
	case ARM_SFT_ROR_REG:
	case ARM_SFT_RRX_REG:
		return E_OP_RR;

	default:
		break;
	}
	return E_OP_VOID;
}

#define DECODE_SHIFT(x) decode_shift(insn->detail->arm.operands[x].shift.type)

static unsigned int regsize32(cs_insn *insn, int n) {
	rz_return_val_if_fail(n >= 0 && n < insn->detail->arm.op_count, 0);
	unsigned int reg = insn->detail->arm.operands[n].reg;
	if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) {
		return 8;
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		return 16;
	}
	return 4; // s0-s31, r0-r15
}

#define REGSIZE32(x) regsize32(insn, x)

#if CS_NEXT_VERSION >= 6
// return postfix
RZ_IPI const char *rz_arm32_cs_esil_prefix_cond(RzAnalysisOp *op, ARMCC_CondCodes cond_type) {
#else
RZ_IPI const char *rz_arm32_cs_esil_prefix_cond(RzAnalysisOp *op, arm_cc cond_type) {
#endif
	const char *close_cond[2];
	close_cond[0] = "";
	close_cond[1] = ",}";
	int close_type = 0;
	switch (cond_type) {
	case CS_ARMCC(EQ):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,?{,");
		break;
	case CS_ARMCC(NE):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,!,?{,");
		break;
	case CS_ARMCC(HS):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,?{,");
		break;
	case CS_ARMCC(LO):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,!,?{,");
		break;
	case CS_ARMCC(MI):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,?{,");
		break;
	case CS_ARMCC(PL):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,!,?{,");
		break;
	case CS_ARMCC(VS):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "vf,?{,");
		break;
	case CS_ARMCC(VC):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "vf,!,?{,");
		break;
	case CS_ARMCC(HI):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,zf,!,&,?{,");
		break;
	case CS_ARMCC(LS):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "cf,!,zf,|,?{,");
		break;
	case CS_ARMCC(GE):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,vf,^,!,?{,");
		break;
	case CS_ARMCC(LT):
		close_type = 1;
		rz_strbuf_setf(&op->esil, "nf,vf,^,?{,");
		break;
	case CS_ARMCC(GT):
		// zf == 0 && nf == vf
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,!,nf,vf,^,!,&,?{,");
		break;
	case CS_ARMCC(LE):
		// zf == 1 || nf != vf
		close_type = 1;
		rz_strbuf_setf(&op->esil, "zf,nf,vf,^,|,?{,");
		break;
	case CS_ARMCC(AL):
		// always executed
		break;
	default:
		break;
	}
	return close_cond[close_type];
}

static const char *arg(RzAnalysis *a, csh *handle, cs_insn *insn, char *buf, int n) {
	buf[0] = 0;
	switch (insn->detail->arm.operands[n].type) {
	case ARM_OP_REG:
		if (ISSHIFTED(n)) {
			if (SHIFTTYPEREG(n)) {
				sprintf(buf, "%s,%s,%s",
					cs_reg_name(*handle, LSHIFT2(n)),
					rz_str_get_null(cs_reg_name(*handle,
						insn->detail->arm.operands[n].reg)),
					DECODE_SHIFT(n));
			} else {
				sprintf(buf, "%u,%s,%s",
					LSHIFT2(n),
					rz_str_get_null(cs_reg_name(*handle,
						insn->detail->arm.operands[n].reg)),
					DECODE_SHIFT(n));
			}
		} else {
			sprintf(buf, "%s",
				rz_str_get_null(cs_reg_name(*handle,
					insn->detail->arm.operands[n].reg)));
		}
		break;
	case ARM_OP_IMM:
		if (a->bits == 64) {
			// 64bit only
			sprintf(buf, "%" PFMT64d, (ut64)insn->detail->arm.operands[n].imm);
		} else {
			// 32bit only
			sprintf(buf, "%" PFMT64d, (ut64)(ut32)insn->detail->arm.operands[n].imm);
		}
		break;
	case ARM_OP_MEM:
		break;
	case ARM_OP_FP:
		sprintf(buf, "%lf", insn->detail->arm.operands[n].fp);
		break;
	default:
		break;
	}
	return buf;
}

#define ARG(x) arg(a, handle, insn, str[x], x)

#define MATH32(opchar)     arm32math(a, op, addr, buf, len, handle, insn, pcdelta, str, opchar, 0)
#define MATH32_NEG(opchar) arm32math(a, op, addr, buf, len, handle, insn, pcdelta, str, opchar, 1)
#define MATH32AS(opchar)   arm32mathaddsub(a, op, addr, buf, len, handle, insn, pcdelta, str, opchar)

static void arm32math(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, int pcdelta, char (*str)[32], const char *opchar, int negate) {
	const char *dest = ARG(0);
	const char *op1;
	const char *op2;
	bool rotate_imm = OPCOUNT() > 3;
	if (OPCOUNT() > 2) {
		op1 = ARG(1);
		op2 = ARG(2);
	} else {
		op1 = dest;
		op2 = ARG(1);
	}
	// right operand
	if (rotate_imm) {
		rz_strbuf_appendf(&op->esil, "%s,", ARG(3));
	}
	if (!strcmp(op2, "pc")) {
		rz_strbuf_appendf(&op->esil, "%d,$$,+", pcdelta);
	} else {
		rz_strbuf_appendf(&op->esil, "%s", op2);
	}
	if (rotate_imm) {
		rz_strbuf_appendf(&op->esil, ",>>>");
	}
	if (negate) {
		rz_strbuf_appendf(&op->esil, ",-1,^");
	}
	if (!strcmp(op1, "pc")) {
		rz_strbuf_appendf(&op->esil, ",%d,$$,+,%s,0xffffffff,&,%s,=", pcdelta, opchar, dest);
	} else {
		if (ISSHIFTED(1)) {
			rz_strbuf_appendf(&op->esil, ",0xffffffff,&,%s,=", dest);
		} else {
			rz_strbuf_appendf(&op->esil, ",%s,%s,0xffffffff,&,%s,=", op1, opchar, dest);
		}
	}
}

static void arm32mathaddsub(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, int pcdelta, char (*str)[32], const char *opchar) {
	const char *dst = ARG(0);
	const char *src;
	bool noflags = false;
	if (!strcmp(dst, "pc")) { // this is because strbuf_prepend doesn't exist and E_TOO_LAZY
		//		rz_strbuf_append (&op->esil, "$$,pc,=,");
		noflags = true;
	}
	if (OPCOUNT() == 3) {
		rz_strbuf_appendf(&op->esil, "%s,0xffffffff,&,%s,=,", ARG(1), dst);
		src = ARG(2);
	} else {
		//		src = (!strcmp (ARG(1), "pc"))? "$$": ARG(1);
		src = ARG(1);
	}
	rz_strbuf_appendf(&op->esil, "%s,%s,%s,0xffffffff,&,%s,=", src, dst, opchar, dst);
	if (noflags) {
		return;
	}
	rz_strbuf_appendf(&op->esil, ",$z,zf,:=,%s,cf,:=,vf,=,0,nf,=",
		(!strcmp(opchar, "+") ? "30,$c,31,$c,^,31,$c" : "30,$c,31,$c,^,32,$b"));
}

RZ_IPI int rz_arm_cs_analysis_op_32_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, bool thumb) {
	int i;
	const char *postfix = NULL;
	char str[32][32];
	int msr_flags;
	int pcdelta = (thumb ? 4 : 8);
	ut32 mask = UT32_MAX;
	int str_ldr_bytes = 4;
	unsigned int width = 0;

	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");
	postfix = rz_arm32_cs_esil_prefix_cond(op, insn->detail->arm.cc);

	switch (insn->id) {
	case ARM_INS_CLZ:
		rz_strbuf_appendf(&op->esil, "%s,!,?{,32,%s,=,BREAK,},0,%s,=,%s,%s,<<,0x80000000,&,!,?{,1,%s,+=,11,GOTO,}", REG(1), REG(0), REG(0), REG(0), REG(1), REG(0));
		break;
	case ARM_INS_IT:
		rz_strbuf_appendf(&op->esil, "2,$$,+,pc,=");
		break;
	case ARM_INS_BKPT:
		rz_strbuf_setf(&op->esil, "%d,%d,TRAP", IMM(0), IMM(0));
		break;
#if CS_NEXT_VERSION < 6
	case ARM_INS_NOP:
#else
	case ARM_INS_HINT:
#endif
		rz_strbuf_setf(&op->esil, ",");
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		rz_strbuf_appendf(&op->esil, "pc,%d,+,lr,=,", thumb);
		/* fallthrough */
	case ARM_INS_BX:
	case ARM_INS_BXJ:
	case ARM_INS_B:
		if (ISREG(0) && REGID(0) == ARM_REG_PC) {
			rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",pc,=", (addr & ~3LL) + pcdelta);
		} else {
			if (ISIMM(0)) {
				rz_strbuf_appendf(&op->esil, "%s,pc,=", ARG(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%d,%s,-,pc,=", thumb, ARG(0));
			}
		}
		break;
	case ARM_INS_UDF:
		rz_strbuf_setf(&op->esil, "%s,TRAP", ARG(0));
		break;
	case ARM_INS_SADD16:
	case ARM_INS_SADD8:
		MATH32AS("+");
		break;
	case ARM_INS_ADDW:
	case ARM_INS_ADD:
		MATH32("+");
		break;
	case ARM_INS_ADC:
		if (OPCOUNT() == 2) {
			rz_strbuf_appendf(&op->esil, "cf,%s,+=,%s,%s,+=", ARG(0), ARG(1), ARG(0));
		} else {
			rz_strbuf_appendf(&op->esil, "cf,%s,+=,%s,%s,+,%s,+=", ARG(0), ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_SSUB16:
	case ARM_INS_SSUB8:
		MATH32AS("-");
		break;
	case ARM_INS_SUBW:
	case ARM_INS_SUB:
		MATH32("-");
		break;
	case ARM_INS_SBC:
		if (OPCOUNT() == 2) {
			rz_strbuf_appendf(&op->esil, "cf,%s,-=,%s,%s,-=", ARG(0), ARG(1), ARG(0));
		} else {
			rz_strbuf_appendf(&op->esil, "cf,%s,-=,%s,%s,+,%s,-=", ARG(0), ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_MUL:
		MATH32("*");
		break;
	case ARM_INS_AND:
		MATH32("&");
		break;
	case ARM_INS_ORR:
		MATH32("|");
		break;
	case ARM_INS_EOR:
		MATH32("^");
		break;
	case ARM_INS_ORN:
		MATH32_NEG("|");
		break;
	case ARM_INS_LSR:
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT() == 2) {
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG(1), ARG(0), ARG(1));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG(2), ARG(1), ARG(2));
			}
		}
		MATH32(">>");
		break;
	case ARM_INS_LSL:
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT() == 2) {
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},", ARG(1), ARG(1), ARG(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},", ARG(2), ARG(2), ARG(1));
			}
		}
		MATH32("<<");
		break;
	case ARM_INS_SVC:
		rz_strbuf_setf(&op->esil, "%s,$", ARG(0));
		break;
	case ARM_INS_PUSH:
#if 0
PUSH { r4, r5, r6, r7, lr }
4,sp,-=,lr,sp,=[4],
4,sp,-=,r7,sp,=[4],
4,sp,-=,r6,sp,=[4],
4,sp,-=,r5,sp,=[4],
4,sp,-=,r4,sp,=[4]

20,sp,-=,lr,r7,r6,r5,r4,5,sp,=[*]
#endif
		rz_strbuf_appendf(&op->esil, "%d,sp,-=,",
			4 * insn->detail->arm.op_count);
		for (i = insn->detail->arm.op_count; i > 0; i--) {
			rz_strbuf_appendf(&op->esil, "%s,", REG(i - 1));
		}
		rz_strbuf_appendf(&op->esil, "%d,sp,=[*]",
			insn->detail->arm.op_count);
		break;
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
	case ARM_INS_STM:
	case ARM_INS_STMIB: {
		int direction = (insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMDB ? -1 : 1);
		int offset = direction > 0 ? -1 : -insn->detail->arm.op_count;
		if (insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMIB) {
			offset++;
		}
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			rz_strbuf_appendf(&op->esil, "%s,%s,%d,+,=[4],",
				REG(i), ARG(0), (i + offset) * 4);
		}
		if (ISWRITEBACK32() == true) { // writeback, reg should be incremented
			rz_strbuf_appendf(&op->esil, "%d,%s,+=,",
				direction * (insn->detail->arm.op_count - 1) * 4, ARG(0));
		}
		break;
	}
	case ARM_INS_VSTMIA:
		rz_strbuf_set(&op->esil, "");
		width = 0;
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			rz_strbuf_appendf(&op->esil, "%s,%d,%s,+,=[%d],",
				REG(i), width, ARG(0), REGSIZE32(i));
			width += REGSIZE32(i);
		}
		// increment if writeback
		if (ISWRITEBACK32()) {
			rz_strbuf_appendf(&op->esil, "%d,%s,+=,", width, ARG(0));
		}
		break;
	case ARM_INS_VSTMDB:
		rz_strbuf_set(&op->esil, "");
		width = 0;
		for (i = insn->detail->arm.op_count - 1; i > 0; i--) {
			width += REGSIZE32(i);
			rz_strbuf_appendf(&op->esil, "%s,%d,%s,-,=[%d],",
				REG(i), width, ARG(0), REGSIZE32(i));
		}
		// decrement writeback is mandatory for VSTMDB
		rz_strbuf_appendf(&op->esil, "%d,%s,-=,", width, ARG(0));
		break;
	case ARM_INS_VLDMIA:
		rz_strbuf_set(&op->esil, "");
		width = 0;
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			rz_strbuf_appendf(&op->esil, "%d,%s,+,[%d],%s,=,",
				width, ARG(0), REGSIZE32(i), REG(i));
			width += REGSIZE32(i);
		}
		// increment if writeback
		if (ISWRITEBACK32()) {
			rz_strbuf_appendf(&op->esil, "%d,%s,+=,", width, ARG(0));
		}
		break;
	case ARM_INS_VLDMDB:
		rz_strbuf_set(&op->esil, "");
		width = 0;
		for (i = insn->detail->arm.op_count - 1; i > 0; i--) {
			width += REGSIZE32(i);
			rz_strbuf_appendf(&op->esil, "%d,%s,-,[%d],%s,=,",
				width, ARG(0), REGSIZE32(i), REG(i));
		}
		// decrement writeback is mandatory for VLDMDB
		rz_strbuf_appendf(&op->esil, "%d,%s,-=,", width, ARG(0));
		break;
	case ARM_INS_ASR:
		// suffix 'S' forces conditional flag to be updated
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT() == 2) {
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG(1), ARG(0), ARG(1));
			} else if (OPCOUNT() == 3) {
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG(2), ARG(1), ARG(2));
			}
		}
		if (OPCOUNT() == 2) {
			if (ISSHIFTED(1)) {
				rz_strbuf_appendf(&op->esil, "%s,%s,=", ARG(1), ARG(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,%s,>>>>,%s,=", ARG(1), ARG(0), ARG(0));
			}
		} else if (OPCOUNT() == 3) {
			rz_strbuf_appendf(&op->esil, "%s,%s,>>>>,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_POP:
#if 0
POP { r4,r5, r6}
r6,r5,r4,3,sp,[*],12,sp,+=
#endif
		for (i = insn->detail->arm.op_count; i > 0; i--) {
			rz_strbuf_appendf(&op->esil, "%s,", REG(i - 1));
		}
		rz_strbuf_appendf(&op->esil, "%d,sp,[*],",
			insn->detail->arm.op_count);
		rz_strbuf_appendf(&op->esil, "%d,sp,+=",
			4 * insn->detail->arm.op_count);
		break;
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDM:
	case ARM_INS_LDMIB: {
		int direction = (insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMDB) ? -1 : 1;
		int offset = direction > 0 ? -1 : -insn->detail->arm.op_count;
		if (insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMIB) {
			offset++;
		}
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			rz_strbuf_appendf(&op->esil, "%s,%d,+,[4],%s,=,", ARG(0), (i + offset) * 4, REG(i));
		}
		if (ISWRITEBACK32()) {
			rz_strbuf_appendf(&op->esil, "%d,%s,+=,",
				direction * (insn->detail->arm.op_count - 1) * 4, ARG(0));
		}
		break;
	}
	case ARM_INS_CMP:
		rz_strbuf_appendf(&op->esil, "%s,%s,==", ARG(1), ARG(0));
		break;
	case ARM_INS_CMN:
		rz_strbuf_appendf(&op->esil, "%s,%s,^,!,!,zf,=", ARG(1), ARG(0));
		break;
	case ARM_INS_MOVT:
		rz_strbuf_appendf(&op->esil, "16,%s,<<,%s,|=", ARG(1), REG(0));
		break;
	case ARM_INS_ADR:
		rz_strbuf_appendf(&op->esil, "%d,$$,+,%s,+,0xfffffffc,&,%s,=",
			pcdelta, ARG(1), REG(0));
		break;
	case ARM_INS_MOV:
	case ARM_INS_VMOV:
	case ARM_INS_MOVW:
		rz_strbuf_appendf(&op->esil, "%s,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_CBZ:
		rz_strbuf_appendf(&op->esil, "%s,!,?{,%" PFMT32u ",pc,=,}",
			REG(0), IMM(1));
		break;
	case ARM_INS_CBNZ:
		rz_strbuf_appendf(&op->esil, "%s,?{,%" PFMT32u ",pc,=,}",
			REG(0), IMM(1));
		break;
		// Encapsulated STR/H/B into a code section
	case ARM_INS_STRT:
	case ARM_INS_STR:
	case ARM_INS_STRHT:
	case ARM_INS_STRH:
	case ARM_INS_STRBT:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
		// case ARM_INS_STLXRB: // capstone has no STLXR?
		switch (insn->id) {
		case ARM_INS_STRD:
			str_ldr_bytes = 8; // just an indication, won't be used in esil code
			break;
		case ARM_INS_STRHT:
		case ARM_INS_STRH:
			str_ldr_bytes = 2;
			break;
		case ARM_INS_STRBT:
		case ARM_INS_STRB:
			str_ldr_bytes = 1;
			break;
		default:
			str_ldr_bytes = 4;
		}
		if (!ISPOSTINDEX32()) {
			if (ISMEM(1) && !HASMEMINDEX(1)) {
				int disp = MEMDISP(1);
				char sign = disp >= 0 ? '+' : '-';
				disp = disp >= 0 ? disp : -disp;
				rz_strbuf_appendf(&op->esil, "%s,0x%x,%s,%c,0xffffffff,&,=[%d]",
					REG(0), disp, MEMBASE(1), sign, str_ldr_bytes);
				if (ISWRITEBACK32()) {
					rz_strbuf_appendf(&op->esil, ",%d,%s,%c,%s,=",
						disp, MEMBASE(1), sign, MEMBASE(1));
				}
			}
			if (HASMEMINDEX(1)) { // e.g. 'str r2, [r3, r1]'
				if (ISSHIFTED(1)) { // e.g. 'str r2, [r3, r1, lsl 4]'
					switch (SHIFTTYPE(1)) {
					case ARM_SFT_LSL:
						rz_strbuf_appendf(&op->esil, "%s,%s,%d,%s,<<,+,0xffffffff,&,=[%d]",
							REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32()) { // e.g. 'str r2, [r3, r1, lsl 4]!'
							rz_strbuf_appendf(&op->esil, ",%s,%d,%s,<<,+,%s,=",
								MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_LSR:
						rz_strbuf_appendf(&op->esil, "%s,%s,%d,%s,>>,+,0xffffffff,&,=[%d]",
							REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32()) {
							rz_strbuf_appendf(&op->esil, ",%s,%d,%s,>>,+,%s,=",
								MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_ASR:
						rz_strbuf_appendf(&op->esil, "%s,%s,%d,%s,>>>>,+,0xffffffff,&,=[%d]",
							REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32()) {
							rz_strbuf_appendf(&op->esil, ",%s,%d,%s,>>>>,+,%s,=",
								MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_ROR:
						rz_strbuf_appendf(&op->esil, "%s,%s,%d,%s,>>>,+,0xffffffff,&,=[%d]",
							REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32()) {
							rz_strbuf_appendf(&op->esil, ",%s,%d,%s,>>>,+,%s,=",
								MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_RRX: // ROR with single bit shift, using previous cf rather than new cf
						// TODO: r2 doesn't mark this as a shift, it falls through to no shift
						break;
					default:
						// Hopefully nothing here
						break;
					}
				} else { // No shift
					rz_strbuf_appendf(&op->esil, "%s,%s,%s,+,0xffffffff,&,=[%d]",
						REG(0), MEMINDEX(1), MEMBASE(1), str_ldr_bytes);
					if (ISWRITEBACK32()) {
						rz_strbuf_appendf(&op->esil, ",%s,%s,+,%s,=",
							MEMINDEX(1), MEMBASE(1), MEMBASE(1));
					}
				}
			}
		}
		if (ISPOSTINDEX32()) { // e.g. 'str r2, [r3], 4
			if (!HASMEMINDEX(1) && (str_ldr_bytes != 8)) { // e.g. 'str r2, [r3], 4
				rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[%d],%d,%s,+=",
					REG(0), MEMBASE(1), str_ldr_bytes, MEMDISP(1), MEMBASE(1));
			} else if (str_ldr_bytes != 8) { // e.g. 'str r2, [r3], r1
				if (ISSHIFTED(1)) { // e.g. 'str r2, [r3], r1, lsl 4'
					switch (SHIFTTYPE(1)) {
					case ARM_SFT_LSL:
						rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,<<,+,%s,=",
							REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						break;
					case ARM_SFT_LSR:
						rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>,+,%s,=",
							REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						break;
					case ARM_SFT_ASR:
						rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>>>,+,%s,=",
							REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						break;
					case ARM_SFT_ROR:
						rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>>,+,%s,=",
							REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						break;
					case ARM_SFT_RRX:
						// TODO
						break;
					default:
						// Hopefully nothing here
						break;
					}
				} else { // No shift
					rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%s,+=",
						REG(0), MEMBASE(1), str_ldr_bytes, MEMINDEX(1), MEMBASE(1));
				}
			} else if (ISREG(1) && str_ldr_bytes == 8) { // e.g. 'strd r2, r3, [r4]', normally should be the only case for ISREG(1).
				if (!HASMEMINDEX(2)) {
					int disp = MEMDISP(2);
					char sign = disp >= 0 ? '+' : '-';
					disp = disp >= 0 ? disp : -disp;
					rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[4],%s,4,%s,+,0xffffffff,&,=[4]",
						REG(0), MEMBASE(2), REG(1), MEMBASE(2));
					if (ISWRITEBACK32()) {
						rz_strbuf_appendf(&op->esil, ",%d,%s,%c,%s,=",
							disp, MEMBASE(2), sign, MEMBASE(2));
					}
				} else {
					if (ISSHIFTED(2)) {
						// it seems strd does not support SHIFT which is good, but have a check nonetheless
					} else {
						rz_strbuf_appendf(&op->esil, "%s,%s,0xffffffff,&,=[4],%s,4,%s,+,0xffffffff,&,=[4]",
							REG(0), MEMBASE(2), REG(1), MEMBASE(2));
						if (ISWRITEBACK32()) {
							const char sign = ISMEMINDEXSUB(2) ? '-' : '+';
							rz_strbuf_appendf(&op->esil, ",%s,%s,%c=",
								MEMINDEX(2), MEMBASE(2), sign);
						}
					}
				}
			}
		}
		break;
	case ARM_INS_TST:
		rz_strbuf_appendf(&op->esil, "0,%s,%s,&,==", ARG(1), ARG(0));
		break;
	case ARM_INS_LDRD:
		addr &= ~3LL;
		if (MEMDISP(2) < 0) {
			const char *pc = "$$";
			if (REGBASE(2) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(2);
				rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",2,2,%s,%d,+,>>,<<,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
					(ut64)MEMDISP(2), pc, pcdelta, REG(0), REG(1));
			} else {
				int disp = ISPOSTINDEX32() ? 0 : MEMDISP(2);
				// not refptr, because we can't grab the reg value statically op->refptr = 4;
				rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",%s,-,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
					(ut64)-disp, MEMBASE(2), REG(0), REG(1));
			}
		} else {
			if (REGBASE(2) == ARM_REG_PC) {
				const char *pc = "$$";
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(2);
				if (HASMEMINDEX(2) || ISREG(2)) {
					const char op_index = ISMEMINDEXSUB(2) ? '-' : '+';
					rz_strbuf_appendf(&op->esil, "%s,2,2,%d,%s,+,>>,<<,%c,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMINDEX(2), pcdelta, pc, op_index, REG(0), REG(1));
				} else {
					rz_strbuf_appendf(&op->esil, "2,2,%d,%s,+,>>,<<,%d,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						pcdelta, pc, MEMDISP(2), REG(0), REG(1));
				}
			} else {
				if (HASMEMINDEX(2)) { // e.g. `ldrd r2, r3 [r4, r1]` or `ldrd r2, r3 [r4], r1`
					const char op_index = ISMEMINDEXSUB(2) ? '-' : '+';
					const char *mem_index = ISPOSTINDEX32() ? "0" : MEMINDEX(2);
					rz_strbuf_appendf(&op->esil, "%s,%s,%c,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						mem_index, MEMBASE(2), op_index, REG(0), REG(1));
				} else {
					int disp = ISPOSTINDEX32() ? 0 : MEMDISP(2);
					rz_strbuf_appendf(&op->esil, "%d,%s,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						disp, MEMBASE(2), REG(0), REG(1));
				}
				if (ISWRITEBACK32()) {
					if (ISPOSTINDEX32()) {
						if (!HASMEMINDEX(2)) {
							rz_strbuf_appendf(&op->esil, ",%s,%d,+,%s,=",
								MEMBASE(2), MEMDISP(2), MEMBASE(2));
						} else {
							const char op_index = ISMEMINDEXSUB(2) ? '-' : '+';
							rz_strbuf_appendf(&op->esil, ",%s,%s,%c,%s,=",
								MEMINDEX(2), MEMBASE(2), op_index, MEMBASE(2));
						}
					} else {
						if (HASMEMINDEX(2)) {
							const char op_index = ISMEMINDEXSUB(2) ? '-' : '+';
							rz_strbuf_appendf(&op->esil, ",%s,%s,%c,%s,=",
								MEMINDEX(2), MEMBASE(2), op_index, MEMBASE(2));
						} else {
							rz_strbuf_appendf(&op->esil, ",%s,%d,+,%s,=",
								MEMBASE(2), MEMDISP(2), MEMBASE(2));
						}
					}
				}
			}
		}
		break;
	case ARM_INS_LDRB:
		if (ISMEM(1) && LSHIFT2(1)) {
			rz_strbuf_appendf(&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[1],0x%x,&,%s,=",
				MEMBASE(1), LSHIFT2(1), MEMINDEX(1), mask, REG(0));
		} else if (HASMEMINDEX(1)) {
			rz_strbuf_appendf(&op->esil, "%s,%s,+,0xffffffff,&,[1],%s,=",
				MEMINDEX(1), MEMBASE(1), REG(0));
		} else {
			rz_strbuf_appendf(&op->esil, "%s,%d,+,[1],%s,=",
				MEMBASE(1), ISPOSTINDEX32() ? 0 : MEMDISP(1), REG(0));
		}
		if (ISWRITEBACK32()) {
			rz_strbuf_appendf(&op->esil, ",%s,%d,+,%s,=",
				MEMBASE(1), MEMDISP(1), MEMBASE(1));
		}
		break;
	case ARM_INS_SXTH:
		rz_strbuf_appendf(&op->esil,
			"15,%s,>>,1,&,?{,15,-1,<<,%s,0xffff,&,|,%s,:=,}{,%s,0xffff,%s,:=,}",
			REG(1), REG(1), REG(0), REG(1), REG(0));
		break;
	case ARM_INS_SXTB:
		rz_strbuf_appendf(&op->esil,
			"7,%s,>>,1,&,?{,7,-1,<<,%s,0xff,&,|,%s,:=,}{,%s,0xff,&,%s,:=,}",
			REG(1), REG(1), REG(0), REG(1), REG(0));
		break;
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM_INS_LDRHT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRT:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDR:
		switch (insn->id) {
		case ARM_INS_LDRHT:
		case ARM_INS_LDRH:
		case ARM_INS_LDRSH:
		case ARM_INS_LDRSHT:
			mask = UT16_MAX;
			break;
		default:
			mask = UT32_MAX;
			break;
		}
		addr &= ~3LL;
		if (MEMDISP(1) < 0) {
			const char *pc = "$$";
			if (REGBASE(1) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(1);
				rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",2,2,%s,>>,<<,+,0xffffffff,&,[4],0x%x,&,%s,=",
					(ut64)MEMDISP(1), pc, mask, REG(0));
			} else {
				st64 disp = MEMDISP(1);
				// not refptr, because we can't grab the reg value statically op->refptr = 4;
				rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",%s,-,0xffffffff,&,[4],0x%x,&,%s,=",
					(ut64)-disp, MEMBASE(1), mask, REG(0));
			}
		} else {
			if (ISMEM(1) && REGBASE(1) == ARM_REG_PC) {
				const char *pc = "$$";
				if (HASMEMINDEX(1)) {
					if (LSHIFT2(1)) {
						rz_strbuf_appendf(&op->esil, "2,2,%d,%s,+,>>,<<,%d,%s,<<,+,0xffffffff,&,[4],0x%x,&,%s,=",
							pcdelta, pc, LSHIFT2(1), MEMINDEX(1), mask, REG(0));
					} else {
						rz_strbuf_appendf(&op->esil, "2,2,%d,%s,+,>>,<<,%s,+,0xffffffff,&,[4],0x%x,&,%s,=",
							pcdelta, pc, MEMINDEX(1), mask, REG(0));
					}
				} else {
					op->refptr = 4;
					op->ptr = addr + pcdelta + MEMDISP(1);
					rz_strbuf_appendf(&op->esil, "2,2,%d,%s,+,>>,<<,%d,+,0xffffffff,&,[4],0x%x,&,%s,=",
						pcdelta, pc, MEMDISP(1), mask, REG(0));
				}
			} else {
				if (ISMEM(1) && LSHIFT2(1)) {
					rz_strbuf_appendf(&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMBASE(1), LSHIFT2(1), MEMINDEX(1), mask, REG(0));
				} else if (HASMEMINDEX(1)) { // e.g. `ldr r2, [r3, r1]`
					rz_strbuf_appendf(&op->esil, "%s,%s,+,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMINDEX(1), MEMBASE(1), mask, REG(0));
				} else if (ISPOSTINDEX32()) {
					rz_strbuf_appendf(&op->esil, "%s,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMBASE(1), mask, REG(0));
				} else {
					rz_strbuf_appendf(&op->esil, "%d,%s,+,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMDISP(1), MEMBASE(1), mask, REG(0));
				}
				if (ISWRITEBACK32()) {
					rz_strbuf_appendf(&op->esil, ",%s,%d,+,%s,=",
						MEMBASE(1), MEMDISP(1), MEMBASE(1));
				}
			}
		}
		break;
	case ARM_INS_MRS:
		// TODO: esil for MRS
		break;
	case ARM_INS_MSR:
		if (insn->detail->arm.operands[0].type != ARM_OP_REG) {
			// New sysop operands added in Capstone v6 are not supported in ESIL.
			break;
		}
#if CS_NEXT_VERSION >= 6
		msr_flags = insn->detail->arm.operands[0].sysop.msr_mask;
#else
		msr_flags = insn->detail->arm.operands[0].reg >> 4;
#endif
		rz_strbuf_appendf(&op->esil, "0,");
		if (msr_flags & 1) {
			rz_strbuf_appendf(&op->esil, "0xFF,|,");
		}
		if (msr_flags & 2) {
			rz_strbuf_appendf(&op->esil, "0xFF00,|,");
		}
		if (msr_flags & 4) {
			rz_strbuf_appendf(&op->esil, "0xFF0000,|,");
		}
		if (msr_flags & 8) {
			rz_strbuf_appendf(&op->esil, "0xFF000000,|,");
		}
		rz_strbuf_appendf(&op->esil, "DUP,!,SWAP,&,%s,SWAP,cpsr,&,|,cpsr,=", REG(1));
		break;
	case ARM_INS_UBFX:
		if (IMM(3) > 0 && IMM(3) <= 32 - IMM(2)) {
			rz_strbuf_appendf(&op->esil, "%d,%s,%d,%" PFMT64u ",<<,&,>>,%s,=",
				IMM(2), REG(1), IMM(2), rz_num_bitmask((ut8)IMM(3)), REG(0));
		}
		break;
	case ARM_INS_UXTB:
		rz_strbuf_appendf(&op->esil, "%s,0xff,&,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_RSB:
		if (OPCOUNT() == 2) {
			rz_strbuf_appendf(&op->esil, "%s,%s,-=", ARG(0), ARG(1));
		} else if (OPCOUNT() == 3) {
			rz_strbuf_appendf(&op->esil, "%s,%s,-,%s,=", ARG(1), ARG(2), ARG(0));
		}
		break;
	case ARM_INS_BIC:
		if (OPCOUNT() == 2) {
			rz_strbuf_appendf(&op->esil, "%s,0xffffffff,^,%s,&=", ARG(1), ARG(0));
		} else {
			rz_strbuf_appendf(&op->esil, "%s,0xffffffff,^,%s,&,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_SMMLA:
		rz_strbuf_appendf(&op->esil, "32,%s,%s,*,>>,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_SMMLAR:
		rz_strbuf_appendf(&op->esil, "32,0x80000000,%s,%s,*,+,>>,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_UMULL:
		rz_strbuf_appendf(&op->esil, "32,%s,%s,*,DUP,0xffffffff,&,%s,=,>>,%s,=",
			REG(2), REG(3), REG(0), REG(1));
		break;
	case ARM_INS_MLS:
		rz_strbuf_appendf(&op->esil, "%s,%s,*,%s,-,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_MLA:
		rz_strbuf_appendf(&op->esil, "%s,%s,*,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_MVN:
		rz_strbuf_appendf(&op->esil, "-1,%s,^,0xffffffff,&,%s,=",
			ARG(1), REG(0));
		break;
	case ARM_INS_BFI: {
		if (OPCOUNT() >= 3 && ISIMM(3) && IMM(3) > 0 && IMM(3) < 64) {
			ut64 mask = rz_num_bitmask((ut8)IMM(3));
			ut64 shift = IMM(2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			rz_strbuf_setf(&op->esil, "%" PFMT64u ",%s,&,%" PFMT64u ",%" PFMT64u ",%s,&,<<,|,0xffffffff,&,%s,=",
				notmask, REG(0), shift, mask, REG(1), REG(0));
		}
		break;
	}
	case ARM_INS_BFC: {
		if (OPCOUNT() >= 2 && ISIMM(2) && IMM(2) > 0 && IMM(2) < 64) {
			ut64 mask = rz_num_bitmask((ut8)IMM(2));
			ut64 shift = IMM(1);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,dst,=
			rz_strbuf_setf(&op->esil, "%" PFMT64u ",%s,&,0xffffffff,&,%s,=",
				notmask, REG(0), REG(0));
		}
		break;
	}
	case ARM_INS_REV: {
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		rz_strbuf_setf(&op->esil,
			"24,0xff,%s,&,<<,%s,=,"
			"16,0xff,8,%s,>>,&,<<,%s,|=,"
			"8,0xff,16,%s,>>,&,<<,%s,|=,"
			"0xff,24,%s,>>,&,%s,|=,",
			r1, r0, r1, r0, r1, r0, r1, r0);
		break;
	}
	case ARM_INS_REV16: {
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		rz_strbuf_setf(&op->esil,
			"8,0xff00ff00,%s,&,>>,%s,=,"
			"8,0x00ff00ff,%s,&,<<,%s,|=,",
			r1, r0, r1, r0);
		break;
	}
	case ARM_INS_REVSH: {
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		rz_strbuf_setf(&op->esil,
			"8,0xff00,%s,&,>>,%s,=,"
			"8,0x00ff,%s,&,<<,%s,|=,"
			"0x8000,%s,&,?{,"
			"0xffff0000,%s,|=,"
			"}",
			r1, r0, r1, r0, r0, r0);
		break;
	}
	case ARM_INS_TBB:
		rz_strbuf_appendf(&op->esil, "%s,%s,+,0xffffffff,&,DUP,[1],1,SWAP,<<,+,pc,+=",
			MEMBASE(0), MEMINDEX(0));
		break;
	case ARM_INS_TBH:
		rz_strbuf_appendf(&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[2],1,SWAP,<<,pc,+=",
			MEMBASE(0), LSHIFT2(0), MEMINDEX(0));
		break;
	default:
		break;
	}
	// Update flags if required...TODO different instructions update different flags, but this should fix
	// many errors
	if (insn->detail->arm.update_flags) {
		switch (insn->id) {
		case ARM_INS_MSR:
			// Updates flags manually
			break;
		case ARM_INS_CMP:
			rz_strbuf_appendf(&op->esil, ",$z,zf,:=,31,$s,nf,:=,32,$b,!,cf,:=,31,$o,vf,:=");
			break;
		case ARM_INS_ADD:
		case ARM_INS_RSB:
		case ARM_INS_SUB:
		case ARM_INS_SBC:
		case ARM_INS_ADC:
		case ARM_INS_CMN:
			rz_strbuf_appendf(&op->esil, ",$z,zf,:=,31,$s,nf,:=,31,$c,cf,:=,31,$o,vf,:=");
			break;
		case ARM_INS_MOV: {
			// Move has already set the dest register at this point.
			// But mind that ARG() always includes the shift of the source register.
			// If the source register is the same as the destination register it would shift the value twice.
			// We need to prepend the move (already in op->esil) to the flag check.
			char move_esil[64];
			switch (SHIFTTYPE(1)) {
			default:
				break;
			case ARM_SFT_LSL:
			case ARM_SFT_LSL_REG:
				rz_strf(move_esil, "%s", rz_strbuf_drain_nofree(&op->esil));
				rz_strbuf_appendf(&op->esil, ",%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},%s", ARG(1), ARG(1), ARG(0), move_esil);
				break;
			case ARM_SFT_LSR:
			case ARM_SFT_LSR_REG:
			case ARM_SFT_ASR:
			case ARM_SFT_ASR_REG:
				rz_strf(move_esil, "%s", rz_strbuf_drain_nofree(&op->esil));
				rz_strbuf_appendf(&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},%s", ARG(1), ARG(0), ARG(1), move_esil);
				break;
			}
		}
		// fallthrough
		default:
			rz_strbuf_appendf(&op->esil, ",$z,zf,:=,31,$s,nf,:=");
		}
	}

	rz_strbuf_append(&op->esil, postfix);

	return 0;
}
