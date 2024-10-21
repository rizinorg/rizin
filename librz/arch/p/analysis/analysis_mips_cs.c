// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/mips.h>

static ut64 t9_pre = UT64_MAX;
// http://www.mrc.uidaho.edu/mrc/people/jff/digital/MIPSir.html

#define OPERAND(x)  insn->detail->mips.operands[x]
#define REGID(x)    insn->detail->mips.operands[x].reg
#define REG(x)      cs_reg_name(*handle, insn->detail->mips.operands[x].reg)
#define IMM(x)      insn->detail->mips.operands[x].imm
#define MEMBASE(x)  cs_reg_name(*handle, insn->detail->mips.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->mips.operands[x].mem.index
#define MEMDISP(x)  insn->detail->mips.operands[x].mem.disp
#define OPCOUNT()   insn->detail->mips.op_count
// TODO scale and disp

#define SET_VAL(op, i) \
	if ((i) < OPCOUNT() && OPERAND(i).type == MIPS_OP_IMM) { \
		(op)->val = OPERAND(i).imm; \
	}

#define CREATE_SRC_DST_3(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->src[1] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

#define CREATE_SRC_DST_2(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

#define SET_SRC_DST_3_REGS(op) \
	CREATE_SRC_DST_3(op); \
	(op)->dst->reg = rz_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->dst->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[0]->reg = rz_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR); \
	(op)->src[0]->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[1]->reg = rz_reg_get(analysis->reg, REG(2), RZ_REG_TYPE_GPR); \
	(op)->src[1]->type = RZ_ANALYSIS_VAL_REG;

#define SET_SRC_DST_3_IMM(op) \
	CREATE_SRC_DST_3(op); \
	(op)->dst->reg = rz_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->dst->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[0]->reg = rz_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR); \
	(op)->src[0]->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[1]->imm = IMM(2); \
	(op)->src[1]->type = RZ_ANALYSIS_VAL_IMM;

#define SET_SRC_DST_2_REGS(op) \
	CREATE_SRC_DST_2(op); \
	(op)->dst->reg = rz_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->src[0]->reg = rz_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR);

#define SET_SRC_DST_3_REG_OR_IMM(op) \
	if (OPERAND(2).type == MIPS_OP_IMM) { \
		SET_SRC_DST_3_IMM(op); \
	} else if (OPERAND(2).type == MIPS_OP_REG) { \
		SET_SRC_DST_3_REGS(op); \
	}

// ESIL macros:

// put the sign bit on the stack
#define ES_IS_NEGATIVE(arg) "1," arg ",<<<,1,&"

// call with delay slot
#define ES_CALL_DR(ra, addr) "pc,4,+," ra ",=," ES_J(addr)
#define ES_CALL_D(addr)      ES_CALL_DR("ra", addr)

// call without delay slot
#define ES_CALL_NDR(ra, addr) "pc," ra ",=," ES_J(addr)
#define ES_CALL_ND(addr)      ES_CALL_NDR("ra", addr)

#define USE_DS 0
#if USE_DS
// emit ERR trap if executed in a delay slot
#define ES_TRAP_DS() "$ds,!,!,?{,$$,1,TRAP,BREAK,},"
// jump to address
#define ES_J(addr) addr ",SETJT,1,SETD"
#else
#define ES_TRAP_DS() ""
#define ES_J(addr)   addr ",pc,="
#endif

#define ES_B(x) "0xff," x ",&"
#define ES_H(x) "0xffff," x ",&"
#define ES_W(x) "0xffffffff," x ",&"

// sign extend 32 -> 64
#define ES_SIGN32_64(arg) es_sign_n_64(a, op, arg, 32)
#define ES_SIGN16_64(arg) es_sign_n_64(a, op, arg, 16)

#define ES_ADD_CK32_OVERF(x, y, z) es_add_ck(op, x, y, z, 32)
#define ES_ADD_CK64_OVERF(x, y, z) es_add_ck(op, x, y, z, 64)

static inline void es_sign_n_64(RzAnalysis *a, RzAnalysisOp *op, const char *arg, int bit) {
	if (a->bits == 64) {
		rz_strbuf_appendf(&op->esil, ",%d,%s,~,%s,=,", bit, arg, arg);
	} else {
		rz_strbuf_append(&op->esil, ",");
	}
}

static inline void es_add_ck(RzAnalysisOp *op, const char *a1, const char *a2, const char *re, int bit) {
	ut64 mask = 1ULL << (bit - 1);
	rz_strbuf_appendf(&op->esil,
		"%d,0x%" PFMT64x ",%s,%s,^,&,>>,%d,0x%" PFMT64x ",%s,%s,+,&,>>,|,1,==,$z,?{,$$,1,TRAP,}{,%s,%s,+,%s,=,}",
		bit - 2, mask, a1, a2, bit - 1, mask, a1, a2, a1, a2, re);
}

#define PROTECT_ZERO() \
	if (REG(0)[0] == 'z') { \
		rz_strbuf_appendf(&op->esil, ","); \
	} else

#define ESIL_LOAD(size) \
	PROTECT_ZERO() { \
		rz_strbuf_appendf(&op->esil, "%s,[" size "],%s,=", \
			ARG(1), REG(0)); \
	}

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_mips *x = &insn->detail->mips;
	for (i = 0; i < x->op_count; i++) {
		cs_mips_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case MIPS_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case MIPS_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", op->imm);
			break;
		case MIPS_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != MIPS_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_kN(pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		pj_end(pj); /* o operand */
	}
	pj_end(pj); /* a operands */
	pj_end(pj);

	rz_strbuf_init(buf);
	rz_strbuf_append(buf, pj_string(pj));
	pj_free(pj);
}

static const char *arg(csh *handle, cs_insn *insn, char *buf, int n) {
	*buf = 0;
	switch (insn->detail->mips.operands[n].type) {
	case MIPS_OP_INVALID:
		break;
	case MIPS_OP_REG:
		sprintf(buf, "%s",
			cs_reg_name(*handle,
				insn->detail->mips.operands[n].reg));
		break;
	case MIPS_OP_IMM: {
		st64 x = (st64)insn->detail->mips.operands[n].imm;
		sprintf(buf, "%" PFMT64d, x);
	} break;
	case MIPS_OP_MEM: {
		int disp = insn->detail->mips.operands[n].mem.disp;
		if (disp < 0) {
			sprintf(buf, "%" PFMT64d ",%s,-",
				(ut64)-insn->detail->mips.operands[n].mem.disp,
				cs_reg_name(*handle,
					insn->detail->mips.operands[n].mem.base));
		} else {
			sprintf(buf, "0x%" PFMT64x ",%s,+",
				(ut64)insn->detail->mips.operands[n].mem.disp,
				cs_reg_name(*handle,
					insn->detail->mips.operands[n].mem.base));
		}
	} break;
	}
	return buf;
}

#define ARG(x) (*str[x] != 0) ? str[x] : arg(handle, insn, str[x], x)

static int analyze_op_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	char str[8][32] = { { 0 } };
	int i;

	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");

	if (insn) {
		// caching operands
		for (i = 0; i < insn->detail->mips.op_count && i < 8; i++) {
			*str[i] = 0;
			ARG(i);
		}
	}

	if (insn) {
		switch (insn->id) {
		case MIPS_INS_NOP:
			rz_strbuf_setf(&op->esil, ",");
			break;
		case MIPS_INS_BREAK:
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%" PFMT64d ",TRAP", (st64)IMM(0), (st64)IMM(0));
			break;
		case MIPS_INS_SD:
			rz_strbuf_appendf(&op->esil, "%s,%s,=[8]",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_SW:
		case MIPS_INS_SWL:
		case MIPS_INS_SWR:
			rz_strbuf_appendf(&op->esil, "%s,%s,=[4]",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_SH:
			rz_strbuf_appendf(&op->esil, "%s,%s,=[2]",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_SWC1:
		case MIPS_INS_SWC2:
			rz_strbuf_setf(&op->esil, "%s,$", ARG(1));
			break;
		case MIPS_INS_SB:
			rz_strbuf_appendf(&op->esil, "%s,%s,=[1]",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_CMP:
#if CS_NEXT_VERSION < 6
		case MIPS_INS_CMPU:
		case MIPS_INS_CMPGU:
		case MIPS_INS_CMPGDU:
#endif
		case MIPS_INS_CMPI:
			rz_strbuf_appendf(&op->esil, "%s,%s,==", ARG(1), ARG(0));
			break;
		case MIPS_INS_DSRA:
			rz_strbuf_appendf(&op->esil,
				"%s,%s,>>,31,%s,>>,?{,32,%s,32,-,0xffffffff,<<,0xffffffff,&,<<,}{,0,},|,%s,=",
				ARG(2), ARG(1), ARG(1), ARG(2), ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case MIPS_INS_SHRAV:
		case MIPS_INS_SHRAV_R:
		case MIPS_INS_SHRA:
		case MIPS_INS_SHRA_R:
		case MIPS_INS_SRA:
			rz_strbuf_appendf(&op->esil,
				"0xffffffff,%s,%s,>>,&,31,%s,>>,?{,%s,32,-,0xffffffff,<<,0xffffffff,&,}{,0,},|,%s,=",
				ARG(2), ARG(1), ARG(1), ARG(2), ARG(0));
			break;
		case MIPS_INS_SHRL:
			// suffix 'S' forces conditional flag to be updated
		case MIPS_INS_SRLV:
		case MIPS_INS_SRL:
			rz_strbuf_appendf(&op->esil, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
			break;
#endif
		case MIPS_INS_SLLV:
		case MIPS_INS_SLL:
			rz_strbuf_appendf(&op->esil, "%s,%s,<<,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case MIPS_INS_BAL:
		case MIPS_INS_JAL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "" ES_CALL_D("%s"), ARG(0));
			break;
		case MIPS_INS_JALR:
		case MIPS_INS_JALRS:
			if (OPCOUNT() < 2) {
				rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "" ES_CALL_D("%s"), ARG(0));
			} else {
				PROTECT_ZERO() {
					rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "" ES_CALL_DR("%s", "%s"), ARG(0), ARG(1));
				}
			}
			break;
		case MIPS_INS_JALRC: // no delay
			if (OPCOUNT() < 2) {
				rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "" ES_CALL_ND("%s"), ARG(0));
			} else {
				PROTECT_ZERO() {
					rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "" ES_CALL_NDR("%s", "%s"), ARG(0), ARG(1));
				}
			}
			break;
		case MIPS_INS_JRADDIUSP:
			// increment stackpointer in X and jump to %ra
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "%s,sp,+=," ES_J("ra"), ARG(0));
			break;
		case MIPS_INS_JR:
		case MIPS_INS_JRC:
		case MIPS_INS_J:
		case MIPS_INS_B: // ???
			// jump to address with conditional
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "" ES_J("%s"), ARG(0));
			break;
		case MIPS_INS_BNE: // bne $s, $t, offset
		case MIPS_INS_BNEL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "%s,%s,==,$z,!,?{," ES_J("%s") ",}",
				ARG(0), ARG(1), ARG(2));
			break;
		case MIPS_INS_BEQ:
		case MIPS_INS_BEQL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "%s,%s,==,$z,?{," ES_J("%s") ",}",
				ARG(0), ARG(1), ARG(2));
			break;
#if CS_NEXT_VERSION < 6
		case MIPS_INS_BZ:
#endif
		case MIPS_INS_BEQZ:
		case MIPS_INS_BEQZC:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "%s,0,==,$z,?{," ES_J("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BNEZ:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "%s,0,==,$z,!,?{," ES_J("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BEQZALC:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "%s,0,==,$z,?{," ES_CALL_ND("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BLEZ:
		case MIPS_INS_BLEZC:
		case MIPS_INS_BLEZL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0,%s,==,$z,?{," ES_J("%s") ",BREAK,},",
				ARG(0), ARG(1));
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "1," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_J("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BGEZ:
		case MIPS_INS_BGEZC:
		case MIPS_INS_BGEZL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_J("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BGEZAL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_CALL_D("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BGEZALC:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_CALL_ND("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BGTZALC:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0,%s,==,$z,?{,BREAK,},", ARG(0));
			rz_strbuf_appendf(&op->esil, "0," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_CALL_ND("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BLTZAL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "1," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_CALL_D("%s") ",}", ARG(0), ARG(1));
			break;
		case MIPS_INS_BLTZ:
		case MIPS_INS_BLTZC:
		case MIPS_INS_BLTZL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "1," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_J("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BGTZ:
		case MIPS_INS_BGTZC:
		case MIPS_INS_BGTZL:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0,%s,==,$z,?{,BREAK,},", ARG(0));
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0," ES_IS_NEGATIVE("%s") ",==,$z,?{," ES_J("%s") ",}",
				ARG(0), ARG(1));
			break;
		case MIPS_INS_BTEQZ:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0,t,==,$z,?{," ES_J("%s") ",}", ARG(0));
			break;
		case MIPS_INS_BTNEZ:
			rz_strbuf_appendf(&op->esil, ES_TRAP_DS() "0,t,==,$z,!,?{," ES_J("%s") ",}", ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case MIPS_INS_MOV:
#endif
		case MIPS_INS_MOVE:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "%s,%s,=", ARG(1), REG(0));
			}
			break;
		case MIPS_INS_MOVZ:
		case MIPS_INS_MOVF:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "0,%s,==,$z,?{,%s,%s,=,}",
					ARG(2), ARG(1), REG(0));
			}
			break;
		case MIPS_INS_MOVT:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "1,%s,==,$z,?{,%s,%s,=,}",
					ARG(2), ARG(1), REG(0));
			}
			break;
#if CS_NEXT_VERSION < 6
		case MIPS_INS_FSUB:
#endif
		case MIPS_INS_SUB:
		case MIPS_INS_SUBU:
		case MIPS_INS_DSUB:
		case MIPS_INS_DSUBU:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "%s,%s,-,%s,=",
					ARG(2), ARG(1), ARG(0));
			}
			break;
		case MIPS_INS_NEG:
#if CS_NEXT_VERSION < 6
		case MIPS_INS_NEGU:
#endif
			rz_strbuf_appendf(&op->esil, "%s,0,-,%s,=,",
				ARG(1), ARG(0));
			break;

		/** signed -- sets overflow flag */
		case MIPS_INS_ADD: {
			PROTECT_ZERO() {
				ES_ADD_CK32_OVERF(ARG(1), ARG(2), ARG(0));
			}
		} break;
		case MIPS_INS_ADDI:
			PROTECT_ZERO() {
				ES_ADD_CK32_OVERF(ARG(1), ARG(2), ARG(0));
			}
			break;
		case MIPS_INS_DADD:
		case MIPS_INS_DADDI:
			ES_ADD_CK64_OVERF(ARG(1), ARG(2), ARG(0));
			break;
		/** unsigned */
		case MIPS_INS_DADDU:
		case MIPS_INS_ADDU:
		case MIPS_INS_ADDIU:
		case MIPS_INS_DADDIU: {
			const char *arg0 = ARG(0);
			const char *arg1 = ARG(1);
			const char *arg2 = ARG(2);
			PROTECT_ZERO() {
				if (*arg2 == '-') {
					rz_strbuf_appendf(&op->esil, "%s,%s,-,%s,=",
						arg2 + 1, arg1, arg0);
				} else {
					rz_strbuf_appendf(&op->esil, "%s,%s,+,%s,=",
						arg2, arg1, arg0);
				}
			}
		} break;
		case MIPS_INS_LI:
#if CS_NEXT_VERSION < 6
		case MIPS_INS_LDI:
#endif
			rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",%s,=", (ut64)IMM(1), ARG(0));
			break;
		case MIPS_INS_LUI:
			rz_strbuf_appendf(&op->esil, "0x%" PFMT64x "0000,%s,=", (ut64)IMM(1), ARG(0));
			break;
		case MIPS_INS_LB:
			op->sign = true;
			ESIL_LOAD("1");
			break;
		case MIPS_INS_LBU:
			// one of these is wrong
			ESIL_LOAD("1");
			break;
		case MIPS_INS_LW:
		case MIPS_INS_LWC1:
		case MIPS_INS_LWC2:
		case MIPS_INS_LWL:
		case MIPS_INS_LWR:
		case MIPS_INS_LWU:
		case MIPS_INS_LL:
			ESIL_LOAD("4");
			break;

		case MIPS_INS_LDL:
		case MIPS_INS_LDC1:
		case MIPS_INS_LDC2:
		case MIPS_INS_LLD:
		case MIPS_INS_LD:
			ESIL_LOAD("8");
			break;

		case MIPS_INS_LWX:
		case MIPS_INS_LH:
		case MIPS_INS_LHU:
		case MIPS_INS_LHX:
			ESIL_LOAD("2");
			break;

		case MIPS_INS_AND:
		case MIPS_INS_ANDI: {
			const char *arg0 = ARG(0);
			const char *arg1 = ARG(1);
			const char *arg2 = ARG(2);
			if (!strcmp(arg0, arg1)) {
				rz_strbuf_appendf(&op->esil, "%s,%s,&=", arg2, arg1);
			} else {
				rz_strbuf_appendf(&op->esil, "%s,%s,&,%s,=", arg2, arg1, arg0);
			}
		} break;
		case MIPS_INS_OR:
		case MIPS_INS_ORI: {
			const char *arg0 = ARG(0);
			const char *arg1 = ARG(1);
			const char *arg2 = ARG(2);
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "%s,%s,|,%s,=",
					arg2, arg1, arg0);
			}
		} break;
		case MIPS_INS_XOR:
		case MIPS_INS_XORI: {
			const char *arg0 = ARG(0);
			const char *arg1 = ARG(1);
			const char *arg2 = ARG(2);
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "%s,%s,^,%s,=",
					arg2, arg1, arg0);
			}
		} break;
		case MIPS_INS_NOR: {
			const char *arg0 = ARG(0);
			const char *arg1 = ARG(1);
			const char *arg2 = ARG(2);
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "%s,%s,|,0xffffffff,^,%s,=",
					arg2, arg1, arg0);
			}
		} break;
		case MIPS_INS_SLT:
		case MIPS_INS_SLTI:
			if (OPCOUNT() < 3) {
				rz_strbuf_appendf(&op->esil, "%s,%s,<,t,=", ARG(1), ARG(0));
			} else {
				rz_strbuf_appendf(&op->esil, "%s,%s,<,%s,=", ARG(2), ARG(1), ARG(0));
			}
			break;
		case MIPS_INS_SLTU:
		case MIPS_INS_SLTIU:
			if (OPCOUNT() < 3) {
				rz_strbuf_appendf(&op->esil, ES_W("%s") "," ES_W("%s") ",<,t,=",
					ARG(1), ARG(0));
			} else {
				rz_strbuf_appendf(&op->esil, ES_W("%s") "," ES_W("%s") ",<,%s,=",
					ARG(2), ARG(1), ARG(0));
			}
			break;
		case MIPS_INS_MUL:
			rz_strbuf_appendf(&op->esil, ES_W("%s,%s,*") ",%s,=", ARG(1), ARG(2), ARG(0));
			ES_SIGN32_64(ARG(0));
			break;
		case MIPS_INS_MULT:
		case MIPS_INS_MULTU:
			rz_strbuf_appendf(&op->esil, ES_W("%s,%s,*") ",lo,=", ARG(0), ARG(1));
			ES_SIGN32_64("lo");
			rz_strbuf_appendf(&op->esil, ES_W("32,%s,%s,*,>>") ",hi,=", ARG(0), ARG(1));
			ES_SIGN32_64("hi");
			break;
		case MIPS_INS_MFLO:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "lo,%s,=", REG(0));
			}
			break;
		case MIPS_INS_MFHI:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "hi,%s,=", REG(0));
			}
			break;
		case MIPS_INS_MTLO:
			rz_strbuf_appendf(&op->esil, "%s,lo,=", REG(0));
			ES_SIGN32_64("lo");
			break;
		case MIPS_INS_MTHI:
			rz_strbuf_appendf(&op->esil, "%s,hi,=", REG(0));
			ES_SIGN32_64("hi");
			break;
#if 0
	// could not test div
	case MIPS_INS_DIV:
	case MIPS_INS_DIVU:
	case MIPS_INS_DDIV:
	case MIPS_INS_DDIVU:
		PROTECT_ZERO () {
			// 32 bit needs sign extend
			rz_strbuf_appendf (&op->esil, "%s,%s,/,lo,=,%s,%s,%%,hi,=", REG(1), REG(0), REG(1), REG(0));
		}
		break;
#endif
		default:
			return -1;
		}
	}
	return 0;
}

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (OPERAND(reg_num).type) {
	case MIPS_OP_REG:
		reg->name = (char *)cs_reg_name(handle, OPERAND(reg_num).reg);
		break;
	case MIPS_OP_MEM:
		if (OPERAND(reg_num).mem.base != MIPS_REG_INVALID) {
			reg->name = (char *)cs_reg_name(handle, OPERAND(reg_num).mem.base);
		}
	default:
		break;
	}
	return 0;
}

typedef struct {
	RzRegItem reg;
} MIPSContext;

static bool mips_init(void **user) {
	MIPSContext *ctx = RZ_NEW0(MIPSContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static void op_fillval(RzAnalysis *analysis, RzAnalysisOp *op, csh *handle, cs_insn *insn) {
	MIPSContext *ctx = (MIPSContext *)analysis->plugin_data;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (OPERAND(1).type == MIPS_OP_MEM) {
			ZERO_FILL(ctx->reg);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->type = RZ_ANALYSIS_VAL_MEM;
			op->src[0]->reg = &ctx->reg;
			parse_reg_name(op->src[0]->reg, *handle, insn, 1);
			op->src[0]->delta = OPERAND(1).mem.disp;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (OPERAND(1).type == MIPS_OP_MEM) {
			ZERO_FILL(ctx->reg);
			op->dst = rz_analysis_value_new();
			op->dst->type = RZ_ANALYSIS_VAL_MEM;
			op->dst->reg = &ctx->reg;
			parse_reg_name(op->dst->reg, *handle, insn, 1);
			op->dst->delta = OPERAND(1).mem.disp;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_OR:
		SET_SRC_DST_3_REG_OR_IMM(op);
		break;
	case RZ_ANALYSIS_OP_TYPE_MOV:
		if (OPCOUNT() == 2 && OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG) {
			SET_SRC_DST_2_REGS(op);
		} else {
			SET_SRC_DST_3_REG_OR_IMM(op);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_DIV: // UDIV
#if 0
capstone bug
------------
	$ r2 -a mips -e cfg.bigendian=1 -c "wx 0083001b" -
	// should be 3 regs, right?
	[0x00000000]> aoj~{}
	[
	  {
	    "opcode": "divu zero, a0, v1",
	    "disasm": "divu zero, a0, v1",
	    "mnemonic": "divu",
	    "sign": false,
	    "prefix": 0,
	    "id": 192,
	    "opex": {
	      "operands": [
		{
		  "type": "reg",
		  "value": "a0"
		},
		{
		  "type": "reg",
		  "value": "v1"
		}
	      ]
	    },
#endif
		if (OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG && OPERAND(2).type == MIPS_OP_REG) {
			SET_SRC_DST_3_REGS(op);
		} else if (OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG) {
			SET_SRC_DST_2_REGS(op);
		} else {
			RZ_LOG_ERROR("mips: unknown div opcode at 0x%08" PFMT64x "\n", op->addr);
		}
		break;
	}
	if (insn && (insn->id == MIPS_INS_SLTI || insn->id == MIPS_INS_SLTIU)) {
		SET_SRC_DST_3_IMM(op);
	}
}

static void set_opdir(RzAnalysisOp *op) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case RZ_ANALYSIS_OP_TYPE_LEA:
		op->direction = RZ_ANALYSIS_OP_DIR_REF;
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static int analyze_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int n = 0, opsize = -1;
	csh hndl = 0;
	cs_insn *insn = NULL;
	int mode = analysis->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

	if (analysis->cpu && *analysis->cpu) {
		if (!strcmp(analysis->cpu, "micro")) {
			mode |= CS_MODE_MICRO;
		} else if (!strcmp(analysis->cpu, "r6")) {
			mode |= CS_MODE_MIPS32R6;
		} else if (!strcmp(analysis->cpu, "v3")) {
			mode |= CS_MODE_MIPS3;
		} else if (!strcmp(analysis->cpu, "v2")) {
			mode |= CS_MODE_MIPS2;
		}
	}
	switch (analysis->bits) {
	case 64:
		mode |= CS_MODE_MIPS64;
		break;
	case 32:
		mode |= CS_MODE_MIPS32;
		break;
	default:
		return -1;
	}

	// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	op->addr = addr;
	if (len < 4) {
		return -1;
	}
	op->size = 4;

	if (cs_open(CS_ARCH_MIPS, mode, &hndl) != CS_ERR_OK) {
		return -1;
	}
	cs_option(hndl, CS_OPT_DETAIL, CS_OPT_ON);

	n = cs_disasm(hndl, (ut8 *)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		goto beach;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s",
			insn->mnemonic,
			insn->op_str[0] ? " " : "",
			insn->op_str);
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	op->refptr = 0;
	switch (insn->id) {
	case MIPS_INS_INVALID:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case MIPS_INS_LB:
	case MIPS_INS_LBU:
	case MIPS_INS_LBUX:
		op->refptr = 1;
		/* fallthrough */
	case MIPS_INS_LW:
	case MIPS_INS_LWC1:
	case MIPS_INS_LWC2:
	case MIPS_INS_LWL:
	case MIPS_INS_LWR:
	case MIPS_INS_LWXC1:
		if (!op->refptr) {
			op->refptr = 4;
		}
		/* fallthrough */
	case MIPS_INS_LD:
	case MIPS_INS_LDC1:
	case MIPS_INS_LDC2:
	case MIPS_INS_LDL:
	case MIPS_INS_LDR:
	case MIPS_INS_LDXC1:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		if (!op->refptr) {
			op->refptr = 8;
		}
		switch (OPERAND(1).type) {
		case MIPS_OP_MEM:
			if (OPERAND(1).mem.base == MIPS_REG_GP) {
				op->ptr = analysis->gp + OPERAND(1).mem.disp;
				if (REGID(0) == MIPS_REG_T9) {
					t9_pre = op->ptr;
				}
			} else if (REGID(0) == MIPS_REG_T9) {
				t9_pre = UT64_MAX;
			}
			break;
		case MIPS_OP_IMM:
			op->ptr = OPERAND(1).imm;
			break;
		case MIPS_OP_REG:
			break;
		default:
			break;
		}
		// TODO: fill
		break;
	case MIPS_INS_SD:
	case MIPS_INS_SW:
	case MIPS_INS_SB:
	case MIPS_INS_SH:
	case MIPS_INS_SWC1:
	case MIPS_INS_SWC2:
	case MIPS_INS_SWL:
	case MIPS_INS_SWR:
	case MIPS_INS_SWXC1:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case MIPS_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case MIPS_INS_SYSCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case MIPS_INS_BREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case MIPS_INS_JALR:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->delay = 1;
#if CS_NEXT_VERSION < 6
		if (REGID(0) == MIPS_REG_25) {
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		}
#else
		if (REGID(0) == MIPS_REG_T9 ||
			REGID(0) == MIPS_REG_T9_64) {
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		}
#endif
		break;
	case MIPS_INS_JAL:
	case MIPS_INS_JALS:
	case MIPS_INS_JALX:
	case MIPS_INS_JRADDIUSP:
	case MIPS_INS_BAL:
	// (no blezal/bgtzal or blezall/bgtzall, only blezalc/bgtzalc)
	case MIPS_INS_BLTZAL: // Branch on <0 and link
	case MIPS_INS_BGEZAL: // Branch on >=0 and link
	case MIPS_INS_BLTZALL: // "likely" versions
	case MIPS_INS_BGEZALL:
	case MIPS_INS_BLTZALC: // compact versions
	case MIPS_INS_BLEZALC:
	case MIPS_INS_BGEZALC:
	case MIPS_INS_BGTZALC:
	case MIPS_INS_JIALC:
	case MIPS_INS_JIC:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = IMM(0);

		switch (insn->id) {
		case MIPS_INS_JIALC:
		case MIPS_INS_JIC:
		case MIPS_INS_BLTZALC:
		case MIPS_INS_BLEZALC:
		case MIPS_INS_BGEZALC:
		case MIPS_INS_BGTZALC:
			// compact versions (no delay)
			op->delay = 0;
			op->fail = addr + 4;
			break;
		default:
			op->delay = 1;
			op->fail = addr + 8;
			break;
		}
		break;
	case MIPS_INS_LI:
	case MIPS_INS_LUI:
		SET_VAL(op, 1);
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case MIPS_INS_MOVE:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case MIPS_INS_ADD:
	case MIPS_INS_ADDI:
	case MIPS_INS_ADDU:
	case MIPS_INS_ADDIU:
	case MIPS_INS_DADD:
	case MIPS_INS_DADDI:
	case MIPS_INS_DADDIU:
		SET_VAL(op, 2);
		op->sign = (insn->id == MIPS_INS_ADDI || insn->id == MIPS_INS_ADD);
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (REGID(0) == MIPS_REG_T9) {
			t9_pre += IMM(2);
		}
		if (REGID(0) == MIPS_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -IMM(2);
		}
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_SUBV:
	case MIPS_INS_SUBVI:
	case MIPS_INS_FSUB:
	case MIPS_INS_FMSUB:
	case MIPS_INS_SUBS_S:
	case MIPS_INS_SUBS_U:
	case MIPS_INS_SUBUH:
	case MIPS_INS_SUBUH_R:
#endif
	case MIPS_INS_SUB:
	case MIPS_INS_DSUBU:
	case MIPS_INS_SUBU:
	case MIPS_INS_DSUB:
		SET_VAL(op, 2);
		op->sign = insn->id == MIPS_INS_SUB;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_MULV:
	case MIPS_INS_MULSA:
	case MIPS_INS_FMUL:
#endif
	case MIPS_INS_MULT:
	case MIPS_INS_MUL:
	case MIPS_INS_DMULT:
	case MIPS_INS_DMULTU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MIPS_INS_XOR:
	case MIPS_INS_XORI:
		SET_VAL(op, 2);
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case MIPS_INS_AND:
	case MIPS_INS_ANDI:
		SET_VAL(op, 2);
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		if (REGID(0) == MIPS_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_ALIGN;
		}
		break;
	case MIPS_INS_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case MIPS_INS_OR:
	case MIPS_INS_ORI:
		SET_VAL(op, 2);
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MIPS_INS_DIV:
	case MIPS_INS_DIVU:
	case MIPS_INS_DDIV:
	case MIPS_INS_DDIVU:
	case MIPS_INS_DIV_S:
#if CS_NEXT_VERSION < 6
	case MIPS_INS_FDIV:
	case MIPS_INS_DIV_U:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_CMPGDU:
	case MIPS_INS_CMPGU:
	case MIPS_INS_CMPU:
#endif
	case MIPS_INS_CMPI:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_BZ:
	case MIPS_INS_BNZ:
	case MIPS_INS_BNEG:
	case MIPS_INS_BNEGI:
#endif
	case MIPS_INS_J:
	case MIPS_INS_B:
	case MIPS_INS_BEQ:
	case MIPS_INS_BNE:
	case MIPS_INS_BNEL:
	case MIPS_INS_BEQL:
	case MIPS_INS_BEQZ:
	case MIPS_INS_BNEZ:
	case MIPS_INS_BTEQZ:
	case MIPS_INS_BTNEZ:
	case MIPS_INS_BLTZ:
	case MIPS_INS_BLTZL:
	case MIPS_INS_BLEZ:
	case MIPS_INS_BLEZL:
	case MIPS_INS_BGEZ:
	case MIPS_INS_BGEZL:
	case MIPS_INS_BGTZ:
	case MIPS_INS_BGTZL:
	case MIPS_INS_BLEZC:
	case MIPS_INS_BGEZC:
	case MIPS_INS_BLTZC:
	case MIPS_INS_BGTZC:
		if (insn->id == MIPS_INS_J || insn->id == MIPS_INS_B) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		}

		if (OPERAND(0).type == MIPS_OP_IMM) {
			op->jump = IMM(0);
		} else if (OPERAND(1).type == MIPS_OP_IMM) {
			op->jump = IMM(1);
		} else if (OPERAND(2).type == MIPS_OP_IMM) {
			op->jump = IMM(2);
		}

		switch (insn->id) {
		case MIPS_INS_BLEZC:
		case MIPS_INS_BGEZC:
		case MIPS_INS_BLTZC:
		case MIPS_INS_BGTZC:
			// compact versions (no delay)
			op->delay = 0;
			op->fail = addr + 4;
			break;
		default:
			op->delay = 1;
			op->fail = addr + 8;
			break;
		}

		break;
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->delay = 1;
		// register is $ra, so jmp is a return
		if (insn->detail->mips.operands[0].reg == MIPS_REG_RA) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			t9_pre = UT64_MAX;
		}
#if CS_NEXT_VERSION < 6
		if (REGID(0) == MIPS_REG_25) {
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
		}
#else
		if (REGID(0) == MIPS_REG_T9 ||
			REGID(0) == MIPS_REG_T9_64) {
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		}
#endif

		break;
	case MIPS_INS_SLT:
	case MIPS_INS_SLTI:
		op->sign = true;
		SET_VAL(op, 2);
		break;
	case MIPS_INS_SLTIU:
		SET_VAL(op, 2);
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_SHRAV:
	case MIPS_INS_SHRAV_R:
	case MIPS_INS_SHRA:
	case MIPS_INS_SHRA_R:
	case MIPS_INS_SRA:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		SET_VAL(op, 2);
		break;
	case MIPS_INS_SHRL:
	case MIPS_INS_SRL:
#endif
	case MIPS_INS_SRLV:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		SET_VAL(op, 2);
		break;
	case MIPS_INS_SLLV:
	case MIPS_INS_SLL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		SET_VAL(op, 2);
		break;
	}
beach:
	set_opdir(op);
	if (insn && mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		opex(&op->opex, hndl, insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (analyze_op_esil(analysis, op, addr, buf, len, &hndl, insn) != 0) {
			rz_strbuf_fini(&op->esil);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(analysis, op, &hndl, insn);
	}

	cs_free(insn, n);
	cs_close(&hndl);
	return opsize;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	switch (analysis->bits) {
	default:
	case 32:
		p =
			"=PC    pc\n"
			"=SP    sp\n"
			"=BP    fp\n"
			"=SN    v0\n"
			"=A0    a0\n"
			"=A1    a1\n"
			"=A2    a2\n"
			"=A3    a3\n"
			"=R0    v0\n"
			"=R1    v1\n"
			"gpr	zero	.32	?	0\n"
			"gpr	at	.32	4	0\n"
			"gpr	v0	.32	8	0\n"
			"gpr	v1	.32	12	0\n"
			"gpr	a0	.32	16	0\n"
			"gpr	a1	.32	20	0\n"
			"gpr	a2	.32	24	0\n"
			"gpr	a3	.32	28	0\n"
			"gpr	t0	.32	32	0\n"
			"gpr	t1	.32	36	0\n"
			"gpr	t2 	.32	40	0\n"
			"gpr	t3 	.32	44	0\n"
			"gpr	t4 	.32	48	0\n"
			"gpr	t5 	.32	52	0\n"
			"gpr	t6 	.32	56	0\n"
			"gpr	t7 	.32	60	0\n"
			"gpr	s0	.32	64	0\n"
			"gpr	s1	.32	68	0\n"
			"gpr	s2	.32	72	0\n"
			"gpr	s3	.32	76	0\n"
			"gpr	s4 	.32	80	0\n"
			"gpr	s5 	.32	84	0\n"
			"gpr	s6 	.32	88	0\n"
			"gpr	s7 	.32	92	0\n"
			"gpr	t8 	.32	96	0\n"
			"gpr	t9 	.32	100	0\n"
			"gpr	k0 	.32	104	0\n"
			"gpr	k1 	.32	108	0\n"
			"gpr	gp 	.32	112	0\n"
			"gpr	sp	.32	116	0\n"
			"gpr	fp	.32	120	0\n"
			"gpr	ra	.32	124	0\n"
			"gpr	pc	.32	128	0\n"
			"gpr	hi	.32	132	0\n"
			"gpr	lo	.32	136	0\n"
			"gpr	t	.32	140	0\n";
		break;
	case 64:
		p =
			"=PC    pc\n"
			"=SP    sp\n"
			"=BP    fp\n"
			"=A0    a0\n"
			"=A1    a1\n"
			"=A2    a2\n"
			"=A3    a3\n"
			"=SN    v0\n"
			"=R0    v0\n"
			"=R1    v1\n"
			"gpr	zero	.64	?	0\n"
			"gpr	at	.64	8	0\n"
			"gpr	v0	.64	16	0\n"
			"gpr	v1	.64	24	0\n"
			"gpr	a0	.64	32	0\n"
			"gpr	a1	.64	40	0\n"
			"gpr	a2	.64	48	0\n"
			"gpr	a3	.64	56	0\n"
			"gpr	t0	.64	64	0\n"
			"gpr	t1	.64	72	0\n"
			"gpr	t2 	.64	80	0\n"
			"gpr	t3 	.64	88	0\n"
			"gpr	t4 	.64	96	0\n"
			"gpr	t5 	.64	104	0\n"
			"gpr	t6 	.64	112	0\n"
			"gpr	t7 	.64	120	0\n"
			"gpr	s0	.64	128	0\n"
			"gpr	s1	.64	136	0\n"
			"gpr	s2	.64	144	0\n"
			"gpr	s3	.64	152	0\n"
			"gpr	s4 	.64	160	0\n"
			"gpr	s5 	.64	168	0\n"
			"gpr	s6 	.64	176	0\n"
			"gpr	s7 	.64	184	0\n"
			"gpr	t8 	.64	192	0\n"
			"gpr	t9 	.64	200	0\n"
			"gpr	k0 	.64	208	0\n"
			"gpr	k1 	.64	216	0\n"
			"gpr	gp 	.64	224	0\n"
			"gpr	sp	.64	232	0\n"
			"gpr	fp	.64	240	0\n"
			"gpr	ra	.64	248	0\n"
			"gpr	pc	.64	256	0\n"
			"gpr	hi	.64	264	0\n"
			"gpr	lo	.64	272	0\n"
			"gpr	t	.64	280	0\n";
		break;
	}
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	KW("\x27\xbd\x00", 3, NULL, 0);
	return l;
}

static bool mips_fini(void *user) {
	MIPSContext *ctx = (MIPSContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_mips_cs = {
	.name = "mips",
	.desc = "Capstone MIPS analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "mips",
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.preludes = analysis_preludes,
	.bits = 16 | 32 | 64,
	.op = &analyze_op,
	.init = mips_init,
	.fini = mips_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_mips_cs,
	.version = RZ_VERSION
};
#endif
