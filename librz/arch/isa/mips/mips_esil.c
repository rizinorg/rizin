// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mips_internal.h"
#include <capstone/capstone.h>
#include <capstone/mips.h>

#define OPCOUNT() insn->detail->mips.op_count
#define REG(x)    cs_reg_name(*handle, insn->detail->mips.operands[x].reg)
#define IMM(x)    insn->detail->mips.operands[x].imm

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

RZ_IPI int analyze_op_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	char str[8][32] = { { 0 } };

	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");

	if (!insn) {
		return 0;
	}

	// caching operands
	for (int i = 0; i < insn->detail->mips.op_count && i < 8; i++) {
		*str[i] = 0;
		ARG(i);
	}
	{
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
#if CS_NEXT_VERSION >= 6
		case MIPS_INS_CMPU_LE_QB:
		case MIPS_INS_CMPGU_LE_QB:
		case MIPS_INS_CMPGDU_LE_QB:
			rz_strbuf_appendf(&op->esil, "%s,%s,<=", ARG(1), ARG(0));
			break;
		case MIPS_INS_CMPU_LT_QB:
		case MIPS_INS_CMPGU_LT_QB:
		case MIPS_INS_CMPGDU_LT_QB:
			rz_strbuf_appendf(&op->esil, "%s,%s,<", ARG(1), ARG(0));
			break;
#endif /* CS_NEXT_VERSION */
		case MIPS_INS_CMP:
#if CS_NEXT_VERSION < 6
		case MIPS_INS_CMPU:
		case MIPS_INS_CMPGU:
		case MIPS_INS_CMPGDU:
#else
		case MIPS_INS_CMPU_EQ_QB:
		case MIPS_INS_CMPGU_EQ_QB:
		case MIPS_INS_CMPGDU_EQ_QB:
#endif /* CS_NEXT_VERSION */
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
#else
		case MIPS_INS_SHRA_PH:
		case MIPS_INS_SHRA_QB:
		case MIPS_INS_SHRA_R_PH:
		case MIPS_INS_SHRA_R_QB:
		case MIPS_INS_SHRA_R_W:
		case MIPS_INS_SHRAV_PH:
		case MIPS_INS_SHRAV_QB:
		case MIPS_INS_SHRAV_R_PH:
		case MIPS_INS_SHRAV_R_QB:
		case MIPS_INS_SHRAV_R_W:
#endif /* CS_NEXT_VERSION */
		case MIPS_INS_SRA:
			rz_strbuf_appendf(&op->esil,
				"0xffffffff,%s,%s,>>,&,31,%s,>>,?{,%s,32,-,0xffffffff,<<,0xffffffff,&,}{,0,},|,%s,=",
				ARG(2), ARG(1), ARG(1), ARG(2), ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case MIPS_INS_SHRL:
#else
		case MIPS_INS_SHRL_PH:
		case MIPS_INS_SHRL_QB:
		case MIPS_INS_SHRLV_PH:
		case MIPS_INS_SHRLV_QB:
#endif /* CS_NEXT_VERSION */
			// suffix 'S' forces conditional flag to be updated
		case MIPS_INS_SRLV:
		case MIPS_INS_SRL:
			rz_strbuf_appendf(&op->esil, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
			break;
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
#else
		case MIPS_INS_BZ_B:
		case MIPS_INS_BZ_D:
		case MIPS_INS_BZ_H:
		case MIPS_INS_BZ_V:
		case MIPS_INS_BZ_W:
#endif /* CS_NEXT_VERSION */
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
#else
		case MIPS_INS_MOV_D:
		case MIPS_INS_MOV_S:
#endif /* CS_NEXT_VERSION */
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
#else
		case MIPS_INS_FSUB_D:
		case MIPS_INS_FSUB_W:
#endif /* CS_NEXT_VERSION */
		case MIPS_INS_SUB:
		case MIPS_INS_SUBU:
		case MIPS_INS_DSUB:
		case MIPS_INS_DSUBU:
			PROTECT_ZERO() {
				rz_strbuf_appendf(&op->esil, "%s,%s,-,%s,=",
					ARG(2), ARG(1), ARG(0));
			}
			break;
#if CS_NEXT_VERSION < 6
		case MIPS_INS_NEGU:
#else
		case MIPS_INS_NEG_D:
		case MIPS_INS_NEG_S:
#endif /* CS_NEXT_VERSION */
		case MIPS_INS_NEG:
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
#else
		case MIPS_INS_LDI_B:
		case MIPS_INS_LDI_D:
		case MIPS_INS_LDI_H:
		case MIPS_INS_LDI_W:
#endif /* CS_NEXT_VERSION */
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
		default:
			return -1;
		}
	}
	return 0;
}
