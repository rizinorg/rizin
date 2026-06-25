// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

#include <capstone/m680x.h>

static int m680xmode(const char *str) {
	if (!str) {
		return CS_MODE_M680X_6800;
	}
	// replace this with the asm.features?
	if (strstr(str, "6800") || strstr(str, "6802") || strstr(str, "6808")) {
		return CS_MODE_M680X_6800;
	} else if (strstr(str, "6801") || strstr(str, "6803")) {
		return CS_MODE_M680X_6801;
	} else if (strstr(str, "6805")) {
		return CS_MODE_M680X_6805;
	} else if (rz_str_casestr(str, "68hc08")) {
		return CS_MODE_M680X_6808;
	} else if (strstr(str, "6809")) {
		return CS_MODE_M680X_6809;
	} else if (strstr(str, "6811")) {
		return CS_MODE_M680X_6811;
	} else if (rz_str_casestr(str, "cpu12")) {
		return CS_MODE_M680X_CPU12;
	} else if (strstr(str, "6301")) {
		return CS_MODE_M680X_6301;
	} else if (strstr(str, "6309")) {
		return CS_MODE_M680X_6309;
	} else if (rz_str_casestr(str, "hcs08")) {
		return CS_MODE_M680X_HCS08;
	}
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	else if (rz_str_casestr(str, "rs08")) {
		return CS_MODE_M680X_RS08;
	} else if (rz_str_casestr(str, "hcs12x")) {
		return CS_MODE_M680X_HCS12X;
	}
#endif
	return CS_MODE_M680X_6800;
}

#define OP(x)   insn->detail->m680x.operands[x]
#define TYPE(x) OP(x).type
#define IMM(x)  OP(x).imm
#define REL(x)  OP(x).rel
#define EXT(x)  OP(x).ext
#define DIR(x)  OP(x).direct_addr

typedef struct {
	csh handle;
	int omode;
	int obits;
} M680XContext;

static bool m680x_analysis_init(void **user) {
	M680XContext *ctx = RZ_NEW0(M680XContext);
	rz_return_val_if_fail(ctx, false);
	ctx->handle = 0;
	ctx->omode = -1;
	ctx->obits = 32;
	*user = ctx;
	return true;
}

static void set_absolute_jump(RzAnalysisOp *op, const cs_m680x_op *operand) {
	if (operand->type == M680X_OP_EXTENDED && !operand->ext.indirect) {
		op->jump = operand->ext.address;
	} else if (operand->type == M680X_OP_DIRECT) {
		op->jump = operand->direct_addr;
	}
}

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	M680XContext *ctx = (M680XContext *)a->plugin_data;
	int n, ret, opsize = -1;
	cs_insn *insn;

	int mode = m680xmode(rz_analysis_get_cpu(a));

	if (mode != ctx->omode || a->bits != ctx->obits) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = mode;
		ctx->obits = a->bits;
	}
	op->size = 4;
	if (ctx->handle == 0) {
		ret = cs_open(CS_ARCH_M680X, mode, &ctx->handle);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm(ctx->handle, (ut8 *)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	if (!memcmp(buf, "\xff\xff", RZ_MIN(len, 2))) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	switch (insn->id) {
	case M680X_INS_INVLD:
	case M680X_INS_ILLGL:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case M680X_INS_BRA:
	case M680X_INS_LBRA:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = UT64_MAX;
		break;
	case M680X_INS_JMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		if (insn->detail->m680x.op_count > 0) {
			set_absolute_jump(op, &OP(0));
		}
		break;
	case M680X_INS_BCC:
	case M680X_INS_BCS:
	case M680X_INS_BEQ:
	case M680X_INS_BGE:
	case M680X_INS_BGT:
	case M680X_INS_BHCC:
	case M680X_INS_BHCS:
	case M680X_INS_BHI:
	case M680X_INS_BIH:
	case M680X_INS_BIL:
	case M680X_INS_BLE:
	case M680X_INS_BLS:
	case M680X_INS_BLT:
	case M680X_INS_BMC:
	case M680X_INS_BMI:
	case M680X_INS_BMS:
	case M680X_INS_BNE:
	case M680X_INS_BPL:
	case M680X_INS_BVC:
	case M680X_INS_BVS:
	case M680X_INS_LBCC:
	case M680X_INS_LBCS:
	case M680X_INS_LBEQ:
	case M680X_INS_LBGE:
	case M680X_INS_LBGT:
	case M680X_INS_LBHI:
	case M680X_INS_LBLE:
	case M680X_INS_LBLS:
	case M680X_INS_LBLT:
	case M680X_INS_LBMI:
	case M680X_INS_LBNE:
	case M680X_INS_LBPL:
	case M680X_INS_LBVC:
	case M680X_INS_LBVS:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = addr + op->size;
		break;
	case M680X_INS_BRCLR:
	case M680X_INS_BRSET:
	case M680X_INS_CBEQ:
	case M680X_INS_CBEQA:
	case M680X_INS_CBEQX:
	case M680X_INS_DBEQ:
	case M680X_INS_DBNE:
	case M680X_INS_DBNZ:
	case M680X_INS_DBNZA:
	case M680X_INS_DBNZX:
	case M680X_INS_IBEQ:
	case M680X_INS_IBNE:
	case M680X_INS_TBEQ:
	case M680X_INS_TBNE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		for (int i = 0; i < insn->detail->m680x.op_count; i++) {
			if (TYPE(i) == M680X_OP_RELATIVE) {
				op->jump = addr + op->size + REL(i).offset;
				break;
			}
		}
		op->fail = addr + op->size;
		break;
	case M680X_INS_BSR:
	case M680X_INS_LBSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = addr + op->size;
		break;
	case M680X_INS_CALL:
	case M680X_INS_JSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		if (insn->detail->m680x.op_count > 0) {
			set_absolute_jump(op, &OP(0));
		}
		break;
	case M680X_INS_RTC:
	case M680X_INS_RTI:
	case M680X_INS_RTS:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case M680X_INS_SWI:
	case M680X_INS_SWI2:
	case M680X_INS_SWI3:
	case M680X_INS_BGND:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_TRAP:
	case M680X_INS_SYS:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case M680X_INS_ADC:
	case M680X_INS_ADCA:
	case M680X_INS_ADCB:
	case M680X_INS_ADCD:
	case M680X_INS_ADCR:
	case M680X_INS_ADD:
	case M680X_INS_ADDA:
	case M680X_INS_ADDB:
	case M680X_INS_ADDD:
	case M680X_INS_ADDE:
	case M680X_INS_ADDF:
	case M680X_INS_ADDR:
	case M680X_INS_ADDW:
	case M680X_INS_ABA:
	case M680X_INS_ABX:
	case M680X_INS_ABY:
	case M680X_INS_AIS:
	case M680X_INS_AIX:
	case M680X_INS_INC:
	case M680X_INS_INCA:
	case M680X_INS_INCB:
	case M680X_INS_INCD:
	case M680X_INS_INCE:
	case M680X_INS_INCF:
	case M680X_INS_INCW:
	case M680X_INS_INCX:
	case M680X_INS_INS:
	case M680X_INS_INX:
	case M680X_INS_INY:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_ADDX:
	case M680X_INS_ADDY:
	case M680X_INS_ADED:
	case M680X_INS_ADEX:
	case M680X_INS_ADEY:
	case M680X_INS_INCY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case M680X_INS_SBA:
	case M680X_INS_SBC:
	case M680X_INS_SBCA:
	case M680X_INS_SBCB:
	case M680X_INS_SBCD:
	case M680X_INS_SBCR:
	case M680X_INS_SUB:
	case M680X_INS_SUBA:
	case M680X_INS_SUBB:
	case M680X_INS_SUBD:
	case M680X_INS_SUBE:
	case M680X_INS_SUBF:
	case M680X_INS_SUBR:
	case M680X_INS_SUBW:
	case M680X_INS_DEC:
	case M680X_INS_DECA:
	case M680X_INS_DECB:
	case M680X_INS_DECD:
	case M680X_INS_DECE:
	case M680X_INS_DECF:
	case M680X_INS_DECW:
	case M680X_INS_DECX:
	case M680X_INS_DES:
	case M680X_INS_DEX:
	case M680X_INS_DEY:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_SBED:
	case M680X_INS_SBEX:
	case M680X_INS_SBEY:
	case M680X_INS_SUBX:
	case M680X_INS_SUBY:
	case M680X_INS_DECY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case M680X_INS_EMACS:
	case M680X_INS_EMUL:
	case M680X_INS_EMULS:
	case M680X_INS_MUL:
	case M680X_INS_MULD:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case M680X_INS_DIV:
	case M680X_INS_DIVD:
	case M680X_INS_DIVQ:
	case M680X_INS_EDIV:
	case M680X_INS_EDIVS:
	case M680X_INS_FDIV:
	case M680X_INS_IDIV:
	case M680X_INS_IDIVS:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case M680X_INS_AND:
	case M680X_INS_ANDA:
	case M680X_INS_ANDB:
	case M680X_INS_ANDCC:
	case M680X_INS_ANDD:
	case M680X_INS_ANDR:
	case M680X_INS_AIM:
	case M680X_INS_BAND:
	case M680X_INS_BCLR:
	case M680X_INS_BIAND:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_ANDX:
	case M680X_INS_ANDY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case M680X_INS_BOR:
	case M680X_INS_BIOR:
	case M680X_INS_ORA:
	case M680X_INS_ORAA:
	case M680X_INS_ORAB:
	case M680X_INS_ORB:
	case M680X_INS_ORCC:
	case M680X_INS_ORD:
	case M680X_INS_ORR:
	case M680X_INS_OIM:
	case M680X_INS_BSET:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_ORX:
	case M680X_INS_ORY:
	case M680X_INS_BTAS:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case M680X_INS_BEOR:
	case M680X_INS_BIEOR:
	case M680X_INS_EIM:
	case M680X_INS_EOR:
	case M680X_INS_EORA:
	case M680X_INS_EORB:
	case M680X_INS_EORD:
	case M680X_INS_EORR:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_EORX:
	case M680X_INS_EORY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case M680X_INS_COM:
	case M680X_INS_COMA:
	case M680X_INS_COMB:
	case M680X_INS_COMD:
	case M680X_INS_COME:
	case M680X_INS_COMF:
	case M680X_INS_COMW:
	case M680X_INS_COMX:
	case M680X_INS_NEG:
	case M680X_INS_NEGA:
	case M680X_INS_NEGB:
	case M680X_INS_NEGD:
	case M680X_INS_NEGX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_COMY:
	case M680X_INS_NEGW:
	case M680X_INS_NEGY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case M680X_INS_ASL:
	case M680X_INS_ASLA:
	case M680X_INS_ASLB:
	case M680X_INS_ASLD:
	case M680X_INS_LSL:
	case M680X_INS_LSLA:
	case M680X_INS_LSLB:
	case M680X_INS_LSLD:
	case M680X_INS_LSLX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_ASLW:
	case M680X_INS_ASLX:
	case M680X_INS_ASLY:
	case M680X_INS_SLA:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case M680X_INS_ASR:
	case M680X_INS_ASRA:
	case M680X_INS_ASRB:
	case M680X_INS_ASRD:
	case M680X_INS_ASRX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_ASRW:
	case M680X_INS_ASRY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case M680X_INS_LSR:
	case M680X_INS_LSRA:
	case M680X_INS_LSRB:
	case M680X_INS_LSRD:
	case M680X_INS_LSRW:
	case M680X_INS_LSRX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_LSRY:
	case M680X_INS_SHA:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case M680X_INS_ROL:
	case M680X_INS_ROLA:
	case M680X_INS_ROLB:
	case M680X_INS_ROLD:
	case M680X_INS_ROLW:
	case M680X_INS_ROLX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_ROLY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case M680X_INS_ROR:
	case M680X_INS_RORA:
	case M680X_INS_RORB:
	case M680X_INS_RORD:
	case M680X_INS_RORW:
	case M680X_INS_RORX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_RORY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case M680X_INS_CBA:
	case M680X_INS_CMP:
	case M680X_INS_CMPA:
	case M680X_INS_CMPB:
	case M680X_INS_CMPD:
	case M680X_INS_CMPE:
	case M680X_INS_CMPF:
	case M680X_INS_CMPR:
	case M680X_INS_CMPS:
	case M680X_INS_CMPU:
	case M680X_INS_CMPW:
	case M680X_INS_CMPX:
	case M680X_INS_CMPY:
	case M680X_INS_CPD:
	case M680X_INS_CPHX:
	case M680X_INS_CPS:
	case M680X_INS_CPX:
	case M680X_INS_CPY:
	case M680X_INS_EMAXD:
	case M680X_INS_EMAXM:
	case M680X_INS_EMIND:
	case M680X_INS_EMINM:
	case M680X_INS_MAXA:
	case M680X_INS_MAXM:
	case M680X_INS_MINA:
	case M680X_INS_MINM:
	case M680X_INS_TST:
	case M680X_INS_TSTA:
	case M680X_INS_TSTB:
	case M680X_INS_TSTD:
	case M680X_INS_TSTE:
	case M680X_INS_TSTF:
	case M680X_INS_TSTW:
	case M680X_INS_TSTX:
	case M680X_INS_TEST:
	case M680X_INS_BIT:
	case M680X_INS_BITA:
	case M680X_INS_BITB:
	case M680X_INS_BITD:
	case M680X_INS_BITMD:
	case M680X_INS_TIM:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_CPED:
	case M680X_INS_CPES:
	case M680X_INS_CPEX:
	case M680X_INS_CPEY:
	case M680X_INS_TSTY:
	case M680X_INS_BITX:
	case M680X_INS_BITY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case M680X_INS_PSHA:
	case M680X_INS_PSHB:
	case M680X_INS_PSHC:
	case M680X_INS_PSHD:
	case M680X_INS_PSHH:
	case M680X_INS_PSHS:
	case M680X_INS_PSHSW:
	case M680X_INS_PSHU:
	case M680X_INS_PSHUW:
	case M680X_INS_PSHX:
	case M680X_INS_PSHY:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_PSHCW:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case M680X_INS_PULA:
	case M680X_INS_PULB:
	case M680X_INS_PULC:
	case M680X_INS_PULD:
	case M680X_INS_PULH:
	case M680X_INS_PULS:
	case M680X_INS_PULSW:
	case M680X_INS_PULU:
	case M680X_INS_PULUW:
	case M680X_INS_PULX:
	case M680X_INS_PULY:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_PULCW:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case M680X_INS_LDA:
	case M680X_INS_LDAA:
	case M680X_INS_LDAB:
	case M680X_INS_LDB:
	case M680X_INS_LDBT:
	case M680X_INS_LDD:
	case M680X_INS_LDE:
	case M680X_INS_LDF:
	case M680X_INS_LDHX:
	case M680X_INS_LDMD:
	case M680X_INS_LDQ:
	case M680X_INS_LDS:
	case M680X_INS_LDU:
	case M680X_INS_LDW:
	case M680X_INS_LDX:
	case M680X_INS_LDY:
	case M680X_INS_LEAS:
	case M680X_INS_LEAU:
	case M680X_INS_LEAX:
	case M680X_INS_LEAY:
	case M680X_INS_ETBL:
	case M680X_INS_TBL:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_GLDAA:
	case M680X_INS_GLDAB:
	case M680X_INS_GLDD:
	case M680X_INS_GLDS:
	case M680X_INS_GLDX:
	case M680X_INS_GLDY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case M680X_INS_STA:
	case M680X_INS_STAA:
	case M680X_INS_STAB:
	case M680X_INS_STB:
	case M680X_INS_STBT:
	case M680X_INS_STD:
	case M680X_INS_STE:
	case M680X_INS_STF:
	case M680X_INS_STHX:
	case M680X_INS_STQ:
	case M680X_INS_STS:
	case M680X_INS_STU:
	case M680X_INS_STW:
	case M680X_INS_STX:
	case M680X_INS_STY:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_GSTAA:
	case M680X_INS_GSTAB:
	case M680X_INS_GSTD:
	case M680X_INS_GSTS:
	case M680X_INS_GSTX:
	case M680X_INS_GSTY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case M680X_INS_MOV:
	case M680X_INS_MOVB:
	case M680X_INS_MOVW:
	case M680X_INS_TFR:
	case M680X_INS_TAB:
	case M680X_INS_TAP:
	case M680X_INS_TAX:
	case M680X_INS_TBA:
	case M680X_INS_TPA:
	case M680X_INS_TSX:
	case M680X_INS_TSY:
	case M680X_INS_TXA:
	case M680X_INS_TXS:
	case M680X_INS_TYS:
	case M680X_INS_RSP:
	case M680X_INS_TFM:
	case M680X_INS_CLR:
	case M680X_INS_CLRA:
	case M680X_INS_CLRB:
	case M680X_INS_CLRD:
	case M680X_INS_CLRE:
	case M680X_INS_CLRF:
	case M680X_INS_CLRH:
	case M680X_INS_CLRW:
	case M680X_INS_CLRX:
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	case M680X_INS_CLRY:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M680X_INS_EXG:
	case M680X_INS_XGDX:
	case M680X_INS_XGDY:
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;
	case M680X_INS_NOP:
	case M680X_INS_BRN:
	case M680X_INS_LBRN:
	case M680X_INS_SYNC:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case M680X_INS_SEX:
	case M680X_INS_SEXW:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case M680X_INS_REV:
	case M680X_INS_REVW:
		op->type = RZ_ANALYSIS_OP_TYPE_REV;
		break;
	case M680X_INS_CLC:
	case M680X_INS_CLI:
	case M680X_INS_CLV:
	case M680X_INS_CWAI:
	case M680X_INS_DAA:
	case M680X_INS_MEM:
	case M680X_INS_NSA:
	case M680X_INS_SEC:
	case M680X_INS_SEI:
	case M680X_INS_SEV:
	case M680X_INS_SLP:
	case M680X_INS_STOP:
	case M680X_INS_WAI:
	case M680X_INS_WAIT:
	case M680X_INS_WAV:
	case M680X_INS_WAVR:
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		break;
	}
beach:
	cs_free(insn, n);
	// cs_close (&handle);
fin:
	return opsize;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"gpr	pc	.16	48	0\n"
		"gpr	sp	.16	48	0\n"
		"gpr	a0	.16	48	0\n"
		"gpr	a1	.16	48	0\n";
	return rz_str_dup(p);
}

static bool m680x_analysis_fini(void *user) {
	M680XContext *ctx = (M680XContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_m680x_cs = {
	.name = "m680x",
	.desc = "Capstone M680X analysis plugin",
	.license = "BSD",
	.esil = false,
	.arch = "m680x",
	.get_reg_profile = &get_reg_profile,
	.bits = 16 | 32,
	.op = &analyze_op,
	.init = m680x_analysis_init,
	.fini = m680x_analysis_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_m680x_cs,
	.version = RZ_VERSION
};
#endif
