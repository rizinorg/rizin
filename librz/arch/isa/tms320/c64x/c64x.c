// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "c64x.h"
#ifdef CAPSTONE_TMS320C64X_H

#define INSOP(n) insn->detail->tms320c64x.operands[n]
#define INSCC    insn->detail->tms320c64x.cc

typedef struct {
	cs_mode omode;
	int obits;
	csh handle;
} TMSContext;

void *tms320_c64x_new() {
	TMSContext *ctx = RZ_NEW0(TMSContext);
	if (!ctx) {
		return false;
	}
	ctx->omode = -1;
	ctx->handle = 0;
	return ctx;
}

void tms320_c64x_free(void *p) {
	if (!p) {
	}
	TMSContext *ctx = (TMSContext *)p;
	if (ctx->handle) {
		cs_close(&ctx->handle);
	}
	free(ctx);
}

int tms320_c64x_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len, void *c64x) {
	TMSContext *ctx = (TMSContext *)c64x;

	cs_insn *insn;
	int n = -1, ret = -1;
	if (op) {
		memset(op, 0, sizeof(RzAsmOp));
		op->size = 4;
	}
	if (ctx->omode != 0) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_TMS320C64X, 0, &ctx->handle);
		if (ret) {
			goto fin;
		}
		ctx->omode = 0;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	if (!op) {
		return 0;
	}
	n = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 4;
		ret = -1;
		goto fin;
	} else {
		ret = 4;
	}
	if (insn->size < 1) {
		goto fin;
	}
	op->size = insn->size;
	rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	char *str = rz_asm_op_get_asm(op);
	if (str) {
		rz_str_replace_char(str, '%', 0);
		rz_str_case(str, false);
	}
	cs_free(insn, n);
fin:
	return ret;
}

char *tms320_c64x_mnemonics(RzAsm *a, int id, bool json, void *c64x) {
	TMSContext *ctx = (TMSContext *)c64x;
	a->cur->disassemble(a, NULL, NULL, -1);
	if (id != -1) {
		const char *vname = cs_insn_name(ctx->handle, id);
		if (json) {
			return vname ? rz_str_newf("[\"%s\"]\n", vname) : NULL;
		}
		return rz_str_dup(vname);
	}
	RzStrBuf *buf = rz_strbuf_new("");
	if (json) {
		rz_strbuf_append(buf, "[");
	}
	for (int i = 1;; i++) {
		const char *op = cs_insn_name(ctx->handle, i);
		if (!op) {
			break;
		}
		if (json) {
			rz_strbuf_append(buf, "\"");
		}
		rz_strbuf_append(buf, op);
		if (json) {
			if (cs_insn_name(ctx->handle, i + 1)) {
				rz_strbuf_append(buf, "\",");
			} else {
				rz_strbuf_append(buf, "\"]\n");
			}
		} else {
			rz_strbuf_append(buf, "\n");
		}
	}
	return rz_strbuf_drain(buf);
}

static void tms320_c64x_opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_tms320c64x *x = &insn->detail->tms320c64x;
	for (i = 0; i < x->op_count; i++) {
		cs_tms320c64x_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case TMS320C64X_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case TMS320C64X_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
			break;
		case TMS320C64X_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != SPARC_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_kN(pj, "disp", (st64)op->mem.disp);
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

int tms320_c64x_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask, void *c64x) {
	TMSContext *ctx = (TMSContext *)c64x;
	cs_insn *insn;
	int mode = 0, n, ret;

	if (mode != ctx->omode) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = mode;
	}
	if (ctx->handle == 0) {
		ret = cs_open(CS_ARCH_TMS320C64X, mode, &ctx->handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	// capstone-next
	n = cs_disasm(ctx->handle, (const ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	} else {
		if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
			tms320_c64x_opex(&op->opex, ctx->handle, insn);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case TMS320C64X_INS_INVALID:
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		case TMS320C64X_INS_AND:
		case TMS320C64X_INS_ANDN:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break;
		case TMS320C64X_INS_NOT:
			op->type = RZ_ANALYSIS_OP_TYPE_NOT;
			break;
		case TMS320C64X_INS_NEG:
			op->type = RZ_ANALYSIS_OP_TYPE_NOT;
			break;
		case TMS320C64X_INS_SWAP2:
		case TMS320C64X_INS_SWAP4:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case TMS320C64X_INS_BNOP:
		case TMS320C64X_INS_NOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		case TMS320C64X_INS_CMPEQ:
		case TMS320C64X_INS_CMPEQ2:
		case TMS320C64X_INS_CMPEQ4:
		case TMS320C64X_INS_CMPGT:
		case TMS320C64X_INS_CMPGT2:
		case TMS320C64X_INS_CMPGTU4:
		case TMS320C64X_INS_CMPLT:
		case TMS320C64X_INS_CMPLTU:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		case TMS320C64X_INS_B:
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			// higher 32bits of the 64bit address is lost, lets clone
			op->jump = INSOP(0).imm + (addr & 0xFFFFFFFF00000000);
			break;
		case TMS320C64X_INS_LDB:
		case TMS320C64X_INS_LDBU:
		case TMS320C64X_INS_LDDW:
		case TMS320C64X_INS_LDH:
		case TMS320C64X_INS_LDHU:
		case TMS320C64X_INS_LDNDW:
		case TMS320C64X_INS_LDNW:
		case TMS320C64X_INS_LDW:
		case TMS320C64X_INS_LMBD:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case TMS320C64X_INS_STB:
		case TMS320C64X_INS_STDW:
		case TMS320C64X_INS_STH:
		case TMS320C64X_INS_STNDW:
		case TMS320C64X_INS_STNW:
		case TMS320C64X_INS_STW:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case TMS320C64X_INS_OR:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case TMS320C64X_INS_SSUB:
		case TMS320C64X_INS_SUB:
		case TMS320C64X_INS_SUB2:
		case TMS320C64X_INS_SUB4:
		case TMS320C64X_INS_SUBAB:
		case TMS320C64X_INS_SUBABS4:
		case TMS320C64X_INS_SUBAH:
		case TMS320C64X_INS_SUBAW:
		case TMS320C64X_INS_SUBC:
		case TMS320C64X_INS_SUBU:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case TMS320C64X_INS_ADD:
		case TMS320C64X_INS_ADD2:
		case TMS320C64X_INS_ADD4:
		case TMS320C64X_INS_ADDAB:
		case TMS320C64X_INS_ADDAD:
		case TMS320C64X_INS_ADDAH:
		case TMS320C64X_INS_ADDAW:
		case TMS320C64X_INS_ADDK:
		case TMS320C64X_INS_ADDKPC:
		case TMS320C64X_INS_ADDU:
		case TMS320C64X_INS_SADD:
		case TMS320C64X_INS_SADD2:
		case TMS320C64X_INS_SADDU4:
		case TMS320C64X_INS_SADDUS2:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		}
		cs_free(insn, n);
	}
	return op->size;
}

#endif /* CAPSTONE_TMS320C64X_H */
