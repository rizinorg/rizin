// SPDX-FileCopyrightText: 2014-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/xcore.h>

#define INSOP(n) insn->detail->xcore.operands[n]

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_xcore *x = &insn->detail->xcore;
	for (i = 0; i < x->op_count; i++) {
		cs_xcore_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case XCORE_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case XCORE_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
			break;
		case XCORE_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != XCORE_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_ki(pj, "disp", op->mem.disp);
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

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	static csh handle = 0;
	static int omode = 0;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	if (!strcmp(a->cpu, "v9")) {
		mode |= CS_MODE_V9;
	}
	if (mode != omode) {
		if (handle) {
			cs_close(&handle);
			handle = 0;
		}
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open(CS_ARCH_XCORE, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	// capstone-next
	n = cs_disasm(handle, (const ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	} else {
		if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
			opex(&op->opex, handle, insn);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case XCORE_INS_DRET:
		case XCORE_INS_KRET:
		case XCORE_INS_RETSP:
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		case XCORE_INS_DCALL:
		case XCORE_INS_KCALL:
		case XCORE_INS_ECALLF:
		case XCORE_INS_ECALLT:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = INSOP(0).imm;
			break;
		/* ??? */
		case XCORE_INS_BL:
		case XCORE_INS_BLA:
		case XCORE_INS_BLAT:
		case XCORE_INS_BT:
		case XCORE_INS_BF:
		case XCORE_INS_BU:
		case XCORE_INS_BRU:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = INSOP(0).imm;
			break;
		case XCORE_INS_SUB:
		case XCORE_INS_LSUB:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case XCORE_INS_ADD:
		case XCORE_INS_LADD:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		}
		cs_free(insn, n);
	}
	//	cs_close (&handle);
	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCORE analysis",
	.license = "BSD",
	.esil = false,
	.arch = "xcore",
	.bits = 32,
	.op = &analyze_op,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_xcore_cs,
	.version = RZ_VERSION
};
#endif
