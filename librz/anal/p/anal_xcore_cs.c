/* rizin - LGPL - Copyright 2014-2017 - pancake */

#include <rz_anal.h>
#include <rz_lib.h>
#include <capstone.h>
#include <xcore.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, ...) rz_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)
#define INSOP(n) insn->detail->xcore.operands[n]

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	rz_strbuf_init (buf);
	rz_strbuf_append (buf, "{");
	cs_xcore *x = &insn->detail->xcore;
	rz_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_xcore_op *op = &x->operands[i];
		if (i > 0) {
			rz_strbuf_append (buf, ",");
		}
		rz_strbuf_append (buf, "{");
		switch (op->type) {
		case XCORE_OP_REG:
			rz_strbuf_append (buf, "\"type\":\"reg\"");
			rz_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case XCORE_OP_IMM:
			rz_strbuf_append (buf, "\"type\":\"imm\"");
			rz_strbuf_appendf (buf, ",\"value\":%"PFMT64d, op->imm);
			break;
		case XCORE_OP_MEM:
			rz_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base != XCORE_REG_INVALID) {
				rz_strbuf_appendf (buf, ",\"base\":\"%s\"", cs_reg_name (handle, op->mem.base));
			}
			rz_strbuf_appendf (buf, ",\"disp\":%"PFMT64d"", op->mem.disp);
			break;
		default:
			rz_strbuf_append (buf, "\"type\":\"invalid\"");
			break;
		}
		rz_strbuf_append (buf, "}");
	}
	rz_strbuf_append (buf, "]");
	rz_strbuf_append (buf, "}");
}

static int analop(RzAnal *a, RzAnalOp *op, ut64 addr, const ut8 *buf, int len, RzAnalOpMask mask) {
	static csh handle = 0;
	static int omode = 0;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	if (!strcmp (a->cpu, "v9")) {
		mode |= CS_MODE_V9;
	}
	if (mode != omode) {
		if (handle) {
			cs_close (&handle);
			handle = 0;
		}
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_XCORE, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	// capstone-next
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANAL_OP_TYPE_ILL;
	} else {
		if (mask & RZ_ANAL_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case XCORE_INS_DRET:
		case XCORE_INS_KRET:
		case XCORE_INS_RETSP:
			op->type = RZ_ANAL_OP_TYPE_RET;
			break;
		case XCORE_INS_DCALL:
		case XCORE_INS_KCALL:
		case XCORE_INS_ECALLF:
		case XCORE_INS_ECALLT:
			op->type = RZ_ANAL_OP_TYPE_CALL;
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
			op->type = RZ_ANAL_OP_TYPE_CALL;
			op->jump = INSOP(0).imm;
			break;
		case XCORE_INS_SUB:
		case XCORE_INS_LSUB:
			op->type = RZ_ANAL_OP_TYPE_SUB;
			break;
		case XCORE_INS_ADD:
		case XCORE_INS_LADD:
			op->type = RZ_ANAL_OP_TYPE_ADD;
			break;
		}
		cs_free (insn, n);
	}
	//	cs_close (&handle);
	return op->size;
}

RzAnalPlugin rz_anal_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCORE analysis",
	.license = "BSD",
	.esil = false,
	.arch = "xcore",
	.bits = 32,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_ANAL,
	.data = &rz_anal_plugin_xcore_cs,
	.version = RZ_VERSION
};
#endif
