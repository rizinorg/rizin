/* rizin - LGPL - Copyright 2017 - pancake */

#include <rz_anal.h>
#include <rz_lib.h>
#include <capstone.h>

#ifdef CAPSTONE_TMS320C64X_H
#define CAPSTONE_HAS_TMS320C64X 1
#else
#define CAPSTONE_HAS_TMS320C64X 0
#warning Cannot find capstone-tms320c64x support
#endif

#if CS_API_MAJOR < 2
#undef CAPSONT_HAS_TMS320C64X
#define CAPSTONE_HAS_TMS320C64X 0
#endif


#if CAPSTONE_HAS_TMS320C64X

#define INSOP(n) insn->detail->tms320c64x.operands[n]
#define INSCC insn->detail->tms320c64x.cc

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	rz_strbuf_init (buf);
	rz_strbuf_append (buf, "{");
	cs_tms320c64x *x = &insn->detail->tms320c64x;
	rz_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_tms320c64x_op *op = &x->operands[i];
		if (i > 0) {
			rz_strbuf_append (buf, ",");
		}
		rz_strbuf_append (buf, "{");
		switch (op->type) {
		case TMS320C64X_OP_REG:
			rz_strbuf_append (buf, "\"type\":\"reg\"");
			rz_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case TMS320C64X_OP_IMM:
			rz_strbuf_append (buf, "\"type\":\"imm\"");
			rz_strbuf_appendf (buf, ",\"value\":%"PFMT64d, op->imm);
			break;
		case TMS320C64X_OP_MEM:
			rz_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base != SPARC_REG_INVALID) {
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
	rz_strbuf_append (buf, "]}");
}

static int tms320c64x_analop(RzAnal *a, RzAnalOp *op, ut64 addr, const ut8 *buf, int len, RzAnalOpMask mask) {
	static csh handle = 0;
	static int omode;
	cs_insn *insn;
	int mode = 0, n, ret;

	if (mode != omode) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_TMS320C64X, mode, &handle);
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
		case TMS320C64X_INS_INVALID:
			op->type = RZ_ANAL_OP_TYPE_ILL;
			break;
		case TMS320C64X_INS_AND:
		case TMS320C64X_INS_ANDN:
			op->type = RZ_ANAL_OP_TYPE_AND;
			break;
		case TMS320C64X_INS_NOT:
			op->type = RZ_ANAL_OP_TYPE_NOT;
			break;
		case TMS320C64X_INS_NEG:
			op->type = RZ_ANAL_OP_TYPE_NOT;
			break;
		case TMS320C64X_INS_SWAP2:
		case TMS320C64X_INS_SWAP4:
		op->type = RZ_ANAL_OP_TYPE_MOV;
			op->type = RZ_ANAL_OP_TYPE_MOV;
			break;
		case TMS320C64X_INS_BNOP:
		case TMS320C64X_INS_NOP:
			op->type = RZ_ANAL_OP_TYPE_NOP;
			break;
		case TMS320C64X_INS_CMPEQ:
		case TMS320C64X_INS_CMPEQ2:
		case TMS320C64X_INS_CMPEQ4:
		case TMS320C64X_INS_CMPGT:
		case TMS320C64X_INS_CMPGT2:
		case TMS320C64X_INS_CMPGTU4:
		case TMS320C64X_INS_CMPLT:
		case TMS320C64X_INS_CMPLTU:
			op->type = RZ_ANAL_OP_TYPE_CMP;
			break;
		case TMS320C64X_INS_B:
			op->type = RZ_ANAL_OP_TYPE_JMP;
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
			op->type = RZ_ANAL_OP_TYPE_LOAD;
			break;
		case TMS320C64X_INS_STB:
		case TMS320C64X_INS_STDW:
		case TMS320C64X_INS_STH:
		case TMS320C64X_INS_STNDW:
		case TMS320C64X_INS_STNW:
		case TMS320C64X_INS_STW:
			op->type = RZ_ANAL_OP_TYPE_STORE;
			break;
		case TMS320C64X_INS_OR:
			op->type = RZ_ANAL_OP_TYPE_OR;
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
			op->type = RZ_ANAL_OP_TYPE_SUB;
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
			op->type = RZ_ANAL_OP_TYPE_ADD;
			break;
		}
		cs_free (insn, n);
	}
	return op->size;
}
#endif

/*

static int archinfo(RzAnal *anal, int q) {
	return 4; // :D
}

RzAnalPlugin rz_anal_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320C64X analysis",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32,
	.archinfo = archinfo,
	.op = &analop
};

#else
RzAnalPlugin rz_anal_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320C64X analysis (unsupported)",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_ANAL,
	.data = &rz_anal_plugin_tms320c64x,
	.version = RZ_VERSION
};
#endif
*/
