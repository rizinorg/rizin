/* radare - LGPL - Copyright 2012-2013 - pancake
	2014 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_anal.h>
#include <rz_util.h>

#include <cr16_disas.h>

static int cr16_op(RzAnal *anal, RzAnalOp *op, ut64 addr,
		const ut8 *buf, int len, RzAnalOpMask mask)
{
	int ret;
	struct cr16_cmd cmd;

	memset(&cmd, 0, sizeof (cmd));

	ret = op->size = cr16_decode_command(buf, &cmd, len);

	if (ret <= 0) {
		return ret;
	}

	op->addr = addr;

	switch (cmd.type) {
	case CR16_TYPE_MOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case CR16_TYPE_MUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case CR16_TYPE_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case CR16_TYPE_CMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case CR16_TYPE_BE:
	case CR16_TYPE_BNE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case CR16_TYPE_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case CR16_TYPE_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case CR16_TYPE_SCOND:
		break;
	case CR16_TYPE_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case CR16_TYPE_SHIFT:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case CR16_TYPE_BIT:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_SLPR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_BCOND:
		if (cmd.reladdr) {
			op->jump = addr + cmd.reladdr;
			op->fail = addr + 2;
		}
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case CR16_TYPE_BR:
	case CR16_TYPE_BAL:
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case CR16_TYPE_EXCP:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case CR16_TYPE_JCOND:
	case CR16_TYPE_JAL:
	case CR16_TYPE_JUMP:
	case CR16_TYPE_JUMP_UNK:
		if (cmd.reladdr) {
			op->jump = addr + cmd.reladdr;
			op->fail = addr + 2;
		}
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case CR16_TYPE_RETX:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case CR16_TYPE_PUSH:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case CR16_TYPE_POP:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case CR16_TYPE_LOAD:
	case CR16_TYPE_DI:
	case CR16_TYPE_EI:
	case CR16_TYPE_STOR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case CR16_TYPE_WAIT:
	case CR16_TYPE_EWAIT:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
	}

	return ret;
}

RzAnalPlugin rz_anal_plugin_cr16 = {
	.name = "cr16",
	.desc = "CR16 code analysis plugin",
	.license = "LGPL3",
	.arch = "cr16",
	.bits = 16,
	.op = cr16_op,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &rz_anal_plugin_cr16,
	.version = R2_VERSION
};
#endif
