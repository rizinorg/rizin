// SPDX-FileCopyrightText: 2012-2013 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>

#include <propeller_disas.h>

static int propeller_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret;
	struct propeller_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));

	ret = op->size = propeller_decode_command(buf, &cmd);

	if (ret < 0) {
		return ret;
	}

	op->addr = addr;

	switch (cmd.opcode) {
	case PROP_TEST:
	case PROP_TESTN:
	case PROP_TJNZ:
	case PROP_TJZ:
	case PROP_CMPS:
	case PROP_CMPSUB:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case PROP_ADD:
	case PROP_ADDX:
	case PROP_ADDABS:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case PROP_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case PROP_RCL:
	case PROP_ROL:
	case PROP_SHL:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case PROP_RCR:
	case PROP_ROR:
	case PROP_SHR:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case PROP_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case PROP_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case PROP_ABS:
	case PROP_MINS:
	case PROP_MIN:
	case PROP_MAX:
	case PROP_MAXS:
	case PROP_RDBYTE:
	case PROP_RDLONG:
	case PROP_RDWORD:
	case PROP_MOV:
	case PROP_MOVD:
	case PROP_MOVI:
	case PROP_MOVS:
	case PROP_WAITVID:
	case PROP_MUXC:
		if (cmd.opcode == PROP_MOV && cmd.dst == 0x44 && cmd.src == 0x3c) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		}
		break;
	case PROP_SUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case PROP_JMP:
	case PROP_DJNZ:
		if (cmd.immed == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = 0x20 + cmd.src;
			op->fail = addr + 2;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			op->fail = addr + 2;
		}
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	return ret;
}

RzAnalysisPlugin rz_analysis_plugin_propeller = {
	.name = "propeller",
	.desc = "Parallax propeller code analysis plugin",
	.license = "LGPL3",
	.arch = "propeller",
	.bits = 32,
	.op = propeller_op,
};
