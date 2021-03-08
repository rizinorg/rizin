// SPDX-FileCopyrightText: 2012-2013 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2013 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

#include <ebc_disas.h>

static void ebc_analysis_jmp8(RzAnalysisOp *op, ut64 addr, const ut8 *buf) {
	int jmpadr = (int8_t)buf[1];
	op->jump = addr + 2 + (jmpadr * 2);
	op->addr = addr;
	op->fail = addr + 2;

	if (TEST_BIT(buf[0], 7)) {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	}
}

static void ebc_analysis_jmp(RzAnalysisOp *op, ut64 addr, const ut8 *buf) {
	op->fail = addr + 6;
	op->jump = (ut64) * (int32_t *)(buf + 2);
	if (TEST_BIT(buf[1], 4)) {
		op->jump += addr + 6;
	}
	if (buf[1] & 0x7) {
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
	} else {
		if (TEST_BIT(buf[1], 7)) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		}
	}
}

static void ebc_analysis_call(RzAnalysisOp *op, ut64 addr, const ut8 *buf) {
	int32_t addr_call;

	op->fail = addr + 6;
	if ((buf[1] & 0x7) == 0 && TEST_BIT(buf[0], 6) == 0 && TEST_BIT(buf[0], 7)) {
		addr_call = *(int32_t *)(buf + 2);

		if (TEST_BIT(buf[1], 4)) {
			op->jump = (addr + 6 + addr_call);
		} else {
			op->jump = addr_call;
		}
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
	}
}

static int ebc_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret;
	ebc_command_t cmd;
	ut8 opcode = buf[0] & EBC_OPCODE_MASK;

	if (!op) {
		return 2;
	}

	op->addr = addr;

	ret = op->size = ebc_decode_command(buf, &cmd);

	if (ret < 0) {
		return ret;
	}

	switch (opcode) {
	case EBC_JMP8:
		ebc_analysis_jmp8(op, addr, buf);
		break;
	case EBC_JMP:
		ebc_analysis_jmp(op, addr, buf);
		break;
	case EBC_MOVBW:
	case EBC_MOVWW:
	case EBC_MOVDW:
	case EBC_MOVQW:
	case EBC_MOVBD:
	case EBC_MOVWD:
	case EBC_MOVDD:
	case EBC_MOVQD:
	case EBC_MOVSNW:
	case EBC_MOVSND:
	case EBC_MOVQQ:
	case EBC_MOVNW:
	case EBC_MOVND:
	case EBC_MOVI:
	case EBC_MOVIN:
	case EBC_MOVREL:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case EBC_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case EBC_CMPEQ:
	case EBC_CMPLTE:
	case EBC_CMPGTE:
	case EBC_CMPULTE:
	case EBC_CMPUGTE:
	case EBC_CMPIEQ:
	case EBC_CMPILTE:
	case EBC_CMPIGTE:
	case EBC_CMPIULTE:
	case EBC_CMPIUGTE:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case EBC_SHR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case EBC_SHL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case EBC_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case EBC_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case EBC_MUL:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case EBC_PUSH:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case EBC_POP:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case EBC_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case EBC_ADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case EBC_SUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case EBC_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case EBC_CALL:
		ebc_analysis_call(op, addr, buf);
		break;
	case EBC_BREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	return ret;
}

RzAnalysisPlugin rz_analysis_plugin_ebc = {
	.name = "ebc",
	.desc = "EBC code analysis plugin",
	.license = "LGPL3",
	.arch = "ebc",
	.bits = 64,
	.op = &ebc_op,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_ebc,
	.version = RZ_VERSION
};
#endif
