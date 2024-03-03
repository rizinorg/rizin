// SPDX-FileCopyrightText: 2014 montekki <i.matveychikov@milabs.ru>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

ut32 get_ins_len(ut8 opcode);

int tms320_c55x_plus_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len) {
	ut16 *ins = (ut16 *)buf;
	ut32 ins_len;

	if (!buf || len <= 0) {
		return 0;
	}

	ins_len = get_ins_len(buf[0]);
	if (ins_len == 0) {
		return 0;
	}

	op->addr = addr;
	op->size = ins_len;

	if (ins_len == 1) {
		if (*ins == 0x20) {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		} else if (*ins == 0x21) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		}
	} else if (ins_len >= 4 && buf[0] == 0xD8) {
		//  BCC conditional absolute jump
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else if (ins_len >= 2 && buf[0] == 0x6A) {
		//  BCC conditional relative jump
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + ((st8)buf[1]) + ins_len;
	} else if (ins_len >= 3 && buf[0] == 0x9A) {
		// BCC conditional relative jump
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
	} else if (ins_len >= 4 && buf[0] == 0x9C) {
		// B unconditional absolute jump
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else if (ins_len >= 3 && buf[0] == 0x68) {
		// B unconditional relative jump
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
	} else if (ins_len == 2 && buf[0] == 0x02) {
		// CALL unconditional absolute call with acumulator register ACx

		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->fail = addr + ins_len;
	} else if (ins_len >= 3 && buf[0] == 0x69) {
		// CALL unconditional relative call
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
	} else if (ins_len >= 3 && buf[0] == 0x9D) {
		// CALL unconditional absolute call
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else if (ins_len >= 3 && buf[0] == 0x9B) {
		// CALLCC conditional relative call
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
	} else if (ins_len >= 4 && buf[0] == 0xD9) {
		// CALLCC conditional absolute call
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	}
	return op->size;
}
