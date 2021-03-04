// SPDX-FileCopyrightText: 2014 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

static int nios2_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *b, int len, RzAnalysisOpMask mask) {
	if (!op) {
		return 1;
	}
	op->size = 4;

	if ((b[0] & 0xff) == 0x3a) {
		// XXX
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
	} else if ((b[0] & 0xf) == 0xa) {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	} else if ((b[0] & 0xf) == 4) {
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	} else if ((b[0] & 0xf) == 5) {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	} else if ((b[0] & 0xf) == 6) {
		// blt, r19, r5, 0x8023480
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		// TODO: address
	} else if ((b[0] & 0xf) == 7) {
		// blt, r19, r5, 0x8023480
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		// TODO: address
	} else {
		switch (b[0]) {
		case 0x3a:
			if (b[1] >= 0xa0 && b[1] <= 0xaf && b[3] == 0x3d) {
				op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			} else if ((b[1] >= 0xe0 && b[1] <= 0xe7) && b[2] == 0x3e && !b[3]) {
				// nextpc ra
				op->type = RZ_ANALYSIS_OP_TYPE_RET;
			}
			break;
		case 0x01:
			// jmpi
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			break;
		case 0x00:
		case 0x20:
		case 0x40:
		case 0x80:
		case 0xc0:
			//
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		case 0x26:
			// beq
			break;
		case 0x07:
		case 0x47:
		case 0x87:
		case 0xc7:
			// ldb
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 0x0d:
		case 0x2d:
		case 0x4d:
		case 0x8d:
		case 0xcd:
			// sth && sthio
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 0x06:
		case 0x46:
		case 0x86:
		case 0xc6:
			// br
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		}
	}
	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_nios2 = {
	.name = "nios2",
	.desc = "NIOS II code analysis plugin",
	.license = "LGPL3",
	.arch = "nios2",
	.esil = false,
	.bits = 32,
	.op = &nios2_op,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_nios2,
	.version = RZ_VERSION
};
#endif
