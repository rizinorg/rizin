// SPDX-FileCopyrightText: 2015 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_lib.h>

static int mal_analysis(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (len) {
		switch ((data[0] + addr) % 94) {
		case 4:
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			break;
		case 5:
		case 23:
			op->type = RZ_ANALYSIS_OP_TYPE_IO;
			break;
		case 39:
			op->type = RZ_ANALYSIS_OP_TYPE_ROR;
			op->type2 = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 40:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 62:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			op->type2 = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 81:
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		}
		return op->size = 1;
	}
	return false;
}

RzAnalysisPlugin rz_analysis_plugin_malbolge = {
	.name = "malbolge",
	.desc = "Malbolge analysis plugin",
	.arch = "malbolge",
	.license = "LGPL3",
	.bits = 32,
	.op = &mal_analysis,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_malbolge,
	.version = RZ_VERSION
};
#endif
