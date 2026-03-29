// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "luajit/arch_2.1.h"

int rz_luajit_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	LuaJITInstructions instr = rz_read_ble32(data, analysis->big_endian);
	return luajit_analysis_op(analysis, op, addr, data, len, instr);
}

RzAnalysisPlugin rz_analysis_plugin_luajit = {
	.name = "luajit",
	.desc = "Luajit bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "luajit",
	.bits = 32,
	.op = &rz_luajit_analysis_op,
	.esil = false
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_luajit,
	.version = RZ_VERSION
};
#endif