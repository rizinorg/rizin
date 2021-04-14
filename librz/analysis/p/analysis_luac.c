// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include <rz_types.h>
#include <rz_analysis.h>

#include "librz/asm/arch/luac/lua_arch.h"

int rz_lua_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!analysis->cpu) {
		eprintf("Warning : no version info\n");
	}
	if (strcmp(analysis->cpu, "5.4") == 0) {
		return lua54_anal_op(analysis, op, addr, data, len);
	} else if (strcmp(analysis->cpu, "5.3") == 0) {
		return lua53_anal_op(analysis, op, addr, data, len);
	} else {
		eprintf("Warning : no matched version\n");
		return 0;
	}
}

RzAnalysisPlugin rz_analysis_plugin_luac = {
	.name = "luac",
	.desc = "Lua bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "luac",
	.bits = 8,
	.op = &rz_lua_analysis_op,
	.esil = false
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_luac,
	.version = RZ_VERSION
};
#endif