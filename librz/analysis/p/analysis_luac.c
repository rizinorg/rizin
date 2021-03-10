
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_analysis.h>

#include "../asm/arch/luac/luac_anal.h"

int rz_lua_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len,  RzAnalysisOpMask mask){
	return lua_anal_op(analysis, op, addr, data, len);
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