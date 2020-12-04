// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_anal.h>
#include <rz_types.h>
#include <rz_lib.h>

static int null_anal(RzAnalysis *anal, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	/* This should better follow the disassembler */
	return op->size = 1;
}

static bool null_set_reg_profile(RzAnalysis* anal){
	return rz_reg_set_profile_string(anal->reg, "");
}

RzAnalysisPlugin rz_anal_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null analysis plugin",
	.arch = "none",
	.license = "LGPL3",
	.bits = 8|16|32|64,	/* is this used? */
	.op = &null_anal,
	.set_reg_profile = &null_set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANAL,
	.data = &rz_anal_plugin_null,
	.version = RZ_VERSION
};
#endif
