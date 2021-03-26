// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "librz/asm/arch/luac/lua_arch.h"

int rz_luac_disasm(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
        LuaOpNameList oplist = NULL;
        int r = 0;

	if (!a->cpu) {
		eprintf("Warning : no version info\n");
		return 0;
	}

	if (strcmp(a->cpu, "5.4") == 0) {
		oplist = get_lua54_opnames();
		r = lua54_disasm(opstruct, buf, len, oplist);
	} else if (strcmp(a->cpu, "5.3") == 0) {
		oplist = get_lua53_opnames();
		r = lua53_disasm(opstruct, buf, len, oplist);
	}

	free_lua_opnames(oplist);
	opstruct->size = r;
	return r;
}

RzAsmPlugin rz_asm_plugin_luac = {
	.name = "luac",
	.arch = "luac",
	.license = "LGPL3",
	.bits = 8,
	.desc = "luac disassemble plugin",
	.disassemble = &rz_luac_disasm
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = rz_asm_plugin_luac,
	.version = RZ_VERSION
};
#endif