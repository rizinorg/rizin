// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "luajit/arch_2.1.h"

int rz_luajit_disasm(const RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
	LuaJITOpNameList oplist = get_luajit_opnames();
	return luajit_disasm(opstruct, buf, len, oplist);
}

RzAsmPlugin rz_asm_plugin_luajit = {
	.name = "luajit",
	.arch = "luajit",
	.license = "LGPL3",
	.bits = 8,
	.desc = "luajit bytecode (LuaJIT) disassembler",
	.disassemble = &rz_luajit_disasm,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_luajit,
	.version = RZ_VERSION
};
#endif