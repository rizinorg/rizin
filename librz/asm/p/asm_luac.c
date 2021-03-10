//
// Created by heersin on 3/6/21.
//

#include "../arch/luac/luac_dis.h"

int rz_luac_disasm(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len){
	return luac_disasm(a, opstruct, buf, len);
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