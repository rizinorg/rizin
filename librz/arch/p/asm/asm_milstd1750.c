// SPDX-FileCopyrightText: 2026 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <milstd1750/milstd1750_disas.h>

RzAsmPlugin rz_asm_plugin_milstd1750 = {
	.name = "milstd1750",
	.arch = "milstd1750",
	.license = "MIT",
	.bits = 8,
	.desc = "MIL-STD 1750 ISA disassembler",
	.disassemble = &rz_milstd1750_disasm,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_milstd1750,
	.version = RZ_VERSION
};
#endif