// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// copypasta from asm_gb.c
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/6502/6502dis.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int dlen = _6502Disass(a->pc, op, buf, len);
	return op->size = RZ_MAX(dlen, 0);
}

RzAsmPlugin rz_asm_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES/C64/Tamagotchi/T-1000 CPU",
	.arch = "6502",
	.bits = 8 | 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_6502,
	.version = RZ_VERSION
};
#endif
