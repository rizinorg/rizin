// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

static int z80_gnu_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	return op->size = z80Disass(op, buf, len);
}

static int z80_gnu_assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	return op->size = z80asm((ut8 *)rz_strbuf_get(&op->buf), buf);
}

RzAsmPlugin rz_asm_plugin_z80_gnu = {
	.name = "z80",
	.desc = "Zilog Z80 disassembler",
	.license = "GPL3",
	.author = "condret",
	.arch = "z80",
	.bits = 8,
	.endian = RZ_SYS_ENDIAN_NONE,
	.disassemble = &z80_gnu_disassemble,
	.assemble = &z80_gnu_assemble,
};
