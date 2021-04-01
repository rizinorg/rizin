// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int opsz = 0;
	rz_strbuf_set(&op->buf_asm, "");
	op->size = opsz;
	return opsz;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	return 0;
}

RzAsmPlugin rz_asm_plugin_null = {
	.name = "null",
	.author = "pancake",
	.version = "1.0.0",
	.arch = "null",
	.license = "MIT",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_NONE,
	.desc = "no disassemble",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_null,
	.version = RZ_VERSION
};
#endif
