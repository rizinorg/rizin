// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "../arch/dcpu16/dcpu16.h"
#include "../arch/dcpu16/dis.c"
#include "../arch/dcpu16/asm.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	char buf_asm[96];
	if (len < 2) {
		return -1; // at least 2 bytes!
	}
	op->size = dcpu16_disasm(buf_asm, sizeof(buf_asm), (const ut16 *)buf, len, NULL);
	rz_strbuf_set(&op->buf_asm, (op->size > 0) ? buf_asm : "(data)");
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	int len = dcpu16_assemble((ut8 *)rz_strbuf_get(&op->buf), buf);
	op->buf.len = len;
	return len;
}

RzAsmPlugin rz_asm_plugin_dcpu16 = {
	.name = "dcpu16",
	.arch = "dpcu",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Mojang's DCPU-16",
	.license = "PD",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_dcpu16,
	.version = RZ_VERSION
};
#endif
