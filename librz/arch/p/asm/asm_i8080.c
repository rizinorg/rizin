// SPDX-FileCopyrightText: 2012-2018 Alexander <alexander@demin.ws>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <i8080/i8080dis.h>

static int do_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int dlen = i8080_disasm(buf, rz_strbuf_get(&op->buf_asm), len);
	return op->size = RZ_MAX(0, dlen);
}

RzAsmPlugin rz_asm_plugin_i8080 = {
	.name = "i8080",
	.desc = "Intel 8080 disassembler",
	.arch = "i8080",
	.license = "BSD",
	.bits = 8,
	.endian = RZ_SYS_ENDIAN_NONE,
	.disassemble = &do_disassemble
};
