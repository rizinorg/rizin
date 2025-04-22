// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2019 astuder <github@adrianstuder.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <8051/8051_ass.h>
#include <8051/8051_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int dlen = 0;
	char *s = rz_8051_disas(a->pc, buf, len, &dlen);
	if (dlen < 0) {
		dlen = 0;
	}
	if (s) {
		rz_strbuf_set(&op->buf_asm, s);
		free(s);
	}
	op->size = dlen;
	return dlen;
}

RzAsmPlugin rz_asm_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.bits = 8,
	.endian = RZ_SYS_ENDIAN_NONE,
	.desc = "Intel 8051 disassembler",
	.disassemble = &disassemble,
	.assemble = &assemble_8051,
	.license = "PD",
	.cpus =
		"8051-generic," // First one is default
		"8051-shared-code-xdata"
};
