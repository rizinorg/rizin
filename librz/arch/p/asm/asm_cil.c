// SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include "cil/cil_dis.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CILOp cilop = { { { 0 } } };
	if (cil_dis(&cilop, buf, len)) {
		return 0;
	}
	rz_strbuf_copy(&op->buf_asm, &cilop.strbuf);
	rz_strbuf_fini(&cilop.strbuf);
	return op->size = cilop.size;
}

RzAsmPlugin rz_asm_plugin_cil = {
	.name = "cil",
	.arch = "cil",
	.desc = ".NET CIL/MSIL (Common Intermediate Language) bytecode disassembler",
	.license = "LGPL3",
	.bits = 16 | 32 | 64,
	.disassemble = &disassemble,
};
