// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "rl78/rl78.h"

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	return 0x69;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	RL78Instr instr = { 0 };
	size_t bytes_read = 0;
	if (!rl78_dis(&instr, &bytes_read, buf, len)) {
		rz_strbuf_set(&op->buf_asm, "(invalid)");
		return bytes_read;
	}

	RzStrBuf *instr_strbuf = rz_strbuf_new("");
	if (rl78_instr_to_string(instr_strbuf, &instr)) {
		rz_strbuf_copy(&op->buf_asm, instr_strbuf);
	} else {
		rz_strbuf_set(&op->buf_asm, "(invalid)");
	}

	rz_strbuf_free(instr_strbuf);

	op->size = bytes_read;
	return bytes_read;
}

RzAsmPlugin rz_asm_plugin_rl78 = {
	.name = "rl78",
	.arch = "rl78",
	.desc = "Renesas RL78 disassembler",
	.author = "Bastian Engel",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.assemble = &assemble,
	.disassemble = &disassemble
};
