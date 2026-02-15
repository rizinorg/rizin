// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>

static int disassemble(RzAsm *a, RzAsmOp *rz_op, const ut8 *buf, int len) {
	int dlen = gbDisass(rz_op, buf, len);
	return rz_op->size = RZ_MAX(0, dlen);
}

static int assemble(RzAsm *a, RzAsmOp *rz_op, const char *buf) {
	return gbAsm(a, rz_op, buf);
}

RzAsmPlugin rz_asm_plugin_gb = {
	.name = "gb",
	.desc = "GameBoy(TM) (z80-like)",
	.arch = "gb",
	.author = "condret",
	.license = "LGPL3",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.assemble = &assemble,
};
