// SPDX-FileCopyrightText: 2012-2015 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <snes/snes_op_table.h>
#include <snes/snes.h>

static int dis(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct snes_asm_flags *snesflags = (struct snes_asm_flags *)a->plugin_data;
	int dlen = snesDisass(snesflags->M, snesflags->X, a->pc, op, buf, len);
	if (dlen < 0) {
		dlen = 0;
	}
	op->size = dlen;
	if (buf[0] == 0xc2) { // REP
		if (buf[1] & 0x10) {
			snesflags->X = 0;
		}
		if (buf[1] & 0x20) {
			snesflags->M = 0;
		}
	} else if (buf[0] == 0xe2) { // SEP
		if (buf[1] & 0x10) {
			snesflags->X = 1;
		}
		if (buf[1] & 0x20) {
			snesflags->M = 1;
		}
	}
	return dlen;
}

static bool snes_asm_init(void **user) {
	*user = RZ_NEW0(struct snes_asm_flags);
	return *user != NULL;
}

static bool snes_asm_fini(void *user) {
	rz_return_val_if_fail(user, false);
	free(user);
	return true;
}

RzAsmPlugin rz_asm_plugin_snes = {
	.name = "snes",
	.desc = "SuperNES CPU disassembler",
	.arch = "snes",
	.bits = 8 | 16,
	.init = snes_asm_init,
	.fini = snes_asm_fini,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.disassemble = &dis
};
