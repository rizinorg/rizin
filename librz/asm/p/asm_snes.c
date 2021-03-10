// SPDX-FileCopyrightText: 2012-2015 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/snes/snesdis.c"
#include "asm_snes.h"

static struct snes_asm_flags *snesflags = NULL;

static bool snes_asm_init(void *user) {
	if (!snesflags) {
		snesflags = malloc(sizeof(struct snes_asm_flags));
	}
	memset(snesflags, 0, sizeof(struct snes_asm_flags));
	return 0;
}

static bool snes_asm_fini(void *user) {
	free(snesflags);
	snesflags = NULL;
	return 0;
}

static int dis(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int dlen = snesDisass(snesflags->M, snesflags->X, a->pc, op, buf, len);
	if (dlen < 0) {
		dlen = 0;
	}
	op->size = dlen;
	if (buf[0] == 0xc2) { //REP
		if (buf[1] & 0x10) {
			snesflags->X = 0;
		}
		if (buf[1] & 0x20) {
			snesflags->M = 0;
		}
	} else if (buf[0] == 0xe2) { //SEP
		if (buf[1] & 0x10) {
			snesflags->X = 1;
		}
		if (buf[1] & 0x20) {
			snesflags->M = 1;
		}
	}
	return dlen;
}

RzAsmPlugin rz_asm_plugin_snes = {
	.name = "snes",
	.desc = "SuperNES CPU",
	.arch = "snes",
	.bits = 8 | 16,
	.init = snes_asm_init,
	.fini = snes_asm_fini,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.disassemble = &dis
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_snes,
	.version = RZ_VERSION
};
#endif
