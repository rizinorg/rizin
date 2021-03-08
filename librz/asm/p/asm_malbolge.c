// SPDX-FileCopyrightText: 2014-2018 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <string.h>

static const char *mal_dis(ut64 c, const ut8 *buf, ut64 len) {
	if (len) {
		switch ((buf[0] + c) % 94) {
		case 4: return "jmp [d]";
		case 5: return "out a";
		case 23: return "in a";
		case 39: return "rotr [d], mov a, [d]";
		case 40: return "mov d, [d]";
		case 62: return "crz [d], a, mov a, [d]";
		case 81: return "end";
		default: return "nop";
		}
	}
	return NULL;
}

static int __disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	const char *opstr = mal_dis(a->pc, buf, len);
	return op->size = opstr ? 1 : 0;
}

RzAsmPlugin rz_asm_plugin_malbolge = {
	.name = "malbolge",
	.desc = "Malbolge Ternary VM",
	.arch = "malbolge",
	.author = "condret",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_NONE,
	.disassemble = &__disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_malbolge,
	.version = RZ_VERSION
};
#endif
