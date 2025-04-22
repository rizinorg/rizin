// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "../binutils_as.h"

#define ASSEMBLER32 "RZ_ARM32_AS"
#define ASSEMBLER64 "RZ_ARM64_AS"

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	int bits = a->bits;
	char *as = "";
#if __arm__
	if (bits <= 32) {
		as = "as";
	}
#elif __aarch64__
	if (bits == 64) {
		as = "as";
	}
#endif
	char cmd_opt[4096];
	snprintf(cmd_opt, sizeof(cmd_opt), "%s %s",
		bits == 16 ? "-mthumb" : "",
		a->big_endian ? "-EB" : "-EL");
	return binutils_assemble(a, op, buf, as,
		bits == 64 ? ASSEMBLER64 : ASSEMBLER32,
		bits <= 32 ? ".syntax unified\n" : "", cmd_opt);
}

RzAsmPlugin rz_asm_plugin_arm_as = {
	.name = "arm.as",
	.desc = "as ARM Assembler (use " ASSEMBLER32 " and " ASSEMBLER64 " environment)",
	.arch = "arm",
	.author = "pancake",
	.license = "LGPL3",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_arm_as,
	.version = RZ_VERSION
};
#endif
