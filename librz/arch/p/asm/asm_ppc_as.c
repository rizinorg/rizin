// SPDX-FileCopyrightText: 2020 eagleoflqj <liumeo@pku.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include "../binutils_as.h"

#define ASSEMBLER "RZ_PPC_AS"

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
#if __powerpc__
	char *as = "as";
#else
	char *as = "";
#endif
	char cmd_opt[4096];
	snprintf(cmd_opt, sizeof(cmd_opt), "-mregnames -a%d %s",
		a->bits, a->big_endian ? "-be" : "-le");
	return binutils_assemble(a, op, buf,
		as, ASSEMBLER, "", cmd_opt);
}

RzAsmPlugin rz_asm_plugin_ppc_as = {
	.name = "ppc.as",
	.desc = "as PPC Assembler (use " ASSEMBLER " environment)",
	.arch = "ppc",
	.author = "eagleoflqj",
	.license = "LGPL3",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ppc_as,
	.version = RZ_VERSION
};
#endif
