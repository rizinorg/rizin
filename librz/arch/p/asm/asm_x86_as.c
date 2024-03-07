// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_asm.h>
#include "../binutils_as.h"

#define ASSEMBLER "RZ_X86_AS"

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
#if __i386__ || __x86_64__
	const char *as = "as";
#else
	const char *as = "";
#endif
	const char *syntaxstr = "";

	switch (a->syntax) {
	case RZ_ASM_SYNTAX_INTEL:
		syntaxstr = ".intel_syntax noprefix\n";
		break;
	case RZ_ASM_SYNTAX_ATT:
		syntaxstr = ".att_syntax\n";
		break;
	}

	char header[4096];
	snprintf(header, sizeof(header), "%s.code%i\n", // .org 0x%"PFMT64x"\n"
		syntaxstr, a->bits);
	return binutils_assemble(a, op, buf, as, ASSEMBLER, header, "");
}

RzAsmPlugin rz_asm_plugin_x86_as = {
	.name = "x86.as",
	.desc = "Intel X86 GNU Assembler (Use " ASSEMBLER " env)",
	.arch = "x86",
	.license = "LGPL3",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.assemble = &assemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_as,
	.version = RZ_VERSION
};
#endif
