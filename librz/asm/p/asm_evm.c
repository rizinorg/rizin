// SPDX-FileCopyrightText: 2023 gogo <gogo246475@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/evm/evmdis.c"
#include "../arch/evm/evmasm.c"

static int disassemble(RzAsm *a, RzAsmOp *rz_op, const ut8 *buf, int len) {
	int dlen = evmDisass(rz_op, buf, len);
	return rz_op->size = RZ_MAX(0, dlen);
}

static int assemble(RzAsm *a, RzAsmOp *rz_op, const char *buf) {
	return evmAsm(a, rz_op, buf);
}

RzAsmPlugin rz_asm_plugin_evm = {
	.name = "evm",
	.desc = "EVM solidity bytecode",
	.arch = "evm",
	.author = "gogo",
	.license = "LGPL3",
	.bits = 256,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_evm,
	.version = RZ_VERSION
};
#endif
