// SPDX-FileCopyrightText: 2015-2021 qnix <qnix@0x80.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/riscv/riscv-opc.c"
#include "../arch/riscv/riscv.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	return op->size = riscv_dis(a, op, buf, len);
}

RzAsmPlugin rz_asm_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V",
	.arch = "riscv",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.license = "GPL",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_riscv,
	.version = RZ_VERSION
};
#endif
