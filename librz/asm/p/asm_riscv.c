/* radare - LGPL - Copyright 2015-2016 - qnix */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/riscv/riscv-opc.c"
#include "../arch/riscv/riscv.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	return op->size = riscv_dis (a, op, buf, len);
}

RzAsmPlugin rz_asm_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V",
	.arch = "riscv",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.license = "GPL",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_riscv,
	.version = RZ_VERSION
};
#endif
