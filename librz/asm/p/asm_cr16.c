/* radare - LGPL - Copyright 2014-2018 - fedor.sakharov */

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <cr16_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct cr16_cmd cmd;
	int ret = cr16_decode_command (buf, &cmd, len);
	rz_strbuf_set (&op->buf_asm, sdb_fmt ("%s %s", cmd.instr, cmd.operands));
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_cr16 = {
	.name = "cr16",
	.license = "LGPL3",
	.desc = "cr16 disassembly plugin",
	.arch = "cr16",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_cr16,
	.version = R2_VERSION
};
#endif
