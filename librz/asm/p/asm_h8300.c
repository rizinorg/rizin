/* radare - LGPL - Copyright 2014-2018 - fedor.sakharov */

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <h8300_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct h8300_cmd cmd;
	int ret = h8300_decode_command(buf, &cmd);
	rz_strbuf_set (&op->buf_asm, sdb_fmt ("%s %s", cmd.instr, cmd.operands));
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_h8300 = {
	.name = "h8300",
	.license = "LGPL3",
	.desc = "H8/300 disassembly plugin",
	.arch = "h8300",
	.bits = 16,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_h8300,
	.version = RZ_VERSION
};
#endif
