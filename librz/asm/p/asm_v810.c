/* radare - LGPL - Copyright 2012-2018 - pancake */

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "../arch/v810/v810_disas.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct v810_cmd cmd = {
		.instr = "",
		.operands = ""
	};
	if (len < 2) {
		return -1;
	}
	int ret = v810_decode_command (buf, len, &cmd);
	if (ret > 0) {
		rz_asm_op_set_asm (op, sdb_fmt ("%s %s", cmd.instr, cmd.operands));
	}
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_v810 = {
	.name = "v810",
	.license = "LGPL3",
	.desc = "v810 disassembly plugin",
	.author = "pancake",
	.arch = "v810",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_v810,
	.version = R2_VERSION
};
#endif
