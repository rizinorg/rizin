/* radare - LGPL - Copyright 2012-2018 - pancake, fedor sakharov */

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <ebc_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ebc_command_t cmd = { {0}, {0} };
	int ret = ebc_decode_command (buf, &cmd);
	const char *buf_asm = (cmd.operands[0])
		? sdb_fmt ("%s %s", cmd.instr, cmd.operands): cmd.instr;
	rz_asm_op_set_asm (op, buf_asm);
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_ebc = {
	.name = "ebc",
	.license = "LGPL3",
	.desc = "EFI Bytecode",
	.author = "Fedor Sakharov",
	.arch = "ebc",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ebc,
	.version = R2_VERSION
};
#endif
