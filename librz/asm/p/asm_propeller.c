// SPDX-FileCopyrightText: 2014 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <propeller_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	const char *buf_asm;
	struct propeller_cmd cmd;
	int ret = propeller_decode_command(buf, &cmd);
	if (cmd.prefix[0] && cmd.operands[0]) {
		buf_asm = sdb_fmt("%s %s %s", cmd.prefix, cmd.instr, cmd.operands);
	} else if (cmd.operands[0]) {
		buf_asm = sdb_fmt("%s %s", cmd.instr, cmd.operands);
	} else {
		buf_asm = sdb_fmt("%s", cmd.instr);
	}
	rz_asm_op_set_asm(op, buf_asm);
	op->size = 4;
	return ret;
}

RzAsmPlugin rz_asm_plugin_propeller = {
	.name = "propeller",
	.license = "LGPL3",
	.desc = "propeller disassembly plugin",
	.arch = "propeller",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_propeller,
	.version = RZ_VERSION
};
#endif
