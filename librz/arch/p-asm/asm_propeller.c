// SPDX-FileCopyrightText: 2014 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <propeller_disas.h>

static int propeller_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	rz_return_val_if_fail(a && op && buf && len >= 4, -1);
	struct propeller_cmd cmd;
	int ret = propeller_decode_command(buf, &cmd);
	if (cmd.prefix[0] && cmd.operands[0]) {
		rz_asm_op_setf_asm(op, "%s %s %s", cmd.prefix, cmd.instr, cmd.operands);
	} else if (cmd.operands[0]) {
		rz_asm_op_setf_asm(op, "%s %s", cmd.instr, cmd.operands);
	} else {
		rz_asm_op_set_asm(op, cmd.instr);
	}
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
	.disassemble = &propeller_disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_propeller,
	.version = RZ_VERSION
};
#endif
