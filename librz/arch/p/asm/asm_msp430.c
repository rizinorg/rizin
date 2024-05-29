// SPDX-FileCopyrightText: 2014-2015 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <msp430/msp430_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct msp430_cmd cmd;
	int ret = msp430_decode_command(buf, len, &cmd);
	if (ret < 1) {
		rz_asm_op_set_asm(op, "invalid");
		goto fail;
	}
	if (cmd.operands[0]) {
		rz_asm_op_setf_asm(op, "%s %s", cmd.instr, cmd.operands);
	} else {
		rz_asm_op_set_asm(op, cmd.instr);
	}

fail:
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_msp430 = {
	.name = "msp430",
	.license = "LGPL3",
	.desc = "msp430 disassembly plugin",
	.arch = "msp430",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};
