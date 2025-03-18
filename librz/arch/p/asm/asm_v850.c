// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <v850/v850_disas.h>

static int v850_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	V850_Inst inst = { 0 };
	inst.addr = a->pc;
	if (len < 2) {
		return -1;
	}
	int ret = v850_decode_command(buf, len, &inst);
	if (ret > 0) {
		rz_asm_op_setf_asm(op, "%s %s", inst.instr, inst.operands);
	} else {
		rz_asm_op_set_asm(op, "invalid");
	}
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_v850 = {
	.name = "v850",
	.license = "LGPL3",
	.desc = "NEC/Renesas V850 disassembler",
	.arch = "v850",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &v850_disassemble
};
