// SPDX-FileCopyrightText: 2014-2018 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <h8300/h8300_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	H8300Instruction cmd = { 0 };
	op->size = -1;
	int ret = h8300_decode_command(buf, len, &cmd, a->pc, a->cpu);
	if (ret <= 0) {
		return -1;
	}
	H8300InstructionStr ins_str = { 0 };
	if (!h8300_make_opstr(&cmd, &ins_str)) {
		return -1;
	}

	op->size = ret;
	rz_asm_op_setf_asm(op, "%s%s%s", ins_str.instr, RZ_STR_ISEMPTY(ins_str.ops_str) ? "" : " ", ins_str.ops_str);
	return ret;
}

RzAsmPlugin rz_asm_plugin_h8300 = {
	.name = "h8300",
	.license = "LGPL3",
	.desc = "Hitachi/Renesas H8/300 disassembly plugin",
	.arch = "h8300",
	.cpus = "h8300h,h8300,h8300l",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};
