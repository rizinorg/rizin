// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <h8500/h8500.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	H8500Instruction ins = { 0 };
	if (!h8500_instruction_parse(buf, len, &ins)) {
		return -1;
	}
	H8500InstructionOpstr opstr = { 0 };
	if (!h8500_instruction_get_opstr(&ins, &opstr)) {
		return -1;
	}
	rz_asm_op_setf_asm(op, "%s%s%s", opstr.mnemonic, RZ_STR_ISEMPTY(opstr.ops_str) ? "" : " ", opstr.ops_str);
	op->size = ins.size;
	return ins.size;
}

RzAsmPlugin rz_asm_plugin_h8500 = {
	.name = "h8500",
	.license = "LGPL3",
	.desc = "Hitachi/Renesas H8/500 disassembler",
	.arch = "h8500",
	.cpus = "h8500",
	.author = "billow",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};
