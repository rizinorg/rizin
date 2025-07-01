// SPDX-FileCopyrightText: 2014-2018 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <h8300/h8300_disas.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct h8300_cmd cmd = { 0 };
	int ret = h8300_decode_command(buf, len, &cmd, a->pc);
	rz_asm_op_setf_asm(op, "%s%s%s", cmd.instr, RZ_STR_ISEMPTY(cmd.ops_str) ? "" : " ", cmd.ops_str);
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_h8300 = {
	.name = "h8300",
	.license = "LGPL3",
	.desc = "Hitachi/Renesas H8/300 disassembly plugin",
	.arch = "h8300",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};
