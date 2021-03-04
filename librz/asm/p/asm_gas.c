// SPDX-FileCopyrightText: 2010-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	int len = 0;
	ut8 *out;
	char *cmd = rz_str_newf(
		"gas /dev/stdin -o /dev/stdout <<__\n"
		"BITS %i\nORG 0x%" PFMT64x "\n%s\n__",
		a->bits, a->pc, buf);
	ut8 *out = (ut8 *)rz_sys_cmd_str(cmd, "", &len);
	if (out) {
		rz_asm_op_set_buf(op, out, len);
		free(out);
	}
	op->size = len;
	free(cmd);
	return len;
}

RzAsmPlugin rz_asm_plugin_x86_gas = {
	.name = "x86.gas",
	.license = "LGPL3",
	.desc = "GNU Assembler (gas)",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_gas,
	.version = RZ_VERSION
};
#endif
