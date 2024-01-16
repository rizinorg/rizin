// SPDX-FileCopyrightText: 2014-2018 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <cr16_disas.h>

static int cr16_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct cr16_cmd cmd = { 0 };
	int ret = cr16_decode_command(buf, &cmd, len);
	if (ret > -1) {
		rz_strbuf_initf(&op->buf_asm, "%s %s", cmd.instr, cmd.operands);
	} else {
		rz_strbuf_set(&op->buf_asm, "invalid");
	}
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_cr16 = {
	.name = "cr16",
	.license = "LGPL3",
	.desc = "cr16 disassembly plugin",
	.arch = "cr16",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &cr16_disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_cr16,
	.version = RZ_VERSION
};
#endif
