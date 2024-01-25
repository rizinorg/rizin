// SPDX-FileCopyrightText: 2014-2015 fedor.sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <msp430_disas.h>

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
	char *buf_asm = rz_strbuf_get(&op->buf_asm);
	if (a->syntax != RZ_ASM_SYNTAX_ATT) {
		rz_str_replace_ch(buf_asm, '#', 0, 1);
		// rz_str_replace_ch (buf_asm, "$", "$$", 1);
		rz_str_replace_ch(buf_asm, '&', 0, 1);
		rz_str_replace_ch(buf_asm, '%', 0, 1);
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

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_msp430,
	.version = RZ_VERSION
};
#endif
