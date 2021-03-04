// SPDX-FileCopyrightText: 2009-2018 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "../arch/arm/winedbg/be_arm.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ut8 buf2[4];
	struct winedbg_arm_insn *arminsn = arm_new();
	arm_set_pc(arminsn, a->pc);
	arm_set_thumb(arminsn, a->bits == 16);
	if (a->big_endian && a->bits == 32) {
		rz_mem_swapendian(buf2, buf, 4);
		arm_set_input_buffer(arminsn, buf2);
	} else {
		arm_set_input_buffer(arminsn, buf);
	}
	op->size = arm_disasm_one_insn(arminsn);
	const char *asmstr = winedbg_arm_insn_asm(arminsn);
	if (asmstr) {
		rz_strbuf_set(&op->buf_asm, asmstr);
		rz_asm_op_set_hex(op, winedbg_arm_insn_hex(arminsn));
	} else {
		rz_strbuf_set(&op->buf_asm, "invalid");
		rz_strbuf_set(&op->buf, "");
	}
	arm_free(arminsn);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_arm_winedbg = {
	.name = "arm.winedbg",
	.arch = "arm",
	.bits = 16 | 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "WineDBG's ARM disassembler",
	.disassemble = &disassemble,
	.license = "LGPL2"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_arm_winedbg,
	.version = RZ_VERSION
};
#endif
