// SPDX-FileCopyrightText: 2024 Heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rx/rx.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	RxInst inst = { 0 };
	st32 bytes_read;

	if (!rx_dis(&inst, &bytes_read, buf, len)) {
		rz_asm_op_set_asm(op, "(invalid)");
		return bytes_read;
	}

	rx_inst_stringify(&inst, &op->buf_asm);
	op->size = bytes_read;
	return bytes_read;
}

RzAsmPlugin rz_asm_plugin_rx = {
	.name = "rx",
	.arch = "rx",
	.desc = "Renesas RX Family disassembler",
	.author = "Heersin",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_rx,
	.version = RZ_VERSION
};
#endif