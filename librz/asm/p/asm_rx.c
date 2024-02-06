// SPDX-FileCopyrightText: 2023 Heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
    size_t bytes_read = 0;

    rz_strbuf_set(&op->buf_asm, "(invalid)");

    op->size = 0;
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