// SPDX-FileCopyrightText: 2018-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"

static int disassemble (RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	HexInsn hi = {0};
	ut32 data = rz_read_le32 (buf);
	op->size = hexagon_disasm_instruction (data, &hi, (ut32) a->pc);
	rz_strbuf_set (&op->buf_asm, hi.mnem);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "xvilka",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_hexagon
};
#endif
