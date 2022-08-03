// SPDX-FileCopyrightText: 2010-2011 eloi <limited-entropy.com>
// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "../arch/sh/disassembler.h"
#include "../arch/sh/assembler.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	SHOp *dis_op = sh_disassembler(rz_read_ble16(buf, a->big_endian));
	op->size = 2;
	if (!dis_op) {
		rz_strbuf_set(&op->buf_asm, "invalid");
	} else {
		char *disasm = sh_op_to_str(dis_op, a->pc);
		rz_strbuf_set(&op->buf_asm, disasm);
		free(disasm);
	}
	RZ_FREE(dis_op);
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	bool success;
	ut16 opcode = sh_assembler(str, a->pc, &success);
	if (!success) {
		return -1;
	}

	ut8 buffer[2];
	rz_write_ble16(buffer, opcode, a->big_endian);
	rz_strbuf_setbin(&ao->buf, buffer, 2);
	return 2;
}

RzAsmPlugin rz_asm_plugin_sh = {
	.name = "sh",
	.arch = "sh",
	.author = "DMaroo",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "SuperH-4 CPU",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_sh,
	.version = RZ_VERSION
};
#endif
