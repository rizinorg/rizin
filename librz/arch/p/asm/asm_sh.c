// SPDX-FileCopyrightText: 2010-2011 eloi <limited-entropy.com>
// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "sh/disassembler.h"
#include "sh/assembler.h"

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

static bool sh_sw_breakpoint(RzAsm *a, RzAsmOp *op) {
	// 	{ 32, 2, 1, "\xc3\x20" }, // Big endian
	// 	{ 32, 2, 0, "\x20\xc3" }, // Little endian
	rz_asm_op_set_buf(op, a->big_endian ? (const ut8 *)"\xc3\x20" : (const ut8 *)"\x20\xc3", 2);
	return true;
}

RzAsmPlugin rz_asm_plugin_sh = {
	.name = "sh",
	.arch = "sh",
	.author = "DMaroo",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "Hitachi/Renesas SuperH-4 disassembler",
	.disassemble = &disassemble,
	.assemble = &assemble,
	.sw_breakpoint = sh_sw_breakpoint,
};
