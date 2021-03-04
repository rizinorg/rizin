// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "../arch/amd29k/amd29k.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!a || !op || !buf || len < 4) {
		return -1;
	}
	char buf_asm[64];
	ut64 offset = a->pc;
	amd29k_instr_t instruction = { 0 };
	op->size = 4;
	if (amd29k_instr_decode(buf, len, &instruction, a->cpu)) {
		amd29k_instr_print(buf_asm, sizeof(buf_asm), offset, &instruction);
		rz_asm_op_set_asm(op, buf_asm);
		return 4;
	}
	rz_asm_op_set_asm(op, "invalid");
	return -1;
}

RzAsmPlugin rz_asm_plugin_amd29k = {
	.name = "amd29k",
	.license = "LGPL3",
	.desc = "AMD 29k RISC CPU",
	.author = "deroad",
	.arch = CPU_29000 "," CPU_29050,
	.cpus = "amd29k",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_amd29k,
	.version = RZ_VERSION
};
#endif
