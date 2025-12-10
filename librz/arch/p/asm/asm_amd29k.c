// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "amd29k/amd29k.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!a || !op || !buf || len < 4) {
		return -1;
	}
	op->size = 4;

	RzStrBuf sb = { 0 };
	ut64 offset = a->pc;
	ut32 cpu_id = AMD29K_29000;
	amd29k_instr_t instruction = { 0 };

	if (RZ_STR_EQ(a->cpu, "29050")) {
		cpu_id = AMD29K_29050;
	}

	if (!amd29k_instr_decode(buf, len, &instruction, cpu_id)) {
		rz_asm_op_set_asm(op, "invalid");
		return -1;
	}

	rz_strbuf_init(&sb);
	amd29k_instr_print(&instruction, offset, &sb);
	rz_asm_op_set_asm(op, rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);

	return op->size;
}

RzAsmPlugin rz_asm_plugin_amd29k = {
	.name = "amd29k",
	.license = "LGPL3",
	.desc = "AMD 29k RISC disassembler",
	.author = "deroad",
	.arch = "amd29k",
	.cpus = "29000,29050",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};
