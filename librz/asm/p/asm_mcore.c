// SPDX-FileCopyrightText: 2018 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/mcore/mcore.h"

static mcore_handle handle = { 0 };

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	mcore_t *instr = NULL;
	char tmp[256];
	if (!op || mcore_init(&handle, buf, len)) {
		return -1;
	}
	op->size = 2;
	if ((instr = mcore_next(&handle))) {
		mcore_snprint(tmp, sizeof(tmp), a->pc, instr);
		mcore_free(instr);
		rz_asm_op_set_asm(op, tmp);
	} else {
		rz_asm_op_set_asm(op, "invalid");
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_mcore = {
	.name = "mcore",
	.desc = "Motorola MCORE disassembler",
	.license = "LGPL3",
	.arch = "mcore",
	.cpus = "mcore,c-sky",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_mcore,
	.version = RZ_VERSION
};
#endif
