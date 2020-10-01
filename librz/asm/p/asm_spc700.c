/* radare - LGPL - Copyright 2012-2014 - pancake
	2014 - condret					*/

// fork of asm_z80.c

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/spc700/spc700dis.c"

static int disassemble(RzAsm *a, RzAsmOp *rz_op, const ut8 *buf, int len) {
	int dlen = spc700Disass(rz_op, buf, len);
	if (dlen < 0) {
		dlen = 0;
	}
	rz_op->size = dlen;
	return dlen;
}

RzAsmPlugin rz_asm_plugin_spc700 = {
	.name = "spc700",
	.desc = "spc700, snes' sound-chip",
	.arch = "spc700",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_NONE, // is this LE?
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_spc700,
	.version = R2_VERSION
};
#endif
