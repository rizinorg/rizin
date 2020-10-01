/* radare - LGPL - Copyright 2012-2018 - pancake, condret */

// fork of asm_z80.c

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/gb/gbdis.c"
#include "../arch/gb/gbasm.c"

static int disassemble(RzAsm *a, RzAsmOp *rz_op, const ut8 *buf, int len) {
	int dlen = gbDisass(rz_op,buf,len);
	return rz_op->size = R_MAX (0, dlen);
}

static int assemble(RzAsm *a, RzAsmOp *rz_op, const char *buf) {
	return gbAsm (a, rz_op, buf);
}

RzAsmPlugin rz_asm_plugin_gb = {
	.name = "gb",
	.desc = "GameBoy(TM) (z80-like)",
	.arch = "z80",
	.author = "condret",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_gb,
	.version = R2_VERSION
};
#endif
