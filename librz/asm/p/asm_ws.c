/* radare - LGPL - Copyright 2014 - condret */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#define WS_API static
#include "../arch/whitespace/wsdis.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	return wsdis (op, buf, len);
}

RzAsmPlugin rz_asm_plugin_ws = {
	.name = "ws",
	.desc = "Whitespace esotheric VM",
	.arch = "whitespace",
	.license = "LGPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ws,
	.version = R2_VERSION
};
#endif
