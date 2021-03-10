// SPDX-FileCopyrightText: 2017-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2018 cgvwzq
// SPDX-License-Identifier: LGPL-3.0-only

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "../arch/wasm/wasm.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	WasmOp wop = { { 0 } };
	int ret = wasm_dis(&wop, buf, len);
	rz_asm_op_set_asm(op, wop.txt);
	free(wop.txt);
	op->size = ret;
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	ut8 *opbuf = (ut8 *)rz_strbuf_get(&op->buf);
	op->size = wasm_asm(buf, opbuf, 32); // XXX hardcoded opsize
	return op->size;
}

RzAsmPlugin rz_asm_plugin_wasm = {
	.name = "wasm",
	.author = "cgvwzq",
	.version = "0.1.0",
	.arch = "wasm",
	.license = "MIT",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "WebAssembly",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_wasm,
	.version = RZ_VERSION
};
#endif
