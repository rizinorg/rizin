/* rizin, Sharp LH5801 disassembler.
 * (C) Copyright 2014-2015 jn, published under the LGPLv3 */

#include "../../arch/lh5801/lh5801.c"
#include <rz_asm.h>
#include <rz_types.h>
#include <rz_lib.h>

static int disassemble(RzAsm *as, RzAsmOp *op, const ut8 *buf, int len) {
	struct lh5801_insn insn = { 0 };
	if (!op) {
		return 0;
	}
	int consumed = lh5801_decode(&insn, buf, len);
	if (consumed == -1 || consumed == 0) {
		rz_strbuf_set(&op->buf_asm, "invalid");
		op->size = 1;
		return 0;
	}
	char buf_asm[128] = { 0 };
	lh5801_print_insn(buf_asm, sizeof(buf_asm), &insn);
	rz_strbuf_set(&op->buf_asm, buf_asm);
	op->size = consumed;
	//op->payload = lh5801_insn_descs[insn.type].format & 3;
	// ^ MAYBE?
	return op->size;
}

RzAsmPlugin rz_asm_plugin_lh5801 = {
	.name = "lh5801",
	.arch = "LH5801",
	.license = "LGPL3",
	.bits = 8,
	.endian = RZ_SYS_ENDIAN_NONE,
	.desc = "SHARP LH5801 disassembler",
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_lh5801,
	.version = RZ_VERSION
};
#endif
