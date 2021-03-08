// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_core.h>

//#include "../../bin/format/java/class.h"
#include "../arch/java/code.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	RzBinJavaObj *obj = NULL;
	RzBin *bin = a->binb.bin;
	RzBinPlugin *plugin = bin && bin->cur && bin->cur->o ? bin->cur->o->plugin : NULL;
	if (plugin && plugin->name) {
		if (!strcmp(plugin->name, "java")) { // XXX slow
			obj = bin->cur->o->bin_obj; //o;
			//eprintf("Handling: %s disasm.\n", b->cur.file);
		}
	}
	char buf_asm[256];
	op->size = rz_java_disasm(obj, a->pc, buf, len, buf_asm, sizeof(buf_asm));
	rz_strbuf_set(&op->buf_asm, buf_asm);
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *input) {
	// TODO: get class info from bin if possible
	// XXX wrong usage of strbuf_get here
	return op->size = rz_java_assemble(a->pc, (ut8 *)rz_strbuf_get(&op->buf), input);
}

RzAsmPlugin rz_asm_plugin_java = {
	.name = "java",
	.desc = "Java bytecode",
	.arch = "java",
	.license = "Apache",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_java,
	.version = RZ_VERSION
};
#endif
