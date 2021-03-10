// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "../arch/pyc/pyc_dis.h"

static pyc_opcodes *opcodes_cache = NULL;

static int disassemble(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
	RzList *shared = NULL;

	RzBin *bin = a->binb.bin;
	ut64 pc = a->pc;

	RzBinPlugin *plugin = bin && bin->cur && bin->cur->o ? bin->cur->o->plugin : NULL;

	if (plugin) {
		if (!strcmp(plugin->name, "pyc")) {
			shared = bin->cur->o->bin_obj;
		}
	}
	RzList *cobjs = rz_list_get_n(shared, 0);
	RzList *interned_table = rz_list_get_n(shared, 1);
	if (!opcodes_cache || !pyc_opcodes_equal(opcodes_cache, a->cpu)) {
		opcodes_cache = get_opcode_by_version(a->cpu);
		opcodes_cache->bits = a->bits;
	}
	int r = rz_pyc_disasm(opstruct, buf, cobjs, interned_table, pc, opcodes_cache);
	opstruct->size = r;
	return r;
}

static bool finish(void *user) {
	if (opcodes_cache) {
		free_opcode(opcodes_cache);
		opcodes_cache = NULL;
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_pyc = {
	.name = "pyc",
	.arch = "pyc",
	.license = "LGPL3",
	.bits = 16 | 8,
	.desc = "PYC disassemble plugin",
	.disassemble = &disassemble,
	.fini = &finish,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_pyc,
	.version = RZ_VERSION
};

#endif
