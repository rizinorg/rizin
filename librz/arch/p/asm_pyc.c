// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "../arch/pyc/pyc_dis.h"

static int disassemble(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
	pyc_opcodes *opcodes_cache = (pyc_opcodes *)a->plugin_data;
	RzList *shared = NULL;

	RzBin *bin = a->binb.bin;
	ut64 pc = a->pc;

	RzBinPlugin *plugin = bin && bin->cur && bin->cur->o ? bin->cur->o->plugin : NULL;

	if (plugin) {
		if (!strcmp(plugin->name, "pyc")) {
			shared = ((RzBinPycObj *)bin->cur->o->bin_obj)->shared;
		}
	}

	RzList *cobjs = NULL;

	if (shared) {
		cobjs = rz_list_get_n(shared, 0);
	}

	if (!opcodes_cache || !pyc_opcodes_equal(opcodes_cache, a->cpu)) {
		a->plugin_data = opcodes_cache = get_opcode_by_version(a->cpu);
		if (opcodes_cache == NULL) {
			RZ_LOG_ERROR("disassembler: pyc: unsupported pyc opcode cpu/version (asm.cpu=%s).\n", a->cpu);
			return len;
		}
		opcodes_cache->bits = a->bits;
	}
	int r = rz_pyc_disasm(opstruct, buf, cobjs, pc, opcodes_cache);
	opstruct->size = r;
	return r;
}

static bool pyc_asm_init(void **user) {
	*user = NULL;
	return true;
}

static bool pyc_asm_fini(void *user) {
	if (!user) {
		return false;
	}
	free_opcode((pyc_opcodes *)user);
	return true;
}

RzAsmPlugin rz_asm_plugin_pyc = {
	.name = "pyc",
	.arch = "pyc",
	.license = "LGPL3",
	.bits = 16 | 8,
	.desc = "PYC disassemble plugin",
	.disassemble = &disassemble,
	.init = &pyc_asm_init,
	.fini = &pyc_asm_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_pyc,
	.version = RZ_VERSION
};

#endif
