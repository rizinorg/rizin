// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "pyc/pyc_dis.h"

static int pyc_asm_disassemble(RzAsm *a, RzAsmOp *aop, const ut8 *buf, int len) {
	pyc_context_t *ctx = (pyc_context_t *)a->plugin_data;
	RzList *shared = NULL;

	RzBin *bin = a->binb.bin;
	ut64 pc = a->pc;

	RzBinPlugin *plugin = bin && bin->cur && bin->cur->o ? bin->cur->o->plugin : NULL;

	if (plugin && !strcmp(plugin->name, "pyc")) {
		shared = ((RzBinPycObj *)bin->cur->o->bin_obj)->shared;
	}

	RzList *cobjs = NULL;

	if (shared) {
		cobjs = rz_list_get_n(shared, 0);
	}

	if (!ctx->cache || RZ_STR_NE(ctx->version, a->cpu)) {
		if (!pyc_context_set_opcode_by_version(a->cpu, ctx)) {
			RZ_LOG_ERROR("disassembler: pyc: unsupported pyc opcode cpu/version (asm.cpu=%s).\n", a->cpu);
			return -1;
		}
		ctx->cache->bits = a->bits;
	}
	int r = rz_pyc_disasm(aop, buf, cobjs, pc, ctx->cache);
	aop->size = r;
	return r;
}

static bool pyc_asm_fini(void *user) {
	pyc_context_free((pyc_context_t *)user);
	return true;
}

static bool pyc_asm_init(void **user) {
	pyc_context_t *context = RZ_NEW0(pyc_context_t);
	if (!context) {
		return false;
	}

	*user = context;
	return true;
}

RzAsmPlugin rz_asm_plugin_pyc = {
	.name = "pyc",
	.arch = "pyc",
	.license = "LGPL3",
	.bits = 16 | 8,
	.desc = "Python bytecode (PYC) disassembler",
	.disassemble = &pyc_asm_disassemble,
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
