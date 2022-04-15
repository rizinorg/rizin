// SPDX-FileCopyrightText: 2022 Jules Maselbas <jmaselbas@kalray.eu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "../../arch/kvx/kvx.h"

/* The bundle store several instruction that cannot be disassembled
 * individually, but each instructions should be printed on it's own
 * line for readability. The function kvx_next_insn does all the magic
 * of figuring out if the next instruction is already decoded in this
 * bundle or if it needs to decode a new bundle */

static bool kvx_init(void **priv) {
	bundle_t *ctx = RZ_NEW0(bundle_t);
	if (!ctx) {
		return false;
	}
	*priv = ctx;
	return true;
}

static bool kvx_fini(void *priv) {
	if (!priv) {
		return false;
	}
	free(priv);
	return true;
}

static int kvx_dis(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	rz_return_val_if_fail(a && op, -1);
	rz_return_val_if_fail(a->plugin_data, -1);
	char strasm[64];
	ut64 addr = a->pc;
	bundle_t *bundle = a->plugin_data;

	if (addr % 4) {
		goto unaligned;
	}

	insn_t *insn = kvx_next_insn(bundle, addr, buf, len);
	if (!insn || !insn->opc) {
		goto invalid;
	}
	op->size = insn->len * sizeof(ut32);

	if (insn->opc) {
		kvx_instr_print(insn, addr, strasm, sizeof(strasm));
		rz_strbuf_set(&op->buf_asm, strasm);
	}

	return op->size;

invalid:
	rz_strbuf_set(&op->buf_asm, "invalid");
	op->size = 4;
	return op->size;

unaligned:
	op->size = 4 - (addr % 4);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_kvx = {
	.name = "kvx",
	.desc = "Kalray VLIW core",
	.arch = "kvx",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.init = kvx_init,
	.fini = kvx_fini,
	.disassemble = kvx_dis,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_kvx,
	.version = RZ_VERSION
};
#endif
