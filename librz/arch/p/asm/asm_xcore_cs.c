// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(xcore_asm);

static int xcore_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	cs_insn *insn;
	int n, ret = -1;
	cs_mode mode = a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	memset(op, 0, sizeof(RzAsmOp));
	op->size = 4;

	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_XCORE, mode, &ctx->handle);
		if (ret) {
			goto fin;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	n = cs_disasm(ctx->handle, (ut8 *)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	}
	ret = 4;
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;

	if (insn->op_str[0]) {
		rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	} else {
		rz_asm_op_set_asm(op, insn->mnemonic);
	}

// TODO: remove the '$'<registername> in the string
beach:
	cs_free(insn, n);
fin:
	return ret;
}

RzAsmPlugin rz_asm_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "XCore Capstone-based disassembler",
	.license = "BSD",
	.author = "pancake",
	.arch = "xcore",
	.cpus = "",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = &xcore_asm_init,
	.fini = &xcore_asm_fini,
	.disassemble = &xcore_disassemble,
	.mnemonics = &xcore_asm_mnemonics,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_xcore_cs,
	.version = RZ_VERSION
};
#endif
