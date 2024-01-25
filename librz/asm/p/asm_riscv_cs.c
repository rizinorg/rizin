// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(riscv);

static int riscv_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	int ret = -1;
	cs_insn *insn;
	cs_mode mode = (a->bits == 64) ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
	op->size = 4;
	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_RISCV, mode, &ctx->handle);
		if (ret) {
			goto fin;
		}
		ctx->omode = mode;
		// cs_option (ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}
#if 0
	if (a->syntax == RZ_ASM_SYNTAX_REGNUM) {
		cs_option (ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
#endif
	int n = cs_disasm(ctx->handle, (ut8 *)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 2;
		goto fin;
	}
	if (insn->size < 1) {
		goto fin;
	}
	op->size = insn->size;
	rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	char *str = rz_asm_op_get_asm(op);
	if (str) {
		// remove the '$'<registername> in the string
		rz_str_replace_char(str, '$', 0);
	}
	cs_free(insn, n);
fin:
	return op->size;
}

RzAsmPlugin rz_asm_plugin_riscv_cs = {
	.name = "riscv.cs",
	.desc = "Capstone RISCV disassembler",
	.license = "BSD",
	.arch = "riscv",
	.cpus = "",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = riscv_init,
	.fini = riscv_fini,
	.disassemble = &riscv_disassemble,
	.mnemonics = riscv_mnemonics,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_riscv_cs,
	.version = RZ_VERSION
};
#endif
