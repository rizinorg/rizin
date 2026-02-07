// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(riscv_asm);

static int riscv_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	int ret = -1;
	cs_insn *insn;
	cs_mode mode = (a->bits == 64) ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
	mode |= mode_from_arch_string(a->cpu);
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
	.name = "riscv",
	.desc = "RISC-V Capstone-based disassembler",
	.license = "BSD",
	.arch = "riscv",
	.cpus = NULL,
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = riscv_asm_init,
	.fini = riscv_asm_fini,
	.disassemble = &riscv_disassemble,
	.mnemonics = riscv_asm_mnemonics,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_riscv_cs,
	.version = RZ_VERSION
};
#endif
