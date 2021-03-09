// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone.h>

#if CSNEXT

static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	cs_insn *insn;
	int mode = (a->bits == 64) ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
	op->size = 4;
	if (cd != 0) {
		cs_close(&cd);
	}
	int ret = cs_open(CS_ARCH_RISCV, mode, &cd);
	if (ret) {
		goto fin;
	}
#if 0
	if (a->syntax == RZ_ASM_SYNTAX_REGNUM) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
#endif
	int n = cs_disasm(cd, (ut8 *)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 2;
		goto beach;
	}
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	char *str = rz_str_newf("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	if (str) {
		rz_str_replace_char(str, '$', 0);
		// remove the '$'<registername> in the string
		rz_asm_op_set_asm(op, str);
		free(str);
	}
	cs_free(insn, n);
beach:
	// cs_close (&cd);
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
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_riscv_cs,
	.version = RZ_VERSION
};
#endif

#else
RzAsmPlugin rz_asm_plugin_riscv_cs = {
	0
};
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.version = RZ_VERSION
};
#endif

#endif
