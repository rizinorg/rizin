// SPDX-FileCopyrightText: 2023 Yaroslav Yashin <yaroslav.yashin@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RzAsm *asm_context, RzAsmOp *op, const ut8 *buf, int len) {
	RZ_LOG_DEBUG("%s\n", "asm_evm_cs.c:disassemble")
	cs_insn *insn;
	int n = -1, ret = -1;
	int mode = CS_MODE_LITTLE_ENDIAN;
	if (op) {
		memset(op, 0, sizeof(RzAsmOp));
		op->size = 4;
	}
	if (cd != 0) {
		cs_close(&cd);
	}
	ret = cs_open(CS_ARCH_EVM, mode, &cd);
	if (ret) {
		goto fin;
	}
	cs_option(cd, CS_OPT_DETAIL, CS_OPT_OFF);
	if (!op) {
		return 0;
	}
	if (asm_context->big_endian) {
		n = cs_disasm(cd, buf, len, asm_context->pc, 1, &insn);
	}
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	} else {
		ret = 4;
	}
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	char *buf_asm = sdb_fmt("%s%s%s",
		insn->mnemonic, insn->op_str[0] ? " " : "",
		insn->op_str);
	rz_str_replace_char(buf_asm, '%', 0);
	rz_asm_op_set_asm(op, buf_asm);
	// TODO: remove the '$'<registername> in the string
	cs_free(insn, n);
beach:
	cs_close(&cd);
fin:
	return ret;
}

RzAsmPlugin rz_asm_plugin_evm_cs = {
	.name = "evm.cs",
	.desc = "Capstone EVM disassembler",
	.license = "BSD",
	.arch = "evm",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	// .mnemonics = mnemonics
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_evm_cs,
	.version = RZ_VERSION
};
#endif
