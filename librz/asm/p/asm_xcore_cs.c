// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode, n, ret = -1;
	mode = a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	memset(op, 0, sizeof(RzAsmOp));
	op->size = 4;
	ret = cs_open(CS_ARCH_XCORE, mode, &handle);
	if (ret) {
		goto fin;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm(handle, (ut8 *)buf, len, a->pc, 1, &insn);
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
	rz_asm_op_set_asm(op, sdb_fmt("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str));
// TODO: remove the '$'<registername> in the string
beach:
	cs_free(insn, n);
	cs_close(&handle);
fin:
	return ret;
}

RzAsmPlugin rz_asm_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCore disassembler",
	.license = "BSD",
	.author = "pancake",
	.arch = "xcore",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_xcore_cs,
	.version = RZ_VERSION
};
#endif
