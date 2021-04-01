// SPDX-FileCopyrightText: 2017-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone.h>
static csh cd = 0;
#include "cs_mnemonics.c"

#ifdef CAPSTONE_TMS320C64X_H
#define CAPSTONE_HAS_TMS320C64X 1
#else
#define CAPSTONE_HAS_TMS320C64X 0
#warning Cannot find capstone-tms320c64x support
#endif

#if CAPSTONE_HAS_TMS320C64X

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	cs_insn *insn;
	int n = -1, ret = -1;
	int mode = 0;
	if (op) {
		memset(op, 0, sizeof(RzAsmOp));
		op->size = 4;
	}
	if (cd != 0) {
		cs_close(&cd);
	}
	ret = cs_open(CS_ARCH_TMS320C64X, mode, &cd);
	if (ret) {
		goto fin;
	}
	cs_option(cd, CS_OPT_DETAIL, CS_OPT_OFF);
	if (!op) {
		return 0;
	}
	n = cs_disasm(cd, buf, len, a->pc, 1, &insn);
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
	rz_asm_op_set_asm(op, sdb_fmt("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str));
	rz_str_replace_char(rz_strbuf_get(&op->buf_asm), '%', 0);
	rz_str_case(rz_strbuf_get(&op->buf_asm), false);
	cs_free(insn, n);
beach:
// cs_close (&cd);
fin:
	return ret;
}

RzAsmPlugin rz_asm_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320c64x disassembler",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG | RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.mnemonics = mnemonics
};

#else

RzAsmPlugin rz_asm_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320c64x disassembler (unsupported)",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.mnemonics = mnemonics
};

#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tms320c64x,
	.version = RZ_VERSION
};
#endif
