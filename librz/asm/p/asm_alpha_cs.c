// SPDX-FileCopyrightText: 2023 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!a || !op) {
		return 0;
	}

	cs_insn *insn;
	int n;
	cs_mode mode = (a->big_endian) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

	static csh handle = 0;

	if (handle == 0) {
		cs_err err = cs_open(CS_ARCH_ALPHA, mode, &handle);
		if (err) {
			RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
			return op->size;
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	memset(op, 0, sizeof(RzAsmOp));
	op->size = 4;
	n = cs_disasm(handle, (ut8 *)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 4;
		return op->size;
	}
	if (insn->size < 1) {
		return op->size;
	}
	op->size = insn->size;
	char *asmstr = rz_str_newf("%s%s%s", insn->mnemonic,
		RZ_STR_ISNOTEMPTY(insn->op_str) ? " " : "", insn->op_str);
	rz_asm_op_set_asm(op, asmstr);
	free(asmstr);
	cs_free(insn, n);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_alpha_cs = {
	.name = "alpha",
	.desc = "Capstone Alpha disassembler",
	.license = "LGPL3",
	.arch = "alpha",
	.bits = 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_alpha_cs,
	.version = RZ_VERSION
};
#endif
