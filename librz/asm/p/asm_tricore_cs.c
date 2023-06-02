// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#include "../arch/tricore/tricore.inc"

#define TRICORE_LONGEST_INSTRUCTION  4
#define TRICORE_SHORTEST_INSTRUCTION 2

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || len < TRICORE_SHORTEST_INSTRUCTION) {
		return -1;
	}

	csh handle;
	cs_insn *insn;
	cs_mode mode = tricore_cpu_to_cs_mode(a->cpu);
	cs_err err = cs_open(CS_ARCH_TRICORE, mode, &handle);
	if (err) {
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
		return -1;
	}
	cs_option(handle, CS_OPT_DETAIL, RZ_STR_ISNOTEMPTY(a->features) ? CS_OPT_ON : CS_OPT_OFF);

	unsigned count = cs_disasm(handle, buf, len, a->pc, 1, &insn);
	if (count <= 0) {
		cs_close(&handle);
		return -1;
	}

	char *asmstr = rz_str_newf("%s%s%s", insn->mnemonic,
		RZ_STR_ISNOTEMPTY(insn->op_str) ? " " : "", insn->op_str);
	rz_asm_op_set_asm(op, asmstr);
	op->size = insn->size;

	free(asmstr);
	cs_close(&handle);
	cs_free(insn, count);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_tricore = {
	.name = "tricore",
	.arch = "tricore",
	.author = "billow",
	.license = "BSD",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens TriCore CPU",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tricore,
	.version = RZ_VERSION
};
#endif
