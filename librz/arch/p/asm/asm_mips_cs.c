// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <mips/mips_internal.h>
#include <capstone/capstone.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(mips_asm);

static int mips_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	cs_insn *insn;
	cs_mode mode = 0;
	int n, ret = -1;
	if (!op) {
		return 0;
	}

	if (!cs_mode_from_cpu(a->cpu, a->bits, a->big_endian, &mode, NULL)) {
		rz_asm_op_set_asm(op, "invalid");
		return -1;
	}

	memset(op, 0, sizeof(RzAsmOp));
	op->size = 4;
	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_MIPS, mode, &ctx->handle);
		if (ret) {
			RZ_LOG_ERROR("failed to open capstone\n");
			goto fin;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
#if CS_NEXT_VERSION > 5
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NO_DOLLAR);
#endif
	}
	if (a->syntax == RZ_ASM_SYNTAX_REGNUM) {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	n = cs_disasm(ctx->handle, (ut8 *)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
#if CS_NEXT_VERSION < 6
		op->size = mode & CS_MODE_MICRO ? 2 : 4;
#else
		op->size = mode & (CS_MODE_MICRO | CS_MODE_NANOMIPS | CS_MODE_MIPS16) ? 2 : 4;
#endif
		goto fin;
	}
	if (insn->size < 1) {
		goto fin;
	}
	op->size = insn->size;
	rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);

#if CS_NEXT_VERSION < 6
	// CS_OPT_SYNTAX_NO_DOLLAR is not available before capstone 6
	char *str = rz_asm_op_get_asm(op);
	if (str) {
		// remove the '$'<registername> in the string
		rz_str_replace_char(str, '$', 0);
	}
#endif
	cs_free(insn, n);
fin:
	return op->size;
}

static int mips_assemble(RzAsm *a, RzAsmOp *op, const char *str) {
	return mips_assemble_opcode(str, a->pc, &op->buf, a->big_endian);
}

static char **mips_cpu_descriptions() {
	static char *cpu_desc[] = {
		"mips3", "MIPS III architecture.",
		"mips1", "MIPS I architecture",
		"mips2", "MIPS II architecture",
		"mips32r2", "MIPS32 Release 2 architecture",
		"mips32r3", "MIPS32 Release 3 architecture",
		"mips32r5", "MIPS32 Release 5 architecture",
		"mips32r6", "MIPS32 Release 6 architecture",
		"mips4", "MIPS IV architecture",
		"mips5", "MIPS V architecture",
		"mips64r2", "MIPS64 Release 2 architecture",
		"mips64r3", "MIPS64 Release 3 architecture",
		"mips64r5", "MIPS64 Release 5 architecture",
		"mips64r6", "MIPS64 Release 6 architecture",
		"octeon", "OCTEON architecture (also known as cnMIPS)",
		"octeonp", "OCTEON+ architecture (also known as cnMIPS+)",
		"nanomips", "nanoMIPS architecture",
		"nms1", "nanoMIPS Release 1 architecture",
		"i7200", "nanoMIPS i7200 architecture",
		"micromips", "microMIPS architecture",
		"micro32r3", "microMIPS32 Release 3 architecture",
		"micro32r6", "microMIPS32 Release 6 architecture",
		"r2300", "R2300 MIPS cpu",
		"r2600", "R2600 MIPS cpu",
		"r2800", "R2800 MIPS cpu",
		"r2000a", "R2000A MIPS cpu",
		"r2000", "R2000 MIPS cpu",
		"r3000a", "R3000A MIPS cpu",
		"r3000", "R3000 MIPS cpu",
		"r10000", "R10000 MIPS cpu",
		"noptr64", "Special MIPS configuration to disable support for 64-bit pointers",
		"nofloat", "Special MIPS configuration to disable support for floating-points",
		NULL
	};

	return cpu_desc;
}

static bool mips_sw_breakpoint(RzAsm *a, RzAsmOp *op) {
	// mips32/64
	// { 32, 4, 0, "\x0d\x00\x00\x00" },
	// { 32, 4, 1, "\x00\x00\x00\x0d" },
	// { 64, 4, 0, "\x0d\x00\x00\x00" },
	// { 64, 4, 1, "\x00\x00\x00\x0d" },
	rz_asm_op_set_buf(op, a->big_endian ? (const ut8 *)"\x00\x00\x00\x0d" : (const ut8 *)"\x0d\x00\x00\x00", 4);
	return true;
}

RzAsmPlugin rz_asm_plugin_mips_cs = {
	.name = "mips",
	.desc = "MIPS Capstone-based disassembler",
	.license = "BSD",
	.arch = "mips",
	.cpus = MIPS_CPUS,
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = mips_asm_init,
	.fini = mips_asm_fini,
	.disassemble = &mips_disassemble,
	.mnemonics = mips_asm_mnemonics,
	.assemble = &mips_assemble,
	.get_cpu_desc = mips_cpu_descriptions,
	.sw_breakpoint = mips_sw_breakpoint,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_mips_cs,
	.version = RZ_VERSION
};
#endif
