// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_M68K_H
#define CAPSTONE_HAS_M68K 1
#else
#define CAPSTONE_HAS_M68K 0
#ifdef _MSC_VER
#pragma message("Cannot find capstone-m68k support")
#else
#warning Cannot find capstone-m68k support
#endif
#endif

#if CAPSTONE_HAS_M68K
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(m68k);

// Size of the longest instruction in bytes
#define M68K_LONGEST_INSTRUCTION 10

static int m68k_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf) {
		return -1;
	}
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	char *buf_asm = NULL;
	cs_insn *insn = NULL;
	int ret = 0, n = 0;
	cs_mode mode = a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

	// replace this with the asm.features?
	if (a->cpu && strstr(a->cpu, "68000")) {
		mode |= CS_MODE_M68K_000;
	}
	if (a->cpu && strstr(a->cpu, "68010")) {
		mode |= CS_MODE_M68K_010;
	}
	if (a->cpu && strstr(a->cpu, "68020")) {
		mode |= CS_MODE_M68K_020;
	}
	if (a->cpu && strstr(a->cpu, "68030")) {
		mode |= CS_MODE_M68K_030;
	}
	if (a->cpu && strstr(a->cpu, "68040")) {
		mode |= CS_MODE_M68K_040;
	}
	if (a->cpu && strstr(a->cpu, "68060")) {
		mode |= CS_MODE_M68K_060;
	}
	if (op) {
		op->size = 4;
	}
	if (mode != ctx->omode) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_M68K, mode, &ctx->handle);
		if (ret) {
			ret = -1;
			goto beach;
		}
		ctx->omode = mode;
	}
	if (RZ_STR_ISNOTEMPTY(a->features)) {
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	} else {
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	if (len > M68K_LONGEST_INSTRUCTION) {
		len = M68K_LONGEST_INSTRUCTION;
	}

	n = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		ret = -1;
		goto beach;
	}
	if (op) {
		op->size = 0;
	}
	if (insn->size < 1) {
		ret = -1;
		goto beach;
	}
	if (op && !op->size) {
		op->size = insn->size;
		buf_asm = rz_str_newf("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	}
	if (op && buf_asm) {
		buf_asm = rz_str_replace(buf_asm, "$", "0x", true);
		if (buf_asm) {
			rz_str_replace_char(buf_asm, '#', 0);
			rz_asm_op_set_asm(op, buf_asm);
		}
	}
	cs_free(insn, n);
beach:

	if (op && buf_asm) {
		if (!strncmp(buf_asm, "dc.w", 4)) {
			rz_asm_op_set_asm(op, "invalid");
		}
		ret = op->size;
	}
	free(buf_asm);
	return ret;
}

RzAsmPlugin rz_asm_plugin_m68k_cs = {
	.name = "m68k",
	.desc = "Capstone M68K disassembler",
	.cpus = "68000,68010,68020,68030,68040,68060",
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.init = m68k_init,
	.fini = m68k_fini,
	.disassemble = &m68k_disassemble,
	.mnemonics = &m68k_mnemonics,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_m68k_cs,
	.version = RZ_VERSION
};
#endif

#else
RzAsmPlugin rz_asm_plugin_m68k_cs = {
	.name = "m68k.cs (unsupported)",
	.desc = "Capstone M68K disassembler (unsupported)",
	.license = "BSD",
	.author = "pancake",
	.arch = "m68k",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_m68k_cs,
	.version = RZ_VERSION
};
#endif

#endif
