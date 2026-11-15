// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include "asm_private.h"
#include <rz_lib.h>
#include <capstone/capstone.h>

#include "cs_helper.h"
#include "m68k/m68k_cs.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(m68k_asm);

static int m68k_set_invalid(RzAsmOp *op, int size) {
	op->size = size;
	rz_asm_op_set_asm(op, "invalid");
	return size;
}

static int m68k_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || !op) {
		return -1;
	}
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	char *buf_asm = NULL;
	cs_insn *insn = NULL;
	size_t count = 0;
	int op_size = -1;
	cs_mode mode = rz_m68k_cs_mode(a->cpu);

	if (mode != ctx->omode) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = -1;
	}
	if (len < M68K_MIN_OP_SIZE) {
		goto beach;
	}

	if (!ctx->handle) {
		if (cs_open(CS_ARCH_M68K, mode, &ctx->handle) != CS_ERR_OK) {
			goto beach;
		}
		ctx->omode = mode;
	}
	if (RZ_STR_ISNOTEMPTY(a->features)) {
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	} else {
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	count = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
	if (count < 1 || !insn) {
		op_size = m68k_set_invalid(op, M68K_MIN_OP_SIZE);
		goto beach;
	}
	if (insn->id == M68K_INS_INVALID || insn->size < 1) {
		op_size = m68k_set_invalid(op, insn->size > 0 ? insn->size : M68K_MIN_OP_SIZE);
		goto beach;
	}
	op_size = insn->size;
	buf_asm = rz_str_newf("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	if (!buf_asm) {
		goto beach;
	}
	buf_asm = rz_str_replace(buf_asm, "$", "0x", true);
	rz_str_replace_char(buf_asm, '#', '\0');
	rz_asm_op_set_asm(op, buf_asm);
	free(buf_asm);
beach:
	op->size = op_size;
	if (insn) {
		cs_free(insn, count);
	}
	return op_size;
}

static char **m68k_cpu_descriptions() {
	static char *cpu_desc[] = {
		"68000", "Motorola 68000: 16/32-bit CISC microprocessor",
		"68010", "Motorola 68010: 16/32-bit microprocessors. Successor to Motoroloa 68000",
		"68020", "Motorola 68020: 32-bit microprocessor with added instructions and additional addressing modes",
		"68030", "Motorola 68030: Enhanced 32-bit microprocessor with integrated MMU",
		"68040", "Motorola 68040: High-performance 32-bit microprocessor with integrated FPU",
		"68060", "Motorola 68060: 32-bit microprocessor, highest performer in m68k series",
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
		"cpu32", "Motorola CPU32: 32-bit embedded-controller CPU core based on the 68020",
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		"coldfire", "Motorola ColdFire: 32-bit embedded-controller family based on the 68000 ISA",
		"cfv1", "Motorola ColdFire V1 core",
		"cfv2", "Motorola ColdFire V2 core",
		"cfv3", "Motorola ColdFire V3 core",
		"cfv4", "Motorola ColdFire V4 core",
		"cfv4e", "Motorola ColdFire V4e core with enhanced MAC and FPU features",
		"cfv5", "Motorola ColdFire V5 core",
#endif
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_m68k_cs = {
	.name = "m68k",
	.desc = "Motorola 68K Capstone-based disassembler",
	.cpus = "68000,68010,68020,68030,68040,68060"
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
		",cpu32"
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		",coldfire,cfv1,cfv2,cfv3,cfv4,cfv4e,cfv5"
#endif
	,
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.init = m68k_asm_init,
	.fini = m68k_asm_fini,
	.disassemble = &m68k_disassemble,
	.mnemonics = &m68k_asm_mnemonics,
	.get_cpu_desc = m68k_cpu_descriptions,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_m68k_cs,
	.version = RZ_VERSION
};
#endif
