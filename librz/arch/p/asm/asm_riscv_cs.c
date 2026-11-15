// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_asm.h>
#include "asm_private.h"
#include <rz_lib.h>
#include <capstone/capstone.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(riscv_asm);

static int riscv_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	int ret = -1;
	cs_insn *insn;
	cs_mode mode = (a->bits == 64) ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
	mode |= mode_from_arch_string(a->cpu);
	mode |= resolve_features_from_list(a->features);
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

/*
 * \brief Places a breakpoint instruction at addr depending on the size of the original instruction there
 * The returned instruction bytes are either (in big endian hex notation):
 * 		0x00100073 → ebreak, or
 * 		0x9002 → c.ebreak
 * \param a  			[in]	The asm plugin.
 * \param addr			[in]	The address to place the breakpoint.
 * \param original		[in]	The original asm op at addr.
 * \param breakpoint	[out]	The asm op to store the breakpoint instruction.
 * \return	    		     	true if the breakpoint was placed successfully, false otherwise.
 */
static bool riscv_sw_breakpoint(const RzAsm *a, ut64 addr, const RzAsmOp *original, RzAsmOp *breakpoint) {
	if (original->size == 2) {
		rz_asm_op_set_buf(breakpoint, a->big_endian ? (const ut8 *)"\x90\x02" : (const ut8 *)"\x02\x90", 2);
	} else if (original->size == 4) {
		rz_asm_op_set_buf(breakpoint, a->big_endian ? (const ut8 *)"\x00\x10\x00\x73" : (const ut8 *)"\x73\x00\x10\x00", 4);
	} else {
		RZ_LOG_ERROR("Can't set breakpoint at 0x%" PFMT64x " : bad size (%ld bytes) of the instruction there, RISC-V instructions are expected to either be 2 or 4 bytes\n", addr, original->buf.len);
		return false;
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_riscv_cs = {
	.name = "riscv",
	.desc = "RISC-V Capstone-based disassembler",
	.license = "BSD",
	.arch = "riscv",
	.cpus = ARCH_RISCV_CPUS,
	.features = ARCH_RISCV_FEATURES,
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = riscv_asm_init,
	.fini = riscv_asm_fini,
	.disassemble = &riscv_disassemble,
	.mnemonics = riscv_asm_mnemonics,
	.sw_breakpoint = riscv_sw_breakpoint,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_riscv_cs,
	.version = RZ_VERSION
};
#endif
