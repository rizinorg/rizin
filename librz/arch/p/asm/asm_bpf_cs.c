// SPDX-FileCopyrightText: 2026 Jagath-P <jagathp0210@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include "capstone.h"
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(bpf_asm);

static int bpf_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	cs_insn *insn;
	int n;
	cs_mode mode = CS_MODE_BPF_EXTENDED | (a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
	op->size = 8;
	if (ctx->omode != mode) {
		if (ctx->handle) {
			cs_close(&ctx->handle);
		}
		ctx->omode = mode;
	}
	if (!ctx->handle) {
		cs_err err = cs_open(CS_ARCH_BPF, mode, &ctx->handle);
		if (err != CS_ERR_OK) {
			rz_warn_if_reached();
			return -1;
		}
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	n = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		cs_free(insn, n);
		return -1;
	}
	if (insn->size != 8 && insn->size != 16) {
		cs_free(insn, n);
		return -1;
	}
	op->size = insn->size;
	if (insn->op_str[0]) {
		rz_asm_op_setf_asm(op, "%s %s", insn->mnemonic, insn->op_str);
	} else {
		rz_asm_op_set_asm(op, insn->mnemonic);
	}
	cs_free(insn, n);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_bpf_cs = {
	.name = "bpf",
	.author = "Jagath-P",
	.license = "LGPL3",
	.desc = "eBPF disassembler",
	.arch = "bpf",
	.bits = 64,
	.endian = RZ_SYS_ENDIAN_BIG | RZ_SYS_ENDIAN_LITTLE,
	.init = &bpf_asm_init,
	.fini = &bpf_asm_fini,
	.disassemble = &bpf_disassemble,
	.mnemonics = &bpf_asm_mnemonics
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_bpf_cs,
	.version = RZ_VERSION
};
#endif
