// SPDX-FileCopyrightText: 2014-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(sparc_asm);

static int sparc_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	cs_insn *insn;
	int n = -1, ret = -1;
	int mode = 0;
	if (a->big_endian) {
		mode = CS_MODE_BIG_ENDIAN;
	}
	if (a->cpu && *a->cpu) {
		if (RZ_STR_EQ(a->cpu, "v9")) {
			mode |= CS_MODE_V9;
		}
		if (a->bits == 64) {
			mode |= CS_MODE_64;
		} else {
			mode |= CS_MODE_32;
		}
	}
	if (op) {
		memset(op, 0, sizeof(RzAsmOp));
		op->size = 4;
	}
	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_SPARC, mode, &ctx->handle);
		if (ret) {
			goto fin;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	if (!op) {
		return 0;
	}
	if (a->big_endian) {
		n = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
	}
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 4;
		ret = -1;
		goto fin;
	} else {
		ret = 4;
	}
	if (insn->size < 1) {
		goto fin;
	}
	op->size = insn->size;
	rz_asm_op_setf_asm(op, "%s%s%s",
		insn->mnemonic, insn->op_str[0] ? " " : "",
		insn->op_str);
	char *buf_asm = rz_asm_op_get_asm(op);
	if (buf_asm) {
		rz_str_replace_char(buf_asm, '%', 0);
		// TODO: remove the '$'<registername> in the string
	}
	cs_free(insn, n);
fin:
	return ret;
}

static char **sparc_cpu_descriptions() {
	static char *cpu_desc[] = {
		"v9", "SPARC V9: 64-bit RISC architecture specification",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_sparc_cs = {
	.name = "sparc",
	.desc = "Sun SPARC Capstone-based disassembler",
	.license = "BSD",
	.arch = "sparc",
	.cpus = "v9,v8",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_BIG | RZ_SYS_ENDIAN_LITTLE,
	.init = sparc_asm_init,
	.fini = sparc_asm_fini,
	.disassemble = &sparc_disassemble,
	.mnemonics = sparc_asm_mnemonics,
	.get_cpu_desc = sparc_cpu_descriptions,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_sparc_cs,
	.version = RZ_VERSION
};
#endif
