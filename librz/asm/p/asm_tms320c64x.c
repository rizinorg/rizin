// SPDX-FileCopyrightText: 2017-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_TMS320C64X_H
#define CAPSTONE_HAS_TMS320C64X 1
#else
#define CAPSTONE_HAS_TMS320C64X 0
#warning Cannot find capstone-tms320c64x support
#endif

#if CAPSTONE_HAS_TMS320C64X
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(tms320c64x);

static int tms320c64x_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	cs_insn *insn;
	int n = -1, ret = -1;
	if (op) {
		memset(op, 0, sizeof(RzAsmOp));
		op->size = 4;
	}
	if (ctx->omode != 0) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_TMS320C64X, 0, &ctx->handle);
		if (ret) {
			goto fin;
		}
		ctx->omode = 0;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	if (!op) {
		return 0;
	}
	n = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
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
	rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	char *str = rz_asm_op_get_asm(op);
	if (str) {
		rz_str_replace_char(str, '%', 0);
		rz_str_case(str, false);
	}
	cs_free(insn, n);
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
	.init = tms320c64x_init,
	.fini = tms320c64x_fini,
	.disassemble = &tms320c64x_disassemble,
	.mnemonics = tms320c64x_mnemonics,
};

#else

RzAsmPlugin rz_asm_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320c64x disassembler (unsupported)",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
};

#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tms320c64x,
	.version = RZ_VERSION
};
#endif
