// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <mips/mips_assembler.h>
#include "capstone.h"
#include "cs_helper.h"
#include "rz_util/rz_log.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(mips_asm);

static int mips_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	cs_insn *insn;
	cs_mode mode = 0;
	int n, ret = -1;
	if (!op) {
		return 0;
	}

	if (!cs_mode_from_cpu(a->cpu, a->features, a->bits, a->big_endian, &mode)) {
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
		op->size = mode & (CS_MODE_MICRO | CS_MODE_NANOMIPS | CS_MODE_MIPS16) ? 2 : 4;
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
	ut8 *opbuf = (ut8 *)rz_strbuf_get(&op->buf);
	int ret = mips_assemble_opcode(str, a->pc, opbuf);
	if (a->big_endian) {
		ut8 *buf = opbuf;
		ut8 tmp = buf[0];
		buf[0] = buf[3];
		buf[3] = tmp;
		tmp = buf[1];
		buf[1] = buf[2];
		buf[2] = tmp;
	}
	return ret;
}

RzAsmPlugin rz_asm_plugin_mips = {
	.name = "mips",
	.desc = "Capstone MIPS disassembler",
	.license = "BSD",
	.arch = "mips",
	.cpus = MIPS_CPUS,
	.features = MIPS_FEATURES,
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = mips_asm_init,
	.fini = mips_asm_fini,
	.disassemble = &mips_disassemble,
	.mnemonics = mips_asm_mnemonics,
	.assemble = &mips_assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_mips,
	.version = RZ_VERSION
};
#endif
