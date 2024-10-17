// SPDX-FileCopyrightText: 2013-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// instruction set : http://www.tachyonsoft.com/inst390m.htm

#include <rz_asm.h>
#include <rz_lib.h>

#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(sysz);

#if CS_NEXT_VERSION < 6
#define SYSTEMZ_ARCH CS_ARCH_SYSZ
#else
#define SYSTEMZ_ARCH CS_ARCH_SYSTEMZ
#endif

static int sysz_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	int n, ret;
	ut64 off = a->pc;
	cs_insn *insn = NULL;
	cs_mode mode = CS_MODE_BIG_ENDIAN;
	op->size = 0;

	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(SYSTEMZ_ARCH, mode, &ctx->handle);
		if (ret) {
			return -1;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	n = cs_disasm(ctx->handle, (const ut8 *)buf, len, off, 1, &insn);
	if (n > 0) {
		if (insn->size > 0) {
			op->size = insn->size;
			rz_asm_op_setf_asm(op, "%s%s%s",
				insn->mnemonic, insn->op_str[0] ? " " : "",
				insn->op_str);
			char *str = rz_asm_op_get_asm(op);
			if (str) {
				char *ptrstr = strstr(str, "ptr ");
				if (ptrstr) {
					memmove(ptrstr, ptrstr + 4, strlen(ptrstr + 4) + 1);
				}
			}
		}
		cs_free(insn, n);
	} else {
		rz_asm_op_set_asm(op, "invalid");
		return -1;
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_sysz = {
	.name = "sysz",
	.desc = "SystemZ CPU disassembler",
	.license = "BSD",
	.arch = "sysz",
	.cpus = "z10,z196,zec12,z13,z14,z15,z16",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_BIG,
	.init = sysz_init,
	.fini = sysz_fini,
	.disassemble = &sysz_disassemble,
	.mnemonics = sysz_mnemonics,
};
