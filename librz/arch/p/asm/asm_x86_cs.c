// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(x86_asm);

#include "asm_x86_vm.c"

static bool check_features(RzAsm *a, cs_insn *insn) {
	if (RZ_STR_ISEMPTY(a->features)) {
		return true;
	}
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	const char *name;
	int i;
	if (!insn || !insn->detail) {
		return true;
	}
	for (i = 0; i < insn->detail->groups_count; i++) {
		int id = insn->detail->groups[i];
		if (id < 128) {
			continue;
		}
		if (id == X86_GRP_MODE32) {
			continue;
		}
		if (id == X86_GRP_MODE64) {
			continue;
		}
		name = cs_group_name(ctx->handle, id);
		if (!name) {
			return true;
		}
		if (!strstr(a->features, name)) {
			return false;
		}
	}
	return true;
}

static int x86_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	int ret, n;
	ut64 off = a->pc;

	cs_mode mode = (a->bits == 64) ? CS_MODE_64 : (a->bits == 32) ? CS_MODE_32
		: (a->bits == 16)                                     ? CS_MODE_16
								      : 0;
	if (op) {
		op->size = 0;
	}
	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_X86, mode, &ctx->handle);
		if (ret) {
			return -1;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_UNSIGNED, CS_OPT_ON);
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	// always unsigned immediates (kernel addresses)
	// maybe rizin should have an option for this too?
	if (a->syntax == RZ_ASM_SYNTAX_MASM) {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
	} else if (a->syntax == RZ_ASM_SYNTAX_ATT) {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	} else {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	}
	if (!op) {
		return true;
	}
	op->size = 1;
	cs_insn *insn = NULL;
	n = cs_disasm(ctx->handle, (const ut8 *)buf, len, off, 1, &insn);
	if (op) {
		op->size = 0;
	}
	if (!check_features(a, insn)) {
		op->size = insn->size;
		rz_asm_op_set_asm(op, "illegal");
	}
	if (op->size == 0 && n > 0 && insn->size > 0) {
		char *ptrstr;
		op->size = insn->size;
		char *buf_asm = rz_str_newf("%s%s%s",
			insn->mnemonic, insn->op_str[0] ? " " : "",
			insn->op_str);
		ptrstr = strstr(buf_asm, "ptr ");
		if (ptrstr) {
			memmove(ptrstr, ptrstr + 4, strlen(ptrstr + 4) + 1);
		}

		if (a->bits == 16 && insn->id == X86_INS_JMP) {
			// https://github.com/capstone-engine/capstone/issues/111
			// according to the x86 manual: the upper two bytes of the EIP register are cleared.
			ut64 jump = insn->detail->x86.operands[0].imm;
			char find[128], repl[128];
			rz_strf(find, "%" PFMT64x, jump);
			jump &= UT16_MAX;
			jump |= (UT64_16U & off);
			rz_strf(repl, "%" PFMT64x, jump);
			buf_asm = rz_str_replace(buf_asm, find, repl, 0);
		}
		rz_asm_op_set_asm(op, buf_asm);
		free(buf_asm);
	} else {
		decompile_vm(a, op, buf, len);
	}
	if (a->syntax == RZ_ASM_SYNTAX_JZ) {
		char *buf_asm = rz_strbuf_get(&op->buf_asm);
		if (!strncmp(buf_asm, "je ", 3)) {
			memcpy(buf_asm, "jz", 2);
		} else if (!strncmp(buf_asm, "jne ", 4)) {
			memcpy(buf_asm, "jnz", 3);
		}
	}
	if (insn) {
		cs_free(insn, n);
	}
	return op->size;
}

static bool x86_sw_breakpoint(RzAsm *a, RzAsmOp *op) {
	// { 0, 1, 0, "\xcc" }, // valid for 16, 32, 64
	// { 0, 2, 0, "\xcd\x03" },
	rz_asm_op_set_buf(op, (const ut8 *)"\xcc", 1);
	return true;
}

RzAsmPlugin rz_asm_plugin_x86_cs = {
	.name = "x86",
	.desc = "X86/X86_64 Capstone-based disassembler",
	.license = "BSD",
	.cpus = "generic",
	.platforms = "generic",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.init = x86_asm_init,
	.fini = x86_asm_fini,
	.mnemonics = x86_asm_mnemonics,
	.disassemble = &x86_disassemble,
	.sw_breakpoint = x86_sw_breakpoint,
	.features = "vm,3dnow,aes,adx,avx,avx2,avx512,bmi,bmi2,cmov,"
		    "f16c,fma,fma4,fsgsbase,hle,mmx,rtm,sha,sse1,sse2,"
		    "sse3,sse41,sse42,sse4a,ssse3,pclmul,xop"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_cs,
	.version = RZ_VERSION
};
#endif
