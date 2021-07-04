// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone.h>

static csh cd = 0;
static int n = 0;

static bool the_end(void *p) {
	if (cd) {
		cs_close(&cd);
		cd = 0;
	}
	return true;
}

static int check_features(RzAsm *a, cs_insn *insn);

#include "cs_mnemonics.c"

#include "asm_x86_vm.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int mode, ret;
	ut64 off = a->pc;

	mode = (a->bits == 64) ? CS_MODE_64 : (a->bits == 32) ? CS_MODE_32
		: (a->bits == 16)                             ? CS_MODE_16
							      : 0;
	if (cd && mode != omode) {
		cs_close(&cd);
		cd = 0;
	}
	if (op) {
		op->size = 0;
	}
	omode = mode;
	if (cd == 0) {
		ret = cs_open(CS_ARCH_X86, mode, &cd);
		if (ret) {
			return 0;
		}
	}
	if (a->features && *a->features) {
		cs_option(cd, CS_OPT_DETAIL, CS_OPT_ON);
	} else {
		cs_option(cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	// always unsigned immediates (kernel addresses)
	// maybe rizin should have an option for this too?
#if CS_API_MAJOR >= 4
	cs_option(cd, CS_OPT_UNSIGNED, CS_OPT_ON);
#endif
	if (a->syntax == RZ_ASM_SYNTAX_MASM) {
#if CS_API_MAJOR >= 4
		cs_option(cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
#endif
	} else if (a->syntax == RZ_ASM_SYNTAX_ATT) {
		cs_option(cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	} else {
		cs_option(cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	}
	if (!op) {
		return true;
	}
	op->size = 1;
	cs_insn *insn = NULL;
	n = cs_disasm(cd, (const ut8 *)buf, len, off, 1, &insn);
	if (op) {
		op->size = 0;
	}
	if (a->features && *a->features) {
		if (!check_features(a, insn)) {
			op->size = insn->size;
			rz_asm_op_set_asm(op, "illegal");
		}
	}
	if (op->size == 0 && n > 0 && insn->size > 0) {
		char *ptrstr;
		op->size = insn->size;
		char *buf_asm = sdb_fmt("%s%s%s",
			insn->mnemonic, insn->op_str[0] ? " " : "",
			insn->op_str);
		ptrstr = strstr(buf_asm, "ptr ");
		if (ptrstr) {
			memmove(ptrstr, ptrstr + 4, strlen(ptrstr + 4) + 1);
		}
		rz_asm_op_set_asm(op, buf_asm);
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

RzAsmPlugin rz_asm_plugin_x86_cs = {
	.name = "x86",
	.desc = "Capstone X86 disassembler",
	.license = "BSD",
	.cpus = "generic",
	.platforms = "generic",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.fini = the_end,
	.mnemonics = mnemonics,
	.disassemble = &disassemble,
	.features = "vm,3dnow,aes,adx,avx,avx2,avx512,bmi,bmi2,cmov,"
		    "f16c,fma,fma4,fsgsbase,hle,mmx,rtm,sha,sse1,sse2,"
		    "sse3,sse41,sse42,sse4a,ssse3,pclmul,xop"
};

static int check_features(RzAsm *a, cs_insn *insn) {
	const char *name;
	int i;
	if (!insn || !insn->detail) {
		return 1;
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
		name = cs_group_name(cd, id);
		if (!name) {
			return 1;
		}
		if (!strstr(a->features, name)) {
			return 0;
		}
	}
	return 1;
}

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_cs,
	.version = RZ_VERSION
};
#endif
