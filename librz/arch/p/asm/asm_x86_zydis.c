// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <Zydis/Zydis.h>

#include "asm_x86_vm.c"

typedef struct {
	ZydisMachineMode omode;
	ZydisStackWidth owidth;
	ZydisFormatter oformat;
	int obits;
} ZydisContext;

static bool x86_zydis_asm_init(void **user) {
	ZydisContext *zydx = RZ_NEW0(ZydisContext);
	if (!zydx) {
		return false;
	}
	zydx->omode = -1;
	*user = zydx;
	return true;
}

static bool x86_zydis_asm_fini(void *p) {
	if (!p) {
		return true;
	}
	ZydisContext *zydx = (ZydisContext *)p;
	free(zydx);
	return true;
}

static char *x86_zydis_asm_mnemonics(RzAsm *a, int id, bool json) {
	if (!a->plugin_data) {
		return NULL;
	}
	ZydisContext *zydx = (ZydisContext *)a->plugin_data;
	int i;
	a->cur->disassemble(a, NULL, NULL, -1);
	if (id != -1) {
		const char *vname = ZydisMnemonicGetString(id);
		if (json) {
			return vname ? rz_str_newf("[\"%s\"]\n", vname) : NULL;
		}
		return rz_str_dup(vname);
	}
	RzStrBuf *buf = rz_strbuf_new("");
	if (json) {
		rz_strbuf_append(buf, "[");
	}
	for (i = 1;; i++) {
		const char *op = ZydisMnemonicGetString(i);
		if (!op) {
			break;
		}
		if (json) {
			rz_strbuf_append(buf, "\"");
		}
		rz_strbuf_append(buf, op);
		if (json) {
			if (ZydisMnemonicGetString(i + 1)) {
				rz_strbuf_append(buf, "\",");
			} else {
				rz_strbuf_append(buf, "\"]\n");
			}
		} else {
			rz_strbuf_append(buf, "\n");
		}
	}
	return rz_strbuf_drain(buf);
}

static int x86_zydis_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ZydisContext *zydx = (ZydisContext *)a->plugin_data;
	int ret, n;
	ut64 off = a->pc;

	ZydisMachineMode mode = (a->bits == 64) ? ZYDIS_MACHINE_MODE_LONG_64 : (a->bits == 32) ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32
		: (a->bits == 16)                                                              ? ZYDIS_MACHINE_MODE_LONG_COMPAT_16
											       : 0;
	ZydisStackWidth width = (a->bits == 64) ? ZYDIS_STACK_WIDTH_64 : (a->bits == 32) ? ZYDIS_STACK_WIDTH_32
		: (a->bits == 16)                                                        ? ZYDIS_STACK_WIDTH_16
											 : 0;
	if (op) {
		op->size = 0;
	}
	if (zydx->omode != mode || zydx->owidth != width) {
		zydx->omode = -1;
		zydx->owidth = -1;
	}

	ZydisFormatter format;
	if (a->syntax == RZ_ASM_SYNTAX_MASM) {
		ZydisFormatterInit(&format, ZYDIS_FORMATTER_STYLE_INTEL_MASM);
	} else if (a->syntax == RZ_ASM_SYNTAX_ATT) {
		ZydisFormatterInit(&format, ZYDIS_FORMATTER_STYLE_ATT);
	} else {
		ZydisFormatterInit(&format, ZYDIS_FORMATTER_STYLE_INTEL);
	}
	ZydisFormatterSetProperty(&format, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	ZydisFormatterSetProperty(&format, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_FALSE);
	ZydisFormatterSetProperty(&format, ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE, ZYAN_FALSE);
	if (!op) {
		return true;
	}
	op->size = 1;
	ZydisDecodedInstruction zydecode;
	ZydisDecodedOperand zydeop[ZYDIS_MAX_OPERAND_COUNT];
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, mode, width);
	bool check = false;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&decoder, buf, len, &zydecode, zydeop))) {
		op->size = 0;
		check = true;
		break;
	}
	if (op->size == 0 && check && zydecode.length > 0) {
		char *ptrstr;
		op->size = zydecode.length;
		char buf_asm[256];
		ZydisFormatterFormatInstruction(&format, &zydecode, zydeop,
			zydecode.operand_count_visible, buf_asm, sizeof(buf_asm), off, ZYAN_NULL);
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
	return op->size;
}

RzAsmPlugin rz_asm_plugin_x86_zydis = {
	.name = "x86",
	.desc = "Zydis X86 disassembler",
	.license = "MIT",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.init = x86_zydis_asm_init,
	.fini = x86_zydis_asm_fini,
	.mnemonics = x86_zydis_asm_mnemonics,
	.disassemble = &x86_zydis_disassemble,
	.features = "vm,3dnow,aes,adx,avx,avx2,avx512,bmi,bmi2,cmov,"
		    "f16c,fma,fma4,fsgsbase,hle,mmx,rtm,sha,sse1,sse2,"
		    "sse3,sse41,sse42,sse4a,ssse3,pclmul,xop"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_zydis,
	.version = RZ_VERSION
};
#endif