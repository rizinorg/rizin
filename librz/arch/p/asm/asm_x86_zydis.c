// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024-2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

#if USE_SYS_ZYDIS
#include <Zydis/Zydis.h>
#else
#include <Zydis.h>
#endif

#include "asm_x86_vm.c"

typedef struct {
	ZydisMachineMode omode;
	ZydisStackWidth owidth;
	ZydisFormatter oformat;
	size_t obits;
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
	rz_return_val_if_fail(a && a->cur, NULL);
	if (!a->plugin_data) {
		return NULL;
	}
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
	for (int i = 1;; i++) {
		const char *op = ZydisMnemonicGetString(i);
		if (!op) {
			break;
		}
		if (json) {
			rz_strbuf_append(buf, "\"");
		}
		rz_strbuf_append(buf, op);
		if (!json) {
			rz_strbuf_append(buf, "\n");
			continue;
		}
		if (ZydisMnemonicGetString(i + 1)) {
			rz_strbuf_append(buf, "\",");
		} else {
			rz_strbuf_append(buf, "\"]\n");
		}
	}
	return rz_strbuf_drain(buf);
}

static int x86_zydis_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	rz_return_val_if_fail(a, 0);
	ZydisContext *zydx = (ZydisContext *)a->plugin_data;
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
	ZydisFormatterSetProperty(&format, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, ZYAN_TRUE);
	ZydisFormatterSetProperty(&format, ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE, ZYDIS_PADDING_DISABLED);
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
		char buf_asm[256] = { 0 };
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
	return op->size;
}

static bool x86_sw_breakpoint(RzAsm *a, RzAsmOp *op) {
	// { 0, 1, 0, "\xcc" }, // valid for 16, 32, 64
	// { 0, 2, 0, "\xcd\x03" },
	rz_asm_op_set_buf(op, (const ut8 *)"\xcc", 1);
	return true;
}

RzAsmPlugin rz_asm_plugin_x86_zydis = {
	.name = "x86",
	.desc = "X86/X86_64 Zydis-based disassembler",
	.license = "MIT",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.init = x86_zydis_asm_init,
	.fini = x86_zydis_asm_fini,
	.mnemonics = x86_zydis_asm_mnemonics,
	.disassemble = &x86_zydis_disassemble,
	.sw_breakpoint = x86_sw_breakpoint,
	.features = "adox_adcx,aes,amd3dnow,amd3dnow_prefetch,amd_invlpgb,amx_bf16,"
		    "amx_fp16,amx_int8,amx_tile,avx,avx2,avx2gather,avx512evex,avx512vex,avxaes,"
		    "avx_ifma,avx_ne_convert,avx_vnni,avx_vnni_int16,avx_vnni_int8,base,bmi1,bmi2,"
		    "cet,cldemote,clflushopt,clfsh,clwb,clzero,enqcmd,f16c,fma,fma4,fred,gfni,"
		    "hreset,icache_prefetch,invpcid,keylocker,keylocker_wide,knc,knce,kncv,lkgs,"
		    "longmode,lzcnt,mcommit,mmx,monitor,monitorx,movbe,movdir,mpx,msrlist,padlock,"
		    "pause,pbndkb,pclmulqdq,pcommit,pconfig,pku,prefetchwt1,pt,rao_int,rdpid,rdpru,"
		    "rdrand,rdseed,rdtscp,rdwrfsgs,rtm,serialize,sgx,sgx_enclv,sha,sha512,sm3,sm4,"
		    "smap,smx,snp,sse,sse2,sse3,sse4,sse4a,ssse3,svm,tbm,tdx,tsx_ldtrk,uintr,vaes,"
		    "vmfunc,vpclmulqdq,vtx,waitpkg,wrmsrns,x87,xop,xsave,xsavec,xsaveopt,xsaves"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_zydis,
	.version = RZ_VERSION
};
#endif
