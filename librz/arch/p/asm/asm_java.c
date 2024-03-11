// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_core.h>

#include "java/jvm.h"
#include "java/assembler.h"

typedef struct java_asm_context_t {
	LookupSwitch ls;
	TableSwitch ts;
	ut16 switchop;
	ut64 pc;
	ut64 last;
	ut32 count;
} JavaAsmContext;

static void java_asm_update_context(JavaAsmContext *ctx) {
	ctx->count++;
	if (ctx->switchop == BYTECODE_AA_TABLESWITCH && ctx->count > ctx->ts.length) {
		ctx->switchop = BYTECODE_00_NOP;
	} else if (ctx->switchop == BYTECODE_AB_LOOKUPSWITCH && ctx->count > ctx->ls.npairs) {
		ctx->switchop = BYTECODE_00_NOP;
	}
}

static ut64 java_asm_find_method(RzAsm *a) {
	ut64 addr = a->pc;
	if (!a->binb.bin) {
		return addr;
	}

	RzBinSection *sec;
	void **it;
	RzBinObject *obj = rz_bin_cur_object(a->binb.bin);
	const RzPVector *vec = obj ? a->binb.get_sections(obj) : NULL;

	rz_pvector_foreach (vec, it) {
		sec = *it;
		ut64 from = sec->vaddr;
		ut64 to = from + sec->vsize;
		if (!(sec->perm & RZ_PERM_X) || addr < from || addr > to) {
			continue;
		}
		return sec->paddr;
	}

	return addr;
}

static int java_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	JavaAsmContext *ctx = (JavaAsmContext *)a->plugin_data;
	rz_strbuf_set(&op->buf_asm, "invalid");

	if (a->pc < ctx->last) {
		ctx->switchop = BYTECODE_00_NOP;
	}
	ctx->last = a->pc;
	switch (ctx->switchop) {
	case BYTECODE_AA_TABLESWITCH: {
		if (len < 4) {
			RZ_LOG_ERROR("[!] java_analysis: no enough data for lookupswitch case.\n");
			return -1;
		}
		op->size = 4;
		ut64 jump = ctx->pc + rz_read_be32(buf);
		rz_strbuf_setf(&op->buf_asm, "case %d: goto 0x%" PFMT64x, ctx->count + ctx->ts.low, jump);
		java_asm_update_context(ctx);
		return op->size;
	}
	case BYTECODE_AB_LOOKUPSWITCH: {
		if (len < 8) {
			RZ_LOG_ERROR("[!] java_analysis: no enough data for lookupswitch case.\n");
			return -1;
		}
		op->size = 8;
		st32 number = (st32)rz_read_be32(buf);
		ut64 jump = ctx->pc + rz_read_at_be32(buf, 4);
		rz_strbuf_setf(&op->buf_asm, "case %d: goto 0x%" PFMT64x, number, jump);
		java_asm_update_context(ctx);
		return op->size;
	}
	default:
		break;
	}

	JavaVM vm = { 0 };
	Bytecode bc = { 0 };

	rz_strbuf_set(&op->buf_asm, "invalid");

	ut64 section = java_asm_find_method(a);
	if (!jvm_init(&vm, buf, len, a->pc, section)) {
		RZ_LOG_ERROR("[!] java_disassemble: bad or invalid data.\n");
		return -1;
	}
	op->size = 1;
	if (jvm_fetch(&vm, &bc)) {
		op->size = bc.size;
		bytecode_snprint(&op->buf_asm, &bc);
		if (bc.opcode == BYTECODE_AA_TABLESWITCH) {
			ctx->count = 0;
			ctx->switchop = BYTECODE_AA_TABLESWITCH;
			ctx->ts = *((TableSwitch *)bc.extra);
			ctx->pc = a->pc;
		} else if (bc.opcode == BYTECODE_AB_LOOKUPSWITCH) {
			ctx->count = 0;
			ctx->switchop = BYTECODE_AB_LOOKUPSWITCH;
			ctx->ls = *((LookupSwitch *)bc.extra);
			ctx->pc = a->pc;
		}
		bytecode_clean(&bc);
	} else {
		RZ_LOG_ERROR("[!] java_disassemble: jvm fetch failed.\n");
		return -1;
	}
	return op->size;
}

static bool java_asm_init(void **user) {
	JavaAsmContext *ctx = RZ_NEW0(JavaAsmContext);
	if (!ctx) {
		return false;
	}
	*user = ctx;
	return true;
}

static bool java_asm_fini(void *user) {
	if (!user) {
		return false;
	}
	JavaAsmContext *ctx = (JavaAsmContext *)user;
	free(ctx);
	return true;
}

static int java_assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ut8 buffer[128];
	st32 written = 0;
	st32 slen = strlen(str);

	if (!java_assembler(str, slen, buffer, sizeof(buffer), a->pc, &written)) {
		return -1;
	}

	rz_strbuf_setbin(&ao->buf, (const ut8 *)&buffer, written);
	return written;
}

RzAsmPlugin rz_asm_plugin_java = {
	.name = "java",
	.desc = "Java bytecode disassembler",
	.arch = "java",
	.license = "LGPL-3",
	.author = "deroad",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.init = java_asm_init,
	.fini = java_asm_fini,
	.disassemble = &java_disassemble,
	.assemble = &java_assemble,
};
