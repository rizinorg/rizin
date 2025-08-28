// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <common_gnu/disas-asm.h>
#include <common_gnu/mybfd.h>

typedef struct {
	struct disassemble_info disasm_obj;
	ut32 Offset;
	RzStrBuf *buf_global;
	int buf_len;
	ut8 bytes[32];
} ArcContext;

/* extern */
int decodeInstr(bfd_vma address, disassemble_info *info);
int ARCTangent_decodeInstr(bfd_vma address, disassemble_info *info, void *data);
int ARCompact_decodeInstr(bfd_vma address, disassemble_info *info, void *data);

static int arc_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info, void *data) {
	ArcContext *ctx = (ArcContext *)data;
	int delta = (memaddr - ctx->Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > sizeof(ctx->bytes)) {
		return -1;
	}
	memcpy(myaddr, ctx->bytes + delta, RZ_MIN(ctx->buf_len - delta, length));
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void generic_print_address_func(bfd_vma address, void *data, struct disassemble_info *info) {
	ArcContext *ctx = (ArcContext *)data;
	if (!ctx->buf_global) {
		return;
	}
	rz_strbuf_appendf(ctx->buf_global, "0x%08" PFMT64x, (ut64)address);
}

static int generic_fprintf_func(void *stream, void *data, const char *format, ...) {
	ArcContext *ctx = (ArcContext *)data;
	int ret;
	va_list ap;
	if (!ctx->buf_global || !format) {
		return 0;
	}
	va_start(ap, format);
	ret = rz_strbuf_vappendf(ctx->buf_global, format, ap);
	va_end(ap);
	return ret;
}

static int arc_gnu_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ArcContext *ctx = (ArcContext *)a->plugin_data;
	if (len < 2) {
		return -1;
	}
	ctx->buf_global = &op->buf_asm;
	ctx->Offset = a->pc;
	if (len > sizeof(ctx->bytes)) {
		len = sizeof(ctx->bytes);
	}
	memcpy(ctx->bytes, buf, len); // TODO handle compact
	ctx->buf_len = len;
	/* prepare disassembler */
	memset(&ctx->disasm_obj, '\0', sizeof(struct disassemble_info));
	ctx->disasm_obj.buffer = ctx->bytes;
	ctx->disasm_obj.buffer_length = len;
	ctx->disasm_obj.read_memory_func = &arc_buffer_read_memory;
	ctx->disasm_obj.symbol_at_address_func = &symbol_at_address;
	ctx->disasm_obj.memory_error_func = &memory_error_func;
	ctx->disasm_obj.print_address_func = &generic_print_address_func;
	ctx->disasm_obj.endian = !a->big_endian;
	ctx->disasm_obj.fprintf_func = &generic_fprintf_func;
	ctx->disasm_obj.stream = stdout;
	ctx->disasm_obj.mach = 0;
	rz_strbuf_set(&op->buf_asm, "");
	if (a->bits == 16) {
		op->size = ARCompact_decodeInstr((bfd_vma)ctx->Offset, &ctx->disasm_obj, a->plugin_data);
	} else {
		op->size = ARCTangent_decodeInstr((bfd_vma)ctx->Offset, &ctx->disasm_obj, a->plugin_data);
	}
	if (op->size == -1) {
		rz_strbuf_set(&op->buf_asm, "(data)");
	}
	return op->size;
}

static bool arc_gnu_init(void **user) {
	ArcContext *ctx = RZ_NEW0(ArcContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool arc_gnu_fini(void *p) {
	ArcContext *ctx = (ArcContext *)p;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_arc_gnu = {
	.name = "arc",
	.arch = "arc",
	.bits = 16 | 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "Argonaut RISC Core",
	.init = &arc_gnu_init,
	.fini = &arc_gnu_fini,
	.disassemble = &arc_gnu_disassemble,
	.license = "GPL3"
};
