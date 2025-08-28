// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// TODO: add support for the assembler

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include <common_gnu/disas-asm.h>
#include "vax/vax.h"

typedef struct {
	unsigned long Offset;
	RzStrBuf *buf_global;
	const ut8 *bytes;
	int bytes_size;
} VaxContext;

static int vax_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info, void *data) {
	VaxContext *ctx = (VaxContext *)data;
	int delta = (memaddr - ctx->Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if (delta > length) {
		return -1;
	}
	memcpy(myaddr, ctx->bytes + delta, RZ_MIN(length, ctx->bytes_size));
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void generic_print_address_func(bfd_vma address, void *data, struct disassemble_info *info) {
	VaxContext *ctx = (VaxContext *)data;
	if (!ctx->buf_global) {
		return;
	}
	rz_strbuf_appendf(ctx->buf_global, "0x%08" PFMT64x, (ut64)address);
}

static int generic_fprintf_func(void *stream, void *data, const char *format, ...) {
	VaxContext *ctx = (VaxContext *)data;
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

static int vax_gnu_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	VaxContext *ctx = (VaxContext *)a->plugin_data;
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	ctx->buf_global = &op->buf_asm;
	ctx->bytes = buf;
	ctx->bytes_size = len;
	ctx->Offset = a->pc;

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.buffer = (ut8 *)ctx->bytes;
	disasm_obj.read_memory_func = &vax_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	op->size = print_insn_vax((bfd_vma)ctx->Offset, &disasm_obj, ctx);

	if (op->size == -1) {
		rz_asm_op_set_asm(op, "(data)");
	}
	return op->size;
}

static bool vax_gnu_init(void **user) {
	VaxContext *ctx = RZ_NEW0(VaxContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool vax_gnu_fini(void *p) {
	VaxContext *ctx = (VaxContext *)p;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_vax_gnu = {
	.name = "vax",
	.arch = "vax",
	.license = "GPL3",
	.bits = 8 | 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "DEC VAX disassembler",
	.disassemble = &vax_gnu_disassemble,
	.init = &vax_gnu_init,
	.fini = &vax_gnu_fini
};
