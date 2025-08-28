// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include <common_gnu/disas-asm.h>

typedef struct {
	unsigned long Offset;
	RzStrBuf *buf_global;
	unsigned char bytes[4];
} HppaContext;

static int hppa_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info, void *data) {
	// XXX rewrite needed
#if 0
	if (length == 4)  {
		// swap
		myaddr[0] = bytes[3];
		myaddr[1] = bytes[2];
		myaddr[2] = bytes[1];
		myaddr[3] = bytes[0];
		return 0;
	}
#endif
	HppaContext *ctx = (HppaContext *)data;
	int delta = (memaddr - ctx->Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	memcpy(myaddr, ctx->bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void generic_print_address_func(bfd_vma address, void *data, struct disassemble_info *info) {
	HppaContext *ctx = (HppaContext *)data;
	if (!ctx->buf_global) {
		return;
	}
	rz_strbuf_appendf(ctx->buf_global, "0x%08" PFMT64x, (ut64)address);
}

static int generic_fprintf_func(void *stream, void *data, const char *format, ...) {
	HppaContext *ctx = (HppaContext *)data;
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

static int hppa_gnu_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	HppaContext *ctx = (HppaContext *)a->plugin_data;
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	ctx->buf_global = &op->buf_asm;
	ctx->Offset = a->pc;
	memcpy(ctx->bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.disassembler_options = (a->bits == 64) ? "64" : "";
	disasm_obj.buffer = ctx->bytes;
	disasm_obj.read_memory_func = &hppa_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_BIG;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	op->size = print_insn_hppa((bfd_vma)ctx->Offset, &disasm_obj, ctx);
	if (op->size == -1) {
		rz_strbuf_set(&op->buf_asm, "(data)");
	}
	return op->size;
}

static bool hppa_gnu_init(void **user) {
	HppaContext *ctx = RZ_NEW0(HppaContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool hppa_gnu_fini(void *p) {
	HppaContext *ctx = (HppaContext *)p;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_hppa_gnu = {
	.name = "hppa",
	.arch = "hppa",
	.license = "GPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.desc = "HP PA-RISC",
	.disassemble = &hppa_gnu_disassemble,
	.init = &hppa_gnu_init,
	.fini = &hppa_gnu_fini
};
