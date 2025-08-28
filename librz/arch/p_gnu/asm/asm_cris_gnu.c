// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#if 0

Documentation
-------------
http://developer.axis.com/old/documentation/hw/etraxfs/des_ref/des_ref.pdf
http://developer.axis.com/old/documentation/hw/etraxfs/iop_howto/iop_howto.pdf

#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_asm.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <cris/cris_context.h>

static int cris_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info, void *data) {
	CrisContext *ctx = (CrisContext *)data;
	int delta = (memaddr - ctx->Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 8) {
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
	CrisContext *ctx = (CrisContext *)data;
	if (!ctx->buf_global) {
		return;
	}
	rz_strbuf_appendf(ctx->buf_global, "0x%08" PFMT64x, (ut64)address);
}

static int generic_fprintf_func(void *stream, void *data, const char *format, ...) {
	CrisContext *ctx = (CrisContext *)data;
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

bfd_boolean cris_parse_disassembler_options(disassemble_info *info, int distype);

// TODO: refactor the gnu code to have a getter instead of exposing so many disasm entrypoints
int print_insn_crisv10_v32_with_register_prefix(bfd_vma vma, disassemble_info *info, void *data);
int print_insn_crisv10_v32_without_register_prefix(bfd_vma vma, disassemble_info *info, void *data);
int print_insn_cris_with_register_prefix(bfd_vma vma, disassemble_info *info, void *data);
int print_insn_cris_without_register_prefix(bfd_vma vma, disassemble_info *info, void *data);
int print_insn_crisv32_with_register_prefix(bfd_vma vma, disassemble_info *info, void *data);
int print_insn_crisv32_without_register_prefix(bfd_vma vma, disassemble_info *info, void *data);

static int cris_gnu_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CrisContext *ctx = (CrisContext *)a->plugin_data;
	struct disassemble_info disasm_obj;
	int mode = 2;
	if (len < 4) {
		return -1;
	}
	ctx->buf_global = &op->buf_asm;
	ctx->Offset = a->pc;
	memcpy(ctx->bytes, buf, RZ_MIN(len, 8)); // TODO handle thumb

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.disassembler_options = (a->bits == 64) ? "64" : "";
	disasm_obj.buffer = ctx->bytes;
	disasm_obj.read_memory_func = &cris_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	if (a->cpu && *a->cpu) {
		// enum cris_disass_family { cris_dis_v0_v10, cris_dis_common_v10_v32, cris_dis_v32 };
		// 0: v0-v10
		// 1: v10-v32
		// 2: v32
		mode = 0;
		if (strstr(a->cpu, "v10")) {
			mode = 1;
		}
		if (strstr(a->cpu, "v32")) {
			mode = 2;
		}
	} else {
		mode = 2;
	}
	(void)cris_parse_disassembler_options(&disasm_obj, mode);
	if (a->syntax == RZ_ASM_SYNTAX_ATT) {
		switch (mode) {
		case 0:
			op->size = print_insn_cris_with_register_prefix((bfd_vma)ctx->Offset, &disasm_obj, ctx);
			break;
		case 1:
			op->size = print_insn_crisv10_v32_with_register_prefix((bfd_vma)ctx->Offset, &disasm_obj, ctx);
			break;
		default:
			op->size = print_insn_crisv32_with_register_prefix((bfd_vma)ctx->Offset, &disasm_obj, ctx);
			break;
		}
	} else {
		switch (mode) {
		case 0:
			op->size = print_insn_cris_without_register_prefix((bfd_vma)ctx->Offset, &disasm_obj, ctx);
			break;
		case 1:
			op->size = print_insn_crisv10_v32_without_register_prefix((bfd_vma)ctx->Offset, &disasm_obj, ctx);
			break;
		default:
			op->size = print_insn_crisv32_without_register_prefix((bfd_vma)ctx->Offset, &disasm_obj, ctx);
			break;
		}
	}
	if (op->size == -1) {
		rz_strbuf_set(&op->buf_asm, "(data)");
	}
	return op->size;
}

static bool cris_gnu_init(void **user) {
	CrisContext *ctx = RZ_NEW0(CrisContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool cris_gnu_fini(void *p) {
	CrisContext *ctx = (CrisContext *)p;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_cris_gnu = {
	.name = "cris",
	.arch = "cris",
	.cpus = "v0,v10,v32",
	.license = "GPL3",
	.author = "pancake",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Axis Communications 32-bit embedded processor disassembler",
	.disassemble = &cris_gnu_disassemble,
	.init = &cris_gnu_init,
	.fini = &cris_gnu_fini
};
