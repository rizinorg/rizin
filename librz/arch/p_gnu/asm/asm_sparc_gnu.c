// SPDX-FileCopyrightText: 2009-2014 nibble <nibble.ds@gmail.com>
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

static unsigned long Offset = 0;
static RzStrBuf *buf_global = NULL;
static unsigned char bytes[4];

static int sparc_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	memcpy(myaddr, bytes, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

typedef struct {
	struct disassemble_info disasm_obj;
} SparcGnuContext;

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	SparcGnuContext *ctx = (SparcGnuContext *)a->plugin_data;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	// disasm inverted
	ut32 newbuf = rz_swap_ut32(*(ut32 *)buf);
	memcpy(bytes, &newbuf, 4); // TODO handle thumb

	rz_strbuf_set(&op->buf_asm, "");
	/* prepare disassembler */
	memset(&ctx->disasm_obj, '\0', sizeof(struct disassemble_info));
	ctx->disasm_obj.buffer = bytes;
	ctx->disasm_obj.read_memory_func = &sparc_buffer_read_memory;
	ctx->disasm_obj.symbol_at_address_func = &symbol_at_address;
	ctx->disasm_obj.memory_error_func = &memory_error_func;
	ctx->disasm_obj.print_address_func = &generic_print_address_func;
	ctx->disasm_obj.endian = a->big_endian;
	ctx->disasm_obj.fprintf_func = &generic_fprintf_func;
	ctx->disasm_obj.stream = stdout;
	ctx->disasm_obj.mach = ((a->bits == 64)
			? bfd_mach_sparc_v9b
			: 0);

	op->size = print_insn_sparc((bfd_vma)Offset, &ctx->disasm_obj);

	if (!strncmp(rz_strbuf_get(&op->buf_asm), "unknown", 7)) {
		rz_asm_op_set_asm(op, "invalid");
	}
	if (op->size == -1) {
		rz_asm_op_set_asm(op, "(data)");
	}
	return op->size;
}

static bool sparc_gnu_init(void **user) {
	SparcGnuContext *ctx = RZ_NEW0(SparcGnuContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool sparc_gnu_fini(void *user) {
	SparcGnuContext *ctx = (SparcGnuContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_sparc_gnu = {
	.name = "sparc.gnu",
	.arch = "sparc",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_BIG | RZ_SYS_ENDIAN_LITTLE,
	.license = "GPL3",
	.init = sparc_gnu_init,
	.fini = sparc_gnu_fini,
	.desc = "Sun SPARC disassembler",
	.disassemble = &disassemble,
};
