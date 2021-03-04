// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "disas-asm.h"

static unsigned long Offset = 0;
static RzStrBuf *buf_global = NULL;
static unsigned char bytes[4];

static int hppa_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
#if 0 // XXX rewrite needed
	if (length == 4)  {
		// swap
		myaddr[0] = bytes[3];
		myaddr[1] = bytes[2];
		myaddr[2] = bytes[1];
		myaddr[3] = bytes[0];
		return 0;
	}
#endif
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	memcpy(myaddr, bytes + delta, length);
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

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy(bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.disassembler_options = (a->bits == 64) ? "64" : "";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &hppa_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_BIG;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	op->size = print_insn_hppa((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1) {
		rz_strbuf_set(&op->buf_asm, "(data)");
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_hppa_gnu = {
	.name = "hppa",
	.arch = "hppa",
	.license = "GPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.desc = "HP PA-RISC",
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_hppa_gnu,
	.version = RZ_VERSION
};
#endif
