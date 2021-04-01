// SPDX-FileCopyrightText: 2009-2014 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "disas-asm.h"
#include <mybfd.h>

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

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	static struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	// disasm inverted
	rz_mem_swapendian(bytes, buf, 4); // TODO handle thumb

	rz_strbuf_set(&op->buf_asm, "");
	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &sparc_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	disasm_obj.mach = ((a->bits == 64)
			? bfd_mach_sparc_v9b
			: 0);

	op->size = print_insn_sparc((bfd_vma)Offset, &disasm_obj);

	if (!strncmp(rz_strbuf_get(&op->buf_asm), "unknown", 7)) {
		rz_asm_op_set_asm(op, "invalid");
	}
	if (op->size == -1) {
		rz_asm_op_set_asm(op, "(data)");
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_sparc_gnu = {
	.name = "sparc.gnu",
	.arch = "sparc",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_BIG | RZ_SYS_ENDIAN_LITTLE,
	.license = "GPL3",
	.desc = "Scalable Processor Architecture",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_sparc_gnu,
	.version = RZ_VERSION
};
#endif
