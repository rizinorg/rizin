// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "disas-asm.h"

int print_insn_big_nios2(bfd_vma address, disassemble_info *info);
int print_insn_little_nios2(bfd_vma address, disassemble_info *info);
static unsigned long Offset = 0;
static RzStrBuf *buf_global = NULL;
static unsigned char bytes[4];

static int nios2_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
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

static int disassemble(RzAsm *a, struct rz_asm_op_t *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy(bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.disassembler_options = "";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &nios2_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	if (disasm_obj.endian == BFD_ENDIAN_BIG) {
		op->size = print_insn_big_nios2((bfd_vma)Offset, &disasm_obj);
	} else {
		op->size = print_insn_little_nios2((bfd_vma)Offset, &disasm_obj);
	}
	if (op->size == -1) {
		rz_asm_op_set_asm(op, "(data)");
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_nios2 = {
	.name = "nios2",
	.arch = "nios2",
	.license = "GPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "NIOS II Embedded Processor",
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_nios2,
	.version = RZ_VERSION
};
#endif
