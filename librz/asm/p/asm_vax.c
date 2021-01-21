// SPDX-License-Identifier: LGPL-3.0-only

// TODO: add support for the assembler

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "disas-asm.h"
#include "../arch/vax/vax.h"

static unsigned long Offset = 0;
static RzStrBuf *buf_global = NULL;
static const ut8 *bytes = NULL;
static int bytes_size = 0;

static int vax_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if (delta > length) {
		return -1;
	}
	memcpy(myaddr, bytes + delta, RZ_MIN(length, bytes_size));
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
	bytes = buf;
	bytes_size = len;
	Offset = a->pc;

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.buffer = (ut8 *)bytes;
	disasm_obj.read_memory_func = &vax_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	op->size = print_insn_vax((bfd_vma)Offset, &disasm_obj);

	if (op->size == -1) {
		rz_asm_op_set_asm(op, "(data)");
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_vax = {
	.name = "vax",
	.arch = "vax",
	.license = "GPL",
	.bits = 8 | 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "VAX",
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_vax,
	.version = RZ_VERSION
};
#endif
