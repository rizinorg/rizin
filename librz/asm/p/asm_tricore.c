// SPDX-FileCopyrightText: 2016 pancake <pancake@nopcode.org>
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
static ut8 bytes[128];
enum {
	TRICORE_GENERIC = 0x00000000,
	TRICORE_RIDER_A = 0x00000001,
	TRICORE_RIDER_B = 0x00000002,
	TRICORE_RIDER_D = TRICORE_RIDER_B,
	TRICORE_V2 = 0x00000004,
	TRICORE_PCP = 0x00000010,
	TRICORE_PCP2 = 0x00000020
};

static int cpu_to_mach(char *cpu_type) {
	if (cpu_type && *cpu_type) {
		if (!strcmp(cpu_type, "generic")) {
			return TRICORE_GENERIC;
		}
		if (!strcmp(cpu_type, "rider-a")) {
			return TRICORE_RIDER_A;
		}
		if ((!strcmp(cpu_type, "rider-b")) || (!strcmp(cpu_type, "rider-d"))) {
			return TRICORE_RIDER_B;
		}
		if (!strcmp(cpu_type, "v2")) {
			return TRICORE_V2;
		}
		if (!strcmp(cpu_type, "pcp")) {
			return TRICORE_PCP;
		}
		if (!strcmp(cpu_type, "pcp2")) {
			return TRICORE_PCP2;
		}
	}
	return TRICORE_RIDER_B;
}

static int tricore_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = memaddr - Offset;
	if (delta >= 0 && length + delta < sizeof(bytes)) {
		memcpy(myaddr, bytes + delta, length);
	}
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
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy(bytes, buf, RZ_MIN(len, 8)); // TODO handle thumb

	/* prepare disassembler */
	memset(&disasm_obj, '\0', sizeof(struct disassemble_info));
	disasm_obj.disassembler_options = (a->bits == 64) ? "64" : "";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &tricore_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	// cpu type
	disasm_obj.mach = cpu_to_mach(a->cpu);

	op->size = print_insn_tricore((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1) {
		rz_asm_op_set_asm(op, " (data)");
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_tricore = {
	.name = "tricore",
	.arch = "tricore",
	.license = "GPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens TriCore CPU",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tricore,
	.version = RZ_VERSION
};
#endif
