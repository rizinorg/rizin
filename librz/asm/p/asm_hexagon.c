// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: 96e220e6886868d6663d966ecc396befffc355e7
// LLVM commit date: 2022-01-05 11:01:52 +0000 (ISO 8601 format)
// Date of code generation: 2022-01-24 07:53:55-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_arch.h"

/**
 * \brief Disassembles a hexagon opcode, write info to op and returns its size.
 *
 * \param a The current RzAsm struct.
 * \param op The RzAsmOp which is be filled with the reversed opcode information.
 * \param buf The buffer with the opcode.
 * \param l The size to read from the buffer.
 * \return int Size of the reversed opcode.
 */
static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	ut32 addr = (ut32)a->pc;
	HexReversedOpcode rev = { .action = HEXAGON_DISAS, .ana_op = NULL, .asm_op = op };

	hexagon_reverse_opcode(a, &rev, buf, addr);

	return op->size;
}

RzAsmPlugin rz_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "xvilka",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_hexagon
};
#endif
