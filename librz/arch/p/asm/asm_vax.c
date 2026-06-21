// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "asm_private.h"

#include "vax/vax.h"

/**
 * \brief Disassemble a single VAX instruction (the RzAsmPlugin callback).
 * \param a the RzAsm instance (provides the program counter via a->pc)
 * \param op receives the rendered assembly text and instruction size
 * \param buf the instruction bytes
 * \param len number of valid bytes in \p buf
 * \return the instruction length in bytes, or -1 on bad arguments
 */
static int vax_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!a || !op || !buf || len < 1) {
		return -1;
	}
	VaxInst inst;
	int size = rz_vax_decode(&inst, buf, len, a->pc);
	if (size < 1 || !inst.name) {
		rz_asm_op_set_asm(op, "invalid");
		return op->size = (size > 0) ? size : 1;
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_vax_format(&inst, &sb);
	rz_asm_op_set_asm(op, rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);
	return op->size = size;
}

RzAsmPlugin rz_asm_plugin_vax = {
	.name = "vax",
	.license = "LGPL3",
	.desc = "DEC VAX-11 disassembler",
	.author = "xvilka",
	.arch = "vax",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &vax_disassemble,
};
