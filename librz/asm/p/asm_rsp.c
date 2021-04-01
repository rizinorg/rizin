// SPDX-FileCopyrightText: 2016 bobby.smiles32 <bobby.smiles32@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
// TODO: add assembler

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>

#include <stdarg.h>
#include <stdio.h>

#include "rsp_idec.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	rsp_instruction rz_instr;
	int i;

	/* all instructions are 32bit words */
	if (len < 4) {
		op->size = 0;
		return 0;
	}
	op->size = 4;

	ut32 iw = rz_read_ble32(buf, a->big_endian);
	rz_instr = rsp_instruction_decode(a->pc, iw);

	rz_strbuf_append(&op->buf_asm, rz_instr.mnemonic);
	for (i = 0; i < rz_instr.noperands; i++) {
		rz_strbuf_append(&op->buf_asm, (i == 0) ? " " : ", ");

		switch (rz_instr.operands[i].type) {
		case RSP_OPND_GP_REG:
			rz_strbuf_append(&op->buf_asm, rsp_gp_reg_soft_names[rz_instr.operands[i].u]);
			break;
		case RSP_OPND_OFFSET:
		case RSP_OPND_TARGET:
			rz_strbuf_appendf(&op->buf_asm, "0x%08" PFMT64x, rz_instr.operands[i].u);
			break;
		case RSP_OPND_ZIMM: {
			int shift = (rz_instr.operands[i].u & ~0xffff) ? 16 : 0;
			rz_strbuf_appendf(&op->buf_asm, "0x%04" PFMT64x,
				rz_instr.operands[i].u >> shift);
		} break;
		case RSP_OPND_SIMM:
			rz_strbuf_appendf(&op->buf_asm, "%s0x%04" PFMT64x,
				(rz_instr.operands[i].s < 0) ? "-" : "",
				(rz_instr.operands[i].s < 0) ? -rz_instr.operands[i].s : rz_instr.operands[i].s);
			break;
		case RSP_OPND_SHIFT_AMOUNT:
			rz_strbuf_appendf(&op->buf_asm, "%" PFMT64u, rz_instr.operands[i].u);
			break;
		case RSP_OPND_BASE_OFFSET:
			rz_strbuf_appendf(&op->buf_asm, "%s0x%04x(%s)",
				(rz_instr.operands[i].s < 0) ? "-" : "",
				(ut32)((rz_instr.operands[i].s < 0) ? -rz_instr.operands[i].s : rz_instr.operands[i].s),
				rsp_gp_reg_soft_names[rz_instr.operands[i].u]);
			break;
		case RSP_OPND_C0_REG:
			rz_strbuf_append(&op->buf_asm, rsp_c0_reg_soft_names[rz_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_CREG:
			rz_strbuf_append(&op->buf_asm, rsp_c2_creg_names[rz_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_ACCU:
			rz_strbuf_append(&op->buf_asm, rsp_c2_accu_names[rz_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_VREG:
			rz_strbuf_append(&op->buf_asm, rsp_c2_vreg_names[rz_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_VREG_BYTE:
		case RSP_OPND_C2_VREG_SCALAR:
			rz_strbuf_appendf(&op->buf_asm, "%s[%u]", rsp_c2_vreg_names[rz_instr.operands[i].u],
				(ut32)rz_instr.operands[i].s);
			break;
		case RSP_OPND_C2_VREG_ELEMENT:
			rz_strbuf_appendf(&op->buf_asm, "%s%s", rsp_c2_vreg_names[rz_instr.operands[i].u], rsp_c2_vreg_element_names[rz_instr.operands[i].s]);
			break;
		default: /* should not happend */
			rz_strbuf_append(&op->buf_asm, "???");
			break;
		}
	}

	return op->size;
}

RzAsmPlugin rz_asm_plugin_rsp = {
	.name = "rsp",
	.desc = "Reality Signal Processor",
	.arch = "rsp",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BI, /* For conveniance, we don't force BIG endian but allow both to be used */
	.license = "LGPL3",
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_rsp,
	.version = RZ_VERSION
};
#endif
