// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rl78_instr.h"

#include <rz_util.h>
#include <rz_types.h>

static const char *RL78_STRINGS_OPERATIONS[] = {
	[RL78_OPERATION_ADD] = "add",
	[RL78_OPERATION_ADDC] = "addc",
	[RL78_OPERATION_ADDW] = "addw",
	[RL78_OPERATION_AND] = "and",
	[RL78_OPERATION_AND1] = "and1",
	[RL78_OPERATION_BC] = "bc",
	[RL78_OPERATION_BF] = "bf",
	[RL78_OPERATION_BH] = "bh",
	[RL78_OPERATION_BNC] = "bnc",
	[RL78_OPERATION_BNH] = "bnh",
	[RL78_OPERATION_BNZ] = "bnz",
	[RL78_OPERATION_BR] = "br",
	[RL78_OPERATION_BRK] = "brk",
	[RL78_OPERATION_BT] = "bt",
	[RL78_OPERATION_BTCLR] = "btclr",
	[RL78_OPERATION_BZ] = "bz",
	[RL78_OPERATION_CALL] = "call",
	[RL78_OPERATION_CALLT] = "callt",
	[RL78_OPERATION_CLRB] = "clrb",
	[RL78_OPERATION_CLRW] = "clrw",
	[RL78_OPERATION_CLR1] = "clr1",
	[RL78_OPERATION_CMP] = "cmp",
	[RL78_OPERATION_CMPS] = "cmps",
	[RL78_OPERATION_CMPW] = "cmpw",
	[RL78_OPERATION_CMP0] = "cmp0",
	[RL78_OPERATION_DEC] = "dec",
	[RL78_OPERATION_DECW] = "decw",
	[RL78_OPERATION_DI] = "di",
	[RL78_OPERATION_DIVHU] = "divhu",
	[RL78_OPERATION_DIVWU] = "divwu",
	[RL78_OPERATION_EI] = "ei",
	[RL78_OPERATION_HALT] = "halt",
	[RL78_OPERATION_INC] = "inc",
	[RL78_OPERATION_INCW] = "incw",
	[RL78_OPERATION_MACH] = "mach",
	[RL78_OPERATION_MACHU] = "machu",
	[RL78_OPERATION_MOV] = "mov",
	[RL78_OPERATION_MOVS] = "movs",
	[RL78_OPERATION_MOVW] = "movw",
	[RL78_OPERATION_MOV1] = "mov1",
	[RL78_OPERATION_MULH] = "mulh",
	[RL78_OPERATION_MULHU] = "mulhu",
	[RL78_OPERATION_MULU] = "mulu",
	[RL78_OPERATION_NOP] = "nop",
	[RL78_OPERATION_NOT1] = "not1",
	[RL78_OPERATION_ONEB] = "oneb",
	[RL78_OPERATION_ONEW] = "onew",
	[RL78_OPERATION_OR] = "or",
	[RL78_OPERATION_OR1] = "or1",
	[RL78_OPERATION_POP] = "pop",
	[RL78_OPERATION_PUSH] = "push",
	[RL78_OPERATION_RET] = "ret",
	[RL78_OPERATION_RETB] = "retb",
	[RL78_OPERATION_RETI] = "reti",
	[RL78_OPERATION_ROL] = "rol",
	[RL78_OPERATION_ROLC] = "rolc",
	[RL78_OPERATION_ROLWC] = "rolwc",
	[RL78_OPERATION_ROR] = "ror",
	[RL78_OPERATION_RORC] = "rorc",
	[RL78_OPERATION_SAR] = "sar",
	[RL78_OPERATION_SARW] = "sarw",
	[RL78_OPERATION_SEL] = "sel",
	[RL78_OPERATION_SET1] = "set1",
	[RL78_OPERATION_SHL] = "shl",
	[RL78_OPERATION_SHLW] = "shlw",
	[RL78_OPERATION_SHR] = "shr",
	[RL78_OPERATION_SHRW] = "shrw",
	[RL78_OPERATION_SKC] = "skc",
	[RL78_OPERATION_SKH] = "skh",
	[RL78_OPERATION_SKNC] = "sknc",
	[RL78_OPERATION_SKNH] = "sknh",
	[RL78_OPERATION_SKNZ] = "sknz",
	[RL78_OPERATION_SKZ] = "skz",
	[RL78_OPERATION_STOP] = "stop",
	[RL78_OPERATION_SUB] = "sub",
	[RL78_OPERATION_SUBC] = "subc",
	[RL78_OPERATION_SUBW] = "subw",
	[RL78_OPERATION_XCH] = "xch",
	[RL78_OPERATION_XCHW] = "xchw",
	[RL78_OPERATION_XOR] = "xor",
	[RL78_OPERATION_XOR1] = "xor1",
};

bool rl78_instr_to_string(RzStrBuf RZ_OUT *dst, const RL78Instr RZ_BORROW *instr) {
	rz_return_val_if_fail(instr->operation > 0 &&
			instr->operation < _RL78_OPERATION_COUNT,
		false);

	// 16 characters suffice for each operand
	RzStrBuf buf_op0, buf_op1;
	bool has_op0 = instr->op0.type != RL78_OP_TYPE_NONE;
	bool has_op1 = instr->op1.type != RL78_OP_TYPE_NONE;

	if (has_op0 && !rl78_operand_to_string(&buf_op0, &instr->op0)) {
		rz_return_val_if_reached(false);
	}

	if (has_op1 && !rl78_operand_to_string(&buf_op1, &instr->op1)) {
		rz_return_val_if_reached(false);
	}

	if (has_op0 && has_op1) {
		rz_strbuf_appendf(dst, "%s %s, %s",
			RL78_STRINGS_OPERATIONS[instr->operation],
			buf_op0.buf, buf_op1.buf);
	} else if (has_op0) {
		rz_strbuf_appendf(dst, "%s %s",
			RL78_STRINGS_OPERATIONS[instr->operation],
			buf_op0.buf);
	} else {
		rz_strbuf_appendf(dst, "%s",
			RL78_STRINGS_OPERATIONS[instr->operation]);
	}

	return true;
}
