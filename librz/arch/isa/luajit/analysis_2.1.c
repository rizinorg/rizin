// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

int luajit_analysis_op(RzAnalysis *anal, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len) {
	if (len < 4) {
		return 0;
	}

	memset(op, 0, sizeof(RzAnalysisOp));
	op->jump = UT64_MAX; // TODO: Supress WARNING of invalid address, 0x0 (op initialized from memeset above) will be invalid address for JMP.
	op->fail = UT64_MAX;
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;
	const ut32 instr = luajit_build_instruction(data);

	st32 jump_offset = (st32)LUAJIT_GET_D(instr) - 0x8000;
	op->addr = addr;
	op->size = 4;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->eob = false;

	if (LUAJIT_GET_OPCODE(instr) > 10000) {
		return op->size;
	}

	switch (LUAJIT_GET_OPCODE(instr)) {
	// Comparison ops
	case OP_ISLT:
	case OP_ISGE:
	case OP_ISLE:
	case OP_ISGT:
	case OP_ISEQV:
	case OP_ISNEV:
	case OP_ISEQS:
	case OP_ISNES:
	case OP_ISEQN:
	case OP_ISNEN:
	case OP_ISEQP:
	case OP_ISNEP:
	// Unary test and copy ops
	case OP_ISTC:
	case OP_ISFC:
	case OP_IST:
	case OP_ISF:
	case OP_ISTYPE:
	case OP_ISNUM:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		op->jump = addr + 8;
		op->fail = addr + 4;
		break;
	// Unary ops
	case OP_MOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case OP_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case OP_UNM:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case OP_LEN:
		op->type = RZ_ANALYSIS_OP_TYPE_LENGTH;
		break;
	// Binary ops
	case OP_ADDVN:
	case OP_ADDNV:
	case OP_ADDVV:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case OP_SUBVN:
	case OP_SUBNV:
	case OP_SUBVV:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case OP_MULVN:
	case OP_MULNV:
	case OP_MULVV:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case OP_DIVVN:
	case OP_DIVNV:
	case OP_DIVVV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case OP_MODVN:
	case OP_MODNV:
	case OP_MODVV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case OP_POW:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case OP_CAT:
		op->type = RZ_ANALYSIS_OP_TYPE_REDUCE;
		break;
	// Constant loads
	case OP_KSTR:
	case OP_KCDATA:
	case OP_KNUM:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case OP_KSHORT:
	case OP_KPRI:
	case OP_KNIL:
		// Moving an embedded value directly into a register
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->eob = false;
		break;
	// Upvalue and proto
	case OP_UGET:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case OP_USETV:
	case OP_USETS:
	case OP_USETN:
	case OP_USETP:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->eob = false;
		break;
	case OP_UCLO:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->eob = true;
		op->jump = addr + 4 + (jump_offset * 4);
		break;
	case OP_FNEW:
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		op->eob = false;
		break;
	// Table ops
	case OP_TNEW:
	case OP_TDUP:
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		op->eob = false;
		break;
	case OP_GGET:
	case OP_TGETV:
	case OP_TGETS:
	case OP_TGETB:
	case OP_TGETR:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case OP_GSET:
	case OP_TSETV:
	case OP_TSETS:
	case OP_TSETB:
	case OP_TSETM:
	case OP_TSETR:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->eob = false;
		break;
	// Calls and vararg handling
	case OP_CALL:
	case OP_CALLM:
	case OP_ITERC:
	case OP_ITERN:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->eob = false;
		// To jump no hardcoded address can be fount in bytecode (It will be in registers).
		break;
	case OP_CALLT:
	case OP_CALLMT:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		break;
	case OP_VARG:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case OP_ISNEXT:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		op->jump = addr + 4 + (jump_offset * 4);
		op->fail = addr + 4;
		break;
	// Returns
	case OP_RETM:
	case OP_RET:
	case OP_RET0:
	case OP_RET1:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		break;
	// Loop Initialization and Steps
	case OP_FORI:
	case OP_JFORI:
	case OP_FORL:
	case OP_IFORL:
	case OP_JFORL:
	case OP_ITERL:
	case OP_IITERL:
	case OP_JITERL:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		// Note: PC already points to the next instruction (addr + 4) when jumping
		op->jump = addr + 4 + (jump_offset * 4);
		op->fail = addr + 4;
		break;
	case OP_JMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->eob = true;
		op->jump = addr + 4 + (jump_offset * 4);
		break;
	// Function headers
	case OP_FUNCF:
	case OP_IFUNCF:
	case OP_JFUNCF:
	case OP_FUNCV:
	case OP_IFUNCV:
	case OP_JFUNCV:
	case OP_FUNCC:
	case OP_FUNCCW:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->eob = false;
		break;
	// The maximum opcode
	case OP__MAX:
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	}
	return op->size;
}