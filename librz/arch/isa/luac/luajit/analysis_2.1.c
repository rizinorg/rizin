// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

int luajit_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, LuaJITInstructions instr) {
	if (len < 4) {
		return 0;
	}

	op->jump = UT64_MAX; // TODO: Supress WARNING of invalid address, 0x0 (op initialized from memeset above) will be invalid address for JMP.
	op->fail = UT64_MAX;
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;

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
	case LUAJIT_OP_ISLT:
	case LUAJIT_OP_ISGE:
	case LUAJIT_OP_ISLE:
	case LUAJIT_OP_ISGT:
	case LUAJIT_OP_ISEQV:
	case LUAJIT_OP_ISNEV:
	case LUAJIT_OP_ISEQS:
	case LUAJIT_OP_ISNES:
	case LUAJIT_OP_ISEQN:
	case LUAJIT_OP_ISNEN:
	case LUAJIT_OP_ISEQP:
	case LUAJIT_OP_ISNEP:
	// Unary test and copy ops
	case LUAJIT_OP_ISTC:
	case LUAJIT_OP_ISFC:
	case LUAJIT_OP_IST:
	case LUAJIT_OP_ISF:
	case LUAJIT_OP_ISTYPE:
	case LUAJIT_OP_ISNUM:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		op->jump = addr + 8;
		op->fail = addr + 4;
		break;
	// Unary ops
	case LUAJIT_OP_MOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case LUAJIT_OP_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case LUAJIT_OP_UNM:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case LUAJIT_OP_LEN:
		op->type = RZ_ANALYSIS_OP_TYPE_LENGTH;
		break;
	// Binary ops
	case LUAJIT_OP_ADDVN:
	case LUAJIT_OP_ADDNV:
	case LUAJIT_OP_ADDVV:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case LUAJIT_OP_SUBVN:
	case LUAJIT_OP_SUBNV:
	case LUAJIT_OP_SUBVV:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case LUAJIT_OP_MULVN:
	case LUAJIT_OP_MULNV:
	case LUAJIT_OP_MULVV:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case LUAJIT_OP_DIVVN:
	case LUAJIT_OP_DIVNV:
	case LUAJIT_OP_DIVVV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case LUAJIT_OP_MODVN:
	case LUAJIT_OP_MODNV:
	case LUAJIT_OP_MODVV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case LUAJIT_OP_POW:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case LUAJIT_OP_CAT:
		op->type = RZ_ANALYSIS_OP_TYPE_REDUCE;
		break;
	// Constant loads
	case LUAJIT_OP_KSTR:
	case LUAJIT_OP_KCDATA:
	case LUAJIT_OP_KNUM:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case LUAJIT_OP_KSHORT:
	case LUAJIT_OP_KPRI:
	case LUAJIT_OP_KNIL:
		// Moving an embedded value directly into a register
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->eob = false;
		break;
	// Upvalue and proto
	case LUAJIT_OP_UGET:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case LUAJIT_OP_USETV:
	case LUAJIT_OP_USETS:
	case LUAJIT_OP_USETN:
	case LUAJIT_OP_USETP:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->eob = false;
		break;
	case LUAJIT_OP_UCLO:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->eob = true;
		op->jump = addr + 4 + (jump_offset * 4);
		break;
	case LUAJIT_OP_FNEW:
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		op->eob = false;
		break;
	// Table ops
	case LUAJIT_OP_TNEW:
	case LUAJIT_OP_TDUP:
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		op->eob = false;
		break;
	case LUAJIT_OP_GGET:
	case LUAJIT_OP_TGETV:
	case LUAJIT_OP_TGETS:
	case LUAJIT_OP_TGETB:
	case LUAJIT_OP_TGETR:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case LUAJIT_OP_GSET:
	case LUAJIT_OP_TSETV:
	case LUAJIT_OP_TSETS:
	case LUAJIT_OP_TSETB:
	case LUAJIT_OP_TSETM:
	case LUAJIT_OP_TSETR:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->eob = false;
		break;
	// Calls and vararg handling
	case LUAJIT_OP_CALL:
	case LUAJIT_OP_CALLM:
	case LUAJIT_OP_ITERC:
	case LUAJIT_OP_ITERN:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->eob = false;
		// To jump no hardcoded address can be fount in bytecode (It will be in registers).
		break;
	case LUAJIT_OP_CALLT:
	case LUAJIT_OP_CALLMT:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		break;
	case LUAJIT_OP_VARG:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->eob = false;
		break;
	case LUAJIT_OP_ISNEXT:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		op->jump = addr + 4 + (jump_offset * 4);
		op->fail = addr + 4;
		break;
	// Returns
	case LUAJIT_OP_RETM:
	case LUAJIT_OP_RET:
	case LUAJIT_OP_RET0:
	case LUAJIT_OP_RET1:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		break;
	// Loop Initialization and Steps
	case LUAJIT_OP_FORI:
	case LUAJIT_OP_JFORI:
	case LUAJIT_OP_FORL:
	case LUAJIT_OP_IFORL:
	case LUAJIT_OP_JFORL:
	case LUAJIT_OP_ITERL:
	case LUAJIT_OP_IITERL:
	case LUAJIT_OP_JITERL:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		// Note: PC already points to the next instruction (addr + 4) when jumping
		op->jump = addr + 4 + (jump_offset * 4);
		op->fail = addr + 4;
		break;
	case LUAJIT_OP_JMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->eob = true;
		op->jump = addr + 4 + (jump_offset * 4);
		break;
	// Function headers
	case LUAJIT_OP_FUNCF:
	case LUAJIT_OP_IFUNCF:
	case LUAJIT_OP_JFUNCF:
	case LUAJIT_OP_FUNCV:
	case LUAJIT_OP_IFUNCV:
	case LUAJIT_OP_JFUNCV:
	case LUAJIT_OP_FUNCC:
	case LUAJIT_OP_FUNCCW:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->eob = false;
		break;
	// The maximum opcode
	case LUAJIT_OP__MAX:
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	}
	return op->size;
}