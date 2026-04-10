// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_54.h"

static LuaInstruction encode_instruction(const ut8 opcode, const char *arg_start, ut16 flag) {
	LuaInstruction instruction = 0;
	int args[LUA_MAX_ARGS4];
	int cur_cnt = 0;

	if (!arg_start) {
		return LUA_INVALID_INSTRUCTION;
	}
	if (!load_args_asm(arg_start, args)) {
		return LUA_INVALID_INSTRUCTION;
	}
	size_t len = strlen(arg_start);
	len -= 1;
	if (arg_start[len] == 'k') {
		SETARG_k(instruction, 1);
	}

	SET_OPCODE54(instruction, opcode);
	if (has_param_flag(flag, PARAM_A)) {
		SETARG_A4(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_B)) {
		SETARG_B4(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_sB)) {
		SETARG_sB(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_C)) {
		SETARG_C4(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_sC)) {
		SETARG_sC(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_Ax)) {
		SETARG_Ax4(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx4(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx4(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_sJ)) {
		SETARG_sJ(instruction, args[cur_cnt++]);
	}
	return instruction;
}

ut32 get_instruction54(const ut8 opcode, const char *arg_start) {
	LuaInstruction instruction = 0x00;
	/* Encode opcode and args */
	switch (opcode) {
	case OP_GETI:
	case OP_MMBIN:
	case OP_GETTABUP:
	case OP_CALL:
	case OP_GETTABLE:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_POW:
	case OP_DIV:
	case OP_IDIV:
	case OP_BAND:
	case OP_BOR:
	case OP_SHL:
	case OP_SHR:
	case OP_ADDK:
	case OP_SUBK:
	case OP_MULK:
	case OP_MODK:
	case OP_POWK:
	case OP_DIVK:
	case OP_IDIVK:
	case OP_BANDK:
	case OP_BORK:
	case OP_BXORK:
	case OP_GETFIELD:
	// iABC k instruction
	case OP_TAILCALL:
	case OP_RETURN:
	case OP_SETTABUP:
	case OP_SETTABLE:
	case OP_SETI:
	case OP_SETFIELD:
	case OP_SELF:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_MMBINK:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B | PARAM_C);
		break;
	// AsBC k instruction
	case OP_MMBINI:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_sB | PARAM_C);
		break;
	// ABsC
	case OP_ADDI:
	case OP_SHRI:
	case OP_SHLI:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B | PARAM_sC);
		break;
	// AB
	case OP_MOVE:
	case OP_UNM:
	case OP_BNOT:
	case OP_NOT:
	case OP_LEN:
	case OP_CONCAT:
	case OP_LOADNIL:
	case OP_GETUPVAL:
	case OP_SETUPVAL:
	// AB with k
	case OP_EQ:
	case OP_LT:
	case OP_LE:
	case OP_TESTSET:
	case OP_EQK:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B);
		break;
	// AsB with k
	case OP_EQI:
	case OP_LTI:
	case OP_LEI:
	case OP_GTI:
	case OP_GEI:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_sB);
		break;
	// AC
	case OP_TFORCALL:
	case OP_VARARG:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_C);
		break;
	// A
	case OP_LOADKX:
	case OP_LOADFALSE:
	case OP_LFALSESKIP:
	case OP_LOADTRUE:
	case OP_CLOSE:
	case OP_TBC:
	case OP_RETURN1:
	case OP_VARARGPREP:
	// A with k
	case OP_TEST:
		instruction = encode_instruction(opcode, arg_start, PARAM_A);
		break;
	// no arg
	case OP_RETURN0:
		SET_OPCODE54(instruction, OP_RETURN0);
		break;
	// A Bx
	case OP_LOADK:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
	case OP_TFORPREP:
	case OP_CLOSURE:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_Bx);
		break;
	// A sBx
	case OP_LOADI:
	case OP_LOADF:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_sBx);
		break;
	// Ax
	case OP_EXTRAARG:
		instruction = encode_instruction(opcode, arg_start, PARAM_Ax);
		break;
	// isJ
	case OP_JMP:
		instruction = encode_instruction(opcode, arg_start, PARAM_sJ);
		break;
	default:
		return LUA_INVALID_INSTRUCTION;
	}

	return instruction;
}

ASM(54)
