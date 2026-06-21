// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_50.h"

static LuaInstruction encode_instruction(const ut8 opcode, const char *arg_start, const ut16 flag, const ut8 arg_num) {
	rz_return_val_if_fail((arg_num > 0) && (arg_num <= LUA_MAX_ARGS0), LUA_INVALID_INSTRUCTION);
	LuaInstruction instruction = 0;
	int args[LUA_MAX_ARGS0];
	int cur_cnt = 0;
	int temp = 0;

	if (!load_args_asm(arg_start, args)) {
		return LUA_INVALID_INSTRUCTION;
	}

	SET_OPCODE50(instruction, opcode);
	if (has_param_flag(flag, PARAM_A)) {
		SETARG_A0(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_B)) {
		temp = args[cur_cnt++];
		temp = temp < 0 ? 0xFF - temp : temp;
		SETARG_B0(instruction, temp);
	}
	if (has_param_flag(flag, PARAM_C)) {
		temp = args[cur_cnt++];
		temp = temp < 0 ? 0xFF - temp : temp;
		SETARG_C0(instruction, temp);
	}
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx0(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx0(instruction, args[cur_cnt++]);
	}
	rz_return_val_if_fail(cur_cnt == arg_num, LUA_INVALID_INSTRUCTION);

	return instruction;
}

ut32 get_instruction50(const ut8 opcode, const char *arg_start) {
	LuaInstruction instruction = 0x00;
	/* Encode opcode and args */
	switch (opcode) {
	case OP_SETUPVAL:
	case OP_UNM:
	case OP_NOT:
	case OP_LOADNIL:
	case OP_GETUPVAL:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B, 2);
		break;
	case OP_TEST:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_C, 2);
		break;
	case OP_LOADK:
	case OP_GETGLOBAL:
	case OP_SETGLOBAL:
	case OP_CLOSURE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_Bx, 2);
		break;
	case OP_MOVE:
	case OP_RETURN:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B, 2);
		break;
	case OP_CONCAT:
	case OP_CALL:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_LOADBOOL:
	case OP_SELF:
	case OP_SETTABLE:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_POW:
	case OP_DIV:
	case OP_EQ:
	case OP_LT:
	case OP_GETTABLE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_C, 3);
		break;
	case OP_JMP:
	case OP_FORLOOP:
	case OP_TFORLOOP:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_sBx, 2);
		break;
	default:
		return LUA_INVALID_INSTRUCTION;
	}
	return instruction;
}

ASM(50)
