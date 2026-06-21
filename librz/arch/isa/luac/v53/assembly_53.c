// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_53.h"

static LuaInstruction encode_instruction(const ut8 opcode, const char *arg_start, const ut16 flag, const ut8 arg_num) {
	rz_return_val_if_fail((arg_num > 0) && (arg_num <= LUA_MAX_ARGS0), LUA_INVALID_INSTRUCTION);
	LuaInstruction instruction = 0;
	int args[LUA_MAX_ARGS0];
	int cur_cnt = 0;
	int temp;

	if (!load_args_asm(arg_start, args)) {
		return LUA_INVALID_INSTRUCTION;
	}

	if (opcode == OP_LOADK) {
		args[1] = MYK(args[1]); ///< MYK(bx)
	}

	SET_OPCODE53(instruction, opcode);
	if (has_param_flag(flag, PARAM_A)) {
		SETARG_A1(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_B)) {
		temp = args[cur_cnt++];
		temp = temp < 0 ? 0xFF - temp : temp;
		SETARG_B1(instruction, temp);
	}
	if (has_param_flag(flag, PARAM_C)) {
		temp = args[cur_cnt++];
		temp = temp < 0 ? 0xFF - temp : temp;
		SETARG_C1(instruction, temp);
	}
	if (has_param_flag(flag, PARAM_Ax)) {
		args[0] = MYK(args[0]);
		SETARG_Ax2(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx1(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx1(instruction, args[cur_cnt++]);
	}
	rz_return_val_if_fail(cur_cnt == arg_num, LUA_INVALID_INSTRUCTION);

	return instruction;
}

ut32 get_instruction53(const ut8 opcode, const char *arg_start) {
	LuaInstruction instruction = 0x00;
	/* Encode opcode and args */
	switch (opcode) {
	case OP_LOADKX:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A, 1);
		break;
	case OP_MOVE:
	case OP_SETUPVAL:
	case OP_UNM:
	case OP_BNOT:
	case OP_NOT:
	case OP_LEN:
	case OP_LOADNIL:
	case OP_RETURN:
	case OP_VARARG:
	case OP_GETUPVAL:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B, 2);
		break;
	case OP_TEST:
	case OP_TFORCALL:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_C, 2);
		break;
	case OP_LOADK:
	case OP_CLOSURE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_Bx, 2);
		break;
	case OP_CONCAT:
	case OP_TESTSET:
	case OP_CALL:
	case OP_TAILCALL:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_LOADBOOL:
	case OP_SELF:
	case OP_GETTABUP:
	case OP_GETTABLE:
	case OP_SETTABUP:
	case OP_SETTABLE:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_MOD:
	case OP_POW:
	case OP_DIV:
	case OP_IDIV:
	case OP_BAND:
	case OP_BOR:
	case OP_BXOR:
	case OP_SHL:
	case OP_SHR:
	case OP_EQ:
	case OP_LT:
	case OP_LE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_C, 3);
		break;
	case OP_JMP:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_sBx, 2);
		break;
	case OP_EXTRAARG:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_Ax, 1);
		break;
	default:
		return LUA_INVALID_INSTRUCTION;
	}
	return instruction;
}

ASM(53)
