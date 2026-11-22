// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_51.h"

static LuaInstruction encode_instruction(const ut8 opcode, const char *arg_start, const ut16 flag, const ut8 arg_num) {
	rz_return_val_if_fail((arg_num > 0) && (arg_num <= LUA_MAX_ARGS0), LUA_INVALID_INSTRUCTION);
	LuaInstruction instruction = 0;
	int args[LUA_MAX_ARGS0];
	int cur_cnt = 0;
	int temp = 0;

	if (!load_args_asm(arg_start, args)) {
		return LUA_INVALID_INSTRUCTION;
	}
	switch (opcode) {
	case OP_LOADK:
	case OP_GETGLOBAL:
	case OP_SETGLOBAL:
		args[1] = MYK(args[1]);
		break;
	case OP_GETTABLE:
	case OP_SETTABLE:
	case OP_NEWTABLE:
	case OP_SELF:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_DIV:
	case OP_MOD:
	case OP_POW:
	case OP_CONCAT:
	case OP_SETLIST:
	case OP_LT:
	case OP_LE:
	case OP_TEST:
	case OP_TESTSET:
	case OP_EQ:
	case OP_CALL:
	case OP_TAILCALL:
		args[2] = ISK(args[2]) ? (MYK(INDEXK(args[2]))) : args[2];
		break;
	case OP_TFORLOOP:
		args[1] = ISK(args[1]) ? (MYK(INDEXK(args[1]))) : args[1];
		args[2] = ISK(args[2]) ? (MYK(INDEXK(args[2]))) : args[2];
		break;
	case OP_CLOSE:
		args[1] = ISK(args[1]) ? (MYK(INDEXK(args[1]))) : args[1];
		break;
	default:
		break;
	}

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
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx1(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx1(instruction, args[cur_cnt++]);
	}
	rz_return_val_if_fail(cur_cnt == arg_num, LUA_INVALID_INSTRUCTION);

	return instruction;
}

ut32 get_instruction51(const ut8 opcode, const char *arg_start, const int version) {
	LuaInstruction instruction = 0x00;
	/* Encode opcode and args */
	switch (opcode) {
	case OP_MOVE:
	case OP_SETUPVAL:
	case OP_UNM:
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
	case OP_CONCAT:
	case OP_TESTSET:
	case OP_CALL:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_LOADBOOL:
	case OP_SELF:
	case OP_SETTABLE:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_MOD:
	case OP_POW:
	case OP_DIV:
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
	default:
		rz_warn_if_reached();
		return LUA_INVALID_INSTRUCTION;
	}
	const LuaOpCode51 opcode2 = get_lua51_opcode_shuffled_index_by_id(opcode, version);
	SET_OPCODE51(instruction, opcode2);
	return instruction;
}

ut32 lua51_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start, const int version) {
	const ut8 opcode = get_lua51_opcode_by_name(opcode_start, opcode_len);
	return get_instruction51(opcode, arg_start, version);
}