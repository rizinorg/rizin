// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_54.h"

static LuaInstruction encode_instruction(ut8 opcode, const char *arg_start, ut16 flag, ut8 arg_num) {
	LuaInstruction instruction = 0;
	int args[4];
	char buffer[64]; // buffer for digits
	int cur_cnt = 0;
	int delta_offset;

	if (arg_num > sizeof(args)) {
		return -1;
	}

	for (int i = 0; i < arg_num; ++i) {
		delta_offset = lua_load_next_arg_start(arg_start, buffer);
		if (delta_offset == 0) {
			return -1;
		}
		if (lua_is_valid_num_value_string(buffer)) {
			args[i] = lua_convert_str_to_num(buffer);
			arg_start += delta_offset;
		} else {
			return -1;
		}
	}

	LUA_SET_OPCODE(instruction, opcode);
	if (has_param_flag(flag, PARAM_A)) {
		SETARG_A(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_B)) {
		SETARG_B(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sB)) {
		SETARG_sB(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_C)) {
		SETARG_C(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sC)) {
		SETARG_sC(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_Ax)) {
		SETARG_Ax(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sJ)) {
		SETARG_sJ(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_k)) {
		SETARG_k(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	rz_return_val_if_fail(cur_cnt == arg_num, -1);

	return instruction;
}

bool lua54_assembly(const char *input, st32 input_size, LuaInstruction *instruction_p) {
	const char *opcode_start; // point to the header
	const char *opcode_end; // point to the first white space
	int opcode_len;

	const char *arg_start;

	ut8 opcode;
	LuaInstruction instruction = 0x00;

	/* Find the opcode */
	opcode_start = input;
	opcode_end = strchr(input, ' ');
	if (opcode_end == NULL) {
		opcode_end = input + input_size;
	}

	opcode_len = opcode_end - opcode_start;
	opcode = get_lua54_opcode_by_name(opcode_start, opcode_len);

	/* Find the arguments */
	arg_start = rz_str_trim_head_ro(opcode_end);

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
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_C,
			3);
		break;
	// iABC k instruction
	case OP_TAILCALL:
	case OP_RETURN:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_MMBINK:
	case OP_SETTABUP:
	case OP_SETTABLE:
	case OP_SETI:
	case OP_SETFIELD:
	case OP_SELF:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_C | PARAM_k,
			4);
		break;
	// AsBC k instruction
	case OP_MMBINI:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_sB | PARAM_C | PARAM_k,
			4);
		break;
	// ABsC
	case OP_ADDI:
	case OP_SHRI:
	case OP_SHLI:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_sC,
			3);
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
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B,
			2);
		break;
	// AB with k
	case OP_EQ:
	case OP_LT:
	case OP_LE:
	case OP_TESTSET:
	case OP_EQK:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_k,
			3);
		break;
	// AsB with k
	case OP_EQI:
	case OP_LTI:
	case OP_LEI:
	case OP_GTI:
	case OP_GEI:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_sB | PARAM_k,
			3);
		break;
	// AC
	case OP_TFORCALL:
	case OP_VARARG:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_C,
			2);
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
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A,
			1);
		break;
	// A with k
	case OP_TEST:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_k,
			2);
		break;
	// no arg
	case OP_RETURN0:
		LUA_SET_OPCODE(instruction, OP_RETURN0);
		break;
	// A Bx
	case OP_LOADK:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
	case OP_TFORPREP:
	case OP_CLOSURE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_Bx,
			2);
		break;
	// A sBx
	case OP_LOADI:
	case OP_LOADF:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_sBx,
			2);
		break;
	// Ax
	case OP_EXTRAARG:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_Ax,
			1);
		break;
	// isJ
	case OP_JMP:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_sJ,
			1);
		break;
	default:
		return false;
	}

	if (instruction == -1) {
		return false;
	}

	*instruction_p = instruction;
	return true;
}
