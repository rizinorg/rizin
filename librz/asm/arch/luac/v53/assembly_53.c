//
// Created by heersin on 3/31/21.
//

#include "arch_53.h"

#define LUA_ASM_OPCODE_NUM LUA_NUM_OPCODES
#define GET_ASM_SIZE(x)    (sizeof(x) - 1)

static int load_next_arg_start(const char *raw_string, char *recv_buf) {
	if (!raw_string) {
		return 0;
	}

	const char *arg_start = NULL;
	const char *arg_end = NULL;
	int arg_len = 0;

	/* locate the start point */
	arg_start = rz_str_trim_head_ro(raw_string);
	if (strlen(arg_start) == 0) {
		return 0;
	}

	arg_end = strchr(arg_start, ' ');
	if (arg_end == NULL) {
                /* is last arg */
		arg_len = strlen(arg_start);
	} else {
		arg_len = arg_end - arg_start;
	}

	/* Set NUL */
	memcpy(recv_buf, arg_start, arg_len);
	recv_buf[arg_len] = 0x00;

	/* Calculate offset */
	return arg_start - raw_string + arg_len;
}

static bool is_valid_num_value_string(const char *str) {
	if (!rz_is_valid_input_num_value(NULL, str)) {
                eprintf("luac_assembler: %s is not a valid number argument\n", str);
                return false;
	}
	return true;
}

static int convert_str_to_num(const char *str) {
	return strtoll(str, NULL, 0);
}

static LuaInstruction encode_iabc_a(ut8 opcode, const char *arg_start, st32 limit) {
	LuaInstruction instruction = -1;

	if (!rz_is_valid_input_num_value(NULL, arg_start)) {
		eprintf("luac_assembler: %s is not a valid number argument\n", arg_start);
		return instruction;
	}

	SET_OPCODE(instruction, opcode);
	SETARG_A(instruction, strtol(arg_start, NULL, 0));

	return instruction;
}

static LuaInstruction encode_iax(ut8 opcode, const char *arg_start, st32 limit) {
        LuaInstruction instruction = -1;

        if (!rz_is_valid_input_num_value(NULL, arg_start)) {
                eprintf("luac_assembler: %s is not a valid number argument\n", arg_start);
                return instruction;
        }

        SET_OPCODE(instruction, opcode);
        SETARG_Ax(instruction, strtol(arg_start, NULL, 0));

        return instruction;
}

static LuaInstruction encode_isbx(ut8 opcode, const char *arg_start, st32 limit) {
        LuaInstruction instruction = -1;

        if (!rz_is_valid_input_num_value(NULL, arg_start)) {
                eprintf("luac_assembler: %s is not a valid number argument\n", arg_start);
                return instruction;
        }

        SET_OPCODE(instruction, opcode);
        SETARG_sBx(instruction, strtol(arg_start, NULL, 0));

        return instruction;
}

static LuaInstruction encode_iabx(ut8 opcode, const char *arg_start, st32 limit) {
        LuaInstruction instruction = -1;
        int arg1_offset;
        int arg2_offset;
        int arg1;
        int arg2;
        char buffer[64];

        /* Find 1st first arg */
        arg1_offset = load_next_arg_start(arg_start, buffer);
        if (arg1_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg1 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        /* Find the 2nd arg */
        arg2_offset = load_next_arg_start(arg_start + arg1_offset, buffer);
        if (arg2_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg2 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        instruction = 0;
        SET_OPCODE(instruction, opcode);
        SETARG_A(instruction, arg1);
        SETARG_Bx(instruction, arg2);

        return instruction;
}

static LuaInstruction encode_iabc_ab(ut8 opcode, const char *arg_start, st32 limit) {
	LuaInstruction instruction = -1;
	int arg1_offset;
	int arg2_offset;
	int arg1;
	int arg2;
	char buffer[64];

	/* Find 1st first arg */
	arg1_offset = load_next_arg_start(arg_start, buffer);
	if (arg1_offset == 0) {
		return -1;
	}
	if (is_valid_num_value_string(buffer)) {
		arg1 = convert_str_to_num(buffer);
	} else {
		return -1;
	}
	eprintf("[arg1]:%s\n", buffer);

	/* Find the 2nd arg */
	arg2_offset = load_next_arg_start(arg_start + arg1_offset, buffer);
	if (arg2_offset == 0) {
		return -1;
	}
	if (is_valid_num_value_string(buffer)) {
		arg2 = convert_str_to_num(buffer);
	} else {
		return -1;
	}
        eprintf("[arg2]:%s\n", buffer);

	instruction = 0;
	SET_OPCODE(instruction, opcode);
	SETARG_A(instruction, arg1);
	SETARG_B(instruction, arg2);

	return instruction;
}

static LuaInstruction encode_iabc_ac(ut8 opcode, const char *arg_start, st32 limit) {
        LuaInstruction instruction = -1;
        int arg1_offset;
        int arg2_offset;
        int arg1;
        int arg2;
        char buffer[64];

        /* Find 1st first arg */
        arg1_offset = load_next_arg_start(arg_start, buffer);
        if (arg1_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg1 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        /* Find the 2nd arg */
        arg2_offset = load_next_arg_start(arg_start + arg1_offset, buffer);
        if (arg2_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg2 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        instruction = 0;
        SET_OPCODE(instruction, opcode);
        SETARG_A(instruction, arg1);
        SETARG_B(instruction, arg2);

        return instruction;
}

static LuaInstruction encode_iabc_abc(ut8 opcode, const char *arg_start, st32 limit) {
        LuaInstruction instruction = -1;
        int arg1_offset;
        int arg2_offset;
	int arg3_offset;
        int arg1;
        int arg2;
	int arg3;
        char buffer[64];

        /* Find 1st first arg */
        arg1_offset = load_next_arg_start(arg_start, buffer);
        if (arg1_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg1 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        /* Find the 2nd arg */
        arg2_offset = load_next_arg_start(arg_start + arg1_offset, buffer);
        if (arg2_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg2 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        /* Find the 2nd arg */
        arg3_offset = load_next_arg_start(arg_start + arg1_offset + arg2_offset, buffer);
        if (arg3_offset == 0) {
                return -1;
        }
        if (is_valid_num_value_string(buffer)) {
                arg3 = convert_str_to_num(buffer);
        } else {
                return -1;
        }

        instruction = 0;
        SET_OPCODE(instruction, opcode);
        SETARG_A(instruction, arg1);
        SETARG_B(instruction, arg2);
	SETARG_C(instruction, arg3);

        return instruction;
}

bool lua53_assembly(const char *input, st32 input_size, LuaInstruction *instruction_p) {
	const char *opcode_start; // point to the header
	const char *opcode_end; // point to the first white space
	int opcode_len;

	const char *arg_start;
	int arg_limit;

	ut8 opcode;
	LuaInstruction instruction = 0x00;

	eprintf("Input : %s, size : %d\n", input, input_size);

	/* Find the opcode */
	opcode_start = input;
	opcode_end = strchr(input, ' ');
	if (opcode_end == NULL) {
		opcode_end = input + input_size;
	}

	opcode_len = opcode_end - opcode_start;
	opcode = get_lua_opcode_by_name(opcode_start, opcode_len);
        eprintf("[start]:%s, [end]:%s, [size]:%d, [opcode]:%d\n", opcode_start, opcode_end, opcode_len, opcode);

	/* Find the arguments */
	arg_start = rz_str_trim_head_ro(opcode_end);
	arg_limit = arg_start - opcode_start;

	/* Encode opcode and args */
	switch (opcode) {
	case OP_LOADKX:
		instruction = encode_iabc_a(opcode, arg_start, arg_limit);
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
		instruction = encode_iabc_ab(opcode, arg_start, arg_limit);
		break;
	case OP_TEST:
	case OP_TFORCALL:
		instruction = encode_iabc_ac(opcode, arg_start, arg_limit);
		break;
	case OP_LOADK:
	case OP_CLOSURE:
		instruction = encode_iabx(opcode, arg_start, arg_limit);
		break;
	case OP_CONCAT:
	case OP_TESTSET:
	case OP_CALL:
	case OP_TAILCALL:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_LOADBOOL:
	case OP_SELF:
		instruction = encode_iabc_abc(opcode, arg_start, arg_limit);
		break;
	case OP_GETTABUP:
	case OP_GETTABLE:
		// special C
		instruction = encode_iabc_abc(opcode, arg_start, arg_limit);
		break;
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
		// special B and C
		instruction = encode_iabc_abc(opcode, arg_start, arg_limit);
		break;
	case OP_JMP:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
		instruction = encode_isbx(opcode, arg_start, arg_limit);
		break;
	case OP_EXTRAARG:
		instruction = encode_iax(opcode, arg_start, arg_limit);
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
