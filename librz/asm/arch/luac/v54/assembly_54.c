//
// Created by heersin on 3/31/21.
//

#include "arch_54.h"

bool lua54_assembly(const char *input, st32 input_size, LuaInstruction *instruction_p) {
        const char *opcode_start; // point to the header
        const char *opcode_end; // point to the first white space
        int opcode_len;

        const char *arg_start;
        int arg_limit;

        ut8 opcode;
        LuaInstruction instruction = 0x00;

        /* Find the opcode */
        opcode_start = input;
        opcode_end = strchr(input, ' ');
        if (opcode_end == NULL) {
                opcode_end = input + input_size;
        }

        opcode_len = opcode_end - opcode_start;
        opcode = get_lua54_opcode_by_name(opcode_start);
        eprintf("[start]:%s, [end]:%s, [size]:%d, [opcode]:%d\n", opcode_start, opcode_end, opcode_len, opcode);

        /* Find the arguments */
        arg_start = rz_str_trim_head_ro(opcode_end);
        arg_limit = arg_start - opcode_start;

        /* Encode opcode and args */
        switch (opcode) {
	case OP_SETTABUP:
	case OP_SETI:
	case OP_GETI:
	case OP_SELF:
	case OP_SETFIELD:
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
		break;
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
		break;
	// iABC k instruction
	case OP_TAILCALL:
	case OP_RETURN:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_MMBINK:
		break;
	// AsBC k instruction
	case OP_MMBINI:
		break;
	// ABsC
	case OP_ADDI:
	case OP_SHRI:
	case OP_SHLI:
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
		break;
	// AB with k
	case OP_EQ:
	case OP_LT:
	case OP_LE:
	case OP_TESTSET:
	case OP_EQK:
		break;
	// AsB with k
	case OP_EQI:
	case OP_LTI:
	case OP_LEI:
	case OP_GTI:
	case OP_GEI:
		break;
	// AC
	case OP_TFORCALL:
	case OP_VARARG:
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
		break;
	// A with k
	case OP_TEST:
		break;
	// no arg
	case OP_RETURN0:
		break;
	// A Bx
	case OP_LOADK:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
	case OP_TFORPREP:
	case OP_CLOSURE:
		break;
	// A sBx
	case OP_LOADI:
	case OP_LOADF:
		break;
	// Ax
	case OP_EXTRAARG:
		break;
	// isJ
	case OP_JMP:
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