// SPDX-FileCopyrightText: 2025 well-mannered-goat <takshformal@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_311(void) {
	pyc_opcodes *ret = opcode_310();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (opcode_func)opcode_311;

	// Removed opcodes
	rm_op(.op_obj = ret->opcodes, .op_name = "POP_BLOCK", .op_code = 87);
	rm_op(.op_obj = ret->opcodes, .op_name = "SETUP_FINALLY", .op_code = 122);
	rm_op(.op_obj = ret->opcodes, .op_name = "YIELD_FROM", .op_code = 72);
	// // Remove BINARY_*
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_MATRIX_MULTIPLY", .op_code = 16);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_POWER", .op_code = 19);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_MULTIPLY", .op_code = 20);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_MODULO", .op_code = 22);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_ADD", .op_code = 23);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBTRACT", .op_code = 24);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_FLOOR_DIVIDE", .op_code = 26);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_TRUE_DIVIDE", .op_code = 27);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_LSHIFT", .op_code = 62);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_RSHIFT", .op_code = 63);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_AND", .op_code = 64);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_XOR", .op_code = 65);
	rm_op(.op_obj = ret->opcodes, .op_name = "BINARY_OR", .op_code = 66);
	// // Remove INPLACE_*
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_MATRIX_MULTIPLY", .op_code = 17);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_FLOOR_DIVIDE", .op_code = 28);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_TRUE_DIVIDE", .op_code = 29);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_ADD", .op_code = 55);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_SUBTRACT", .op_code = 56);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_MULTIPLY", .op_code = 57);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_MODULO", .op_code = 59);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_POWER", .op_code = 67);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_LSHIFT", .op_code = 75);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_RSHIFT", .op_code = 76);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_AND", .op_code = 77);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_XOR", .op_code = 78);
	rm_op(.op_obj = ret->opcodes, .op_name = "INPLACE_OR", .op_code = 79);

	rm_op(.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION", .op_code = 131);
	rm_op(.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_KW", .op_code = 141);
	rm_op(.op_obj = ret->opcodes, .op_name = "CALL_METHOD", .op_code = 161);

	rm_op(.op_obj = ret->opcodes, .op_name = "DUP_TOP_TWO", .op_code = 5);
	rm_op(.op_obj = ret->opcodes, .op_name = "DUP_TOP", .op_code = 4);
	rm_op(.op_obj = ret->opcodes, .op_name = "ROT_TWO", .op_code = 2);
	rm_op(.op_obj = ret->opcodes, .op_name = "ROT_THREE", .op_code = 3);
	rm_op(.op_obj = ret->opcodes, .op_name = "ROT_FOUR", .op_code = 6);

	rm_op(.op_obj = ret->opcodes, .op_name = "JUMP_ABSOLUTE", .op_code = 113);
	rm_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 114);
	rm_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 115);

	rm_op(.op_obj = ret->opcodes, .op_name = "SETUP_WITH", .op_code = 143);
	rm_op(.op_obj = ret->opcodes, .op_name = "SETUP_ASYNC_WITH", .op_code = 154);

	// // New Opcodes
	def_op(.op_obj = ret->opcodes, .op_name = "ASYNC_GEN_WRAP", .op_code = 87, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "RETURN_GENERATOR", .op_code = 75, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "SEND", .op_code = 123, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COPY_FREE_VARS", .op_code = 149, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "MAKE_CELL", .op_code = 135, .pop = 0, .push = 0);

	def_op(.op_obj = ret->opcodes, .op_name = "CHECK_EXC_MATCH", .op_code = 36, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CHECK_EG_MATCH", .op_code = 37, .pop = 9, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "PREP_RERAISE_STAR", .op_code = 88, .pop = 2, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "PUSH_EXC_INFO", .op_code = 35, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "RESUME", .op_code = 151, .pop = 0, .push = 0);

	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD_NO_INTERRUPT", .op_code = 134, .pop = 0, .push = 0, .conditional = false);

	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP", .op_code = 122, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADAPTIVE", .op_code = 3, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADD_FLOAT", .op_code = 4, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADD_INT", .op_code = 5, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADD_UNICODE", .op_code = 6, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_INPLACE_ADD_UNICODE", .op_code = 7, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_MULTIPLY_FLOAT", .op_code = 8, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_MULTIPLY_INT", .op_code = 13, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBTRACT_FLOAT", .op_code = 14, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBTRACT_INT", .op_code = 16, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR_ADAPTIVE", .op_code = 17, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR_DICT", .op_code = 18, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR_GETITEM", .op_code = 19, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR_LIST_INT", .op_code = 20, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR_TUPLE_INT", .op_code = 21, .pop = 2, .push = 1);

	nargs_op(.op_obj = ret->opcodes, .op_name = "CALL", .op_code = 171, .pop = 9, .push = 1);
	nargs_op(.op_obj = ret->opcodes, .op_name = "KW_NAMES", .op_code = 172, .pop = 0, .push = 0);
	nargs_op(.op_obj = ret->opcodes, .op_name = "PRECALL", .op_code = 166, .pop = 0, .push = 0);
	nargs_op(.op_obj = ret->opcodes, .op_name = "PUSH_NULL", .op_code = 2, .pop = 0, .push = 1);

	// //
	def_op(.op_obj = ret->opcodes, .op_name = "COPY", .op_code = 120, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "SWAP", .op_code = 99, .pop = 1, .push = 1);

	jrel_op00(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD", .op_code = 140, .pop = 9, .push = 1, .conditional = false);

	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_TRUE", .op_code = 115, .pop = 0, .push = 0, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_FALSE", .op_code = 114, .pop = 0, .push = 0, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_NOT_NONE", .op_code = 128, .pop = 0, .push = 0, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_NONE", .op_code = 129, .pop = 0, .push = 0, .conditional = true);

	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_BACKWARD_IF_TRUE", .op_code = 176, .pop = 0, .push = 0, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_BACKWARD_IF_FALSE", .op_code = 175, .pop = 0, .push = 0, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_BACKWARD_IF_NOT_NONE", .op_code = 173, .pop = 0, .push = 0, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_BACKWARD_IF_NONE", .op_code = 174, .pop = 0, .push = 0, .conditional = true);

	def_op(.op_obj = ret->opcodes, .op_name = "BEFORE_WITH", .op_code = 53, .pop = 0, .push = 2);

	rm_op(.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE_OR_POP", .op_code = 112);
	rm_op(.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE_OR_POP", .op_code = 111);

	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE_OR_POP", .op_code = 112, .conditional = true);
	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE_OR_POP", .op_code = 111, .conditional = true);

	def_op(.op_obj = ret->opcodes, .op_name = "CACHE", .op_code = 0, .pop = 0, .push = 0);

	return ret;
}