// SPDX-FileCopyrightText: 2025 well-mannered-goat <takshformal@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_312(void) {
	pyc_opcodes *ret = opcode_311();
	if (!ret) {
		return NULL;
	}

	rm_op(.op_obj = ret->opcodes, .op_name = "LOAD_METHOD", .op_code = 160);
	rm_op(.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE_OR_POP", .op_code = 111);
	rm_op(.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE_OR_POP", .op_code = 112);
	rm_op(.op_obj = ret->opcodes, .op_name = "PRECALL", .op_code = 166);
	rm_op(.op_obj = ret->opcodes, .op_name = "LOAD_CLASSDEREF", .op_code = 148);

	rm_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_TRUE", .op_code = 115);
	rm_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_FALSE", .op_code = 114);
	rm_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_NOT_NONE", .op_code = 128);
	rm_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_FORWARD_IF_NONE", .op_code = 129);

	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 114, .conditional = true);
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 115, .conditional = true);
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_NOT_NONE", .op_code = 128, .conditional = true);
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_NONE", .op_code = 129, .conditional = true);

	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SLICE", .op_code = 26, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "STORE_SLICE", .op_code = 27, .pop = 4, .push = 0);

	def_op(.op_obj = ret->opcodes, .op_name = "CALL_INTRINSIC_1", .op_code = 173, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_INTRINSIC_2", .op_code = 174, .pop = 2, .push = 1);

	def_op(.op_obj = ret->opcodes, .op_name = "CLEANUP_THROW", .op_code = 55, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "END_SEND", .op_code = 5, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "END_FOR", .op_code = 4, .pop = 0, .push = 0);

	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_AND_CLEAR", .op_code = 143, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_CHECK", .op_code = 127, .pop = 0, .push = 1);

	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FROM_DICT_OR_DEREF", .op_code = 176, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FROM_DICT_OR_GLOBALS", .op_code = 175, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_LOCALS", .op_code = 87, .pop = 0, .push = 1);

	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SUPER_ATTR", .op_code = 141, .pop = 3, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "RETURN_CONST", .op_code = 121, .pop = 0, .push = 0);

	ret->version_sig = (opcode_func)opcode_312;

	return ret;
}
