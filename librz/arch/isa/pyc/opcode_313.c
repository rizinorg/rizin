// SPDX-FileCopyrightText: 2025 well-mannered-goat <takshformal@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_313(void) {
	pyc_opcodes *ret = new_pyc_opcodes();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (opcode_func)opcode_313;

	def_op(.op_obj = ret->opcodes, .op_name = "CACHE", .op_code = 0, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "BEFORE_ASYNC_WITH", .op_code = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BEFORE_WITH", .op_code = 2, .pop = 0, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SLICE", .op_code = 4, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR", .op_code = 5, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CHECK_EG_MATCH", .op_code = 6, .pop = 9, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CHECK_EXC_MATCH", .op_code = 7, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CLEANUP_THROW", .op_code = 8, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "DELETE_SUBSCR", .op_code = 9, .pop = 2, .push = 0); // Implements del TOS1[TOS].
	def_op(.op_obj = ret->opcodes, .op_name = "END_ASYNC_FOR", .op_code = 10, .pop = 7, .push = 0); // POP is 0, when not 7
	def_op(.op_obj = ret->opcodes, .op_name = "END_FOR", .op_code = 11, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "END_SEND", .op_code = 12, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "FORMAT_SIMPLE", .op_code = 14, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "FORMAT_WITH_SPEC", .op_code = 15, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_AITER", .op_code = 16, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_ANEXT", .op_code = 18, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_ITER", .op_code = 19, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_LEN", .op_code = 20, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_YIELD_FROM_ITER", .op_code = 21, .pop = 0, .push = 1);
	// 22
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ASSERTION_ERROR", .op_code = 23, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_BUILD_CLASS", .op_code = 24, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_LOCALS", .op_code = 25, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MAKE_FUNCTION", .op_code = 26, .pop = 9, .push = 1); // TOS is number of args if < 3.6
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_KEYS", .op_code = 27, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_MAPPING", .op_code = 28, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_SEQUENCE", .op_code = 29, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "NOP", .op_code = 30);
	def_op(.op_obj = ret->opcodes, .op_name = "POP_EXCEPT", .op_code = 31, .pop = 1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "POP_TOP", .op_code = 32, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "PUSH_EXC_INFO", .op_code = 33, .pop = 1, .push = 2);
	nargs_op(.op_obj = ret->opcodes, .op_name = "PUSH_NULL", .op_code = 34, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "RETURN_GENERATOR", .op_code = 35, .pop = 0, .push = 0);
	def_op00(.op_obj = ret->opcodes, .op_name = "RETURN_VALUE", .op_code = 36, .pop = 1, .push = 0, .fallthrough = false);
	def_op(.op_obj = ret->opcodes, .op_name = "SETUP_ANNOTATIONS", .op_code = 37);
	def_op(.op_obj = ret->opcodes, .op_name = "STORE_SLICE", .op_code = 38, .pop = 4, .push = 0);
	store_op(.op_obj = ret->opcodes, .op_name = "STORE_SUBSCR", .op_code = 39, .pop = 3, .push = 0); // Implements TOS1[TOS] = TOS2.
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL", .op_code = 40, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "UNARY_INVERT", .op_code = 41, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNARY_NEGATIVE", .op_code = 42, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNARY_NOT", .op_code = 43, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "WITH_EXCEPT_START", .op_code = 44, .pop = 3, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP", .op_code = 45, .pop = 2, .push = 1);
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_CONST_KEY_MAP", .op_code = 46, .pop = -1, .push = 1); // TOS is count of kwargs
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_LIST", .op_code = 47, .pop = 9, .push = 1); // TOS is count of list items
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_MAP", .op_code = 48, .pop = 0, .push = 1); // TOS is count of kwarg items
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_SET", .op_code = 49, .pop = 9, .push = 1); // TOS is count of set items
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_SLICE", .op_code = 50, .pop = 9, .push = 1); // TOS is number of items to pop
	def_op(.op_obj = ret->opcodes, .op_name = "BUILD_STRING", .op_code = 51);
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_TUPLE", .op_code = 52, .pop = 9, .push = 1); // TOS is count of tuple items
	nargs_op(.op_obj = ret->opcodes, .op_name = "CALL", .op_code = 53, .pop = 9, .push = 1);
	nargs_op(.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_EX", .op_code = 54, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_INTRINSIC_1", .op_code = 55, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_INTRINSIC_2", .op_code = 56, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_KW", .op_code = 57, .pop = 9, .push = 1);
	compare_op(.op_obj = ret->opcodes, .op_name = "COMPARE_OP", .op_code = 58, .pop = 2, .push = 1); // Comparison operator
	def_op(.op_obj = ret->opcodes, .op_name = "CONTAINS_OP", .op_code = 59, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "CONVERT_VALUE", .op_code = 60, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COPY", .op_code = 61, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COPY_FREE_VARS", .op_code = 62, .pop = 0, .push = 0);
	name_op(.op_obj = ret->opcodes, .op_name = "DELETE_ATTR", .op_code = 63, .pop = 1, .push = 0); // ""
	free_op(.op_obj = ret->opcodes, .op_name = "DELETE_DEREF", .op_code = 64, .pop = 0, .push = 0);
	local_op(.op_obj = ret->opcodes, .op_name = "DELETE_FAST", .op_code = 65, .pop = 0, .push = 0); // Local variable number
	name_op(.op_obj = ret->opcodes, .op_name = "DELETE_GLOBAL", .op_code = 66, .pop = 0, .push = 0); // ""
	name_op(.op_obj = ret->opcodes, .op_name = "DELETE_NAME", .op_code = 67, .pop = 0, .push = 0); // ""
	def_op(.op_obj = ret->opcodes, .op_name = "DICT_MERGE", .op_code = 68, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "DICT_UPDATE", .op_code = 69, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "EXTENDED_ARG", .op_code = 71);
	jrel_op(.op_obj = ret->opcodes, .op_name = "FOR_ITER", .op_code = 72, .pop = 9, .push = 1, .conditional = true);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_AWAITABLE", .op_code = 73, .pop = 0, .push = 0);
	name_op(.op_obj = ret->opcodes, .op_name = "IMPORT_FROM", .op_code = 74, .pop = 0, .push = 1); // Operand is in name list
	name_op(.op_obj = ret->opcodes, .op_name = "IMPORT_NAME", .op_code = 75, .pop = 1, .push = 1); // Operand is in name list
	def_op(.op_obj = ret->opcodes, .op_name = "IS_OP", .op_code = 76, .pop = 0, .push = 0);
	jrel_op00(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD", .op_code = 77, .pop = 9, .push = 1, .conditional = false);
	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD_NO_INTERRUPT", .op_code = 78, .pop = 0, .push = 0, .conditional = false);
	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_FORWARD", .op_code = 79, .pop = 0, .push = 0); // Number of bytes to skip
	def_op(.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 80, .pop = 2, .push = 1); // Calls list.append(TOS[-i], TOS).
	def_op(.op_obj = ret->opcodes, .op_name = "LIST_EXTEND", .op_code = 81, .pop = 0, .push = 0);
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR", .op_code = 82, .pop = 1, .push = 1); // Operand is in name list
	const_op00(.op_obj = ret->opcodes, .op_name = "LOAD_CONST", .op_code = 83, .pop = 0, .push = 1);
	free_op(.op_obj = ret->opcodes, .op_name = "LOAD_DEREF", .op_code = 84, .pop = 0, .push = 1);
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST", .op_code = 85, .pop = 0, .push = 1); // Local variable number
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_AND_CLEAR", .op_code = 86, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_CHECK", .op_code = 87, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_LOAD_FAST", .op_code = 88, .pop = 0, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FROM_DICT_OR_DEREF", .op_code = 89, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_FROM_DICT_OR_GLOBALS", .op_code = 90, .pop = 1, .push = 1);
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_GLOBAL", .op_code = 91, .pop = 0, .push = 1); // Operand is in name list
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_NAME", .op_code = 92, .pop = 0, .push = 1); // Operand is in name list
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SUPER_ATTR", .op_code = 93, .pop = 3, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "MAKE_CELL", .op_code = 94, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "MAP_ADD", .op_code = 95, .pop = 2, .push = 1); // Calls dict.setitem(TOS1[-i], TOS, TOS1)
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_CLASS", .op_code = 96, .pop = 3, .push = 1);
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 97, .pop = 9, .push = 1, .conditional = true); // ""
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_NONE", .op_code = 98, .conditional = true);
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_NOT_NONE", .op_code = 99, .conditional = true);
	jabs_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 100, .pop = 9, .push = 1, .conditional = true); // ""
	def_op00(.op_obj = ret->opcodes, .op_name = "RAISE_VARARGS", .op_code = 101, .pop = 9, .push = 1, .fallthrough = false);
	def_op(.op_obj = ret->opcodes, .op_name = "RERAISE", .op_code = 102, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "RETURN_CONST", .op_code = 103, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "SEND", .op_code = 104, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "SET_ADD", .op_code = 105, .pop = 1, .push = 0); // Calls set.add(TOS1[-i], TOS).
	def_op(.op_obj = ret->opcodes, .op_name = "SET_FUNCTION_ATTRIBUTE", .op_code = 106, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "SET_UPDATE", .op_code = 107, .pop = 1, .push = 0);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_ATTR", .op_code = 108, .pop = 2, .push = 0, .func = NAME_OP); // Operand is in name list
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_DEREF", .op_code = 109, .pop = 1, .push = 0, .func = FREE_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_FAST", .op_code = 110, .pop = 1, .push = 0, .func = LOCAL_OP); // Local variable number
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_FAST_LOAD_FAST", .op_code = 111, .pop = 1, .push = 1, .func = LOCAL_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_FAST_STORE_FAST", .op_code = 112, .pop = 0, .push = 0, .func = LOCAL_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_GLOBAL", .op_code = 113, .pop = 1, .push = 0, .func = NAME_OP); // ""
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_NAME", .op_code = 114, .pop = 1, .push = 0, .func = NAME_OP); // Operand is in name list
	def_op(.op_obj = ret->opcodes, .op_name = "SWAP", .op_code = 115, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNPACK_EX", .op_code = 116, .pop = 9, .push = 1); // assignment with a starred target; TOS is #entries
	varargs_op(.op_obj = ret->opcodes, .op_name = "UNPACK_SEQUENCE", .op_code = 117, .pop = 9, .push = 1); // TOS is number of tuple items
	def_op(.op_obj = ret->opcodes, .op_name = "YIELD_VALUE", .op_code = 118, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "RESUME", .op_code = 149, .pop = 0, .push = 0);

	ret->extended_arg = 71;
	ret->have_argument = 0;
	ret->jump_use_instruction_offset = true;

	rz_list_purge(ret->opcode_arg_fmt);
	add_arg_fmt(ret, "CALL_FUNCTION_EX", format_CALL_FUNCTION_EX_36);
	add_arg_fmt(ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_36);
	add_arg_fmt(ret, "EXTENDED_ARG", format_extended_arg_36);
	return ret;
}