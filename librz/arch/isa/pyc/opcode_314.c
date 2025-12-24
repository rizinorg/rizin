// SPDX-FileCopyrightText: 2025 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_314(void) {
	pyc_opcodes *ret = new_pyc_opcodes();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (opcode_func)opcode_314;

	def_op(.op_obj = ret->opcodes, .op_name = "CACHE", .op_code = 0, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_SLICE", .op_code = 1, .pop = 3, .push = 1);
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_TEMPLATE", .op_code = 2, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_INPLACE_ADD_UNICODE", .op_code = 3, .pop = 2, .push = 0);
	nargs_op(.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_EX", .op_code = 4, .pop = -1, .push = 1); // pop is -1 as it depends on the value of oparg
	def_op(.op_obj = ret->opcodes, .op_name = "CHECK_EG_MATCH", .op_code = 5, .pop = 2, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "CHECK_EXC_MATCH", .op_code = 6, .pop = 2, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "CLEANUP_THROW", .op_code = 7, .pop = 3, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "DELETE_SUBSCR", .op_code = 8, .pop = 2, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "END_FOR", .op_code = 9, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "END_SEND", .op_code = 10, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "EXIT_INIT_CHECK", .op_code = 11, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "FORMAT_SIMPLE", .op_code = 12, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "FORMAT_WITH_SPEC", .op_code = 13, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_AITER", .op_code = 14, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_ANEXT", .op_code = 15, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_ITER", .op_code = 16, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "RESERVED", .op_code = 17, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_LEN", .op_code = 18, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_YIELD_FROM_ITER", .op_code = 19, .pop = 1, .push = 1);
	def_op00(.op_obj = ret->opcodes, .op_name = "INTERPRETER_EXIT", .op_code = 20, .pop = 1, .push = 0, .fallthrough = false); // contains a return statement
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_BUILD_CLASS", .op_code = 21, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_LOCALS", .op_code = 22, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MAKE_FUNCTION", .op_code = 23, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_KEYS", .op_code = 24, .pop = 2, .push = 3);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_MAPPING", .op_code = 25, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_SEQUENCE", .op_code = 26, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "NOP", .op_code = 27, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "NOT_TAKEN", .op_code = 28, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "POP_EXCEPT", .op_code = 29, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "POP_ITER", .op_code = 30, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "POP_TOP", .op_code = 31, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "PUSH_EXC_INFO", .op_code = 32, .pop = 1, .push = 2);
	nargs_op(.op_obj = ret->opcodes, .op_name = "PUSH_NULL", .op_code = 33, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "RETURN_GENERATOR", .op_code = 34, .pop = 0, .push = 1);
	def_op00(.op_obj = ret->opcodes, .op_name = "RETURN_VALUE", .op_code = 35, .pop = 1, .push = 0, .fallthrough = false);
	def_op(.op_obj = ret->opcodes, .op_name = "SETUP_ANNOTATIONS", .op_code = 36, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "STORE_SLICE", .op_code = 37, .pop = 4, .push = 0);
	store_op(.op_obj = ret->opcodes, .op_name = "STORE_SUBSCR", .op_code = 38, .pop = 3, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL", .op_code = 39, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNARY_INVERT", .op_code = 40, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNARY_NEGATIVE", .op_code = 41, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNARY_NOT", .op_code = 42, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "WITH_EXCEPT_START", .op_code = 43, .pop = 5, .push = 6);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP", .op_code = 44, .pop = 2, .push = 1);
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_INTERPOLATION", .op_code = 45, .pop = -1, .push = 1);
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_LIST", .op_code = 46, .pop = 9, .push = 1); // TOS depends on oparg (values[oparg])
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_MAP", .op_code = 47, .pop = 9, .push = 1); // TOS depends on oparg (values[oparg*2])
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_SET", .op_code = 48, .pop = 9, .push = 1); // TOS depends on oparg (values[oparg])
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_SLICE", .op_code = 49, .pop = 9, .push = 1); // TOS depends on oparg (values[oparg])
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_STRING", .op_code = 50, .pop = 9, .push = 1); // TOS depends on oparg (values[oparg])
	varargs_op(.op_obj = ret->opcodes, .op_name = "BUILD_TUPLE", .op_code = 51, .pop = 9, .push = 1); // TOS depends on oparg (values[oparg])
	nargs_op(.op_obj = ret->opcodes, .op_name = "CALL", .op_code = 52, .pop = -1, .push = 1); // both pop and push depend on oparg
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_INTRINSIC_1", .op_code = 53, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_INTRINSIC_2", .op_code = 54, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_KW", .op_code = 55, .pop = -1, .push = 1);
	compare_op(.op_obj = ret->opcodes, .op_name = "COMPARE_OP", .op_code = 56, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CONTAINS_OP", .op_code = 57, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CONVERT_VALUE", .op_code = 58, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COPY", .op_code = 59, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COPY_FREE_VARS", .op_code = 60, .pop = 0, .push = 0);
	name_op(.op_obj = ret->opcodes, .op_name = "DELETE_ATTR", .op_code = 61, .pop = 1, .push = 0); // the oparg refers to the index in FRAME_CO_NAMES
	free_op(.op_obj = ret->opcodes, .op_name = "DELETE_DEREF", .op_code = 62, .pop = 0, .push = 0);
	local_op(.op_obj = ret->opcodes, .op_name = "DELETE_FAST", .op_code = 63, .pop = 0, .push = 0); // since it indexes into the localsplus array
	name_op(.op_obj = ret->opcodes, .op_name = "DELETE_GLOBAL", .op_code = 64, .pop = 0, .push = 0);
	name_op(.op_obj = ret->opcodes, .op_name = "DELETE_NAME", .op_code = 65, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "DICT_MERGE", .op_code = 66, .pop = -1, .push = -1); // Both the pop and push depend on the oparg
	def_op(.op_obj = ret->opcodes, .op_name = "DICT_UPDATE", .op_code = 67, .pop = -1, .push = -1); // Both the pop and push depend on the oparg
	def_op(.op_obj = ret->opcodes, .op_name = "END_ASYNC_FOR", .op_code = 68, .pop = 2, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "EXTENDED_ARG", .op_code = 69, .pop = 0, .push = 0);
	jrel_op(.op_obj = ret->opcodes, .op_name = "FOR_ITER", .op_code = 70, .pop = 1, .push = 2, .conditional = true);
	def_op(.op_obj = ret->opcodes, .op_name = "GET_AWAITABLE", .op_code = 71, .pop = 1, .push = 1);
	name_op(.op_obj = ret->opcodes, .op_name = "IMPORT_FROM", .op_code = 72, .pop = 1, .push = 2);
	name_op(.op_obj = ret->opcodes, .op_name = "IMPORT_NAME", .op_code = 73, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "IS_OP", .op_code = 74, .pop = 2, .push = 1);
	jrel_op00(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD", .op_code = 75, .pop = 0, .push = 0, .conditional = false);
	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD_NO_INTERRUPT", .op_code = 76, .pop = 0, .push = 0, .conditional = false); //
	jrel_op(.op_obj = ret->opcodes, .op_name = "JUMP_FORWARD", .op_code = 77, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 78, .pop = -1, .push = -1); // Both the pop and push depend on the oparg
	def_op(.op_obj = ret->opcodes, .op_name = "LIST_EXTEND", .op_code = 79, .pop = -1, .push = -1); // Both the pop and push depend on the oparg
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR", .op_code = 80, .pop = 1, .push = -1); // push depends on oparg
	const_op(.op_obj = ret->opcodes, .op_name = "LOAD_COMMON_CONSTANT", .op_code = 81);
	const_op(.op_obj = ret->opcodes, .op_name = "LOAD_CONST", .op_code = 82);
	free_op(.op_obj = ret->opcodes, .op_name = "LOAD_DEREF", .op_code = 83, .pop = 0, .push = 1);
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST", .op_code = 84, .pop = 0, .push = 1);
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_AND_CLEAR", .op_code = 85, .pop = 0, .push = 1); // since it indexes into the localsplus array
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_BORROW", .op_code = 86, .pop = 0, .push = 1);
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_BORROW_LOAD_FAST_BORROW", .op_code = 87, .pop = 0, .push = 2);
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_CHECK", .op_code = 88, .pop = 0, .push = 1); // oparg refers to an index in localsplus array
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FAST_LOAD_FAST", .op_code = 89, .pop = 0, .push = 2); // ""
	local_op(.op_obj = ret->opcodes, .op_name = "LOAD_FROM_DICT_OR_DEREF", .op_code = 90, .pop = 1, .push = 1); // ""
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_FROM_DICT_OR_GLOBALS", .op_code = 91, .pop = 1, .push = 1); // oparg refers to index in FRAME_CO_NAMES
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_GLOBAL", .op_code = 92, .pop = 0, .push = -1);
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_NAME", .op_code = 93, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SMALL_INT", .op_code = 94, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SPECIAL", .op_code = 95, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SUPER_ATTR", .op_code = 96, .pop = 3, .push = -1);
	local_op(.op_obj = ret->opcodes, .op_name = "MAKE_CELL", .op_code = 97, .pop = 0, .push = 0); // since it indexes into the localsplus array
	def_op(.op_obj = ret->opcodes, .op_name = "MAP_ADD", .op_code = 98, .pop = -1, .push = -1); // Both the pop and push depend on the oparg
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_CLASS", .op_code = 99, .pop = 3, .push = 1);
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 100, .pop = 1, .push = 0, .conditional = true); // calls JUMPBY
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_NONE", .op_code = 101, .pop = 1, .push = 0, .conditional = true); // ""
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_NOT_NONE", .op_code = 102, .pop = 1, .push = 0, .conditional = true); // ""
	jrel_op(.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 103, .pop = 1, .push = 0, .conditional = true); //
	def_op00(.op_obj = ret->opcodes, .op_name = "RAISE_VARARGS", .op_code = 104, .pop = 9, .push = 0, .fallthrough = false); // contains a goto
	def_op00(.op_obj = ret->opcodes, .op_name = "RERAISE", .op_code = 105, .pop = -1, .push = 9, .fallthrough = false); // ""
	def_op(.op_obj = ret->opcodes, .op_name = "SEND", .op_code = 106, .pop = 2, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "SET_ADD", .op_code = 107, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "SET_FUNCTION_ATTRIBUTE", .op_code = 108, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "SET_UPDATE", .op_code = 109, .pop = -1, .push = -1);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_ATTR", .op_code = 110, .pop = 2, .push = 0, .func = NAME_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_DEREF", .op_code = 111, .pop = 1, .push = 0, .func = FREE_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_FAST", .op_code = 112, .pop = 1, .push = 0, .func = LOCAL_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_FAST_LOAD_FAST", .op_code = 113, .pop = 1, .push = 1, .func = LOCAL_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_FAST_STORE_FAST", .op_code = 114, .pop = 2, .push = 0, .func = LOCAL_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_GLOBAL", .op_code = 115, .pop = 1, .push = 0, .func = NAME_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_NAME", .op_code = 116, .pop = 1, .push = 0, .func = NAME_OP);
	def_op(.op_obj = ret->opcodes, .op_name = "SWAP", .op_code = 117, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNPACK_EX", .op_code = 118, .pop = 1, .push = -1);
	varargs_op(.op_obj = ret->opcodes, .op_name = "UNPACK_SEQUENCE", .op_code = 119, .pop = 1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "YIELD_VALUE", .op_code = 120, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "RESUME", .op_code = 128, .pop = 0, .push = 0);
	//
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADD_FLOAT", .op_code = 129, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADD_INT", .op_code = 130, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_ADD_UNICODE", .op_code = 131, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_EXTEND", .op_code = 132, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_MULTIPLY_FLOAT", .op_code = 133, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_MULTIPLY_INT", .op_code = 134, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBSCR_DICT", .op_code = 135, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBSCR_GETITEM", .op_code = 136, .pop = 2, .push = 0); // since it creates a new frame(doesnt push)
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBSCR_LIST_INT", .op_code = 137, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBSCR_LIST_SLICE", .op_code = 138, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBSCR_STR_INT", .op_code = 139, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBSCR_TUPLE_INT", .op_code = 140, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBTRACT_FLOAT", .op_code = 141, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "BINARY_OP_SUBTRACT_INT", .op_code = 142, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_ALLOC_AND_ENTER_INIT", .op_code = 143, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_BOUND_METHOD_EXACT_ARGS", .op_code = 144, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_BOUND_METHOD_GENERAL", .op_code = 145, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_BUILTIN_CLASS", .op_code = 146, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_BUILTIN_FAST", .op_code = 147, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_BUILTIN_FAST_WITH_KEYWORDS", .op_code = 148, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_BUILTIN_O", .op_code = 149, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_ISINSTANCE", .op_code = 150, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_KW_BOUND_METHOD", .op_code = 151, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_KW_NON_PY", .op_code = 152, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_KW_PY", .op_code = 153, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_LEN", .op_code = 154, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_LIST_APPEND", .op_code = 155, .pop = 3, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_METHOD_DESCRIPTOR_FAST", .op_code = 156, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS", .op_code = 157, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_METHOD_DESCRIPTOR_NOARGS", .op_code = 158, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_METHOD_DESCRIPTOR_O", .op_code = 159, .pop = -1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_NON_PY_GENERAL", .op_code = 160, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_PY_EXACT_ARGS", .op_code = 161, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_PY_GENERAL", .op_code = 162, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_STR_1", .op_code = 163, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_TUPLE_1", .op_code = 164, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CALL_TYPE_1", .op_code = 165, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COMPARE_OP_FLOAT", .op_code = 166, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COMPARE_OP_INT", .op_code = 167, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "COMPARE_OP_STR", .op_code = 168, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CONTAINS_OP_DICT", .op_code = 169, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "CONTAINS_OP_SET", .op_code = 170, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "FOR_ITER_GEN", .op_code = 171, .pop = 1, .push = 1); // push is 1 since it creates a new frame
	def_op(.op_obj = ret->opcodes, .op_name = "FOR_ITER_LIST", .op_code = 172, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "FOR_ITER_RANGE", .op_code = 173, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "FOR_ITER_TUPLE", .op_code = 174, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD_JIT", .op_code = 175, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "JUMP_BACKWARD_NO_JIT", .op_code = 176, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_CLASS", .op_code = 177, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_CLASS_WITH_METACLASS_CHECK", .op_code = 178, .pop = 1, .push = 1);
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN", .op_code = 179, .pop = 1, .push = 0); // oparg refers to an index in FRAME_CO_NAMES
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_INSTANCE_VALUE", .op_code = 180, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_METHOD_LAZY_DICT", .op_code = 181, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_METHOD_NO_DICT", .op_code = 182, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_METHOD_WITH_VALUES", .op_code = 183, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_MODULE", .op_code = 184, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_NONDESCRIPTOR_NO_DICT", .op_code = 185, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES", .op_code = 186, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_PROPERTY", .op_code = 187, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_SLOT", .op_code = 188, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_ATTR_WITH_HINT", .op_code = 189, .pop = 1, .push = 1);
	const_op(.op_obj = ret->opcodes, .op_name = "LOAD_CONST_IMMORTAL", .op_code = 190); // oparg refers to an index in FRAME_CO_CONSTS
	const_op(.op_obj = ret->opcodes, .op_name = "LOAD_CONST_MORTAL", .op_code = 191); // ""
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_GLOBAL_BUILTIN", .op_code = 192, .pop = 0, .push = 2);
	name_op(.op_obj = ret->opcodes, .op_name = "LOAD_GLOBAL_MODULE", .op_code = 193, .pop = 0, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SUPER_ATTR_ATTR", .op_code = 194, .pop = 3, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "LOAD_SUPER_ATTR_METHOD", .op_code = 195, .pop = 3, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "RESUME_CHECK", .op_code = 196, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "SEND_GEN", .op_code = 197, .pop = 2, .push = 1);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_ATTR_INSTANCE_VALUE", .op_code = 198, .pop = 2, .push = 0, .func = NAME_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_ATTR_SLOT", .op_code = 199, .pop = 2, .push = 0, .func = NAME_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_ATTR_WITH_HINT", .op_code = 200, .pop = 2, .push = 0, .func = NAME_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_SUBSCR_DICT", .op_code = 201, .pop = 3, .push = 0, .func = DEF_OP);
	store_op00(.op_obj = ret->opcodes, .op_name = "STORE_SUBSCR_LIST_INT", .op_code = 202, .pop = 3, .push = 0, .func = DEF_OP);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL_ALWAYS_TRUE", .op_code = 203, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL_BOOL", .op_code = 204, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL_INT", .op_code = 205, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL_LIST", .op_code = 206, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL_NONE", .op_code = 207, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "TO_BOOL_STR", .op_code = 208, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNPACK_SEQUENCE_LIST", .op_code = 209, .pop = 1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNPACK_SEQUENCE_TUPLE", .op_code = 210, .pop = 1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "UNPACK_SEQUENCE_TWO_TUPLE", .op_code = 211, .pop = 1, .push = 2);
	//
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_END_FOR", .op_code = 234, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_POP_ITER", .op_code = 235, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_END_SEND", .op_code = 236, .pop = 2, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_FOR_ITER", .op_code = 237, .pop = 1, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_INSTRUCTION", .op_code = 238, .pop = 0, .push = 0);
	jrel_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_JUMP_FORWARD", .op_code = 239, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_NOT_TAKEN", .op_code = 240, .pop = 0, .push = 0);
	jabs_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_POP_JUMP_IF_TRUE", .op_code = 241, .pop = 1, .push = 0); // jabs_op as it calls INSTRUMENTED_JUMP
	jabs_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_POP_JUMP_IF_FALSE", .op_code = 242, .pop = 1, .push = 0);
	jabs_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_POP_JUMP_IF_NONE", .op_code = 243, .pop = 1, .push = 0);
	jabs_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_POP_JUMP_IF_NOT_NONE", .op_code = 244, .pop = 1, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_RESUME", .op_code = 245, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_RETURN_VALUE", .op_code = 246, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_YIELD_VALUE", .op_code = 247, .pop = 1, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_END_ASYNC_FOR", .op_code = 248, .pop = 2, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_LOAD_SUPER_ATTR", .op_code = 249, .pop = 3, .push = 2);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_CALL", .op_code = 250, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_CALL_KW", .op_code = 251, .pop = -1, .push = -1);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_CALL_FUNCTION_EX", .op_code = 252, .pop = 9, .push = 9); // depends on kwargs
	jrel_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_JUMP_BACKWARD", .op_code = 253, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "INSTRUMENTED_LINE", .op_code = 254, .pop = 0, .push = 0);
	def_op(.op_obj = ret->opcodes, .op_name = "ENTER_EXECUTOR", .op_code = 255, .pop = 0, .push = 0);

	ret->extended_arg = 71;
	ret->have_argument = 0;
	ret->jump_use_instruction_offset = true;

	rz_list_purge(ret->opcode_arg_fmt);
	return ret;
}