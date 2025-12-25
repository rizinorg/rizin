// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

// The actual code of one opcode varies across the versions.
// That's why I specify one opcode by its name, not its code.

static inline void analysis_push(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg, ut32 type, st32 push_cnt) {
	op->type = type;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = OBJECT_SIZE_ON_STACK * push_cnt;
}

static inline void analysis_pop(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg, ut32 type, st32 push_cnt) {
	op->type = type;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = -(OBJECT_SIZE_ON_STACK * push_cnt);
}

static inline void analysis_relative_jump_backward(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg, ut32 type) {
	op->type = type;
	op->jump = op->addr + 2 - (2 * oparg);
}

static inline void analysis_BEFORE_ASYNC_WITH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_BEGIN_FINALLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_ADD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_ADD, 1);
}

static inline void analysis_BINARY_AND(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_AND, 1);
}

static inline void analysis_BINARY_CALL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4b3/Include/opcode.h
	// I can not find this opcode even in v1.4 version source code.
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_BINARY_DIVIDE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_DIV, 1);
}

static inline void analysis_BINARY_FLOOR_DIVIDE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_DIV, 1);
}

static inline void analysis_BINARY_LSHIFT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_SHL, 1);
}

static inline void analysis_BINARY_MATRIX_MULTIPLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_MODULO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_MOD, 1);
}

static inline void analysis_BINARY_MULTIPLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_MUL, 1);
}

static inline void analysis_BINARY_OR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_OR, 1);
}

static inline void analysis_BINARY_POWER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_RSHIFT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_SHR, 1);
}

static inline void analysis_BINARY_SUBSCR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_SUBTRACT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_SUB, 1);
}

static inline void analysis_BINARY_TRUE_DIVIDE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_DIV, 1);
}

static inline void analysis_BINARY_XOR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_XOR, 1);
}

static inline void analysis_BREAK_LOOP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	//  This is actually a jump, but require further analysis
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->jump = -1;
	op->fail = -1;
}

static inline void analysis_BUILD_CLASS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, 2);
}

static inline void analysis_BUILD_CONST_KEY_MAP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg);
}

static inline void analysis_BUILD_FUNCTION(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NEW;
}

static inline void analysis_BUILD_LIST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg);
}

static inline void analysis_BUILD_LIST_UNPACK(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_MAP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, 2 * oparg - 1);
}

static inline void analysis_BUILD_MAP_UNPACK(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_MAP_UNPACK_WITH_CALL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg);
}

static inline void analysis_BUILD_SET(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_SET_UNPACK(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_SLICE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_STRING(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_TUPLE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_TUPLE_UNPACK(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg - 1);
}

static inline void analysis_BUILD_TUPLE_UNPACK_WITH_CALL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_NEW, oparg);
}

static inline void analysis_CALL_FUNCTION(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// TODO
	// Get callee function from stack
	// Parse oparg by version info
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
	op->jump = -1;
}

static inline void analysis_CALL_FUNCTION_EX(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
	op->jump = -1;
}

static inline void analysis_CALL_FUNCTION_KW(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
	op->jump = -1;
}

static inline void analysis_CALL_FUNCTION_VAR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
	op->jump = -1;
}

static inline void analysis_CALL_FUNCTION_VAR_KW(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
	op->jump = -1;
}

static inline void analysis_CALL_METHOD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
	op->jump = -1;
}

static inline void analysis_DELETE_ATTR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_DEREF(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_GLOBAL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_NAME(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_SLICE_0(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_SLICE_1(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_SLICE_2(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_SLICE_3(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DELETE_SUBSCR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_DUP_TOP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UPUSH, 1);
}

static inline void analysis_DUP_TOPX(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UPUSH, 1);
}

static inline void analysis_DUP_TOP_TWO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UPUSH, 2);
}

static inline void analysis_END_ASYNC_FOR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// If TOS is StopAsyncIteration pop 7 values from the stack and restore the exception state using the second three of them.
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_END_FINALLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	//  This is actually a jump, but require further analysis
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->jump = -1;
	op->fail = -1;
}

static inline void analysis_EXEC_STMT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_EXTENDED_ARG(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_FORMAT_VALUE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	if ((oparg & 0x04) == 0x04) {
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -OBJECT_SIZE_ON_STACK;
	}
}

static inline void analysis_FOR_LOOP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/b2b1ed17819ecb24a78d07d3ff1e8e6bc6137721/Python/ceval.c#L1499
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_GET_AITER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_GET_ANEXT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_GET_AWAITABLE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_GET_ITER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_GET_YIELD_FROM_ITER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_IMPORT_FROM(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_IMPORT_NAME(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_IMPORT_STAR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_INPLACE_ADD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ADD;
}

static inline void analysis_INPLACE_AND(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_AND;
}

static inline void analysis_INPLACE_DIVIDE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_DIV;
}

static inline void analysis_INPLACE_FLOOR_DIVIDE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_DIV;
}

static inline void analysis_INPLACE_LSHIFT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_SHL;
}

static inline void analysis_INPLACE_MATRIX_MULTIPLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_INPLACE_MODULO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_MOD;
}

static inline void analysis_INPLACE_MULTIPLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_MUL;
}

static inline void analysis_INPLACE_OR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_OR;
}

static inline void analysis_INPLACE_POWER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_INPLACE_RSHIFT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_SHR;
}

static inline void analysis_INPLACE_SUBTRACT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_SUB;
}

static inline void analysis_INPLACE_TRUE_DIVIDE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_DIV;
}

static inline void analysis_INPLACE_XOR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_XOR;
}

static inline void analysis_LIST_APPEND(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_ASSERTION_ERROR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_ATTR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_LOAD_BUILD_CLASS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_CLASSDEREF(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_CLOSURE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_CONST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_DEREF(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_GLOBAL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_GLOBALS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/24260ec91623c18569225229d5becb852010ae2c/Include/opcode.h#L80
	// Can't find this opcode
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_LOAD_LOCAL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_LOCALS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_METHOD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_NAME(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_MAKE_CLOSURE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg);
}

static inline void analysis_MAKE_FUNCTION(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg);
}

static inline void analysis_MAP_ADD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_NOP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NOP;
}

static inline void analysis_POP_BLOCK(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_POP, 1);
}

static inline void analysis_POP_EXCEPT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_POP, 1);
}

static inline void analysis_POP_FINALLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// FIXME
	// POP_FINALLY will pop 6 elements if TOS is an exception type
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_POP, 1);
}

static inline void analysis_POP_TOP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_POP, 1);
}

static inline void analysis_PRINT_EXPR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_PRINT_ITEM(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_PRINT_ITEM_TO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_PRINT_NEWLINE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_PRINT_NEWLINE_TO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_RAISE_EXCEPTION(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/6c3a3aa17b028f6b93067083d32c7eaa4338757c/Include/opcode.h#L89
	// Can't find this opcode
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_RAISE_VARARGS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg);
}

static inline void analysis_RERAISE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 3);
}

static inline void analysis_RESERVE_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/6c3a3aa17b028f6b93067083d32c7eaa4338757c/Include/opcode.h#L134
	// Can't find this opcode
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_RETURN_VALUE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = -OBJECT_SIZE_ON_STACK;
	op->eob = true;
}

static inline void analysis_ROT_FOUR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Lifts second, third and forth stack items one position up, moves top down to position four.
	op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
}

static inline void analysis_ROT_THREE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Lifts second and third stack item one position up, moves top down to position three.
	op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
}

static inline void analysis_ROT_TWO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Swaps the two top-most stack items.
	op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
}

static inline void analysis_SETUP_ANNOTATIONS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_SET_ADD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_SET_FUNC_ARGS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4/Python/ceval.c
	// Can't find this opcode
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_SET_LINENO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_SLICE_0(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_SLICE_1(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_SLICE_2(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_SLICE_3(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_STOP_CODE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
}

static inline void analysis_STORE_ANNOTATION(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_STORE_ATTR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_STORE_DEREF(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_STORE_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_STORE_GLOBAL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_STORE_LOCALS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_STORE_MAP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_STORE_NAME(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_STORE_SLICE_0(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_STORE_SLICE_1(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 3);
}

static inline void analysis_STORE_SLICE_2(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 3);
}

static inline void analysis_STORE_SLICE_3(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 4);
}

static inline void analysis_STORE_SUBSCR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 3);
}

static inline void analysis_UNARY_CALL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4b3/Include/opcode.h
	// I can not find this opcode even in v1.4 version source code.
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_UNARY_CONVERT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_UNARY_INVERT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NOT;
}

static inline void analysis_UNARY_NEGATIVE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_UNARY_NOT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NOT;
}

static inline void analysis_UNARY_POSITIVE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_UNPACK_ARG(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg - 1);
}

static inline void analysis_UNPACK_EX(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, (oparg & 0xFF) + (oparg >> 8));
}

static inline void analysis_UNPACK_LIST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg - 1);
}

static inline void analysis_UNPACK_SEQUENCE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg - 1);
}

static inline void analysis_UNPACK_TUPLE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg - 1);
}

static inline void analysis_UNPACK_VARARG(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4b3/Include/opcode.h
	// I can not find this opcode even in v1.4 version source code.
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_WITH_CLEANUP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Need the value on stack
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_WITH_CLEANUP_FINISH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_WITH_CLEANUP_START(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Need the value on stack
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_WITH_EXCEPT_START(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_YIELD_FROM(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_YIELD_VALUE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_FOR_ITER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static inline void analysis_SETUP_LOOP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static inline void analysis_SETUP_EXCEPT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static inline void analysis_SETUP_FINALLY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static inline void analysis_SETUP_WITH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static inline void analysis_SETUP_ASYNC_WITH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

// 3.11.0 opcodes
static inline void analysis_ASYNC_GEN_WRAP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_RETURN_GENERATOR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NEW;
}

static inline void analysis_SEND(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_COPY_FREE_VARS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_MAKE_CELL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NEW;
}

static inline void analysis_CHECK_EXC_MATCH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_COND;
}

static inline void analysis_CHECK_EG_MATCH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_COND;
}

static inline void analysis_PREP_RERAISE_STAR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NEW;
}

static inline void analysis_PUSH_EXC_INFO(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_RESUME(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NOP;
}

static inline void analysis_JUMP_BACKWARD_NO_INTERRUPT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_relative_jump_backward(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_JMP);
}

// combined BINARY_* and INPLACE_* in one
static inline void analysis_BINARY_OP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	switch (oparg) {
	case 0:
		analysis_BINARY_ADD(op, op_obj, oparg);
		break;
	case 1:
		analysis_BINARY_AND(op, op_obj, oparg);
		break;
	case 2:
		analysis_BINARY_FLOOR_DIVIDE(op, op_obj, oparg);
		break;
	case 3:
		analysis_BINARY_LSHIFT(op, op_obj, oparg);
		break;
	case 4:
		analysis_BINARY_MATRIX_MULTIPLY(op, op_obj, oparg);
		break;
	case 5:
		analysis_BINARY_MULTIPLY(op, op_obj, oparg);
		break;
	case 6:
		analysis_BINARY_MODULO(op, op_obj, oparg);
		break;
	case 7:
		analysis_BINARY_OR(op, op_obj, oparg);
		break;
	case 8:
		analysis_BINARY_POWER(op, op_obj, oparg);
		break;
	case 9:
		analysis_BINARY_RSHIFT(op, op_obj, oparg);
		break;
	case 10:
		analysis_BINARY_SUBTRACT(op, op_obj, oparg);
		break;
	case 11:
		analysis_BINARY_TRUE_DIVIDE(op, op_obj, oparg);
		break;
	case 12:
		analysis_BINARY_XOR(op, op_obj, oparg);
		break;
	case 13:
		analysis_INPLACE_ADD(op, op_obj, oparg);
		break;
	case 14:
		analysis_INPLACE_AND(op, op_obj, oparg);
		break;
	case 15:
		analysis_INPLACE_FLOOR_DIVIDE(op, op_obj, oparg);
		break;
	case 16:
		analysis_INPLACE_LSHIFT(op, op_obj, oparg);
		break;
	case 17:
		analysis_INPLACE_MATRIX_MULTIPLY(op, op_obj, oparg);
		break;
	case 18:
		analysis_INPLACE_MULTIPLY(op, op_obj, oparg);
		break;
	case 19:
		analysis_INPLACE_MODULO(op, op_obj, oparg);
		break;
	case 20:
		analysis_INPLACE_OR(op, op_obj, oparg);
		break;
	case 21:
		analysis_INPLACE_POWER(op, op_obj, oparg);
		break;
	case 22:
		analysis_INPLACE_RSHIFT(op, op_obj, oparg);
		break;
	case 23:
		analysis_INPLACE_SUBTRACT(op, op_obj, oparg);
		break;
	case 24:
		analysis_INPLACE_TRUE_DIVIDE(op, op_obj, oparg);
		break;
	case 25:
		analysis_INPLACE_XOR(op, op_obj, oparg);
		break;
	default:
		analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
		break;
	}
}

static inline void analysis_CALL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
}

static inline void analysis_KW_NAMES(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_PRECALL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NOP;
}

static inline void analysis_PUSH_NULL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_PUSH, 1);
}

static inline void analysis_COPY(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_PUSH, 1);
}

static inline void analysis_SWAP(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_JUMP_BACKWARD(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_relative_jump_backward(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_JMP);
}

static inline void analysis_POP_JUMP_FORWARD_IF_TRUE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
}

static inline void analysis_POP_JUMP_FORWARD_IF_FALSE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
}

static inline void analysis_POP_JUMP_FORWARD_IF_NOT_NONE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
}

static inline void analysis_POP_JUMP_FORWARD_IF_NONE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
}

static inline void analysis_POP_JUMP_BACKWARD_IF_TRUE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_relative_jump_backward(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_CJMP);
}

static inline void analysis_POP_JUMP_BACKWARD_IF_FALSE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_relative_jump_backward(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_CJMP);
}

static inline void analysis_POP_JUMP_BACKWARD_IF_NOT_NONE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_relative_jump_backward(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_CJMP);
}

static inline void analysis_POP_JUMP_BACKWARD_IF_NONE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_relative_jump_backward(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_CJMP);
}

static inline void analysis_BEFORE_WITH(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_CACHE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_NOP;
}

static inline void analysis_BINARY_SLICE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_STORE_SLICE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 4);
}

static inline void analysis_CALL_INTRINSIC_1(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
}

static inline void analysis_CALL_INTRINSIC_2(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UCALL, 1);
}

static inline void analysis_CLEANUP_THROW(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_END_SEND(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_END_FOR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_LOAD_FAST_AND_CLEAR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_FAST_CHECK(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_FROM_DICT_OR_DEREF(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_FROM_DICT_OR_GLOBALS(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_LOAD_SUPER_ATTR(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 3);
}

static inline void analysis_RETURN_CONST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_TO_BOOL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_LOAD_FAST_LOAD_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_STORE_FAST_STORE_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_STORE_FAST_LOAD_FAST(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_CALL_KW(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
}

static inline void analysis_SET_FUNCTION_ATTRIBUTE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_CONVERT_VALUE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_FORMAT_SIMPLE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_FORMAT_WITH_SPEC(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_POP_ITER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_INSTRUMENTED_POP_ITER(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline void analysis_LOAD_SPECIAL(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_SMALL_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_FAST_BORROW(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_LOAD_FAST_BORROW_LOAD_FAST_BORROW(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_LOAD_COMMON_CONSTANT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_push(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BUILD_INTERPOLATION(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, oparg + 1);
}

static inline void analysis_BUILD_TEMPLATE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_ADD_FLOAT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_ADD, 1);
}

static inline void analysis_BINARY_OP_ADD_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_ADD, 1);
}

static inline void analysis_BINARY_OP_ADD_UNICODE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_ADD, 1);
}

static inline void analysis_BINARY_OP_EXTEND(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_MULTIPLY_FLOAT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_MUL, 1);
}

static inline void analysis_BINARY_OP_MULTIPLY_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_MUL, 1);
}

static inline void analysis_BINARY_OP_SUBSCR_DICT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_SUBSCR_GETITEM(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 2);
}

static inline void analysis_BINARY_OP_SUBSCR_LIST_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_SUBSCR_LIST_SLICE(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_SUBSCR_STR_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_SUBSCR_TUPLE_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_UNK, 1);
}

static inline void analysis_BINARY_OP_SUBTRACT_FLOAT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_SUB, 1);
}

static inline void analysis_BINARY_OP_SUBTRACT_INT(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	analysis_pop(op, op_obj, oparg, RZ_ANALYSIS_OP_TYPE_SUB, 1);
}

static op_analysis_func op_analysis[] = {
	{ "BEFORE_ASYNC_WITH", analysis_BEFORE_ASYNC_WITH },
	{ "BEGIN_FINALLY", analysis_BEGIN_FINALLY },
	{ "BINARY_ADD", analysis_BINARY_ADD },
	{ "BINARY_AND", analysis_BINARY_AND },
	{ "BINARY_CALL", analysis_BINARY_CALL },
	{ "BINARY_DIVIDE", analysis_BINARY_DIVIDE },
	{ "BINARY_FLOOR_DIVIDE", analysis_BINARY_FLOOR_DIVIDE },
	{ "BINARY_LSHIFT", analysis_BINARY_LSHIFT },
	{ "BINARY_MATRIX_MULTIPLY", analysis_BINARY_MATRIX_MULTIPLY },
	{ "BINARY_MODULO", analysis_BINARY_MODULO },
	{ "BINARY_MULTIPLY", analysis_BINARY_MULTIPLY },
	{ "BINARY_OR", analysis_BINARY_OR },
	{ "BINARY_POWER", analysis_BINARY_POWER },
	{ "BINARY_RSHIFT", analysis_BINARY_RSHIFT },
	{ "BINARY_SUBSCR", analysis_BINARY_SUBSCR },
	{ "BINARY_SUBTRACT", analysis_BINARY_SUBTRACT },
	{ "BINARY_TRUE_DIVIDE", analysis_BINARY_TRUE_DIVIDE },
	{ "BINARY_XOR", analysis_BINARY_XOR },
	{ "BREAK_LOOP", analysis_BREAK_LOOP },
	{ "BUILD_CLASS", analysis_BUILD_CLASS },
	{ "BUILD_CONST_KEY_MAP", analysis_BUILD_CONST_KEY_MAP },
	{ "BUILD_FUNCTION", analysis_BUILD_FUNCTION },
	{ "BUILD_LIST", analysis_BUILD_LIST },
	{ "BUILD_LIST_UNPACK", analysis_BUILD_LIST_UNPACK },
	{ "BUILD_MAP", analysis_BUILD_MAP },
	{ "BUILD_MAP_UNPACK", analysis_BUILD_MAP_UNPACK },
	{ "BUILD_MAP_UNPACK_WITH_CALL", analysis_BUILD_MAP_UNPACK_WITH_CALL },
	{ "BUILD_SET", analysis_BUILD_SET },
	{ "BUILD_SET_UNPACK", analysis_BUILD_SET_UNPACK },
	{ "BUILD_SLICE", analysis_BUILD_SLICE },
	{ "BUILD_STRING", analysis_BUILD_STRING },
	{ "BUILD_TUPLE", analysis_BUILD_TUPLE },
	{ "BUILD_TUPLE_UNPACK", analysis_BUILD_TUPLE_UNPACK },
	{ "BUILD_TUPLE_UNPACK_WITH_CALL", analysis_BUILD_TUPLE_UNPACK_WITH_CALL },
	{ "CALL_FUNCTION", analysis_CALL_FUNCTION },
	{ "CALL_FUNCTION_EX", analysis_CALL_FUNCTION_EX },
	{ "CALL_FUNCTION_KW", analysis_CALL_FUNCTION_KW },
	{ "CALL_FUNCTION_VAR", analysis_CALL_FUNCTION_VAR },
	{ "CALL_FUNCTION_VAR_KW", analysis_CALL_FUNCTION_VAR_KW },
	{ "CALL_METHOD", analysis_CALL_METHOD },
	{ "DELETE_ATTR", analysis_DELETE_ATTR },
	{ "DELETE_DEREF", analysis_DELETE_DEREF },
	{ "DELETE_FAST", analysis_DELETE_FAST },
	{ "DELETE_GLOBAL", analysis_DELETE_GLOBAL },
	{ "DELETE_NAME", analysis_DELETE_NAME },
	{ "DELETE_SLICE_0", analysis_DELETE_SLICE_0 },
	{ "DELETE_SLICE_1", analysis_DELETE_SLICE_1 },
	{ "DELETE_SLICE_2", analysis_DELETE_SLICE_2 },
	{ "DELETE_SLICE_3", analysis_DELETE_SLICE_3 },
	{ "DELETE_SUBSCR", analysis_DELETE_SUBSCR },
	{ "DUP_TOP", analysis_DUP_TOP },
	{ "DUP_TOPX", analysis_DUP_TOPX },
	{ "DUP_TOP_TWO", analysis_DUP_TOP_TWO },
	{ "END_ASYNC_FOR", analysis_END_ASYNC_FOR },
	{ "END_FINALLY", analysis_END_FINALLY },
	{ "EXEC_STMT", analysis_EXEC_STMT },
	{ "EXTENDED_ARG", analysis_EXTENDED_ARG },
	{ "FORMAT_VALUE", analysis_FORMAT_VALUE },
	{ "FOR_LOOP", analysis_FOR_LOOP },
	{ "GET_AITER", analysis_GET_AITER },
	{ "GET_ANEXT", analysis_GET_ANEXT },
	{ "GET_AWAITABLE", analysis_GET_AWAITABLE },
	{ "GET_ITER", analysis_GET_ITER },
	{ "GET_YIELD_FROM_ITER", analysis_GET_YIELD_FROM_ITER },
	{ "IMPORT_FROM", analysis_IMPORT_FROM },
	{ "IMPORT_NAME", analysis_IMPORT_NAME },
	{ "IMPORT_STAR", analysis_IMPORT_STAR },
	{ "INPLACE_ADD", analysis_INPLACE_ADD },
	{ "INPLACE_AND", analysis_INPLACE_AND },
	{ "INPLACE_DIVIDE", analysis_INPLACE_DIVIDE },
	{ "INPLACE_FLOOR_DIVIDE", analysis_INPLACE_FLOOR_DIVIDE },
	{ "INPLACE_LSHIFT", analysis_INPLACE_LSHIFT },
	{ "INPLACE_MATRIX_MULTIPLY", analysis_INPLACE_MATRIX_MULTIPLY },
	{ "INPLACE_MODULO", analysis_INPLACE_MODULO },
	{ "INPLACE_MULTIPLY", analysis_INPLACE_MULTIPLY },
	{ "INPLACE_OR", analysis_INPLACE_OR },
	{ "INPLACE_POWER", analysis_INPLACE_POWER },
	{ "INPLACE_RSHIFT", analysis_INPLACE_RSHIFT },
	{ "INPLACE_SUBTRACT", analysis_INPLACE_SUBTRACT },
	{ "INPLACE_TRUE_DIVIDE", analysis_INPLACE_TRUE_DIVIDE },
	{ "INPLACE_XOR", analysis_INPLACE_XOR },
	{ "LIST_APPEND", analysis_LIST_APPEND },
	{ "LOAD_ASSERTION_ERROR", analysis_LOAD_ASSERTION_ERROR },
	{ "LOAD_ATTR", analysis_LOAD_ATTR },
	{ "LOAD_BUILD_CLASS", analysis_LOAD_BUILD_CLASS },
	{ "LOAD_CLASSDEREF", analysis_LOAD_CLASSDEREF },
	{ "LOAD_CLOSURE", analysis_LOAD_CLOSURE },
	{ "LOAD_CONST", analysis_LOAD_CONST },
	{ "LOAD_DEREF", analysis_LOAD_DEREF },
	{ "LOAD_FAST", analysis_LOAD_FAST },
	{ "LOAD_GLOBAL", analysis_LOAD_GLOBAL },
	{ "LOAD_GLOBALS", analysis_LOAD_GLOBALS },
	{ "LOAD_LOCAL", analysis_LOAD_LOCAL },
	{ "LOAD_LOCALS", analysis_LOAD_LOCALS },
	{ "LOAD_METHOD", analysis_LOAD_METHOD },
	{ "LOAD_NAME", analysis_LOAD_NAME },
	{ "MAKE_CLOSURE", analysis_MAKE_CLOSURE },
	{ "MAKE_FUNCTION", analysis_MAKE_FUNCTION },
	{ "MAP_ADD", analysis_MAP_ADD },
	{ "NOP", analysis_NOP },
	{ "POP_BLOCK", analysis_POP_BLOCK },
	{ "POP_EXCEPT", analysis_POP_EXCEPT },
	{ "POP_FINALLY", analysis_POP_FINALLY },
	{ "POP_TOP", analysis_POP_TOP },
	{ "PRINT_EXPR", analysis_PRINT_EXPR },
	{ "PRINT_ITEM", analysis_PRINT_ITEM },
	{ "PRINT_ITEM_TO", analysis_PRINT_ITEM_TO },
	{ "PRINT_NEWLINE", analysis_PRINT_NEWLINE },
	{ "PRINT_NEWLINE_TO", analysis_PRINT_NEWLINE_TO },
	{ "RAISE_EXCEPTION", analysis_RAISE_EXCEPTION },
	{ "RAISE_VARARGS", analysis_RAISE_VARARGS },
	{ "RERAISE", analysis_RERAISE },
	{ "RESERVE_FAST", analysis_RESERVE_FAST },
	{ "RETURN_VALUE", analysis_RETURN_VALUE },
	{ "ROT_FOUR", analysis_ROT_FOUR },
	{ "ROT_THREE", analysis_ROT_THREE },
	{ "ROT_TWO", analysis_ROT_TWO },
	{ "SETUP_ANNOTATIONS", analysis_SETUP_ANNOTATIONS },
	{ "SET_ADD", analysis_SET_ADD },
	{ "SET_FUNC_ARGS", analysis_SET_FUNC_ARGS },
	{ "SET_LINENO", analysis_SET_LINENO },
	{ "SLICE_0", analysis_SLICE_0 },
	{ "SLICE_1", analysis_SLICE_1 },
	{ "SLICE_2", analysis_SLICE_2 },
	{ "SLICE_3", analysis_SLICE_3 },
	{ "STOP_CODE", analysis_STOP_CODE },
	{ "STORE_ANNOTATION", analysis_STORE_ANNOTATION },
	{ "STORE_ATTR", analysis_STORE_ATTR },
	{ "STORE_DEREF", analysis_STORE_DEREF },
	{ "STORE_FAST", analysis_STORE_FAST },
	{ "STORE_GLOBAL", analysis_STORE_GLOBAL },
	{ "STORE_LOCALS", analysis_STORE_LOCALS },
	{ "STORE_MAP", analysis_STORE_MAP },
	{ "STORE_NAME", analysis_STORE_NAME },
	{ "STORE_SLICE_0", analysis_STORE_SLICE_0 },
	{ "STORE_SLICE_1", analysis_STORE_SLICE_1 },
	{ "STORE_SLICE_2", analysis_STORE_SLICE_2 },
	{ "STORE_SLICE_3", analysis_STORE_SLICE_3 },
	{ "STORE_SUBSCR", analysis_STORE_SUBSCR },
	{ "UNARY_CALL", analysis_UNARY_CALL },
	{ "UNARY_CONVERT", analysis_UNARY_CONVERT },
	{ "UNARY_INVERT", analysis_UNARY_INVERT },
	{ "UNARY_NEGATIVE", analysis_UNARY_NEGATIVE },
	{ "UNARY_NOT", analysis_UNARY_NOT },
	{ "UNARY_POSITIVE", analysis_UNARY_POSITIVE },
	{ "UNPACK_ARG", analysis_UNPACK_ARG },
	{ "UNPACK_EX", analysis_UNPACK_EX },
	{ "UNPACK_LIST", analysis_UNPACK_LIST },
	{ "UNPACK_SEQUENCE", analysis_UNPACK_SEQUENCE },
	{ "UNPACK_TUPLE", analysis_UNPACK_TUPLE },
	{ "UNPACK_VARARG", analysis_UNPACK_VARARG },
	{ "WITH_CLEANUP", analysis_WITH_CLEANUP },
	{ "WITH_CLEANUP_FINISH", analysis_WITH_CLEANUP_FINISH },
	{ "WITH_CLEANUP_START", analysis_WITH_CLEANUP_START },
	{ "WITH_EXCEPT_START", analysis_WITH_EXCEPT_START },
	{ "YIELD_FROM", analysis_YIELD_FROM },
	{ "YIELD_VALUE", analysis_YIELD_VALUE },
	// Fix jump info
	{ "FOR_ITER", analysis_FOR_ITER },
	{ "SETUP_LOOP", analysis_SETUP_LOOP },
	{ "SETUP_EXCEPT", analysis_SETUP_EXCEPT },
	{ "SETUP_FINALLY", analysis_SETUP_FINALLY },
	{ "SETUP_WITH", analysis_SETUP_WITH },
	{ "SETUP_ASYNC_WITH", analysis_SETUP_ASYNC_WITH },
	{ "ASYNC_GEN_WRAP", analysis_ASYNC_GEN_WRAP },
	{ "RETURN_GENERATOR", analysis_RETURN_GENERATOR },
	{ "SEND", analysis_SEND },
	{ "COPY_FREE_VARS", analysis_COPY_FREE_VARS },
	{ "JUMP_BACKWARD_NO_INTERRUPT", analysis_JUMP_BACKWARD_NO_INTERRUPT },
	{ "MAKE_CELL", analysis_MAKE_CELL },
	{ "CHECK_EXC_MATCH", analysis_CHECK_EXC_MATCH },
	{ "CHECK_EG_MATCH", analysis_CHECK_EG_MATCH },
	{ "PREP_RERAISE_STAR", analysis_PREP_RERAISE_STAR },
	{ "PUSH_EXC_INFO", analysis_PUSH_EXC_INFO },
	{ "RESUME", analysis_RESUME },
	{ "BINARY_OP", analysis_BINARY_OP },
	{ "CALL", analysis_CALL },
	{ "KW_NAMES", analysis_KW_NAMES },
	{ "PRECALL", analysis_PRECALL },
	{ "PUSH_NULL", analysis_PUSH_NULL },
	{ "COPY", analysis_COPY },
	{ "SWAP", analysis_SWAP },
	{ "JUMP_BACKWARD", analysis_JUMP_BACKWARD },
	{ "POP_JUMP_FORWARD_IF_TRUE", analysis_POP_JUMP_FORWARD_IF_TRUE },
	{ "POP_JUMP_FORWARD_IF_FALSE", analysis_POP_JUMP_FORWARD_IF_FALSE },
	{ "POP_JUMP_FORWARD_IF_NOT_NONE", analysis_POP_JUMP_FORWARD_IF_NOT_NONE },
	{ "POP_JUMP_FORWARD_IF_NONE", analysis_POP_JUMP_FORWARD_IF_NONE },
	{ "POP_JUMP_BACKWARD_IF_TRUE", analysis_POP_JUMP_BACKWARD_IF_TRUE },
	{ "POP_JUMP_BACKWARD_IF_FALSE", analysis_POP_JUMP_BACKWARD_IF_FALSE },
	{ "POP_JUMP_BACKWARD_IF_NOT_NONE", analysis_POP_JUMP_BACKWARD_IF_NOT_NONE },
	{ "POP_JUMP_BACKWARD_IF_NONE", analysis_POP_JUMP_BACKWARD_IF_NONE },
	{ "BEFORE_WITH", analysis_BEFORE_WITH },
	{ "CACHE", analysis_CACHE },
	{ "BINARY_SLICE", analysis_BINARY_SLICE },
	{ "STORE_SLICE", analysis_STORE_SLICE },
	{ "CALL_INTRINSIC_1", analysis_CALL_INTRINSIC_1 },
	{ "CALL_INTRINSIC_2", analysis_CALL_INTRINSIC_2 },
	{ "CLEANUP_THROW", analysis_CLEANUP_THROW },
	{ "END_SEND", analysis_END_SEND },
	{ "END_FOR", analysis_END_FOR },
	{ "LOAD_FAST_AND_CLEAR", analysis_LOAD_FAST_AND_CLEAR },
	{ "LOAD_FAST_CHECK", analysis_LOAD_FAST_CHECK },
	{ "LOAD_FROM_DICT_OR_DEREF", analysis_LOAD_FROM_DICT_OR_DEREF },
	{ "LOAD_FROM_DICT_OR_GLOBALS", analysis_LOAD_FROM_DICT_OR_GLOBALS },
	{ "LOAD_SUPER_ATTR", analysis_LOAD_SUPER_ATTR },
	{ "RETURN_CONST", analysis_RETURN_CONST },
	{ "TO_BOOL", analysis_TO_BOOL },
	{ "LOAD_FAST_LOAD_FAST", analysis_LOAD_FAST_LOAD_FAST },
	{ "STORE_FAST_LOAD_FAST", analysis_STORE_FAST_LOAD_FAST },
	{ "STORE_FAST_STORE_FAST", analysis_STORE_FAST_STORE_FAST },
	{ "CALL_KW", analysis_CALL_KW },
	{ "SET_FUNCTION_ATTRIBUTE", analysis_SET_FUNCTION_ATTRIBUTE },
	{ "CONVERT_VALUE", analysis_CONVERT_VALUE },
	{ "FORMAT_SIMPLE", analysis_FORMAT_SIMPLE },
	{ "FORMAT_WITH_SPEC", analysis_FORMAT_WITH_SPEC },
	{ "POP_ITER", analysis_POP_ITER },
	{ "INSTRUMENTED_POP_ITER", analysis_INSTRUMENTED_POP_ITER },
	{ "LOAD_SPECIAL", analysis_LOAD_SPECIAL },
	{ "LOAD_SMALL_INT", analysis_LOAD_SMALL_INT },
	{ "LOAD_FAST_BORROW", analysis_LOAD_FAST_BORROW },
	{ "LOAD_FAST_BORROW_LOAD_FAST_BORROW", analysis_LOAD_FAST_BORROW_LOAD_FAST_BORROW },
	{ "LOAD_COMMON_CONSTANT", analysis_LOAD_COMMON_CONSTANT },
	{ "BUILD_INTERPOLATION", analysis_BUILD_INTERPOLATION },
	{ "BUILD_TEMPLATE", analysis_BUILD_TEMPLATE },
	{ "BINARY_OP_ADD_FLOAT", analysis_BINARY_OP_ADD_FLOAT },
	{ "BINARY_OP_ADD_INT", analysis_BINARY_OP_ADD_INT },
	{ "BINARY_OP_ADD_UNICODE", analysis_BINARY_OP_ADD_UNICODE },
	{ "BINARY_OP_EXTEND", analysis_BINARY_OP_EXTEND },
	{ "BINARY_OP_MULTIPLY_FLOAT", analysis_BINARY_OP_MULTIPLY_FLOAT },
	{ "BINARY_OP_MULTIPLY_INT", analysis_BINARY_OP_MULTIPLY_INT },
	{ "BINARY_OP_SUBSCR_DICT", analysis_BINARY_OP_SUBSCR_DICT },
	{ "BINARY_OP_SUBSCR_GETITEM", analysis_BINARY_OP_SUBSCR_GETITEM },
	{ "BINARY_OP_SUBSCR_LIST_INT", analysis_BINARY_OP_SUBSCR_LIST_INT },
	{ "BINARY_OP_SUBSCR_LIST_SLICE", analysis_BINARY_OP_SUBSCR_LIST_SLICE },
	{ "BINARY_OP_SUBSCR_STR_INT", analysis_BINARY_OP_SUBSCR_STR_INT },
	{ "BINARY_OP_SUBSCR_TUPLE_INT", analysis_BINARY_OP_SUBSCR_TUPLE_INT },
	{ "BINARY_OP_SUBTRACT_FLOAT", analysis_BINARY_OP_SUBTRACT_FLOAT },
	{ "BINARY_OP_SUBTRACT_INT", analysis_BINARY_OP_SUBTRACT_INT },
};

void analysis_pyc_op(RzAnalysisOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	size_t i;
	for (i = 0; i < (sizeof(op_analysis) / sizeof(op_analysis_func)); i++) {
		if (!strcmp(op_analysis[i].op_name, op_obj->op_name)) {
			op_analysis[i].func(op, op_obj, oparg);
			break;
		}
	}
}