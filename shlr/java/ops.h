// SPDX-License-Identifier: Apache-2.0

#include <rz_analysis.h>

#ifndef RZ_JAVA_OPS_H
#define RZ_JAVA_OPS_H

enum {
	RZ_ANAL_JAVA_ILL_OP  =-1,   /* illegal instruction // trap */
	RZ_ANAL_JAVA_NULL_OP = 0,
	RZ_ANAL_JAVA_NOP = 1, /* does nothing */
	RZ_ANAL_JAVA_STORE_OP  = 1 << 20,  // Load or Store memory operation
	RZ_ANAL_JAVA_LOAD_OP   = 1 << 21,  // Load or Store memory operation
	RZ_ANAL_JAVA_REG_OP	= 1 << 22,  // register operation
	RZ_ANAL_JAVA_OBJ_OP	= 1 << 23,  // operates on an object
	RZ_ANAL_JAVA_STACK_OP  = 1 << 25,  // stack based operation
	RZ_ANAL_JAVA_BIN_OP	= 1 << 26,  // binary operation
	RZ_ANAL_JAVA_CODE_OP   = 1 << 27,  // operates on code
	RZ_ANAL_JAVA_DATA_OP   = 1 << 28,  // operates on data
	RZ_ANAL_JAVA_UNK_OP  = 1 << 29,  /* unknown opcode type */
	RZ_ANAL_JAVA_REP_OP  = 1 << 30,  /* repeats next instruction N times */
	RZ_ANAL_JAVA_COND_OP = 1 << 31,
};

enum {
	RZ_ANAL_JAVA_TYPE_REF_NULL  = 0,
	RZ_ANAL_JAVA_TYPE_REF_UNK   = 1 << 1,
	RZ_ANAL_JAVA_TYPE_REF	   = 1 << 2,
	RZ_ANAL_JAVA_TYPE_SIGNED	= 1 << 3,
	RZ_ANAL_JAVA_TYPE_PRIM	  = 1 << 4,
	RZ_ANAL_JAVA_TYPE_CONST	 = 1 << 5,
	RZ_ANAL_JAVA_TYPE_STATIC	= 1 << 6,
	RZ_ANAL_JAVA_TYPE_VOLATILE  = 1 << 7,
	RZ_ANAL_JAVA_TYPE_PUBLIC	= 1 << 8,

	RZ_ANAL_JAVA_TYPE_BOOL   = 1 << 10,
	RZ_ANAL_JAVA_TYPE_BYTE   = 1 << 11,
	RZ_ANAL_JAVA_TYPE_SHORT  = 1 << 12,
	RZ_ANAL_JAVA_TYPE_INT32  = 1 << 13,
	RZ_ANAL_JAVA_TYPE_INTEGER = 1 << 13,
	RZ_ANAL_JAVA_TYPE_INT64  = 1 << 14,
	RZ_ANAL_JAVA_TYPE_LONG   = 1 << 14,
	RZ_ANAL_JAVA_TYPE_FLOAT  = 1 << 15,
	RZ_ANAL_JAVA_TYPE_DOUBLE = 1 << 16,
	RZ_ANAL_JAVA_TYPE_STRING = 1 << 17,
	RZ_ANAL_JAVA_TYPE_CHAR   = 1 << 18,
	RZ_ANAL_JAVA_TYPE_VOID   = 1 << 19,
};

// code ops
enum {
	RZ_ANAL_JAVA_CODEOP_JMP	= 1 << 1  | RZ_ANAL_JAVA_CODE_OP,/* mandatory jump */
	RZ_ANAL_JAVA_CODEOP_CALL   = 1 << 2  | RZ_ANAL_JAVA_CODE_OP,/* call to subroutine (branch+link) */
	RZ_ANAL_JAVA_CODEOP_RET	= 1 << 3  | RZ_ANAL_JAVA_CODE_OP,/* returns from subrutine */
	RZ_ANAL_JAVA_CODEOP_TRAP   = 1 << 4  | RZ_ANAL_JAVA_CODE_OP,/* it's a trap! */
	RZ_ANAL_JAVA_CODEOP_SWI	= 1 << 5  | RZ_ANAL_JAVA_CODE_OP,/* syscall  software interrupt */
	RZ_ANAL_JAVA_CODEOP_IO	 = 1 << 6  | RZ_ANAL_JAVA_CODE_OP,
	RZ_ANAL_JAVA_CODEOP_LEAVE  = 1 << 7  | RZ_ANAL_JAVA_CODE_OP,
	RZ_ANAL_JAVA_CODEOP_SWITCH = 1 << 8  | RZ_ANAL_JAVA_CODE_OP,
	RZ_ANAL_JAVA_CODEOP_CJMP   = RZ_ANAL_JAVA_COND_OP | RZ_ANAL_JAVA_CODE_OP | RZ_ANAL_JAVA_CODEOP_JMP,
	RZ_ANAL_JAVA_CODEOP_EOB	= RZ_ANAL_JAVA_CODEOP_JMP | RZ_ANAL_JAVA_CODEOP_RET | RZ_ANAL_JAVA_CODEOP_LEAVE | RZ_ANAL_JAVA_CODEOP_SWITCH,
};

enum {
	// call return types
			RZ_ANAL_JAVA_RET_TYPE_REF_NULL = 1 << 10,
	RZ_ANAL_JAVA_RET_TYPE_REF	  = 1 << 11 ,
	RZ_ANAL_JAVA_RET_TYPE_PRIM	 = 1 << 12 ,
	RZ_ANAL_JAVA_RET_TYPE_CONST	= 1 << 13,
	RZ_ANAL_JAVA_RET_TYPE_STATIC   = 1 << 14,
};

// jmp conditionals
enum {
	// TODO these should be mapped to some sort of
	// flags register
			RZ_ANAL_JAVA_COND_EQ  = 1 << 11,
	RZ_ANAL_JAVA_COND_NE  = 1 << 12,
	RZ_ANAL_JAVA_COND_GE  = 1 << 13,
	RZ_ANAL_JAVA_COND_GT  = 1 << 14,
	RZ_ANAL_JAVA_COND_LE  = 1 << 15,
	RZ_ANAL_JAVA_COND_LT  = 1 << 16,
	RZ_ANAL_JAVA_COND_AL  = 1 << 17,
	RZ_ANAL_JAVA_COND_NV  = 1 << 18,
	RZ_ANAL_JAVA_COND_NULL  = 1 << 19,
};

// bin ops
enum {
	RZ_ANAL_JAVA_BINOP_NEG = 0 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_XCHG = 1 << 1 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_CMP  = 1 << 2  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_ADD  = 1 << 3  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_SUB  = 1 << 4  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_MUL  = 1 << 6  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_DIV  = 1 << 7  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_SHR  = 1 << 8  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_SHL  = 1 << 9  | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_SAL  = 1 << 10 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_SAR  = 1 << 11 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_OR   = 1 << 12 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_AND  = 1 << 14 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_XOR  = 1 << 15 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_NOT  = 1 << 16 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_MOD  = 1 << 17 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_ROR  = 1 << 18 | RZ_ANAL_JAVA_BIN_OP,
	RZ_ANAL_JAVA_BINOP_ROL  = 1 << 19 | RZ_ANAL_JAVA_BIN_OP,
};

// Object ops
enum {
	RZ_ANAL_JAVA_OBJOP_CAST  = 1 << 0 | RZ_ANAL_JAVA_OBJ_OP,
	RZ_ANAL_JAVA_OBJOP_CHECK = 1 << 1 | RZ_ANAL_JAVA_OBJ_OP,
	RZ_ANAL_JAVA_OBJOP_NEW   = 1 << 2 | RZ_ANAL_JAVA_OBJ_OP,
	RZ_ANAL_JAVA_OBJOP_DEL   = 1 << 3 | RZ_ANAL_JAVA_OBJ_OP,
	RZ_ANAL_JAVA_OBJOP_SIZE   = 1 << 4 | RZ_ANAL_JAVA_OBJ_OP,
};


// Memory or Data Operations
// Locations of item loaded (base of indirect)
enum {
	RZ_ANAL_JAVA_LDST_FROM_REF   =  1 << 1,
	RZ_ANAL_JAVA_LDST_FROM_MEM   =  1 << 1,

	RZ_ANAL_JAVA_LDST_FROM_REG   =  1 << 2,
	RZ_ANAL_JAVA_LDST_FROM_STACK =  1 << 3,
	RZ_ANAL_JAVA_LDST_FROM_CONST =  1 << 4,
	RZ_ANAL_JAVA_LDST_FROM_VAR   =  1 << 5,

	// If indirect load, where are we getting the indirection,
			RZ_ANAL_JAVA_LDST_INDIRECT_REF  = 1 << 6,
	RZ_ANAL_JAVA_LDST_INDIRECT_MEM  = 1 << 6,

	RZ_ANAL_JAVA_LDST_INDIRECT_REG   =  1 << 7,
	RZ_ANAL_JAVA_LDST_INDIRECT_STACK =  1 << 8,
	RZ_ANAL_JAVA_LDST_INDIRECT_IDX   =  1 << 9,
	RZ_ANAL_JAVA_LDST_INDIRECT_VAR   =  1 << 10,

	// Location to put the item,
			RZ_ANAL_JAVA_LDST_TO_REF  = 1 << 11,
	RZ_ANAL_JAVA_LDST_TO_MEM  = 1 << 11,

	RZ_ANAL_JAVA_LDST_TO_REG = 1 << 12,
	RZ_ANAL_JAVA_LDST_TO_STACK =  1 << 13,
	RZ_ANAL_JAVA_LDST_TO_VAR =    1 << 14,

	// Stack, Memory, Register, Bss, Data ,
			RZ_ANAL_JAVA_LDST_OP_PUSH  = 1 << 15  ,
	RZ_ANAL_JAVA_LDST_OP_POP   = 1 << 16,
	RZ_ANAL_JAVA_LDST_OP_MOV   = 1 << 17 ,
	RZ_ANAL_JAVA_LDST_OP_EFF_ADDR   = 1 << 18,
};

enum {

	RZ_ANAL_JAVA_LDST_LOAD_FROM_CONST_REF_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		RZ_ANAL_JAVA_LOAD_OP |\
		RZ_ANAL_JAVA_LDST_FROM_REF |\
		RZ_ANAL_JAVA_LDST_FROM_CONST |\
		RZ_ANAL_JAVA_LDST_TO_STACK |\
		RZ_ANAL_JAVA_TYPE_REF,



	RZ_ANAL_JAVA_LDST_LOAD_FROM_CONST_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		RZ_ANAL_JAVA_LOAD_OP |\
		RZ_ANAL_JAVA_LDST_FROM_CONST |\
		RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_CONST_INDIRECT_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		RZ_ANAL_JAVA_LOAD_OP |\
		RZ_ANAL_JAVA_LDST_FROM_CONST |\
		RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_VAR_INDIRECT_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_VAR |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_VAR_INDIRECT_TO_STACK_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_VAR |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_VAR_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_VAR |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_VAR_TO_STACK_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_VAR |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_REF_INDIRECT_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_REF |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_REF_INDIRECT_TO_STACK_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_REF |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_STACK,

	RZ_ANAL_JAVA_LDST_STORE_FROM_STACK_INDIRECT_TO_VAR = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_STORE_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_STACK |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_VAR,

	RZ_ANAL_JAVA_LDST_STORE_FROM_STACK_INDIRECT_TO_VAR_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_STORE_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_STACK |\
		 RZ_ANAL_JAVA_LDST_INDIRECT_IDX |\
		 RZ_ANAL_JAVA_LDST_TO_VAR,

	RZ_ANAL_JAVA_LDST_STORE_FROM_STACK_TO_VAR = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_STORE_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_STACK |\
		 RZ_ANAL_JAVA_LDST_TO_VAR,

	RZ_ANAL_JAVA_LDST_STORE_FROM_STACK_TO_VAR_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_STORE_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_STACK |\
		 RZ_ANAL_JAVA_LDST_TO_VAR,

	RZ_ANAL_JAVA_LDST_STORE_FROM_STACK_INDIRECT_TO_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_STORE_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_STACK |\
		 RZ_ANAL_JAVA_LDST_TO_REF,

	RZ_ANAL_JAVA_LDST_STORE_FROM_STACK_INDIRECT_TO_REF_REF = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_STORE_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_STACK |\
		 RZ_ANAL_JAVA_LDST_TO_REF,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_REF_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		 RZ_ANAL_JAVA_LOAD_OP |\
		 RZ_ANAL_JAVA_LDST_FROM_REF |\
		 RZ_ANAL_JAVA_LDST_TO_STACK |\
		 RZ_ANAL_JAVA_TYPE_PRIM,

	RZ_ANAL_JAVA_LDST_LOAD_FROM_PRIM_VAR_TO_STACK = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		   RZ_ANAL_JAVA_LOAD_OP |\
		   RZ_ANAL_JAVA_LDST_FROM_VAR |\
		   RZ_ANAL_JAVA_TYPE_PRIM,

	RZ_ANAL_JAVA_LDST_LOAD_GET_STATIC = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		RZ_ANAL_JAVA_LOAD_OP |\
		RZ_ANAL_JAVA_LDST_FROM_REF |\
		RZ_ANAL_JAVA_LDST_TO_STACK |\
		RZ_ANAL_JAVA_TYPE_REF,

	RZ_ANAL_JAVA_LDST_STORE_PUT_STATIC = RZ_ANAL_JAVA_LDST_OP_POP |\
		RZ_ANAL_JAVA_STORE_OP |\
		RZ_ANAL_JAVA_LDST_FROM_STACK |\
		RZ_ANAL_JAVA_LDST_TO_REF |\
		RZ_ANAL_JAVA_TYPE_REF,

	RZ_ANAL_JAVA_LDST_LOAD_GET_FIELD = RZ_ANAL_JAVA_LDST_OP_PUSH |\
		RZ_ANAL_JAVA_LOAD_OP |\
		RZ_ANAL_JAVA_LDST_FROM_REF |\
		RZ_ANAL_JAVA_LDST_TO_STACK |\
		RZ_ANAL_JAVA_TYPE_REF,

	RZ_ANAL_JAVA_LDST_STORE_PUT_FIELD = RZ_ANAL_JAVA_LDST_OP_POP |\
		RZ_ANAL_JAVA_STORE_OP |\
		RZ_ANAL_JAVA_LDST_FROM_STACK |\
		RZ_ANAL_JAVA_LDST_TO_REF |\
		RZ_ANAL_JAVA_TYPE_REF,
};

#endif
