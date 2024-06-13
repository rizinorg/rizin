// SPDX-FileCopyrightText: 2020-2021 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ROP_H
#define RZ_ROP_H

#endif // RZ_ROP_H

typedef enum rzil_instr_type {
	// Register to register
	MOV_CONST, // reg <- const
	MOV_REG, // reg <- reg
	MOV_OP_CONST, // reg <- reg OP const
	MOV_OP_REG, // reg <- reg OP reg
	// Call functions
	SYSCALL,
} RzILInstructionType;

typedef enum {
	SRC_REG,
	DST_REG,
	OP,
	DST_CONST,
	DST_REG_SECOND,
	NUM_ARGS
} RzRopArgType;

typedef struct rz_rop_constraint {
	RzILInstructionType type;
	char *args[NUM_ARGS];
} RzRopConstraint;