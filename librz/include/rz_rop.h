// SPDX-FileCopyrightText: 2020-2021 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ROP_H
#define RZ_ROP_H

#endif // RZ_ROP_H

#include <rz_cmd.h>

typedef struct rz_rop_op_t {
	RzILOpPure *op;
} RzRopOp;

typedef struct rz_rop_memory_t {
	RzList *dependencies;
	RzList *stored_in_regs;
} RzRopMemoryOp;

typedef struct rz_rop_gadget_info_t {
	ut64 address;
	ut64 stack_change;
	RzList *modified_registers;
	RzRopMemoryOp memory_write;
	RzRopMemoryOp memory_read;
} RzRopGadgetInfo;

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
	SRC_CONST,
	DST_REG_SECOND,
	OP,
	NUM_ARGS
} RzRopArgType;

typedef struct rz_rop_endlist_pair_t {
	int instr_offset;
	int delay_size;
} RzRopEndListPair;

typedef struct rz_rop_constraint_t {
	RzILInstructionType type;
	char *args[NUM_ARGS];
} RzRopConstraint;

typedef struct rz_rop_gadget_analysis_t {
	ut64 addr;
} RzRopGadgetAnalysis;

// Command APIs
RZ_API int rz_core_search_rop(RzCore *core, const char *greparg, int regexp, RzCmdStateOutput *state);
RZ_API RzCmdStatus rz_core_rop_gadget_info(RzCore *core, const char *input, RzCmdStateOutput *state);
RZ_API bool analyze_constraint(RzCore *core, char *str, RzRopConstraint *rop_constraint);
RZ_API void populate_gadget_info(RzCore *core, RzRopGadgetInfo *info, RzILOpEffect *effect);
RZ_API void add_reg_to_list(RzCore *core, RzList *list, const char *str);

// ROP Constraint APIs
RZ_API void rz_rop_constraint_free(RZ_NULLABLE void *data);
RZ_API RzList /*<RzRopConstraint *>*/ *rz_rop_constraint_list_new(void);