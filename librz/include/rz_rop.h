// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ROP_H
#define RZ_ROP_H

#endif // RZ_ROP_H

#include <rz_cmd.h>

typedef struct rz_reg_info_t {
	char *name;
	bool is_mem_read;
	bool is_pc_write;
	bool is_var_read;
	bool is_var_write;
	bool is_mem_write;
	ut64 init_val;
	ut64 new_val;
} RzRegInfo;

typedef struct rz_rop_gadget_info_t {
	ut64 address;
	ut64 stack_change;
	ut64 curr_pc_val;
	bool is_pc_write;
	bool is_syscall;
	RzPVector /*<RzRegInfo*>*/ *modified_registers;
	RzList /*<RzRegInfo*>*/ *dependencies;
} RzRopGadgetInfo;

typedef enum rzil_instr_type {
	// Register to register
	MOV_CONST, ///< reg <- const
	MOV_REG, ///< reg <- reg
	MOV_OP_CONST, ///< reg <- reg OP const
	MOV_OP_REG, ///< reg <- reg OP reg
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

// Command APIs
RZ_API int rz_core_search_rop(RzCore *core, const char *greparg, int regexp, RzCmdStateOutput *state);
RZ_API RzCmdStatus rz_core_rop_gadget_info(RzCore *core, const char *input, RzCmdStateOutput *state);
RZ_API bool analyze_constraint(RzCore *core, char *str, RzRopConstraint *rop_constraint);

// ROP Constraint APIs
RZ_API void rz_rop_constraint_free(RZ_NULLABLE void *data);
RZ_API RzList /*<RzRopConstraint *>*/ *rz_rop_constraint_list_new(void);