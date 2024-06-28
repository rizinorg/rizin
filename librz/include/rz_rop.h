// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ROP_H
#define RZ_ROP_H

#include <rz_cmd.h>

/**
 * \file rz_rop.h
 * \brief Return-Oriented Programming (ROP) related APIs and structures..
 *
 * This file contains definitions, structures, and function prototypes for handling ROP gadgets and constraints.
 */

/**
 * \brief Information about a register.
 */
typedef struct rz_reg_info_t {
	char *name;
	bool is_mem_read; ///< Register involved in Memory read.
	bool is_pc_write; ///< PC write flag.
	bool is_var_read; ///< Register involved in Variable read.
	bool is_var_write; ///< Register involved in Variable write.
	bool is_mem_write; ///< Register involved in Memory write.
	ut64 init_val;
	ut64 new_val;
} RzRegInfo;

/**
 * \brief Information about a ROP gadget.
 */
typedef struct rz_rop_gadget_info_t {
	ut64 address; ///< Gadget address.
	ut64 stack_change; ///< Stack change.
	ut64 curr_pc_val; ///< Current PC value.
	bool is_pc_write; ///< PC write flag.
	bool is_syscall; ///< Syscall flag.
	RzPVector /*<RzRegInfo *>*/ *modified_registers; ///< Modified registers.
	RzList /*<RzRegInfo *>*/ *dependencies; ///< Dependencies.
} RzRopGadgetInfo;

/**
 * \brief Types of IL instructions for ROP constraints.
 */
typedef enum rzil_instr_type {
	MOV_CONST, ///< reg <- const
	MOV_REG, ///< reg <- reg
	MOV_OP_CONST, ///< reg <- reg OP const
	MOV_OP_REG, ///< reg <- reg OP reg
	SYSCALL, ///< syscall
} RzILInstructionType;

/**
 * \brief Argument types for ROP constraints.
 */
typedef enum {
	SRC_REG,
	DST_REG,
	SRC_CONST,
	DST_REG_SECOND,
	OP,
	NUM_ARGS
} RzRopArgType;

/**
 * \brief ROP request mask for filtering gadgets.
 */
typedef enum {
	RZ_ROP_GADGET_PRINT = 1 << 0, ///< Print ROP gadgets.
	RZ_ROP_GADGET_DETAIL = 1 << 1, ///< Detailed ROP gadgets.
	RZ_ROP_GADGET_ALL = RZ_ROP_GADGET_PRINT | RZ_ROP_GADGET_DETAIL ///< All ROP gadgets requests.
} RzRopRequestMask;

/**
 * \brief Pair representing an end gadget with instruction offset and delay size.
 */
typedef struct rz_rop_endlist_pair_t {
	int instr_offset; ///< Instruction offset.
	int delay_size; ///< Delay size.
} RzRopEndListPair;

/**
 * \brief Structure representing a ROP constraint.
 */
typedef struct rz_rop_constraint_t {
	RzILInstructionType type; ///< IL instruction type.
	char *args[NUM_ARGS]; ///< Arguments.
} RzRopConstraint;

// Command APIs
RZ_API int rz_core_search_rop(RzCore *core, const char *greparg, int regexp, RzRopRequestMask type, RzCmdStateOutput *state);
RZ_API RzCmdStatus rz_core_rop_gadget_info(RzCore *core, const char *input, RzCmdStateOutput *state);
RZ_API bool analyze_constraint(RzCore *core, char *str, RzRopConstraint *rop_constraint);

// ROP Constraint APIs
RZ_API void rz_rop_constraint_free(RZ_NULLABLE void *data);
RZ_API RzList /*<RzRopConstraint *>*/ *rz_rop_constraint_list_new(void);

#endif // RZ_ROP_H
