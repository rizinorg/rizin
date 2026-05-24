// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_GADGET_H
#define RZ_GADGET_H

/**
 * \file rz_gadget.h
 * \brief Gadget (ROP, JOP, COP) related APIs and structures.
 *
 * This file contains definitions, structures, and function prototypes for handling ROP, JOP and COP gadgets and constraints.
 */

#include <rz_cmd.h>
#include <rz_il.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Information about a register.
 */
typedef struct rz_gadget_reg_info_t {
	char *name;
	bool is_mem_read; ///< Register involved in Memory read.
	bool is_pc_write; ///< PC write flag.
	bool is_var_read; ///< Register involved in Variable read.
	bool is_var_write; ///< Register involved in Variable write.
	bool is_mem_write; ///< Register involved in Memory write.
	ut64 init_val;
	ut64 new_val;
	ut64 bits; ///< Register bits for capturing cast
	RzILOpPure *value_transformations; ///< TODO: Captures Value transformations.
} RzGadgetRegInfo;

/**
 * \brief Information about a gadget.
 */
typedef struct rz_gadget_info_t {
	ut64 address; ///< Gadget address.
	ut64 stack_change; ///< Stack change.
	ut64 curr_pc_val; ///< Current PC value.
	ut32 size; ///< Gadget size.
	bool is_pc_write; ///< PC write flag.
	bool is_syscall; ///< Syscall flag.
	RzIterator /*RzAnalysisBytes *>*/ *analysis_cache; ///< Stores \p RzAnalysisBytes for the gadget.
	RzPVector /*<RzGadgetRegInfo *>*/ *modified_registers; ///< Modified registers.
	RzList /*<RzGadgetRegInfo *>*/ *dependencies; ///< Dependencies.
} RzGadgetInfo;

/**
 * \brief Type of gadget to search for.
 */
typedef enum {
	RZ_GADGET_TYPE_ROP, ///< Return-Oriented Programming.
	RZ_GADGET_TYPE_JOP, ///< Jump-Oriented Programming.
	RZ_GADGET_TYPE_COP, ///< Call-Oriented Programming.
} RzGadgetType;

/**
 * \brief Gadget cache node
 */
typedef struct rz_gadget_cache_node_t {
	RBNode rb; ///< intrusive RBTree node
	ut64 addr; ///< gadget start address
	RzPVector /*<RzCoreAsmHit *>*/ *hitlist; ///< cached hitlist object for one gadget
	int delay_size; ///< delay size for delay slot archs
} RzGadgetCacheNode;

/**
 * \brief Types of IL instructions for Gadget constraints.
 */
typedef enum rz_gadget_il_instr_type {
	RZ_GADGET_IL_INSTR_MOV_CONST, ///< reg <- const
	RZ_GADGET_IL_INSTR_MOV_REG, ///< reg <- reg
	RZ_GADGET_IL_INSTR_MOV_OP_CONST, ///< reg <- reg OP const
	RZ_GADGET_IL_INSTR_MOV_OP_REG, ///< reg <- reg OP reg
	RZ_GADGET_IL_INSTR_SYSCALL, ///< syscall
} RzGadgetILInstructionType;

/**
 * \brief Argument types for Gadget constraints.
 */
typedef enum {
	RZ_GADGET_ARG_SRC_REG,
	RZ_GADGET_ARG_DST_REG,
	RZ_GADGET_ARG_SRC_CONST,
	RZ_GADGET_ARG_SRC_REG_SECOND,
	RZ_GADGET_ARG_OP,
	RZ_GADGET_ARG_NUM_ARGS
} RzGadgetArgType;

/**
 * \brief Gadget request mask for filtering gadgets.
 */
typedef enum {
	RZ_GADGET_PRINT = 1 << 0, ///< Print Gadget.
	RZ_GADGET_PRINT_DETAIL = 1 << 1, ///< Detailed Gadget.
	RZ_GADGET_ANALYZE = 1 << 2, ///< Detailed Gadget.
	RZ_GADGET_ALL = RZ_GADGET_PRINT | RZ_GADGET_PRINT_DETAIL | RZ_GADGET_ANALYZE ///< All Gadget requests.
} RzGadgetRequestMask;

/**
 * \brief Gadget search mask for filtering gadgets given details.
 */
typedef enum {
	RZ_GADGET_DETAIL_SEARCH_NON = 0,
	RZ_GADGET_DETAIL_SEARCH_STACK = 1 << 0, ///< Search gadgets by stack changes.
	RZ_GADGET_DETAIL_SEARCH_SIZE = 1 << 1, ///< Search gadgets by gadget sizes.
	// RZ_GADGET_DETAIL_SEARCH_WRITE = 1 << 2, ///< Search gadgets by written registers.
	// RZ_GADGET_DETAIL_SEARCH_READ = 1 << 3, ///< Search gadgets by read registers.
} RzGadgetDetailSearchMask;

/**
 * \brief Filter conditions while searching gadgets by stack changes.
 */
typedef enum {
	RZ_GADGET_DETAIL_CMP_EQ = 1, ///< ==
	RZ_GADGET_DETAIL_CMP_GT = 1 << 1, ///< >
	RZ_GADGET_DETAIL_CMP_GE = RZ_GADGET_DETAIL_CMP_GT | RZ_GADGET_DETAIL_CMP_EQ, ///< >=
	RZ_GADGET_DETAIL_CMP_LT = 1 << 2, ///< <
	RZ_GADGET_DETAIL_CMP_LE = RZ_GADGET_DETAIL_CMP_LT | RZ_GADGET_DETAIL_CMP_EQ, ///< <=
} RzGadgetDetailSearchCmpOp;

/**
 * \brief Pair representing an end gadget with instruction offset and delay size.
 */
typedef struct rz_gadget_endlist_pair_t {
	int instr_offset; ///< Instruction offset.
	int delay_size; ///< Delay size.
} RzGadgetEndListPair;

/**
 * \brief Structure representing a Gadget constraint.
 */
typedef struct rz_gadget_constraint_t {
	RzGadgetILInstructionType type; ///< IL instruction type.
	char *args[RZ_GADGET_ARG_NUM_ARGS]; ///< Arguments.
} RzGadgetConstraint;

/**
 * \brief Structure representing a Gadget search context.
 */
typedef struct rz_gadget_search_context_t {
	RzGadgetType type; ///< Type of gadget to search for.
	size_t max_instr; ///< Gadget search max length.
	bool subchains; ///< Display every length gadget from gadget.len=X to 2.
	bool allow_conditional; ///< Include conditional jump, calls and returns in gadget search.
	bool comments; ///< Display comments in gadget search output.
	char *greparg; ///< Grep argument string.
	const char *arch; ///< Architecture of the binary.
	bool regexp; ///< Regular expression argument flag.
	bool cache; ///< Cache the search results.
	RzGadgetRequestMask mask; ///< Mask for kind of gadget request operation.
	RzGadgetDetailSearchMask detail_mask; ///< Mask for searching gadgets given details.
	RzCmdStateOutput *state; ///< Command state output.
	int increment; ///< Gadget search increment value.
	ut64 max_count; ///< Maximum number of hits (0: no limit).
	ut64 from; ///< Start address to start gadget search.
	ut64 to; ///< End address to stop gadget search.
	RzList /*<RzGadgetEndListPair *>*/ *end_list; ///< List of end gadgets.
	HtSU *unique_hitlists; ///< Cache unique gadget hitlists.
	bool ret_val; ///< Flag to indicate return the search results.
	RzStrBuf *buf; ///< String buffer for storing search results.
	RzPVector /*<RzGadgetConstraint *>*/ *constraints; ///< User constraints for filtering.
} RzGadgetSearchContext;

/**
 * \brief Enum for different Gadget register events.
 */
typedef enum {
	RZ_GADGET_EVENT_VAR_READ,
	RZ_GADGET_EVENT_VAR_WRITE,
	RZ_GADGET_EVENT_MEM_READ,
	RZ_GADGET_EVENT_MEM_WRITE,
	RZ_GADGET_EVENT_PC_WRITE,
	RZ_GADGET_EVENT_COUNT ///< This should always be the last element.
} RzGadgetEvent;

/**
 * \brief Function pointer type for event check functions.
 */
typedef bool (*rz_gadget_event_check_fn)(const RzGadgetRegInfo *);

/**
 * \brief Array of event check functions.
 */
extern rz_gadget_event_check_fn rz_gadget_event_functions[RZ_GADGET_EVENT_COUNT];

// Command APIs
RZ_API RzCmdStatus rz_core_gadget_search(RZ_NONNULL RzCore *core, RZ_NONNULL RzGadgetSearchContext *context);
RZ_API RzCmdStatus rz_core_gadget_info(RZ_NONNULL RzCore *core, RZ_NONNULL RZ_BORROW RzGadgetSearchContext *context);
RZ_API bool rz_core_gadget_analyze_constraint(const RZ_NONNULL RzCore *core, const RZ_NONNULL char *str,
	RZ_NULLABLE RZ_OUT RzGadgetConstraint *gadget_constraint);
RZ_API RZ_OWN RzPVector /*<RzGadgetConstraint *>*/ *rz_core_gadget_constraint_map_parse(const RZ_NONNULL RzCore *core, int argc, const char **argv);
RZ_API bool rz_core_handle_gadget_request_type(RZ_NONNULL RzCore *core, RZ_NONNULL RzGadgetSearchContext *context, RZ_NONNULL RzPVector /*<RzCoreAsmHit *>*/ *hitlist, int delay_size);
RZ_API RZ_NULLABLE RZ_OWN RzList /*<char *>*/ *rz_core_gadget_handle_grep_args(RZ_NULLABLE const char *greparg, const bool regexp);

// Gadget Search Context APIs
RZ_API RZ_OWN RzGadgetSearchContext *rz_core_gadget_search_context_new(RZ_NONNULL const RzCore *core, const RzGadgetType gadget_type, RZ_NULLABLE const char *greparg, bool regexp,
	RzGadgetRequestMask mask, RzGadgetDetailSearchMask detail_mask, RZ_NULLABLE RZ_BORROW RzCmdStateOutput *state);
RZ_API void rz_core_gadget_search_context_free(RZ_NULLABLE RzGadgetSearchContext *context);

// Gadget Constraint APIs
RZ_API void rz_core_gadget_constraint_free(RZ_NULLABLE void *data);
RZ_API RZ_OWN RzGadgetConstraint *rz_core_gadget_constraint_parse_args(const RZ_NONNULL RzCore *core, const RZ_NONNULL char *token);

// Gadget Info APIs
RZ_API void rz_core_gadget_info_free(RZ_NULLABLE RzGadgetInfo *gadget_info);
RZ_API void rz_core_gadget_info_add_register(const RZ_NONNULL RZ_OUT RzGadgetInfo *gadget_info,
	RZ_NONNULL RzGadgetRegInfo *reg_info, bool is_dependency);
RZ_API void rz_core_gadget_info_update_register(const RZ_INOUT RzGadgetInfo *gadget_info, RZ_INOUT RZ_NONNULL RzGadgetRegInfo *new_reg_info);
RZ_API RZ_OWN RzGadgetInfo *rz_core_gadget_info_new(ut64 address);
RZ_API RZ_OWN RzGadgetRegInfo *rz_core_gadget_reg_info_dup(RZ_BORROW RZ_NONNULL RzGadgetRegInfo *src);
RZ_API void rz_core_gadget_reg_info_free(RZ_NULLABLE RzGadgetRegInfo *reg_info);
RZ_API RZ_OWN RzGadgetRegInfo *rz_core_gadget_reg_info_new(RZ_NONNULL const RzCore *core, RZ_NONNULL const RzILEvent *evt,
	ut64 init_val, ut64 new_val);
RZ_API RZ_BORROW RzGadgetRegInfo *rz_core_gadget_info_get_modified_register(const RZ_NONNULL RzGadgetInfo *gadget_info,
	const RZ_NONNULL char *name);
RZ_API bool rz_core_gadget_info_has_register(const RZ_NONNULL RzGadgetInfo *gadget_info, const RZ_NONNULL char *name);
RZ_API RZ_OWN RzPVector /*<RzGadgetRegInfo *>*/ *rz_core_gadget_get_reg_info_by_event(const RZ_NONNULL RzGadgetInfo *gadget_info, RzGadgetEvent event);
RZ_API RZ_OWN RzPVector /*<RzGadgetRegInfo *>*/ *rz_core_gadget_get_reg_info_by_reg_names(const RZ_NONNULL RzGadgetInfo *gadget_info, RZ_NONNULL const RzPVector /*<char *>*/ *registers);
RZ_API bool rz_core_gadget_reg_info_has_event(const RZ_NONNULL RzGadgetInfo *gadget_info,
	RzGadgetEvent event, const RZ_NULLABLE char *reg_name);
RZ_API RZ_OWN RzPVector /*<RzGadgetRegInfo *>*/ *rz_core_gadget_reg_info_find(const RZ_NONNULL RzGadgetInfo *gadget_info, const RZ_NONNULL char *name);

#ifdef __cplusplus
}
#endif
#endif // RZ_GADGET_H
