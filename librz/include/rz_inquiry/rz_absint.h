// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file RzIL-based abstract interpretation and analysis based on it
 */

#ifndef RZ_ABSINT
#define RZ_ABSINT

#include <rz_inquiry/rz_il_cache.h>
#include <rz_arch.h>
#include <rz_io.h>

typedef enum rz_absint_trace_options_t {
	RZ_ABSINT_TRACE_NONE = 0,
	RZ_ABSINT_TRACE_IL_BLOCK = (1 << 0), ///< e inquiry.trace=ilblock; log il blocks as they are lifted
	RZ_ABSINT_TRACE_EVAL_BLOCK = (1 << 1), ///< e inquiry.trace=evallock; log coarse information about absint blocks as they are evaluated
	RZ_ABSINT_TRACE_BOUNDS = (1 << 2) ///< e inquiry.trace=bounds; log resolving absint block bounds based on instruction offsets and in-edges
} RzAbsIntTraceOptions;

typedef struct rz_absint_run_context_t RzAbsIntRunContext;
typedef struct rz_absint_result_t RzAbsIntResult;

/**
 * \brief An abstract value representing a set of RzILVal
 *
 * The actual abstraction and structure of this is defined by the plugin in use.
 * `struct rz_absint_val_opaque` is defined nowhere. Is is used to ensure
 * type-checking of passing this opaque pointer.
 */
typedef struct rz_absint_val_opaque RzAbsIntVal;

/**
 * \brief Helper to explicitly cast a plugin-defined abstract value to an opaque RzAbsIntAbstrVal
 */
static inline RzAbsIntVal *rz_absint_val_pack(void *val) {
	return val;
}

/**
 * \brief Helper to explicitly cast an opaque RzAbsIntAbstrVal to a plugin-defined abstract value
 */
static inline void *rz_absint_val_unpack(const RzAbsIntVal *val) {
	return (void *)val;
}

typedef enum rz_absint_pc_state_t {
	RZ_ABSINT_PC_CONST, ///< Single known value
	RZ_ABSINT_PC_UNREACHABLE, ///< Bottom/unreachable state, if this is set, pc field is unused and undefined
	RZ_ABSINT_PC_ANY ///< Top state, if this is set, pc field is unused and undefined
} RzAbsIntPCState;

typedef struct rz_absint_state_t {
	ut64 pc; ///< Interpreter location in the code. This is not necessarily identical to the ISA's program counter register, but simply points to the instruction to execute next.
	RzAbsIntPCState pc_state;

	HtUP /*<RzAbsIntAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzAbsIntAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzAbsIntAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
} RzAbsIntState;

/**
 * \brief Basic Block as part of the abstract interpretation loop
 * Represents a block of instructions of which only the last may have a control effect.
 * Unlike IL blocks, the last instruction may also not have a control effect, which is
 * the case when the instruction directly following this block has an in-edge.
 * And unlike in RzAnalysisBlock, a call instruction also terminates an interpreter block.
 */
typedef struct rz_absint_block_t {
	RzIntervalNode *node; ///< Backref to the node containing this block. end value is inclusive. TODO: remove this if RBTree is used directly
	/**
	 * Least upper bound of all states discovered at the entry of the block.
	 * pc_state of this state must be RZ_ABSINT_PC_CONST and pc points to the first instruction of the block.
	 */
	RzAbsIntState *entry_state; // TODO: flatten to remove indirection
	RzVector /*<ut16>*/ insn_offsets; ///< starting at the second instruction in the block (since first is always 0), offsets from the start of the block
	bool bounds_resolved; ///< Set to true once insn_offsets and node->end are filled.
	bool uninterpreted; ///< True if the entry state has not yet been started to interpret, i.e. the block is part of RzAbsIntFunctionState.queue
	bool non_fallthrough_in; ///< True if there is an in-edge to this block that is not only a fallthrough. Used when merging consecutive blocks after interpretation.
	bool added_to_analysis; ///< Only used after interpretation, when adding to analysis. Marks blocks that have been merged with the previous.

	// Out-edges
	bool fallthrough; ///< if true, there is an edge to the block after the end of this one
	RzVector /*<ut64>*/ jump_targets; ///< Explicit jump targets, does not contain fallthrough address
} RzAbsIntBlock;

typedef struct rz_absint_instance_t RzAbsIntInstance;

typedef struct rz_absint_value_domain_t {
	const char *name;

	RZ_OWN RzAbsIntVal *(*val_new_top)(void); ///< allocate a new abstract value and initialize it as top
	void (*val_free)(RzAbsIntVal *val);
	bool (*is_top)(RZ_NONNULL const RzAbsIntVal *val); ///< return whether the given value is top
	bool (*may_be_bool)(RZ_NONNULL const RzAbsIntVal *val, bool value); ///< return whether the given value's concrete set contains \p value
	void (*set_top)(RZ_OUT RZ_NONNULL RzAbsIntVal *dst); ///< Set \p val to be top
	void (*set_const_bool)(RZ_OUT RZ_NONNULL RzAbsIntVal *dst, bool src); ///< set \p dst to the least value that includes \p src
	void (*set_const_bv)(RZ_OUT RZ_NONNULL RzAbsIntVal *dst, RZ_IN RZ_NONNULL RzBitVector *src); ///< set \p dst to the least value that includes \p src

	/**
	 * \brief Concretize an abstract value to a single bit vector, if possible
	 *
	 * If \p val represents exactly one concrete value, this returns true.
	 * Additionally, the concrete value is written to \p out if passed.
	 */
	bool (*to_concrete_const)(RZ_NONNULL const RzAbsIntVal *val, RZ_NULLABLE RZ_OUT RzBitVector *out);

	RZ_OWN void (*copy)(RzAbsIntVal *dst, const RzAbsIntVal *src);

	/**
	 * \brief Performs the join operation on two abstract values (least upper bound, lattice theory)
	 *
	 * This is the least upper bound (lattice theory). In detail, it means \p a should be set to the least
	 * abstract value whose corresponding concrete value set is a superset of both the concrete value sets
	 * of \p a and \p b.
	 *
	 * \return True if a was changed
	 */
	bool (*join)(RZ_BORROW RZ_INOUT RzAbsIntVal *a, RZ_BORROW RZ_IN const RzAbsIntVal *b);

	/**
	 * \brief Builds a string for printing an abstract value.
	 *
	 * \return Returns false in case of error, True otherwise.
	 */
	bool (*val_as_str)(RZ_NONNULL const RzAbsIntVal *state,
		RZ_NONNULL RZ_OUT RzStrBuf *str_buf);

	void (*eval_cast)(ut32 length, RZ_NONNULL const RzAbsIntVal *fill, RZ_INOUT RZ_NONNULL RzAbsIntVal *val); ///< RZ_IL_OP_CAST
	void (*eval_shift)(bool right, RZ_NONNULL RZ_INOUT RzAbsIntVal *x, RZ_NONNULL const RzAbsIntVal *y, RZ_NONNULL const RzAbsIntVal *fill_bit); ///< RZ_IL_OP_SHIFTL, RZ_IL_OP_SHIFTR

	/**
	 * \brief Evaluate a binary operation on two abstract values
	 *
	 * \param code The operation to evaluate. May be any IL op that takes exactly two bitvector or boolean operands.
	 * \param x Output, as well as `x` (or `low`) operand
	 * \param y `y` (or `low`) operand
	 */
	void (*eval_binop)(RzILOpPureCode code, RZ_NONNULL RZ_INOUT RzAbsIntVal *x, RZ_NONNULL const RzAbsIntVal *y);

	/**
	 * \brief Evaluate a unary operation on an abstract value
	 *
	 * \param code The operation to evaluate. May be any IL op that takes exactly one bitvector or boolean operand.
	 * \param val Output, as well as operand
	 */
	void (*eval_unop)(RzILOpPureCode code, RZ_NONNULL RZ_INOUT RzAbsIntVal *val);
} RzAbsIntValueDomain;

typedef struct rz_absint_io_read_request_t {
	size_t mem_idx; ///< The memory space to read/write.
	bool big_endian; ///< Set if the data is big endian ordered.
	const RzBitVector *addr; ///< The address to read/write.
	RzBitVector *ld_data; ///< The bit vector to load into. It is BORROWED.
	size_t n_bits; ///< The number of bits to read/write.
} RzAbsIntIOReadRequest;

typedef enum rz_absint_io_read_result_t {
	RZ_ABSINT_IO_READ_RESULT_OK, ///< ld_data fully written
	RZ_ABSINT_IO_READ_RESULT_TOP, ///< result should be considered top (memory contents unknown)
	RZ_ABSINT_IO_READ_RESULT_BREAK ///< interpreter is signaled to stop
} RzAbsIntIOReadResult;

typedef enum rz_absint_lift_block_result_t {
	RZ_ABSINT_LIFT_BLOCK_RESULT_OK, ///< block_out is filled
	RZ_ABSINT_LIFT_BLOCK_RESULT_FAILED,
	RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK ///< interpreter is signaled to stop
} RzAbsIntLiftBlockResult;

typedef struct rz_absint_config_t {
	RzAbsIntValueDomain *val_domain;
	RzAbsIntTraceOptions trace_opts;

	void *cb_user;
	RzAbsIntIOReadResult (*io_read)(RZ_NONNULL RZ_OWN RzAbsIntIOReadRequest *req, void *user);
	RzAbsIntLiftBlockResult (*lift_block)(ut64 addr, RZ_OUT const RzILCacheBlock **block_out, void *user);
} RzAbsIntConfig;

/**
 * \brief Root local data of a single interpreter thread
 */
struct rz_absint_instance_t {
	RzAbsIntConfig config;

	RzAnalysisILContext *il_ctx; ///< Context about available global vars and memory
	HtUP *var_name_hashes; ///< Map of DJB2 hashes to variable names.
	RZ_DEPRECATE const char *arch_name; ///< Name of architecture. Used only by work-arounds until we have RzArch.
};

RZ_API RZ_OWN RzAbsIntInstance *rz_absint_instance_new(RzAnalysis *analysis, RZ_NONNULL RZ_BORROW const RzAbsIntConfig *config);
RZ_API void rz_absint_instance_free(RZ_OWN RZ_NULLABLE RzAbsIntInstance *iset);

/**
 * \brief Dimensions describing what kind of information should be retrieved from the interpreter run
 */
typedef enum rz_absint_result_dimen_t {
	/**
	 * \brief The basic information that is always included in every run
	 * This includes block boundaries, control flow edges and entry states for each block.
	 */
	RZ_ABSINT_RESULT_DIMEN_BASE = 0,
	RZ_ABSINT_RESULT_DIMEN_XREFS = 1 << 0, ///< fills RzAbsIntResult.xrefs
	RZ_ABSINT_RESULT_DIMEN_COMMENTS = 1 << 1 ///< per-address textual state description for debugging, fills RzAbsIntResult.comments
} RzAbsIntResultDimen;

/**
 * \brief Local data during an interpreter run
 */
struct rz_absint_run_context_t {
	RzAbsIntInstance *inst; //< parent interpreter thread

	RzList /*<RzAbsIntBlock>*/ *queue; ///< States that have to be interpreted still. If this is empty, a fixpoint has been reached.
	/**
	 * \brief All currently discovered blocks by address.
	 * TODO: If the interval tree concept is kept, this should eventually be refactored to use RBTree directly and embed RBNode
	 * inside RzAbsIntBlock to remove the additional indirection.
	 */
	RzIntervalTree /*<RzAbsIntBlock>*/ blocks;
	RzAbsIntResultDimen res_dimen;
	RzAbsIntResult *res; ///< If not NULL, a fixpoint has been reached already and we are now collecting results

	// Tracking data local to a single block interpretation
	RzAbsIntBlock *block; ///< The currently interpreted interp block
	ut64 il_block_end; ///< The address directly after the last instruction of the currently interpreted IL block, may be further than the last instruction of the interp block!
	RzAbsIntState *astate; ///< The abstract state of the interpreter.
	ut64 insn_addr; ///< The address of the currently evaluated instruction. This is not equal to astate->pc since that is already advanced by the instruction size.
	bool block_stores_ret_addr; ///< It was detected that the block stores an address that may be a return address. Used for detecting calls.
};

struct rz_absint_result_t {
	ut64 entry; ///< always filled
	RzIntervalTree /*<RzAbsIntBlock>*/ blocks; ///< always filled
	RzVector /*<RzAnalysisXRef>*/ xrefs; ///< filled if RZ_ABSINT_RESULT_DIMEN_XREFS is requested
	HtUP /*<char *>*/ *comments; ///< filled if RZ_ABSINT_RESULT_DIMEN_COMMENTS
} /*RzAbsIntResult*/;

typedef enum rz_absint_result_code_t {
	RZ_ABSINT_RESULT_OK,
	RZ_ABSINT_RESULT_FAILED,
	RZ_ABSINT_RESULT_BREAK
} RzAbsIntResultCode;

RZ_API RzAbsIntResultCode rz_absint_run(RzAbsIntInstance *inst, ut64 entry_point, RzAbsIntResultDimen dimen, RZ_NONNULL RZ_OUT RzAbsIntResult **res_out);
RZ_API void rz_absint_result_free(RzAbsIntInstance *inst, RzAbsIntResult *res);
RZ_API bool rz_absint_result_apply_to_analysis(RZ_NONNULL RzAbsIntResult *res, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE const char *fcn_name);

extern RZ_API RzAbsIntValueDomain rz_absint_value_domain_const;

typedef struct rz_absint_driver_config_t {
	RZ_NONNULL RzAnalysis *analysis;
	RZ_NONNULL RzIO *io;
	RZ_NONNULL RzSetU *entry_points;
	RzAbsIntResultDimen dimens;
	RzAbsIntTraceOptions trace_opts;
	void *cb_user;
	char *(*choose_fcn_name)(ut64 addr, void *user);
} RzAbsIntDriverConfig;

RZ_API bool rz_absint_driver_run(RZ_NONNULL RZ_BORROW RzAbsIntDriverConfig *config);

#endif // RZ_ABSINT
