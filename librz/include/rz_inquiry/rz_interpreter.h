// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The header file for the RzInterp contains declarations for
 * all RzIL based interpreters.
 */

#ifndef RZ_INTERPRETER
#define RZ_INTERPRETER

#include <rz_inquiry/rz_il_cache.h>
#include <rz_arch.h>
#include <rz_io.h>
#include <rz_types.h>
#include <rz_util.h>

typedef struct rz_interp_run_context_t RzInterpRunContext;
typedef struct rz_interp_result_t RzInterpResult;

/**
 * \brief An abstract value representing a set of RzILVal
 *
 * The actual abstraction and structure of this is defined by the plugin in use.
 * `struct rz_interp_opaque_abstr_val_t` is defined nowhere. Is is used to ensure
 * type-checking of passing this opaque pointer.
 */
typedef struct rz_interp_abstr_val_t RzInterpAbstrVal;

/**
 * \brief Helper to explicitly cast a plugin-defined abstract value to an opaque RzInterpAbstrVal
 */
static inline RzInterpAbstrVal *rz_interp_abstr_val_pack(void *val) {
	return val;
}

/**
 * \brief Helper to explicitly cast an opaque RzInterpAbstrVal to a plugin-defined abstract value
 */
static inline void *rz_interp_abstr_val_unpack(const RzInterpAbstrVal *val) {
	return (void *)val;
}

typedef enum {
	RZ_INTERP_PC_CONST, ///< Single known value
	RZ_INTERP_PC_UNREACHABLE, ///< Bottom/unreachable state, if this is set, pc field is unused and undefined
	RZ_INTERP_PC_ANY ///< Top state, if this is set, pc field is unused and undefined
} RzInterpPCState;

typedef struct {
	ut64 pc; ///< Interpreter location in the code. This is not necessarily identical to the ISA's program counter register, but simply points to the instruction to execute next.
	RzInterpPCState pc_state;

	HtUP /*<RzInterpAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzInterpAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzInterpAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
} RzInterpAbstrState;

/**
 * \brief Basic Block as part of the abstract interpretation loop
 * Represents a block of instructions of which only the last may have a control effect.
 * Unlike IL blocks, the last instruction may also not have a control effect, which is
 * the case when the instruction directly following this block has an in-edge.
 * And unlike in RzAnalysisBlock, a call instruction also terminates an interpreter block.
 */
typedef struct {
	RzIntervalNode *node; ///< Backref to the node containing this block. end value is inclusive. TODO: remove this if RBTree is used directly
	/**
	 * Least upper bound of all states discovered at the entry of the block.
	 * pc_state of this state must be RZ_INTERP_PC_CONST and pc points to the first instruction of the block.
	 */
	RzInterpAbstrState *entry_state; // TODO: flatten to remove indirection
	RzVector /*<ut16>*/ insn_offsets; ///< starting at the second instruction in the block (since first is always 0), offsets from the start of the block
	bool bounds_resolved; ///< Set to true once insn_offsets and node->end are filled.
	bool uninterpreted; ///< True if the entry state has not yet been started to interpret, i.e. the block is part of RzInterpFunctionState.queue
	bool non_fallthrough_in; ///< True if there is an in-edge to this block that is not only a fallthrough. Used when merging consecutive blocks after interpretation.
	bool added_to_analysis; ///< Only used after interpretation, when adding to analysis. Marks blocks that have been merged with the previous.

	// Out-edges
	bool fallthrough; ///< if true, there is an edge to the block after the end of this one
	RzVector /*<ut64>*/ jump_targets; ///< Explicit jump targets, does not contain fallthrough address
} RzInterpBlock;

typedef struct rz_interp_instance_t RzInterpInstance;

typedef struct {
	const char *name;

	RZ_OWN RzInterpAbstrVal *(*val_new_top)(void); ///< allocate a new abstract value and initialize it as top
	void (*val_free)(RzInterpAbstrVal *val);
	bool (*is_top)(RZ_NONNULL const RzInterpAbstrVal *val); ///< return whether the given value is top
	bool (*may_be_bool)(RZ_NONNULL const RzInterpAbstrVal *val, bool value); ///< return whether the given value's concrete set contains \p value
	void (*set_top)(RZ_OUT RZ_NONNULL RzInterpAbstrVal *dst); ///< Set \p val to be top
	void (*set_const_bool)(RZ_OUT RZ_NONNULL RzInterpAbstrVal *dst, bool src); ///< set \p dst to the least value that includes \p src
	void (*set_const_bv)(RZ_OUT RZ_NONNULL RzInterpAbstrVal *dst, RZ_IN RZ_NONNULL RzBitVector *src); ///< set \p dst to the least value that includes \p src

	/**
	 * \brief Concretize an abstract value to a single bit vector, if possible
	 *
	 * If \p val represents exactly one concrete value, this returns true.
	 * Additionally, the concrete value is written to \p out if passed.
	 */
	bool (*to_concrete_const)(RZ_NONNULL const RzInterpAbstrVal *val, RZ_NULLABLE RZ_OUT RzBitVector *out);

	RZ_OWN void (*copy)(RzInterpAbstrVal *dst, const RzInterpAbstrVal *src);

	/**
	 * \brief Performs the join operation on two abstract values (least upper bound, lattice theory)
	 *
	 * This is the least upper bound (lattice theory). In detail, it means \p a should be set to the least
	 * abstract value whose corresponding concrete value set is a superset of both the concrete value sets
	 * of \p a and \p b.
	 *
	 * \return True if a was changed
	 */
	bool (*join)(RZ_BORROW RZ_INOUT RzInterpAbstrVal *a, RZ_BORROW RZ_IN const RzInterpAbstrVal *b);

	/**
	 * \brief Builds a string for printing an abstract value.
	 *
	 * \return Returns false in case of error, True otherwise.
	 */
	bool (*val_as_str)(RZ_NONNULL const RzInterpAbstrVal *state,
		RZ_NONNULL RZ_OUT RzStrBuf *str_buf);

	void (*eval_cast)(ut32 length, RZ_NONNULL const RzInterpAbstrVal *fill, RZ_INOUT RZ_NONNULL RzInterpAbstrVal *val); ///< RZ_IL_OP_CAST
	void (*eval_shift)(bool right, RZ_NONNULL RZ_INOUT RzInterpAbstrVal *x, RZ_NONNULL const RzInterpAbstrVal *y, RZ_NONNULL const RzInterpAbstrVal *fill_bit); ///< RZ_IL_OP_SHIFTL, RZ_IL_OP_SHIFTR

	/**
	 * \brief Evaluate a binary operation on two abstract values
	 *
	 * \param code The operation to evaluate. May be any IL op that takes exactly two bitvector or boolean operands.
	 * \param x Output, as well as `x` (or `low`) operand
	 * \param y `y` (or `low`) operand
	 */
	void (*eval_binop)(RzILOpPureCode code, RZ_NONNULL RZ_INOUT RzInterpAbstrVal *x, RZ_NONNULL const RzInterpAbstrVal *y);

	/**
	 * \brief Evaluate a unary operation on an abstract value
	 *
	 * \param code The operation to evaluate. May be any IL op that takes exactly one bitvector or boolean operand.
	 * \param val Output, as well as operand
	 */
	void (*eval_unop)(RzILOpPureCode code, RZ_NONNULL RZ_INOUT RzInterpAbstrVal *val);

} RzInterpValueAbstraction;

typedef struct rz_interp_io_read_request_t {
	size_t mem_idx; ///< The memory space to read/write.
	bool big_endian; ///< Set if the data is big endian ordered.
	const RzBitVector *addr; ///< The address to read/write.
	RzBitVector *ld_data; ///< The bit vector to load into. It is BORROWED.
	size_t n_bits; ///< The number of bits to read/write.
} RzInterpIOReadRequest;

typedef enum rz_interp_io_read_result_t {
	RZ_INTERP_IO_READ_RESULT_OK, ///< ld_data fully written
	RZ_INTERP_IO_READ_RESULT_TOP, ///< result should be considered top (memory contents unknown)
	RZ_INTERP_IO_READ_RESULT_BREAK ///< interpreter is signaled to stop
} RzInterpIOReadResult;

typedef enum rz_interp_lift_block_result_t {
	RZ_INTERP_LIFT_BLOCK_RESULT_OK, ///< block_out is filled
	RZ_INTERP_LIFT_BLOCK_RESULT_FAILED,
	RZ_INTERP_LIFT_BLOCK_RESULT_BREAK ///< interpreter is signaled to stop
} RzInterpLiftBlockResult;

typedef struct rz_interp_config_t {
	RzInterpValueAbstraction *val_domain;

	void *cb_user;
	RzInterpIOReadResult (*io_read)(RZ_NONNULL RZ_OWN RzInterpIOReadRequest *req, void *user);
	RzInterpLiftBlockResult (*lift_block)(ut64 addr, RZ_OUT const RzILCacheBlock **block_out, void *user);
} RzInterpConfig;

/**
 * \brief Root local data of a single interpreter thread
 */
RZ_LIFETIME(RzInquiry)
struct rz_interp_instance_t {
	RzInterpConfig config;

	RzAnalysisILContext *il_ctx; ///< Context about available global vars and memory
	HtUP *var_name_hashes; ///< Map of DJB2 hashes to variable names.
	RZ_DEPRECATE const char *arch_name; ///< Name of architecture. Used only by work-arounds until we have RzArch.
};

RZ_API RZ_OWN RzInterpInstance *rz_interp_instance_new(RzAnalysis *analysis, RZ_NONNULL RZ_BORROW const RzInterpConfig *config);
RZ_API void rz_interp_instance_free(RZ_OWN RZ_NULLABLE RzInterpInstance *iset);

/**
 * \brief Dimensions describing what kind of information should be retrieved from the interpreter run
 */
typedef enum rz_interp_result_dimen_t {
	/**
	 * \brief The basic information that is always included in every run
	 * This includes block boundaries, control flow edges and entry states for each block.
	 */
	RZ_INTERP_RESULT_DIMEN_BASE = 0,
	RZ_INTERP_RESULT_DIMEN_XREFS = 1 << 0, ///< fills RzInterpResult.xrefs
	RZ_INTERP_RESULT_DIMEN_COMMENTS = 1 << 1 ///< per-address textual state description for debugging, fills RzInterpResult.comments
} RzInterpResultDimen;

/**
 * \brief Local data during an interpreter run
 */
struct rz_interp_run_context_t {
	RzInterpInstance *inst; //< parent interpreter thread

	RzList /*<RzInterpBlock>*/ *queue; ///< States that have to be interpreted still. If this is empty, a fixpoint has been reached.
	/**
	 * \brief All currently discovered blocks by address.
	 * TODO: If the interval tree concept is kept, this should eventually be refactored to use RBTree directly and embed RBNode
	 * inside RzInterpBlock to remove the additional indirection.
	 */
	RzIntervalTree /*<RzInterpBlock>*/ blocks;
	RzInterpResultDimen res_dimen;
	RzInterpResult *res; ///< If not NULL, a fixpoint has been reached already and we are now collecting results

	// Tracking data local to a single block interpretation
	RzInterpBlock *block; ///< The currently interpreted interp block
	ut64 il_block_end; ///< The address directly after the last instruction of the currently interpreted IL block, may be further than the last instruction of the interp block!
	RzInterpAbstrState *astate; ///< The abstract state of the interpreter.
	ut64 insn_addr; ///< The address of the currently evaluated instruction. This is not equal to astate->pc since that is already advanced by the instruction size.
	RzAnalysisCallCandidate call_cand; ///< Data of a call candidate.
};

struct rz_interp_result_t {
	ut64 entry; ///< always filled
	RzIntervalTree /*<RzInterpBlock>*/ blocks; ///< always filled
	RzVector /*<RzAnalysisXRef>*/ xrefs; ///< filled if RZ_INTERP_RESULT_DIMEN_XREFS is requested
	HtUP /*<char *>*/ *comments; ///< filled if RZ_INTERP_RESULT_DIMEN_COMMENTS
} /*RzInterpResult*/;

RZ_API RzInterpResult *rz_interp_run(RzInterpInstance *inst, ut64 entry_point, RzInterpResultDimen dimen);
RZ_API bool rz_interp_result_apply_to_analysis(RZ_NONNULL RzInterpResult *res, RZ_NONNULL RzAnalysis *analysis);

extern RZ_API RzInterpValueAbstraction rz_interp_value_domain_const;

RZ_API bool rz_interp_driver_run(RzCore *core, RZ_OWN RzSetU *entry_points);

#endif // RZ_INTERPRETER
