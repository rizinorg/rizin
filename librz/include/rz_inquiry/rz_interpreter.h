// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The header file for the RzInterp contains declarations for
 * all RzIL based interpreters.
 */

#ifndef RZ_INTERPRETER
#define RZ_INTERPRETER

#include <rz_inquiry/rz_bcfg.h>
#include <rz_inquiry/rz_il_cache.h>
#include <rz_arch.h>
#include <rz_io.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief Only one IO request at a time is possible (currently).
 */
#define RZ_INTERP_IO_RBUF_SIZE           128
#define RZ_INTERP_YIELD_RBUF_SIZE        128
#define RZ_INTERP_ENTRY_POINTS_RBUF_SIZE 4

typedef struct rz_interp_run_state RzInterpRunState;
typedef struct rz_interp_run_context_t RzInterpRunContext;

typedef enum rz_interp_state_flag {
	/**
	 * \brief Interpreter is still outside of its defined loop.
	 * E.g. shortly after its thread was spawned.
	 */
	RZ_INTERP_RUN_STATE_OUT_OF_LOOP,
	RZ_INTERP_RUN_STATE_INIT, ///< Initialization state.
	RZ_INTERP_RUN_STATE_EMU, ///< Emulation state.
	RZ_INTERP_RUN_STATE_CLEAN, ///< Cleaning state.
	RZ_INTERP_RUN_STATE_TERM, ///< Termination state.
} RzInterpRunStateFlag;

/**
 * \brief An abstract value representing a set of RzILVal
 *
 * The actual abstraction and structure of this is defined by the plugin in use.
 * `struct rz_interp_opaque_abstr_val_t` is defined nowhere. Is is used to ensure
 * type-checking of passing this opaque pointer.
 */
typedef struct rz_interp_opaque_abstr_val_t RzInterpAbstrVal;

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

typedef struct {
	RzInquiryBCFGEdgeType cf_type; ///< Control flow type.
	/**
	 * \brief The address of the block which changes the control flow.
	 * This might be UT64_MAX, if there was no jump that flow originated from.
	 * If the interpreter was just initialized, for example.
	 */
	ut64 src_block_addr;
	/**
	 * \brief The original target address a block branches to.
	 */
	ut64 target_addr;
	/**
	 * \brief Set after a attempted jump to an ignored code region.
	 * This is almost always a call to an unloaded imported symbol.
	 * 0 is an invalid address here.
	 */
	ut64 alt_target;
	/**
	 * \brief Equal to alt_target if alt_target != 0.
	 * Otherwise equal to target_addr
	 */
	ut64 actual_target;
	/**
	 * \brief Number of bytes of the destination code block.
	 * Only set after the IL block was provided by the cache.
	 */
	size_t target_block_size;
	/**
	 * \brief Control flow type.
	 */
	RzInquiryBCFGEdgeType type;
} RzInterpCtrlFlow;

typedef enum {
	RZ_INTERP_PC_CONST, ///< Single known value
	RZ_INTERP_PC_UNREACHABLE, ///< Bottom/unreachable state, if this is set, pc field is unused and undefined
	RZ_INTERP_PC_ANY ///< Top state, if this is set, pc field is unused and undefined
} RzInterpPCState;

typedef struct {
	ut64 pc; ///< Interpreter location in the code. This is not necessarily identical to the ISA's program counter register, but simply points to the instruction to execute.
	RzInterpPCState pc_state;
	bool uninterpreted; ///< True if this state has not yet been started to interpret, i.e. is part of RzInterpFunctionState.queue

	HtUP *var_name_hashes; ///< Map of DJB2 hashes to variable names.
	HtUP /*<RzInterpAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzInterpAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzInterpAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
	const char *arch_name; ///< Name of architecture. Used by work-arounds until we have RzArch.
	ut64 bb_addr;
	ut64 bb_size;
} RzInterpAbstrState;

typedef enum {
	/**
	 * \brief The yield is an cross reference.
	 */
	RZ_INTERP_YIELD_KIND_XREF = 0,

	/**
	 * \brief This yield is a simple flag, signaling if the current basic block
	 * storing the next PC (address _after_ the basic block) to memory or an register.
	 *
	 * If the last branch instruction does not jump to the neighboring basic block
	 * it is a strong indicator that the jump is a call and the next address a return point.
	 */
	RZ_INTERP_YIELD_KIND_CALL_CANDIDATE,

	/**
	 * \brief Yield is a RzInterpCtrlFlow.
	 * Reported by every interpreter.
	 */
	RZ_INTERP_YIELD_KIND_CONTROL_FLOW,
	RZ_INTERP_YIELD_KIND_NUM,
} RzInterpYieldKind;

/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield ring buffer or not.
 */
typedef bool (*RzInterpYieldFilter)(const void *element, const void *filter_data);

typedef struct {
	RzPVector /*<RzBinSection *>*/ *io_boundaries;
} RzInterpYieldFilterData;

/**
 * \brief A ring buffer to push interpretation yields into.
 */
typedef struct {
	RzInterpYieldKind kind;
	RzInterpYieldFilter filter;
	RzInterpYieldFilterData *filter_data;
	RzThreadRingBuf *rbuf;
} RzInterpYieldRBuf;

typedef struct rz_interp_instance_t RzInterpInstance;

typedef struct {
	const char *name;

	RZ_OWN RzInterpAbstrVal *(*val_new_top)(void); ///< allocate a new abstract value and initialize it as top
	void (*val_free)(RzInterpAbstrVal *val);
	bool (*is_top)(RZ_NONNULL const RzInterpAbstrVal *val); ///< return whether the given value is top
	bool (*may_be_bool)(RZ_NONNULL const RzInterpAbstrVal *val, bool value); ///< return whether the given value's concrete set contains \p value
	void (*set_top)(RZ_OUT RZ_NONNULL RzInterpAbstrVal *dst); ///< Set \p val to be top
	void (*set_const)(RZ_OUT RZ_NONNULL RzInterpAbstrVal *dst, RZ_IN RZ_NONNULL RzBitVector *src); ///< set \p dst to the least value that includes \p src

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
	 * \brief Evaluate \p pure and return the result in \p out
	 */
	bool (*eval_pure)(RzInterpRunContext *ctx, const RzILOpPure *pure, RZ_OUT RzInterpAbstrVal *out);

	/**
	 * \brief Builds a string for printing an abstract value.
	 *
	 * \return Returns false in case of error, True otherwise.
	 */
	bool (*val_as_str)(RZ_NONNULL const RzInterpAbstrVal *state,
		RZ_NONNULL RZ_OUT RzStrBuf *str_buf);

} RzInterpPlugin;

typedef struct {
	size_t mem_idx; ///< The memory space to read/write.
	bool big_endian; ///< Set if the data is big endian ordered.
	const RzBitVector *addr; ///< The address to read/write.
	const RzBitVector *st_data; ///< The data to store.
	RzBitVector *ld_data; ///< The bit vector to load into. It is BORROWED.
	size_t n_bits; ///< The number of bits to read/write.
} RzInterpIOReadRequest;

typedef struct {
	bool req_ok; ///< Set to true if IO request succeeded.
} RzInterpIOResult;

/**
 * \brief Root local data of a single interpreter thread
 */
RZ_LIFETIME(RzInquiry)
struct rz_interp_instance_t {
	RzAnalysis *a; ///< TODO: remove

	RzInterpRunState *run_state; ///< The state the interpreter is currently in.
	/**
	 * \brief The semaphore to sync RzInquiry and the interpreter between the Clean and Init run state.
	 */
	RzThreadSemaphore *run_state_sync;

	/**
	 * \brief Entry points the interpreter starts interpreting from.
	 */
	RzThreadRingBuf *entry_points;

	RzAnalysisILContext *il_ctx; ///< Context about available global vars and memory

	RZ_LIFETIME(RzILCache)
	RZ_BORROW RzILCacheClient *il_cache_client;

	RzThreadRingBuf /*<RzInterpIORequest>*/ *io_request_rbuf; ///< The ring buffer for read/write requests to the IO layer.
	RzThreadRingBuf /*<const RzInterpIOResult *>*/ *io_result_rbuf; ///< The ring buffer for the read/write requests' answers.

	/**
	 * \brief The ring buffers to push the yield of interpretation into.
	 * These ring buffers are shared with other interpreter sets.
	 */
	RZ_BORROW RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM];
	/**
	 * \brief Ignored address ranges.
	 */
	const RzVector /*<RzInterval>*/ *ignored_code;
	/**
	 * \brief The interpreter plugin.
	 */
	RzInterpPlugin *plugin;
};

RZ_API RZ_OWN RzInterpRunState *rz_interp_run_state_new();
RZ_API void rz_interp_run_state_free(RZ_OWN RZ_NULLABLE RzInterpRunState *state);
RZ_API RzInterpRunStateFlag rz_interp_run_state_get(RZ_BORROW RZ_NONNULL RzInterpRunState *state);
RZ_API RzInterpRunStateFlag rz_interp_run_state_get_unsafe(const RZ_NONNULL RzInterpRunState *state);
RZ_API const char *rz_interp_run_state_flag_str(RzInterpRunStateFlag flag);

RZ_IPI void rz_interp_run_state_set(RZ_BORROW RZ_NONNULL RzInterpRunState *state, RzInterpRunStateFlag flag);

RZ_API void rz_interp_yield_rbuf_free(RZ_OWN RZ_NULLABLE RzInterpYieldRBuf *yield_rbuf);

RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_new(
	RZ_NONNULL RzInterpInstance *inst,
	const char *arch_name);
RZ_API void rz_interp_abstr_state_free(RzInterpInstance *inst, RZ_OWN RZ_NULLABLE RzInterpAbstrState *state);
RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_clone(RZ_NONNULL RzInterpInstance *iset, const RzInterpAbstrState *state);
RZ_API bool rz_interp_abstr_state_as_str(RZ_NONNULL RzInterpInstance *inst, RZ_NONNULL const RzInterpAbstrState *state, RZ_NONNULL RZ_OUT RzStrBuf *sb);
RZ_API void rz_interp_abstr_state_as_str_short(RZ_NONNULL RzInterpInstance *inst, RZ_NONNULL const RzInterpAbstrState *astate, RZ_NONNULL RZ_OUT RzStrBuf *sb);

RZ_API RZ_OWN RzInterpYieldRBuf *rz_interp_yield_rbuf_new(RzInterpYieldKind kind,
	RzInterpYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data);

RZ_API RZ_OWN RzInterpInstance *rz_interp_instance_new(
	RzAnalysis *analysis,
	RZ_NONNULL RZ_OWN RzInterpPlugin *plugin,
	RZ_NONNULL RZ_BORROW RzILCacheClient *il_cache_client,
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);
RZ_API void rz_interp_instance_free(RZ_OWN RZ_NULLABLE RzInterpInstance *iset);

/**
 * \brief Local data during an interpreter run
 */
struct rz_interp_run_context_t {
	RzInterpInstance *inst; //< parent interpreter thread

	RzList /*<RzInterpAbstrState>*/ *queue; ///< States that have to be interpreted still. If this is empty, a fixpoint has been reached.
	HtUP /*<RzInterpAbstrState>*/ *pc_states; ///< Currently discovered states at the entries of blocks.

	// Tracking data local to a single block interpretation
	RzInterpAbstrState *astate; ///< The abstract state of the interpreter.
	RzAnalysisCallCandidate call_cand; ///< Data of a call candidate.
};

/*
 * \brief Register a newly discovered state
 *
 * This will join the state with the already known one at the same pc and add it to the
 * queue for further interpretation if there were changes.
 */
RZ_API void rz_interp_run_push(RZ_BORROW RZ_NONNULL RzInterpRunContext *ctx, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as);

RZ_API bool rz_interp_instance_th(RZ_NONNULL RZ_OWN RzInterpInstance *iset);

#endif // RZ_INTERPRETER
