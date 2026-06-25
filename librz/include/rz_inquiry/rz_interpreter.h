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
 * \brief The abstractions this module supports.
 */
typedef enum {
	/**
	 * \brief An undefined abstracted value.
	 */
	RZ_INTERP_ABSTRACTION_UNDEF = 0,
	/**
	 * \brief Value abstraction into constant and bottom values.
	 */
	RZ_INTERP_ABSTRACTION_CONST = 1 << 0,
	/**
	 * \brief Value abstraction into Heap[base, offset] and bottom values.
	 */
	RZ_INTERP_ABSTRACTION_HEAP = 1 << 1,
	/**
	 * \brief Value abstraction into Stack[base, offset] and bottom values.
	 */
	RZ_INTERP_ABSTRACTION_STACK = 1 << 2,
} RzInterpAbstraction;

/**
 * \brief An arbitrary abstract value.
 */
typedef struct {
	RzInterpAbstraction kind; ///< The abstraction of the value.
	void *abstr_data; ///< The abstract data. It is managed by individual interpreter.
} RzInterpAbstrVal;

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

	RzInterpAbstraction kinds; ///< The abstractions of the state.
	HtUP *var_name_hashes; ///< Map of DJB2 hashes to variable names.
	HtUP /*<RzInterpAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzInterpAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzInterpAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
	RzAnalysisILConfig *il_config; ///< The IL configuration of the RzArch plugin.
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

typedef struct rz_interpreter_set RzInterpSet;

typedef struct {
	const char *name;
	const char *author;
	const char *version;
	const char *desc;
	const char *license;
	/**
	 * \brief Supported abstractions. Multiple flags can be set.
	 */
	RzInterpAbstraction supported_abstractions;
	/**
	 * \brief The yield type this interpreter generates.
	 */
	RzInterpYieldKind supported_yields[RZ_INTERP_YIELD_KIND_NUM];
	bool (*init)(void **plugin_data);
	bool (*reset)(void *plugin_data);
	bool (*fini)(void *plugin_data);

	/**
	 * \brief Clones the given abstract value.
	 */
	RZ_OWN RzInterpAbstrVal *(*clone_val)(const RzInterpAbstrVal *val, void *plugin_data);

	/**
	 * \brief Initializes the abstract state.
	 */
	bool (*init_state)(RZ_BORROW RzInterpAbstrState *state, void *plugin_data);
	/**
	 * \brief Reset the abstract state.
	 */
	bool (*reset_state)(RZ_BORROW RzInterpAbstrState *state, ut64 entry_point, void *plugin_data);
	/**
	 * \brief Closes the abstract state and frees all its abstract data and sets the pointers to NULL.
	 */
	bool (*fini_state)(RZ_BORROW RzInterpAbstrState *state, void *plugin_data);
	/**
	 * \brief Hashes the state.
	 */
	ut64 (*hash_state)(RZ_NONNULL const RzInterpAbstrState *state,
		void *plugin_data);
	/**
	 * \brief Performs the join operation on states (least upper bound, lattice theory)
	 * \return True if a was changed
	 */
	bool (*join_state)(RZ_BORROW RZ_INOUT RzInterpAbstrState *a, RZ_BORROW RZ_IN const RzInterpAbstrState *b, void *plugin_data);
	/**
	 * \brief Evaluates an effect with the mutable state.
	 */
	bool (*eval)(RZ_NONNULL RzInterpSet *iset,
		RZ_NONNULL const RzILCacheBlock *il_bb,
		void *plugin_data);
	/**
	 * \brief Determines the next successor addresses from state.
	 *
	 * \return Returns false in case of error. The interpretation must abort.
	 * True otherwise.
	 */
	bool (*successors)(RZ_NONNULL const RzInterpAbstrState *state,
		RZ_NONNULL RZ_OUT RzVector /*<RzInterpBranch>*/ *successors,
		void *plugin_data);

	/**
	 * \brief Builds a string for printing an abstract value.
	 *
	 * \return Returns false in case of error, True otherwise.
	 */
	bool (*val_as_str)(RZ_NONNULL const RzInterpAbstrVal *state,
		RZ_NONNULL RZ_OUT RzStrBuf *str_buf,
		void *plugin_data);

	/**
	 * \brief Builds a string for printing the current state.
	 *
	 * \return Returns false in case of error, True otherwise.
	 */
	bool (*state_as_str)(RZ_NONNULL const RzInterpAbstrState *state,
		RZ_NONNULL RZ_OUT RzStrBuf *str_buf,
		void *plugin_data);

	/**
	 * \brief Set the abstract PC to the given address.
	 */
	bool (*set_pc)(RZ_NONNULL RzInterpAbstrState *state,
		ut64 pc,
		void *plugin_data);
} RzInterpPlugin;

typedef enum {
	RZ_INTERP_IO_READ,
	RZ_INTERP_IO_WRITE,
} RzInterpIOReqType;

typedef struct {
	RzInterpIOReqType type;
	size_t mem_idx; ///< The memory space to read/write.
	bool big_endian; ///< Set if the data is big endian ordered.
	const RzBitVector *addr; ///< The address to read/write.
	const RzBitVector *st_data; ///< The data to store.
	RzBitVector *ld_data; ///< The bit vector to load into. It is BORROWED.
	size_t n_bits; ///< The number of bits to read/write.
} RzInterpIORequest;

typedef struct {
	bool req_ok; ///< Set to true if IO request succeeded.
} RzInterpIOResult;

typedef struct {
	RzList /*<RzInterpAbstrState>*/ *queue; ///< States that have to be interpreted still. If this is empty, a fixpoint has been reached.
	HtUP /*<RzInterpAbstrState>*/ *pc_states; ///< Currently discovered states at the entries of blocks.
} RzInterpFunctionState;

/**
 * \brief The set of required objects for an interpreter to run.
 */
RZ_LIFETIME(RzInquiry)
struct rz_interpreter_set {
	RzAnalysis *a; ///< TODO: remove

	// TODO: Move this one into each plugin?
	RzInterpAbstrState *astate; ///< The abstract state of the interpreter.

	RzInterpFunctionState fcn_state;

	RzInterpRunState *run_state; ///< The state the interpreter is currently in.
	/**
	 * \brief The semaphore to sync RzInquiry and the interpreter between the Clean and Init run state.
	 */
	RzThreadSemaphore *run_state_sync;

	/**
	 * \brief Entry points the interpreter starts interpreting from.
	 */
	RzThreadRingBuf *entry_points;

	RzAnalysisILVM *il_vm; ///< The RzAnalysisILVM for memory IO.

	RZ_LIFETIME(RzILCache)
	RZ_BORROW RzThreadQueue /*<const RzInterpILOp *>*/ *il_queue; ///< The queue to receive the IL effects.
	RZ_LIFETIME(RzILCache)
	RZ_BORROW RzThreadRingBuf /*<RzInterpBranch>*/ *il_request_rbuf; ///< The ring buffer to send requests to the cache what address to get the next IL op from.

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
	/**
	 * \brief The private data of a single interpreter thread.
	 */
	RZ_BORROW void *interp_priv;
};

RZ_API RZ_OWN RzInterpRunState *rz_interp_run_state_new();
RZ_API void rz_interp_run_state_free(RZ_OWN RZ_NULLABLE RzInterpRunState *state);
RZ_API RzInterpRunStateFlag rz_interp_run_state_get(RZ_BORROW RZ_NONNULL RzInterpRunState *state);
RZ_API RzInterpRunStateFlag rz_interp_run_state_get_unsafe(const RZ_NONNULL RzInterpRunState *state);
RZ_API const char *rz_interp_run_state_flag_str(RzInterpRunStateFlag flag);

RZ_IPI void rz_interp_run_state_set(RZ_BORROW RZ_NONNULL RzInterpRunState *state, RzInterpRunStateFlag flag);

RZ_API void rz_interpreter_yield_rbuf_free(RZ_OWN RZ_NULLABLE RzInterpYieldRBuf *yield_rbuf);

RZ_API RZ_OWN RzInterpAbstrState *rz_interpreter_abstr_state_new(
	const char *arch_name,
	RzInterpAbstraction kinds,
	RZ_OWN RZ_NONNULL RzAnalysisILConfig *il_config,
	RZ_NULLABLE const RzILRegBinding *reg_bindings);
RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpAbstrState *state);
RZ_API RZ_OWN RzInterpAbstrState *rz_interpreter_abstr_state_clone(RZ_NONNULL RzInterpSet *iset, const RzInterpAbstrState *state);

RZ_API RZ_OWN RzInterpYieldRBuf *rz_interpreter_yield_rbuf_new(RzInterpYieldKind kind,
	RzInterpYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data);

RZ_API RZ_OWN RzInterpSet *rz_interpreter_set_new(
	RzAnalysis *analysis,
	RZ_NONNULL RZ_OWN RzInterpPlugin *plugin,
	RzInterpAbstraction abstraction,
	RZ_NONNULL RZ_BORROW RzThreadRingBuf *il_request_rbuf,
	RZ_NONNULL RZ_BORROW RzThreadQueue *il_queue,
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);
RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpSet *iset);

/*
 * \brief Register a newly discovered state
 *
 * This will join the state with the already known one at the same pc and add it to the
 * queue for further interpretation if there were changes.
 */
RZ_API void rz_interp_set_push(RZ_BORROW RZ_NONNULL RzInterpSet *iset, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as);

RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpSet *iset);

#endif // RZ_INTERPRETER
