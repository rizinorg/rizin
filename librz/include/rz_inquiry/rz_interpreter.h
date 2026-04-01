// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The header file for the RzInterpreter contains declarations for
 * all RzIL based interpreters.
 */

#ifndef RZ_INTERPRETER
#define RZ_INTERPRETER

#include "rz_util/rz_bitvector.h"
#include <rz_arch.h>
#include <rz_io.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief Only one IO request at a time is possible (currently).
 */
#define RZ_INTERPRETER_IO_RBUF_SIZE    128
#define RZ_INTERPRETER_IL_QUEUE_SIZE   128
#define RZ_INTERPRETER_ADDR_RBUF_SIZE  1024
#define RZ_INTERPRETER_YIELD_RBUF_SIZE 128

typedef struct rz_intp_run_state RzIntpRunState;

typedef enum rz_intp_state_flag {
	RZ_INTP_RUN_STATE_INIT, ///< Initialization state.
	RZ_INTP_RUN_STATE_EMU, ///< Emulation state.
	RZ_INTP_RUN_STATE_CLEAN, ///< Cleaning state.
	RZ_INTP_RUN_STATE_TERM, ///< Termination state.
} RzIntpRunStateFlag;

/**
 * \brief The abstractions this module supports.
 */
typedef enum {
	/**
	 * \brief An undefined abstracted value.
	 */
	RZ_INTERPRETER_ABSTRACTION_UNDEF = 0,
	/**
	 * \brief Value abstraction into constant and bottom values.
	 */
	RZ_INTERPRETER_ABSTRACTION_CONST = 1 << 0,
	/**
	 * \brief Value abstraction into Heap[base, offset] and bottom values.
	 */
	RZ_INTERPRETER_ABSTRACTION_HEAP = 1 << 1,
	/**
	 * \brief Value abstraction into Stack[base, offset] and bottom values.
	 */
	RZ_INTERPRETER_ABSTRACTION_STACK = 1 << 2,
} RzInterpreterAbstraction;

/**
 * \brief An arbitrary abstract value.
 */
typedef struct {
	RzInterpreterAbstraction kind; ///< The abstraction of the value.
	void *abstr_data; ///< The abstract data. It is managed by individual interpreter.
} RzInterpreterAbstrVal;

typedef struct {
	ut64 branching_bb_addr; ///< The address of the bb which branches.
	ut64 target_addr; ///< The target address it branches to.
	/**
	 * \brief Set after a attempted jump to an ignored code region.
	 * This is almost always a call to an imported symbol.
	 * Instead of using the target_addr above, the il_cache should serve the alt_target_addr.
	 * target_addr should still be marked as potential cfep.
	 *
	 * 0 is an invalid address here.
	 */
	ut64 alt_target;
} RzInterpreterBranch;

typedef struct {
	RzInterpreterAbstraction kinds; ///< The abstractions of the state.
	HtUP *var_name_hashes; ///< Map of DJB2 hashes to variable names.
	HtUP /*<RzInterpreterAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzInterpreterAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzInterpreterAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
	RzInterpreterAbstrVal *pc; ///< In our RzIL implementation the PC is not part of the register file.
	RzAnalysisILConfig *il_config; ///< The IL configuration of the RzArch plugin.
	const char *arch_name; ///< Name of architecture. Used by work-arounds until we have RzArch.
	ut64 bb_addr;
	ut64 bb_size;
} RzInterpreterAbstrState;

typedef enum {
	/**
	 * \brief The yield is an cross reference.
	 */
	RZ_INTERPRETER_YIELD_KIND_XREF = 1 << 0,

	/**
	 * \brief This yield is a simple flag, signaling if the current basic block
	 * storing the next PC (address _after_ the basic block) to memory or an register.
	 *
	 * If the last branch instruction does not jump to the neighboring basic block
	 * it is a strong indicator that the jump is a call and the next address a return point.
	 */
	RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE = 1 << 1,
} RzInterpreterYieldKind;

/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield ring buffer or not.
 */
typedef bool (*RzInterpreterYieldFilter)(const void *element, const void *filter_data);

typedef struct {
	RzPVector /*<RzBinSection *>*/ *io_boundaries;
} RzInterpreterYieldFilterData;

/**
 * \brief A ring buffer to push interpretation yields into.
 */
typedef struct {
	RzInterpreterYieldKind kind;
	RzInterpreterYieldFilter filter;
	RzInterpreterYieldFilterData *filter_data;
	RzThreadRingBuf *rbuf;
} RzInterpreterYieldRBuf;

typedef struct {
	RzPVector *il_ops; ///< The sequence of IL operations of this basic block.
	size_t size; ///< The number of bytes the basic block has.
	ut64 bb_addr; ///< The address where the basic block starts.
} RzInterpreterILBB;

typedef struct {
	RzILOpEffect *effect; ///< Vector with all instruction packets of a basic block.
	size_t insn_pkt_size; ///< The size of the instruction packet. Used to increment the PC if no JMP occurred.
} RzInterpreterInsnPkt;

typedef struct rz_interpreter_set RzInterpreterSet;

typedef struct {
	const char *name;
	const char *author;
	const char *version;
	const char *desc;
	const char *license;
	/**
	 * \brief Supported abstractions. Multiple flags can be set.
	 */
	RzInterpreterAbstraction supported_abstractions;
	/**
	 * \brief The yield type this interpreter generates.
	 */
	RzInterpreterYieldKind supported_yields;
	bool (*init)(void **plugin_data);
	bool (*fini)(void *plugin_data);
	/**
	 * \brief Initializes the abstract state.
	 */
	bool (*init_state)(RZ_BORROW RzInterpreterAbstrState *state, ut64 entry_point, void *plugin_data);
	/**
	 * \brief Closes the abstract state and frees all its abstract data and sets the pointers to NULL.
	 */
	bool (*fini_state)(RZ_BORROW RzInterpreterAbstrState *state, void *plugin_data);
	/**
	 * \brief Clones the abstract state.
	 */
	RZ_OWN RzInterpreterAbstrState *(*clone_state)(const RzInterpreterAbstrState *state, void *plugin_data);
	/**
	 * \brief Hashes the state.
	 */
	ut64 (*hash_state)(RZ_NONNULL const RzInterpreterAbstrState *state,
		void *plugin_data);
	/**
	 * \brief Evaluates an effect with the mutable state.
	 */
	bool (*eval)(RZ_NONNULL RzInterpreterSet *iset,
		RZ_NONNULL const RzInterpreterILBB *il_bb,
		void *plugin_data);
	/**
	 * \brief Determines the next successor addresses from state.
	 *
	 * \return Returns false in case of error. The interpretation must abort.
	 * True otherwise.
	 */
	bool (*successors)(RZ_NONNULL const RzInterpreterAbstrState *state,
		RZ_NONNULL RZ_OUT RzVector /*<ut64>*/ *successors,
		void *plugin_data);

	/**
	 * \brief Builds a string for printing the current state.
	 *
	 * \return Returns false in case of error. The interpretation must abort.
	 * True otherwise.
	 */
	bool (*state_as_str)(RZ_NONNULL const RzInterpreterAbstrState *state,
		RZ_NONNULL RZ_OUT RzStrBuf *str_buf,
		void *plugin_data);
	/**
	 * \brief Set the abstract PC to the given address.
	 */
	bool (*set_pc)(RZ_NONNULL RzInterpreterAbstrState *state,
		ut64 pc,
		void *plugin_data);
} RzInterpreterPlugin;

typedef enum {
	RZ_INTERPRETER_IO_READ,
	RZ_INTERPRETER_IO_WRITE,
} RzInterpreterIOReqType;

typedef struct {
	RzInterpreterIOReqType type;
	size_t mem_idx; ///< The memory space to read/write.
	bool big_endian; ///< Set if the data is big endian ordered.
	const RzBitVector *addr; ///< The address to read/write.
	const RzBitVector *st_data; ///< The data to store.
	RzBitVector *ld_data; ///< The bit vector to load into. It is BORROWED.
	size_t n_bits; ///< The number of bits to read/write.
} RzInterpreterIORequest;

typedef struct {
	bool req_ok; ///< Set to true if IO request succeeded.
} RzInterpreterIOResult;

/**
 * \brief The set of required objects for an interpreter to run.
 */
RZ_LIFETIME(RzInquiry)
struct rz_interpreter_set {
	// TODO: Move this one into each plugin?
	RzInterpreterAbstrState *astate; ///< The abstract state of the interpreter.

	RzIntpRunState *run_state; ///< The state the interpreter is currently in.
	/**
	 * \brief The semaphore to sync RzInquiry and the interpreter between the Clean and Init run state.
	 */
	RzThreadSemaphore *run_state_sync;

	RzAnalysisILVM *il_vm; ///< The RzAnalysisILVM for memory IO.

	RzThreadQueue /*<const RzInterpreterILOp *>*/ *il_queue; ///< The queue to receive the IL effects.
	RzThreadRingBuf /*<RzInterpreterBranch>*/ *branch_rbuf; ///< The ring buffer to send requests to the cache what address to get the next IL op from.
	RzThreadRingBuf /*<RzInterpreterIORequest>*/ *io_request_rbuf; ///< The ring buffer for read/write requests to the IO layer.
	RzThreadRingBuf /*<const RzInterpreterIOResult *>*/ *io_result_rbuf; ///< The ring buffer for the read/write requests' answers.

	/**
	 * \brief The ring buffers to push the yield of interpretation into.
	 * These ring buffers are shared with other interpreter sets.
	 */
	HtUP /*<RzInterpreterYieldKind, RzInterpreterYieldRBuf *>*/ *yield_rbufs;
	/**
	 * \brief Ignored address ranges.
	 */
	const RzVector /*<RzInterval>*/ *ignored_code;
	/**
	 * \brief The interpreter plugin.
	 */
	RzInterpreterPlugin *plugin;
	/**
	 * \brief The private data of a single interpreter thread.
	 */
	RZ_BORROW void *intrpr_priv;
};

RZ_API RZ_OWN RzIntpRunState *rz_intp_run_state_new();
RZ_API void rz_intp_run_state_free(RZ_OWN RZ_NULLABLE RzIntpRunState *state);
RZ_API RzIntpRunStateFlag rz_intp_run_state_get(RZ_BORROW RZ_NONNULL RzIntpRunState *state);
RZ_API void rz_intp_run_state_set(RZ_BORROW RZ_NONNULL RzIntpRunState *state, RzIntpRunStateFlag flag);
RZ_API const char *rz_intp_run_state_flag_str(RzIntpRunStateFlag flag);

RZ_API void rz_interpreter_il_bb_free(RZ_NULLABLE RZ_OWN RzInterpreterILBB *il_bb);
RZ_API void rz_interpreter_insn_pkt_free(RZ_NULLABLE RZ_OWN RzInterpreterInsnPkt *pkt);

RZ_API void rz_interpreter_yield_rbuf_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldRBuf *yield_rbuf);

RZ_API RZ_OWN RzInterpreterAbstrState *rz_interpreter_abstr_state_new(
	const char *arch_name,
	RzInterpreterAbstraction kinds,
	RZ_OWN RZ_NONNULL RzAnalysisILConfig *il_config,
	RZ_NULLABLE const RzILRegBinding *reg_bindings);
RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpreterAbstrState *state);

RZ_API RZ_OWN RzInterpreterYieldRBuf *rz_interpreter_yield_rbuf_new(RzInterpreterYieldKind kind,
	RzInterpreterYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data);

RZ_API RZ_OWN RzInterpreterSet *rz_interpreter_set_new(
	RzAnalysis *analysis,
	RZ_NONNULL RZ_OWN RzInterpreterPlugin *plugin,
	RzInterpreterAbstraction abstraction,
	RZ_OWN RzPVector /*<RzBinSection *>*/ *sections,
	RzInterpreterYieldFilter yield_filter,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code);
RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpreterSet *iset);

RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpreterSet *iset);

#endif // RZ_INTERPRETER
