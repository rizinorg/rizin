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
#define RZ_INTERPRETER_IO_QUEUE_SIZE    1
#define RZ_INTERPRETER_IL_QUEUE_SIZE    128
#define RZ_INTERPRETER_ADDR_QUEUE_SIZE  1024
#define RZ_INTERPRETER_YIELD_QUEUE_SIZE 4096

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

/**
 * objects the interpreter should use to send over the queues.
 *
 * TODO: Race conditions ahead, if one party is faster in overwriting one value
 * than the other using it.
 * Shouldn't happen though as long as there is only one interpreter
 * and one RzInquiry managing everything.
 */
typedef struct {
	RZ_LIFETIME(RzInquiry)
	ut64 shared_addr; ///< The address object passed to an IL cache for BB requests.
	RZ_LIFETIME(RzInquiry)
	RzAnalysisXRef xref; ///< The xref object passed over the queue.
	RZ_LIFETIME(RzInquiry)
	ut64 return_loc; ///< The return location passed over the queue.
	RZ_LIFETIME(RzInquiry)
	bool stores_npc; ///< The stores next pc flag passed over the queue.
} RzInterpreterSharedObjects;

typedef struct {
	RzInterpreterAbstraction kinds; ///< The abstractions of the state.
	HtUP *var_name_hashes; ///< Map of DJB2 hashes to variable names.
	HtUP /*<RzInterpreterAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzInterpreterAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzInterpreterAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
	RzInterpreterAbstrVal *pc; ///< In our RzIL implementation the PC is not part of the register file.
	RzAnalysisILConfig *il_config; ///< The IL configuration of the RzArch plugin.
	const char *arch_name; ///< Name of architecture. Used by work-arounds until we have RzArch.
	/**
	 * \brief Shared objects. Pointers to the members are passed over the queue.
	 * TODO: This is obviously not the final solution. Just some poor man's shared memory.
	 */
	RzInterpreterSharedObjects *shared_obj;
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
	RZ_INTERPRETER_YIELD_KIND_ST_NPC = 1 << 1,

	/**
	 * \brief This yield is a simple flag, signaling for a given address that it
	 * a location where a functions' return instruction jumps to.
	 *
	 * TODO: This is one of the yields which has uncertainty attached to it.
	 * Currently a return point is defined as instruction after a call.
	 * But this is no given! If for example the call never returns (e.g. `call about()`).
	 * Of course we could change the definition. But for the prototype this is good enough.
	 */
	RZ_INTERPRETER_YIELD_KIND_RET_LOC = 1 << 2,
} RzInterpreterYieldKind;

/**
 * \brief A yield of an interpreter. Type is implied by the queue.
 * Object is a union so the elements pushed over the queue are small.
 */
typedef union {
	RzAnalysisXRef *abstr_const;
	bool backs_up_npc;
	ut64 return_point;
} RzInterpreterYield;

/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield queue or not.
 */
typedef bool (*RzInterpreterYieldFilter)(const void *element, const void *filter_data);

typedef struct {
	RzPVector /*<RzBinSection *>*/ *io_boundaries;
} RzInterpreterYieldFilterData;

/**
 * \brief A queue to push interpretation yields into.
 */
typedef struct {
	RzInterpreterYieldKind kind;
	RzInterpreterYieldFilter filter;
	RzInterpreterYieldFilterData *filter_data;
	RzThreadQueue /*<const RzInterpreterYield>*/ *yield_queue;
} RzInterpreterYieldQueue;

typedef struct {
	RzPVector *il_ops; ///< The sequence of IL operations of this basic block.
	size_t size; ///< The number of bytes the basic block has.
	ut64 bb_addr; ///< The address where the basic block starts.
} RzInterpreterILBB;

typedef struct {
	RzILOpEffect *effect; ///< Vector with all instruction packets of a basic block.
	size_t insn_pkt_size; ///< The size of the instruction packet. Used to increment the PC if no JMP occurred.
} RzInterpreterInsnPkt;

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
	bool (*eval)(RZ_NONNULL RzInterpreterAbstrState *state,
		RZ_NONNULL const RzInterpreterILBB *il_bb,
		RZ_NONNULL RZ_BORROW HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
		RZ_NONNULL RZ_BORROW RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
		RZ_NONNULL RZ_BORROW RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
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
 * \brief The set of required queues for an interpreter to run.
 */
typedef struct {
	RzInterpreterAbstrState *state; ///< The abstract state of the interpreter.
	RzThreadQueue /*<const ut64 *>*/ *addr_queue; ///< The queue to send requests to the cache what address to get the next IL op from.
	RzThreadQueue /*<const RzInterpreterILOp *>*/ *il_queue; ///< The queue to receive the IL effects.
	// TODO: We need to decide how to distribute the yield.
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues; ///< The queues to push the yield of interpretation into.
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request; ///< The queue for read/write requests to the IO layer.
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result; ///< The queue for the read/write requests' answers.
	RzAtomicBool *is_running_flag; ///< Flag for the interpreter thread to toggle when done.
	RzVector /*<RzInterval>*/ *ignored_code;
	/**
	 * \brief The entry points for the interpreters.
	 * Each address has its lifted IL op in the il_queue at the same index.
	 */
	RzVector /*<ut64>*/ *entry_points;
	RzInterpreterPlugin *plugin;
} RzInterpreterSet;

RZ_API void rz_interpreter_il_bb_free(RZ_NULLABLE RZ_OWN RzInterpreterILBB *il_bb);
RZ_API void rz_interpreter_insn_pkt_free(RZ_NULLABLE RZ_OWN RzInterpreterInsnPkt *pkt);

RZ_API void rz_interpreter_yield_queue_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldQueue *yield_queue);

RZ_API RZ_OWN RzInterpreterAbstrState *rz_interpreter_abstr_state_new(
	const char *arch_name,
	RzInterpreterAbstraction kinds,
	RZ_OWN RZ_NONNULL RzAnalysisILConfig *il_config,
	RZ_NULLABLE const RzILRegBinding *reg_bindings);
RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpreterAbstrState *state);

RZ_API RZ_OWN RzInterpreterYieldQueue *rz_interpreter_yield_queue_new(RzInterpreterYieldKind kind,
	RzInterpreterYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data);

RZ_API RZ_OWN RzInterpreterSet *rz_interpreter_set_new(
	RZ_NONNULL RZ_OWN RzInterpreterPlugin *plugin,
	RZ_NONNULL RZ_OWN RzInterpreterAbstrState *state,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const ut64 *>*/ *addr_queue,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue,
	RZ_NONNULL RZ_OWN HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<RzInterpreterIORequest *>*/ *io_request,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<RzInterpreterIOResult *>*/ *io_result,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag,
	RZ_NONNULL RZ_OWN RzVector /*<ut64>*/ *entry_points,
	RZ_NONNULL RZ_OWN RzVector /*<RzInterval>*/ *ignored_code);
RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpreterSet *iset);
RZ_API void rz_interpreter_set_add_entry_points(RZ_NONNULL RzInterpreterSet *iset, const RzVector /*<ut64>*/ *entry_points);

RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpreterSet *queue_set);

#endif // RZ_INTERPRETER
