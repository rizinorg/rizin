// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The header file for the RzInterpreter contains declarations for
 * all RzIL based interpreters.
 */

#ifndef RZ_INTERPRETER
#define RZ_INTERPRETER

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

typedef struct {
	RzInterpreterAbstraction kinds; ///< The abstractions of the state.
	HtUP /*<RzInterpreterAbstrVal *>*/ *globals; ///< Global variables (mostly registers). Indexed by DJB2 hash of global name.
	HtUP /*<RzInterpreterAbstrVal *>*/ *locals; ///< Local variables. Indexed by DJB2 hash of the local name.
	HtUP /*<RzInterpreterAbstrVal *>*/ *lets; ///< Let variables. Indexed by DJB2 hash of the let name.
	RzInterpreterAbstrVal *pc; ///< In our RzIL implementation the PC is not part of the register file.
	/**
	 * \brief The number by which the PC is incremented for a NOP instruction.
	 * Usually this is simply the instruction width. But it can be 0
	 * if the architecture doesn't have a fixed increment (e.g. VLIW processors).
	 * If 0 the RzArch plugin is expected to always return an effect with a
	 * (conditional) JUMP at the end of each effect.
	 */
	ut64 nop_pc_inc;
	size_t addr_bits; ///< Number of bits of a memory address.
	void *ext; ///< Optional state extensions. Managed by individual interpreters.
} RzInterpreterAbstrState;

typedef enum {
	RZ_INTERPRETER_YIELD_KIND_XREF = 1 << 0,
} RzInterpreterYieldKind;

/**
 * \brief A yield of an interpreter. Type is implied by the queue.
 * Object is a union so the elements pushed over the queue are small.
 */
typedef union {
	RzAnalysisXRef *abstr_const;
} RzInterpreterYield;

/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield queue or not.
 */
typedef bool (*RzInterpreterYieldFilter)(const void *element, const void *filter_data);

typedef struct {
	RzList /*<RzIOMap *>*/ *io_boundaries;
} RzInterpreterYieldFilterData;

/**
 * \brief A queue to push interpretation yields into.
 */
typedef struct {
	RzInterpreterYieldKind kind;
	RzInterpreterYieldFilter filter;
	RzInterpreterYieldFilterData *filter_data;
	RzThreadQueue /*<RzInterpreterYield>*/ *yield_queue;
} RzInterpreterYieldQueue;

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
	 * \brief Closes the abstract state and frees all its abstract data.
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
		RZ_NONNULL const RzILOpEffect *effect,
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
} RzInterpreterPlugin;

typedef enum {
	RZ_INTERPRETER_IO_READ,
	RZ_INTERPRETER_IO_WRITE,
} RzInterpreterIOReqType;

typedef struct {
	RzInterpreterIOReqType type;
	ut64 addr; ///< The address to read/write.
	size_t n_bytes; ///< The number of bytes to read/write.
	const ut8 *data; ///< The data to write.
} RzInterpreterIORequest;

typedef struct {
	const ut8 *data; ///< The data read. NULL in case of failed read.
	ut64 n_bytes; ///< The number of bytes to read.
} RzInterpreterIOResR;

typedef struct {
	RzInterpreterIOReqType type;
	bool req_ok; ///< Set to true if IO request succeeded.
	RzInterpreterIOResR read;
} RzInterpreterIOResult;

/**
 * \brief The set of required queues for an interpreter to run.
 */
typedef struct {
	RzInterpreterAbstrState *state; ///< The abstract state of the interpreter.
	RzThreadQueue /*<const ut64 *>*/ *addr_queue; ///< The queue to send requests to the cache what address to get the next IL op from.
	RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue; ///< The queue to receive the IL effects.
	// TODO: We need to decide how to distribute the yield.
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues; ///< The queues to push the yield of interpretation into.
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request; ///< The queue for read/write requests to the IO layer.
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result; ///< The queue for the read/write requests' answers.
	RzAtomicBool *is_running_flag; ///< Flag for the interpreter thread to toggle when done.
	/**
	 * \brief The entry points for the interpreters.
	 * Each address has its lifted IL op in the il_queue at the same index.
	 */
	RzVector /*<ut64>*/ *entry_points;
	RzInterpreterPlugin *plugin;
} RzInterpreterSet;

RZ_API void rz_interpreter_il_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<RzILOpEffect>*/ *q);
RZ_API void rz_interpreter_addr_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<ut64>*/ *q);
RZ_API void rz_interpreter_yield_queue_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldQueue *yield_queue);

RZ_API RZ_OWN RzInterpreterAbstrState *rz_interpreter_abstr_state_new(
	RzInterpreterAbstraction kinds,
	RZ_NULLABLE const RzPVector *reg_names,
	ut64 nop_pc_increment,
	size_t addr_bits);
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
	RZ_NONNULL RZ_OWN RzVector /*<ut64>*/ *entry_points);
RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpreterSet *iset);

RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpreterSet *queue_set);

#endif // RZ_INTERPRETER
