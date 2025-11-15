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

#define RZ_INTERPRETER_IL_QUEUE_SIZE    128
#define RZ_INTERPRETER_ADDR_QUEUE_SIZE  1024
#define RZ_INTERPRETER_YIELD_QUEUE_SIZE 4096

/**
 * \brief The abstractions this module supports.
 */
typedef enum {
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
 * \brief An abitrary abstract value.
 */
typedef struct {
	RzInterpreterAbstraction kind; ///< The abstraction of the value.
	void *abstr_data;
} RzInterpreterAbstrVal;

typedef struct {
	RzInterpreterAbstraction kinds; ///< The abstractions of the state.
	HtSP *reg_map; ///< The register file. Currently a hashmap.
	void *state;
} RzInterpreterAbstrState;

typedef enum {
	RZ_INTERPRETER_YIELD_KIND_XREF = 1 << 0,
} RzInterpreterYieldKind;

/**
 * \brief A yield of an interpreter. Type is implied by the queue.
 * Object is a union so the elements pushed over the queu are small.
 */
typedef union {
	RzAnalysisXRef *abstr_const;
} RzInterpreterYield;

/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield queue or not.
 */
typedef bool (*RzInterpreterYieldFilter)(const void *element, const void *filter_data);

/**
 * \brief A queue to push interpretation yields into.
 */
typedef struct {
	RzInterpreterYieldKind kind;
	const RzInterpreterYieldFilter *filter;
	union {
		RzList /*<RzIOMap *>*/ *io_boundaries;
	} filter_data;
	RzThreadQueue /*<RzInterpreterYield>*/ *yield_queue;
} RzInterpreterYieldQueue;

/**
 * \brief The set of required queues for an interpreter to run.
 */
typedef struct {
	RzThreadQueue /*<ut64 *>*/ *addr_queue; ///< The queue to send requests to the cache what address to get the next IL op from.
	RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue; ///< The queue to receive the IL effects.
	// TODO: We need to decide how to distribute the yield.
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues; ///< The queues to push the yield of interpretation into.
	RzAtomicBool *is_running_flag; ///< Flag for the interpreter thread to toggle when done.
} RzInterpreterQueueSet;

RZ_API void rz_interpreter_il_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<RzILOpEffect>*/ *q);
RZ_API void rz_interpreter_addr_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<ut64>*/ *q);
RZ_API void rz_interpreter_yield_queue_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldQueue *yield_queue);

RZ_API RZ_OWN RzInterpreterYieldQueue *rz_interpreter_yield_queue_new(RzInterpreterYieldKind kind,
	const RzInterpreterYieldFilter *filter,
	RZ_OWN RZ_NULLABLE void *filter_data);

RZ_API RZ_OWN RzInterpreterQueueSet *rz_interpreter_queue_set_new(
	RZ_NONNULL RZ_OWN RzThreadQueue /*<ut64 *>*/ *addr_queue,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue,
	RZ_NONNULL RZ_OWN HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag);
RZ_API void rz_interpreter_queue_set_free(RZ_NULLABLE RZ_OWN RzInterpreterQueueSet *qset);

RZ_API bool rz_interpreter_run(RZ_OWN RZ_NONNULL RzInterpreterQueueSet *queue_set);

#endif // RZ_INTERPRETER
