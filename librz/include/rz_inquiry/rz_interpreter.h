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
 * \brief The abstractions this module supports.
 */
typedef enum {
	/**
	 * \brief Value abstraction into constant and bottom values.
	 */
	RZ_INTERPRETER_ABSTRACTION_CONST = 1 << 0,
} RzInterpreterAbstraction;

/**
 * \brief An abitrary abstract value.
 */
typedef struct {
	RzInterpreterAbstraction kind;
	void *abstr_data;
} RzInterpreterAbstrVal;

typedef enum {
	RZ_INTERPRETER_YIELD_KIND_ABSTR_VAL, ///< Yield object is an abstract value.
	RZ_INTERPRETER_YIELD_KIND_CFG_EDGE, ///< Yield object a discovered CFG edge.
} RzInterpreterYieldKind;

typedef void *RzInterpreterYield; ///< A yield of an interpreter. Type is implied by the queue.

// TODO: Could be private
/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield queue or not.
 */
typedef bool (*RzInterpreterYieldFilter)(RzInterpreterYieldKind kind, const RzInterpreterYield *yield);

/**
 * \brief A queue to push interpretation yields into.
 */
typedef struct {
	RzInterpreterAbstraction kind;
	RzInterpreterYieldFilter *filter;
	RzThreadQueue /*<RzInquiryYield>*/ *yield_queue;
} RzInterpreterYieldQueue;

/**
 * \brief The IL effect scopes pushed over the IL queue.
 * The elements are always RzILOpEffects, but they can represent
 * more or less instructions.
 */
typedef enum {
	RZ_INTERPRETER_IL_QUEUE_ELEM_SCOPE_IPKT, ///< RzILOpEffect scope is one atomically execute instruction packet.
	RZ_INTERPRETER_IL_QUEUE_ELEM_SCOPE_BB, ///< RzILOpEffect scope is one basic block (n instruction packets with a branch or termination at the end).
} RzInterpreterILQueueElemScope;

typedef struct {
	RzInterpreterILQueueElemScope effect_scope;
	RzILOpEffect *il_effect;
} RzInterpreterILQueueElement;

typedef struct {
	RzThreadQueue /*<RzInquiryILQueueElement *>*/ *yield_queue;
} RzInterpreterILQueue;

/**
 * \brief Performs abstract interpretation.
 */
RZ_API bool rz_interpreter_run(
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzInquiryILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzInquiryYieldQueue*>*/ *yield_queues);

#endif // RZ_INTERPRETER
