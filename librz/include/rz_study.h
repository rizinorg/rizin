// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STUDY
#define RZ_STUDY

#ifdef __cplusplus
extern "C" {
#endif

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
	RZ_STUDY_ABSTRACTION_CONST = 1 << 0,
} RzStudyAbstraction;

/**
 * \brief An abitrary abstract value.
 */
typedef struct {
	RzStudyAbstraction kind;
	void *abstr_data;
} RzStudyAbstrVal;

typedef enum {
	RZ_STUDY_YIELD_KIND_ABSTR_VAL, ///< Yield object is an abstract value.
	RZ_STUDY_YIELD_KIND_CFG_EDGE, ///< Yield object a discovered CFG edge.
} RzStudyYieldKind;

typedef void *RzStudyYield; ///< A yield of an interpreter. Type is implied by the queue.

// TODO: Could be private
/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield queue or not.
 */
typedef bool (*RzStudyYieldFilter)(RzStudyYieldKind kind, const RzStudyYield *yield);

/**
 * \brief A queue to push interpretation yields into.
 */
typedef struct {
	RzStudyAbstraction kind;
	RzStudyYieldFilter *filter;
	RzThreadQueue /*<RzStudyYield>*/ *yield_queue;
} RzStudyYieldQueue;

/**
 * \brief The IL effect scopes pushed over the IL queue.
 * The elements are always RzILOpEffects, but they can represent
 * more or less instructions.
 */
typedef enum {
	RZ_STUDY_IL_QUEUE_ELEM_SCOPE_IPKT, ///< RzILOpEffect scope is one atomically execute instruction packet.
	RZ_STUDY_IL_QUEUE_ELEM_SCOPE_BB, ///< RzILOpEffect scope is one basic block (n instruction packets with a branch or termination at the end).
} RzStudyILQueueElemScope;

typedef struct {
	RzStudyILQueueElemScope effect_scope;
	RzILOpEffect *il_effect;
} RzStudyILQueueElement;

typedef struct {
	RzThreadQueue /*<RzStudyILQueueElement *>*/ *yield_queue;
} RzStudyILQueue;

typedef struct {
	const char *name;
	const char *author;
	const char *version;
	const char *desc;
	const char *license;
	RzStudyAbstraction supported_abstractions;
	bool (*init)(void **plugin_data);
	bool (*fini)(void *plugin_data);
	// TODO: Configuration or initial setup of interpreter not yet implemented.
	bool (*interpret)(
		// TODO: The entry point could be in the reveive queue already.
		// Saves one more parameter, keeps the IPI on point.
		ut64 entry_point,
		RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
		RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzStudyILQueueElement *>*/ *receive_il,
		RZ_NONNULL RZ_BORROW RzPVector /*<RzStudyYieldQueue*>*/ *yield_queues);
} RzStudyInterpreterPlugin;

/**
 * \brief Performs abstract interpretation.
 */
RZ_API bool rz_study_abstract_interpretation(
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzStudyILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzStudyYieldQueue*>*/ *yield_queues);

#ifdef __cplusplus
}
#endif
#endif // RZ_STUDY
