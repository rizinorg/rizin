// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_INQUIRY
#define RZ_INQUIRY

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
	RZ_INQUIRY_ABSTRACTION_CONST = 1 << 0,
} RzInquiryAbstraction;

/**
 * \brief An abitrary abstract value.
 */
typedef struct {
	RzInquiryAbstraction kind;
	void *abstr_data;
} RzInquiryAbstrVal;

typedef enum {
	RZ_INQUIRY_YIELD_KIND_ABSTR_VAL, ///< Yield object is an abstract value.
	RZ_INQUIRY_YIELD_KIND_CFG_EDGE, ///< Yield object a discovered CFG edge.
} RzInquiryYieldKind;

typedef void *RzInquiryYield; ///< A yield of an interpreter. Type is implied by the queue.

// TODO: Could be private
/**
 * \brief A filter for abstract values to decide if they should be pushed into
 * the yield queue or not.
 */
typedef bool (*RzInquiryYieldFilter)(RzInquiryYieldKind kind, const RzInquiryYield *yield);

/**
 * \brief A queue to push interpretation yields into.
 */
typedef struct {
	RzInquiryAbstraction kind;
	RzInquiryYieldFilter *filter;
	RzThreadQueue /*<RzInquiryYield>*/ *yield_queue;
} RzInquiryYieldQueue;

/**
 * \brief The IL effect scopes pushed over the IL queue.
 * The elements are always RzILOpEffects, but they can represent
 * more or less instructions.
 */
typedef enum {
	RZ_INQUIRY_IL_QUEUE_ELEM_SCOPE_IPKT, ///< RzILOpEffect scope is one atomically execute instruction packet.
	RZ_INQUIRY_IL_QUEUE_ELEM_SCOPE_BB, ///< RzILOpEffect scope is one basic block (n instruction packets with a branch or termination at the end).
} RzInquiryILQueueElemScope;

typedef struct {
	RzInquiryILQueueElemScope effect_scope;
	RzILOpEffect *il_effect;
} RzInquiryILQueueElement;

typedef struct {
	RzThreadQueue /*<RzInquiryILQueueElement *>*/ *yield_queue;
} RzInquiryILQueue;

typedef struct {
	const char *name;
	const char *author;
	const char *version;
	const char *desc;
	const char *license;
	RzInquiryAbstraction supported_abstractions;
	bool (*init)(void **plugin_data);
	bool (*fini)(void *plugin_data);
	// TODO: Configuration or initial setup of interpreter not yet implemented.
	bool (*interpret)(
		// TODO: The entry point could be in the reveive queue already.
		// Saves one more parameter, keeps the IPI on point.
		ut64 entry_point,
		RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
		RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzInquiryILQueueElement *>*/ *receive_il,
		RZ_NONNULL RZ_BORROW RzPVector /*<RzInquiryYieldQueue*>*/ *yield_queues);
} RzInquiryInterpreterPlugin;

typedef struct rz_inquiry_plugin_t {
	RzInquiryInterpreterPlugin *p_interpreter;
	// RzInquiryAlgorithm *p_algorithm;
} RzInquiryPlugin;

typedef struct {
	/**
	 * \brief RzInquiry interpreter plugins. Indexed by name.
	 */
	HtSP /*<RzInquiryPlugin *>*/ *plugins;
} RzInquiry;

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);
RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_NONNULL RzInquiryPlugin *plugin);

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void);
RZ_API void rz_inquiry_free(RZ_OWN RZ_NULLABLE RzInquiry *a);

/**
 * \brief Performs abstract interpretation.
 */
RZ_API bool rz_inquiry_abstract_interpretation(
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzInquiryILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzInquiryYieldQueue*>*/ *yield_queues);

#ifdef __cplusplus
}
#endif
#endif // RZ_INQUIRY
