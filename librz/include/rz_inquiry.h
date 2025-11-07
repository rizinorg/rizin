// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The header file for the RzInquiry module provides the declarations
 * for RzInquiry plugins. As well as access to broader analysis functions.
 */

#ifndef RZ_INQUIRY
#define RZ_INQUIRY

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_inquiry/rz_interpreter.h>

typedef struct {
	const char *name;
	const char *author;
	const char *version;
	const char *desc;
	const char *license;
	RzInterpreterAbstraction supported_abstractions;
	bool (*init)(void **plugin_data);
	bool (*fini)(void *plugin_data);
	bool (*interpret)(
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

#ifdef __cplusplus
}
#endif
#endif // RZ_INQUIRY
