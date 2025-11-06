// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include <rz_inquiry.h>

/**
 * \brief Runs a set of interpreters to inquire the requested yield.
 * What interpreters are spawned depend on the queues in \p yield_queues.
 */
RZ_API bool rz_interpreter_run(
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzInquiryILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzInquiryYieldQueue *>*/ *yield_queues) {
	return true;
}
