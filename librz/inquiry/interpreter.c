// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for analysis interpreters.
 */

#include <rz_inquiry.h>

RZ_API bool rz_inquiry_abstract_interpretation(
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzInquiryILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzInquiryYieldQueue *>*/ *yield_queues) {
	return true;
}
