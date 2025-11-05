// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for analysis interpreters.
 */

#include <rz_study.h>

RZ_API bool rz_study_abstract_interpretation(
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzStudyILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzStudyYieldQueue *>*/ *yield_queues) {
	return true;
}
