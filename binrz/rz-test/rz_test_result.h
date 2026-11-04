// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TEST_RESULT_H
#define RZ_TEST_RESULT_H

typedef enum rz_test_test_result_t {
	RZ_TEST_RESULT_OK,
	RZ_TEST_RESULT_FAILED,
	RZ_TEST_RESULT_BROKEN,
	RZ_TEST_RESULT_FIXED
} RzTestResult;

#endif
