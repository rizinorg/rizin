// SPDX-FileCopyrightText: 2026 vk3089790-arch <vk3089790@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_mutual_info.h>
#include "minunit.h"

static bool test_mutual_info_basic(void) {
    RzMutualInfo ctx;
    rz_mutual_info_init(&ctx);

    ut8 data_a[] = { 0, 1, 0, 1, 0, 1, 0, 1 };
    ut8 data_b[] = { 0, 1, 0, 1, 0, 1, 0, 1 };
    rz_mutual_info_update(&ctx, data_a, data_b, sizeof(data_a));

    double result = rz_mutual_info_final(&ctx);

    char val[16] = { 0 };
    rz_strf(val, "%.6f", result);
    mu_assert_streq(val, "1.000000", "identical patterns should have max mutual info");

    mu_end;
}

static bool test_mutual_info_independent(void) {
    RzMutualInfo ctx;
    rz_mutual_info_init(&ctx);

    ut8 data_a[] = { 0, 0, 1, 1, 0, 0, 1, 1 };
    ut8 data_b[] = { 0, 1, 0, 1, 0, 1, 0, 1 };
    rz_mutual_info_update(&ctx, data_a, data_b, sizeof(data_a));

    double result = rz_mutual_info_final(&ctx);

    char val[16] = { 0 };
    rz_strf(val, "%.6f", result);
    mu_assert_streq(val, "0.000000", "independent data should have zero mutual info");

    mu_end;
}

static bool test_mutual_info_zero_length(void) {
    RzMutualInfo ctx;
    rz_mutual_info_init(&ctx);

    double result = rz_mutual_info_final(&ctx);

    char val[16] = { 0 };
    rz_strf(val, "%.6f", result);
    mu_assert_streq(val, "0.000000", "mutual info with no data should be zero, not NaN");

    mu_end;
}

static int all_tests(void) {
    mu_run_test(test_mutual_info_basic);
    mu_run_test(test_mutual_info_independent);
    mu_run_test(test_mutual_info_zero_length);
    return tests_passed != tests_run;
}

mu_main(all_tests)