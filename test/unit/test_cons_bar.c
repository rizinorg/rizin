// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_rz_progressbar(void) {
	RzBarOptions opts = { 0 };
	RzStrBuf *buf;

	opts.unicode = false;
	opts.color = false;
	opts.legend = false;

	buf = rz_progressbar(&opts, 50, 50);
	mu_assert_streq_free(rz_strbuf_drain(buf), "[#################------------------]", "Progressbar no legend");

	opts.legend = true;
	buf = rz_progressbar(&opts, 50, 50);
	mu_assert_streq_free(rz_strbuf_drain(buf), "  50% [#################------------------]", "Progressbar with legend");

	buf = rz_progressbar(&opts, -10, 50);
	mu_assert_streq_free(rz_strbuf_drain(buf), "   0% [-----------------------------------]", "Progressbar pc < 0");

	buf = rz_progressbar(&opts, 110, 50);
	mu_assert_streq_free(rz_strbuf_drain(buf), " 100% [###################################]", "Progressbar pc > 100");

	opts.legend = false;
	buf = rz_progressbar(&opts, 25, -1);
	mu_assert_streq_free(rz_strbuf_drain(buf), "[###############------------------------------------------------]", "Progressbar width=-1");

	opts.unicode = true;
	buf = rz_progressbar(&opts, 75, 50);
	mu_assert_streq_free(rz_strbuf_drain(buf), "[██████████████████████████―――――――――]", "Progressbar unicode");

	mu_end;
}

bool test_rz_rangebar(void) {
	RzBarOptions opts = { 0 };
	RzStrBuf *buf;

	opts.unicode = false;
	opts.color = false;

	buf = rz_rangebar(&opts, 0, 10, 0, 100, 10);
	mu_assert_streq_free(rz_strbuf_drain(buf), "|##--------|", "Simple range");

	buf = rz_rangebar(&opts, 50, 60, 0, 100, 10);
	mu_assert_streq_free(rz_strbuf_drain(buf), "|----###---|", "Simple range 2");

	buf = rz_rangebar(&opts, 90, 100, 0, 100, 10);
	mu_assert_streq_free(rz_strbuf_drain(buf), "|--------##|", "Simple range 3");

	buf = rz_rangebar(&opts, 0, 100, 0, 100, 10);
	mu_assert_streq_free(rz_strbuf_drain(buf), "|##########|", "Full range");

	opts.unicode = true;
	buf = rz_rangebar(&opts, 0, 10, 0, 100, 10);
	mu_assert_streq_free(rz_strbuf_drain(buf), "|██――――――――|", "Unicode range");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_progressbar);
	mu_run_test(test_rz_rangebar);
	return tests_passed != tests_run;
}

mu_main(all_tests)
