// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_cons_to_html() {
	char *html;

	html = rz_cons_html_filter("\x1b[32mhello\x1b[0m", NULL);
	mu_assert_notnull(html, "HTML output should not be null");
	mu_assert_streq_free(html, "<font color='#0f0'>hello</font>", "Simple font color");

	html = rz_cons_html_filter("\x1b[31mhello\x1b[0mabc", NULL);
	mu_assert_streq_free(html, "<font color='#f00'>hello</font>abc", "Simple font color2");

	html = rz_cons_html_filter("\x1b[31mhe\x1b[44mllo\x1b[0mabc", NULL);
	mu_assert_streq_free(html, "<font color='#f00'>he</font><font color='#f00' style='background-color:#00f'>llo</font>abc", "Color and background");

	html = rz_cons_html_filter("\x1b[44mhe\x1b[31mllo\x1b[0mabc", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#00f'>he</font><font color='#f00' style='background-color:#00f'>llo</font>abc", "Background and color");

	html = rz_cons_html_filter("AA\x1b[31mBB\x1b[32mCC\x1b[0mDD", NULL);
	mu_assert_streq_free(html, "AA<font color='#f00'>BB</font><font color='#0f0'>CC</font>DD", "Switch color");

	html = rz_cons_html_filter("<p>hello</p>", NULL);
	mu_assert_streq_free(html, "&lt;p&gt;hello&lt;/p&gt;", "Escape brackets");

	html = rz_cons_html_filter("hello\nworld", NULL);
	mu_assert_streq_free(html, "hello<br />world", "Newline to br");

	html = rz_cons_html_filter("\x1b[7mInverted\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='text-decoration:underline overline'>Inverted</font>", "Invert filter");

	html = rz_cons_html_filter("AA\x1b[31mBB\x1b[32m\x1b[41mCC\x1b[0mDD", NULL);
	mu_assert_streq_free(html, "AA<font color='#f00'>BB</font><font color='#0f0' style='background-color:#f00'>CC</font>DD", "Multiple changes");

	html = rz_cons_html_filter("\x1b[33m0x0005d01\x1b[0m \x1b[36mand\x1b[36m foo", NULL);
	mu_assert_streq_free(html, "<font color='#ff0'>0x0005d01</font>&nbsp;<font color='#aaf'>and</font><font color='#aaf'>&nbsp;foo</font>", "Space and reset");

	html = rz_cons_html_filter("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[0mCCC", NULL);
	mu_assert_streq_free(html, "<font color='#ff0'>AAAA</font>"
				   "<font color='#ff0' style='text-decoration:underline overline'>BBBB</font>"
				   "<font color='#ff0' style='text-decoration:underline overline'>BBB</font>CCC",
		"Invert");

	html = rz_cons_html_filter("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[27mCCC", NULL);
	mu_assert_streq_free(html, "<font color='#ff0'>AAAA</font>"
				   "<font color='#ff0' style='text-decoration:underline overline'>BBBB</font>"
				   "<font color='#ff0' style='text-decoration:underline overline'>BBB</font><font color='#ff0'>CCC</font>",
		"Invert rest");

	html = rz_cons_html_filter("\x1b[41m\x1b[31mBB\x1b[39mCC", NULL);
	mu_assert_streq_free(html, "<font color='#f00' style='background-color:#f00'>BB</font>"
				   "<font style='background-color:#f00'>CC</font>",
		"Default font color color");

	html = rz_cons_html_filter("\x1b[41m\x1b[31mBB\x1b[49mCC", NULL);
	mu_assert_streq_free(html, "<font color='#f00' style='background-color:#f00'>BB</font><font color='#f00'>CC</font>", "Default background color");

	html = rz_cons_html_filter("aaa" Color_RESET "bbb", NULL);
	mu_assert_streq_free(html, "aaabbb", "Only reset");

	html = rz_cons_html_filter("aaa" Color_RESET Color_RED "bbb", NULL);
	mu_assert_streq_free(html, "aaa<font color='#f00'>bbb</font>", "Color after reset");

	html = rz_cons_html_filter("aaa" Color_RESET Color_RED Color_RESET "bbb", NULL);
	mu_assert_streq_free(html, "aaabbb", "Color after reset");

	html = rz_cons_html_filter("aaa" Color_RESET Color_RED Color_RESET Color_BGGREEN "bbb", NULL);
	mu_assert_streq_free(html, "aaa<font style='background-color:#0f0'>bbb</font>", "Reset color reset color");

	html = rz_cons_html_filter(Color_RED Color_BGGREEN "aaa" Color_RESET Color_RESET_BG "bbb", NULL);
	mu_assert_streq_free(html, "<font color='#f00' style='background-color:#0f0'>aaa</font>bbb", "Two different resets");

	html = rz_cons_html_filter(Color_RED Color_BGGREEN "aaa" Color_RESET_BG Color_RESET "bbb", NULL);
	mu_assert_streq_free(html, "<font color='#f00' style='background-color:#0f0'>aaa</font>bbb", "Two different resets opposite order");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_cons_to_html);
	return tests_passed != tests_run;
}

mu_main(all_tests)
