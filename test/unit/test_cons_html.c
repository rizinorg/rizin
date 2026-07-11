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

	/* Bright foreground colors (90-97) */

	html = rz_cons_html_filter("\x1b[90mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#777'>Bright&nbsp;foreground</font>", "Bright black");

	html = rz_cons_html_filter("\x1b[91mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#ff5555'>Bright&nbsp;foreground</font>", "Bright red");

	html = rz_cons_html_filter("\x1b[92mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#55ff55'>Bright&nbsp;foreground</font>", "Bright green");

	html = rz_cons_html_filter("\x1b[93mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#ffff55'>Bright&nbsp;foreground</font>", "Bright yellow");

	html = rz_cons_html_filter("\x1b[94mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#5555ff'>Bright&nbsp;foreground</font>", "Bright blue");

	html = rz_cons_html_filter("\x1b[95mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#ff55ff'>Bright&nbsp;foreground</font>", "Bright magenta");

	html = rz_cons_html_filter("\x1b[96mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#55ffff'>Bright&nbsp;foreground</font>", "Bright cyan");

	html = rz_cons_html_filter("\x1b[97mBright foreground\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font color='#ffffff'>Bright&nbsp;foreground</font>", "Bright white");

	/* Bright background colors (100-107) */

	html = rz_cons_html_filter("\x1b[100mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#777'>Bright&nbsp;background</font>", "Bright background black");

	html = rz_cons_html_filter("\x1b[101mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#ff5555'>Bright&nbsp;background</font>", "Bright background red");

	html = rz_cons_html_filter("\x1b[102mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#55ff55'>Bright&nbsp;background</font>", "Bright background green");

	html = rz_cons_html_filter("\x1b[103mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#ffff55'>Bright&nbsp;background</font>", "Bright background yellow");

	html = rz_cons_html_filter("\x1b[104mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#5555ff'>Bright&nbsp;background</font>", "Bright background blue");

	html = rz_cons_html_filter("\x1b[105mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#ff55ff'>Bright&nbsp;background</font>", "Bright background magenta");

	html = rz_cons_html_filter("\x1b[106mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#55ffff'>Bright&nbsp;background</font>", "Bright background cyan");

	html = rz_cons_html_filter("\x1b[107mBright background\x1b[0m", NULL);
	mu_assert_streq_free(html, "<font style='background-color:#ffffff'>Bright&nbsp;background</font>", "Bright background white");

	/* Explicit foreground reset (39m) */

	html = rz_cons_html_filter("\x1b[91mAA\x1b[39mBB", NULL);
	mu_assert_streq_free(html,
		"<font color='#ff5555'>AA</font>BB",
		"Reset bright foreground");

	html = rz_cons_html_filter("\x1b[91m\x1b[42mAA\x1b[39mBB", NULL);
	mu_assert_streq_free(html,
		"<font color='#ff5555' style='background-color:#0f0'>AA</font>"
		"<font style='background-color:#0f0'>BB</font>",
		"Reset foreground preserve background");

	html = rz_cons_html_filter("\x1b[101mAA\x1b[49mBB", NULL);
	mu_assert_streq_free(html,
		"<font style='background-color:#ff5555'>AA</font>BB",
		"Reset bright background");

	html = rz_cons_html_filter("\x1b[91m\x1b[101mAA\x1b[49mBB", NULL);
	mu_assert_streq_free(html,
		"<font color='#ff5555' style='background-color:#ff5555'>AA</font>"
		"<font color='#ff5555'>BB</font>",
		"Reset background preserve foreground");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_cons_to_html);
	return tests_passed != tests_run;
}

mu_main(all_tests)
