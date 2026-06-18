// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_parse.h>
#include <rz_util.h>
#include <limits.h>
#include "minunit.h"

// Mimic rz_print_colorize_asm_str(): wrap a single token in its own truecolor
// SGR escape, exactly as the disassembler does before the operand is handed to
// rz_parse_filter(). A demangled C++ symbol tokenizes into dozens of such
// tokens, so the colorized operand balloons well past the fixed operand buffer.
static void append_colored_token(RzStrBuf *sb, const char *tok) {
	rz_strbuf_appendf(sb, "\x1b[38;2;204;204;204m%s\x1b[0m", tok);
}

// Return true if `s` (scanned up to `max` bytes, stopping at NUL) contains a CSI
// escape "\x1b[" whose parameter/intermediate bytes are not followed by a final
// byte (0x40-0x7e), i.e. a truncated/garbled escape. Emitting such a fragment is
// what made the terminal answer with a Device-Attributes reply in issue #3831.
static bool has_unterminated_csi(const char *s, size_t max) {
	for (size_t i = 0; i < max && s[i]; i++) {
		if ((unsigned char)s[i] != 0x1b) {
			continue;
		}
		if (i + 1 >= max || s[i + 1] != '[') {
			return true; // lone/unknown ESC
		}
		size_t j = i + 2;
		// CSI parameter (0x30-0x3f) and intermediate (0x20-0x2f) bytes
		while (j < max && s[j] && (unsigned char)s[j] >= 0x20 && (unsigned char)s[j] <= 0x3f) {
			j++;
		}
		if (j >= max || !s[j] || !((unsigned char)s[j] >= 0x40 && (unsigned char)s[j] <= 0x7e)) {
			return true; // no final byte before end -> truncated escape
		}
		i = j;
	}
	return false;
}

// Regression for https://github.com/rizinorg/rizin/issues/3831
// A colored operand longer than the destination buffer must be truncated
// without splitting an ANSI escape and must stay NUL-terminated inside the
// buffer. The plain strncpy() used before neither terminated the buffer (so the
// operand bled into the adjacent strsub[] buffer) nor respected escape
// boundaries (so the cut could land inside "\x1b[38;2;.." and, followed by the
// bled bytes, form a stray "\x1b[..c" Device-Attributes query).
bool test_rz_parse_filter_ansi_truncation_no_partial_escape(void) {
	RzParse *p = rz_parse_new();
	mu_assert_notnull(p, "rz_parse_new");
	// No analysis/flags are bound in this isolated test; keep the substitution
	// branches from consulting them so only the final copy path is exercised.
	p->minval = INT_MAX;

	const int len = 1024; // == sizeof(ds->str) in librz/core/disasm.c
	// 1020 filler bytes followed by a fresh color escape, so that the cut at
	// len-1 deterministically lands inside the "\x1b[38;2;.." parameters.
	RzStrBuf *sb = rz_strbuf_new("");
	for (int i = 0; i < 1020; i++) {
		rz_strbuf_append(sb, "A");
	}
	rz_strbuf_append(sb, "\x1b[38;2;204;204;204mTAIL\x1b[0m");
	char *data = rz_strbuf_drain(sb);
	mu_assert_true(strlen(data) > (size_t)len, "precondition: colored operand overflows the buffer");

	char *str = malloc(len);
	mu_assert_notnull(str, "malloc");
	memset(str, 0xff, len); // no stale NUL, so a missing terminator is detectable

	rz_parse_filter(p, 0x1000, NULL, NULL, data, str, len, false);

	mu_assert_notnull(memchr(str, 0, len), "filtered string must be NUL-terminated within the buffer");
	mu_assert_false(has_unterminated_csi(str, len), "filtered string must not contain a partial ANSI escape");
	mu_assert_true(strlen(str) <= (size_t)(len - 1), "length stays within the buffer");
	mu_assert_memeq((const ut8 *)str, (const ut8 *)data, strlen(str), "result is a verbatim prefix of the input (no bleed)");

	free(str);
	free(data);
	rz_parse_free(p);
	mu_end;
}

// Same regression, driven by a realistic colorized libc++ demangled operand
// (the kind `pdf` produces with bin.demangle=true and truecolor).
bool test_rz_parse_filter_ansi_truncation_realistic_symbol(void) {
	RzParse *p = rz_parse_new();
	mu_assert_notnull(p, "rz_parse_new");
	p->minval = INT_MAX;

	const int len = 1024;
	static const char *toks[] = {
		"call", "  ", "std", "::", "__1", "::", "vector", "<", "std", "::",
		"__1", "::", "basic_string", "<", "char", ",", " ", "std", "::", "__1",
		"::", "char_traits", "<", "char", ">", ">", ">", "::", "method", "(",
		"std", "::", "__1", "::", "allocator", "<", "char", ">", ")"
	};
	RzStrBuf *sb = rz_strbuf_new("");
	while (rz_strbuf_length(sb) <= (size_t)(len + 64)) {
		for (size_t i = 0; i < RZ_ARRAY_SIZE(toks); i++) {
			append_colored_token(sb, toks[i]);
		}
	}
	char *data = rz_strbuf_drain(sb);
	mu_assert_true(strlen(data) > (size_t)len, "precondition: colored operand overflows the buffer");

	char *str = malloc(len);
	mu_assert_notnull(str, "malloc");
	memset(str, 0xff, len);

	rz_parse_filter(p, 0x1000, NULL, NULL, data, str, len, false);

	mu_assert_notnull(memchr(str, 0, len), "filtered string must be NUL-terminated within the buffer");
	mu_assert_false(has_unterminated_csi(str, len), "filtered string must not contain a partial ANSI escape");
	mu_assert_memeq((const ut8 *)str, (const ut8 *)data, strlen(str), "result is a verbatim prefix of the input (no bleed)");

	free(str);
	free(data);
	rz_parse_free(p);
	mu_end;
}

// A colored operand that fits within the buffer must be copied through
// unchanged (and NUL-terminated): the fix must not alter the common case.
bool test_rz_parse_filter_ansi_short_passthrough(void) {
	RzParse *p = rz_parse_new();
	mu_assert_notnull(p, "rz_parse_new");
	p->minval = INT_MAX;

	const int len = 1024;
	RzStrBuf *sb = rz_strbuf_new("");
	append_colored_token(sb, "call");
	append_colored_token(sb, "  ");
	append_colored_token(sb, "sym.imp.puts");
	char *data = rz_strbuf_drain(sb);
	mu_assert_true(strlen(data) < (size_t)len, "precondition: colored operand fits in the buffer");

	char *str = malloc(len);
	mu_assert_notnull(str, "malloc");
	memset(str, 0xff, len);

	rz_parse_filter(p, 0x1000, NULL, NULL, data, str, len, false);

	mu_assert_streq(str, data, "short colored operand must be copied unchanged");

	free(str);
	free(data);
	rz_parse_free(p);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_parse_filter_ansi_truncation_no_partial_escape);
	mu_run_test(test_rz_parse_filter_ansi_truncation_realistic_symbol);
	mu_run_test(test_rz_parse_filter_ansi_short_passthrough);
	return tests_passed != tests_run;
}

mu_main(all_tests)
