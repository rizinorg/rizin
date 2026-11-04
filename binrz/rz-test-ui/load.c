// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test_ui.h"
#include <errno.h>

static const struct {
	const char *name;
	const char *seq;
} NAMED_KEYS[] = {
	{ "<UP>", "\x1b[A" },
	{ "<DOWN>", "\x1b[B" },
	{ "<RIGHT>", "\x1b[C" },
	{ "<LEFT>", "\x1b[D" },
	{ "<ENTER>", "\r" },
	{ "<RET>", "\r" },
	{ "<ESC>", "\x1b" },
	{ "<TAB>", "\t" },
	{ "<BS>", "\x7f" },
	{ "<DEL>", "\x1b[3~" },
	{ "<PGUP>", "\x1b[5~" },
	{ "<PGDN>", "\x1b[6~" },
	{ "<HOME>", "\x1b[H" },
	{ "<END>", "\x1b[F" },
	{ "<SPACE>", " " },
	{ "<F1>", "\x1bOP" },
	{ "<F2>", "\x1bOQ" },
	{ "<F3>", "\x1bOR" },
	{ "<F4>", "\x1bOS" },
	{ "<F5>", "\x1b[15~" },
	{ "<F6>", "\x1b[17~" },
	{ "<F7>", "\x1b[18~" },
	{ "<F8>", "\x1b[19~" },
	{ "<F9>", "\x1b[20~" },
	{ "<F10>", "\x1b[21~" },
	{ "<F11>", "\x1b[23~" },
	{ "<F12>", "\x1b[24~" },
	{ NULL, NULL }
};

/** \brief Reject overflow and partial numbers instead of silently weakening tests. */
static bool parse_number(const char **text, ut64 limit, ut64 *out) {
	const char *p = *text;
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	if (*p < '0' || *p > '9') {
		return false;
	}
	errno = 0;
	char *end;
	ut64 value = strtoull(p, &end, 0);
	if (errno == ERANGE || end == p || value > limit || (*end && *end != ' ' && *end != '\t')) {
		return false;
	}
	while (*end == ' ' || *end == '\t') {
		end++;
	}
	*text = end;
	*out = value;
	return true;
}

static bool parse_column(const char **text, st64 *out) {
	bool negative = **text == '-';
	if (negative) {
		(*text)++;
	}
	ut64 value;
	if (!parse_number(text, RZ_TEST_UI_MAX_COLS, &value)) {
		return false;
	}
	*out = negative ? -(st64)value : (st64)value;
	return true;
}

static bool args_valid(const char *args) {
	char quote = 0;
	for (const char *p = args; *p; p++) {
		if (*p == '\\') {
			if (!*++p) {
				return false;
			}
		} else if (*p == quote) {
			quote = 0;
		} else if (!quote && (*p == '\'' || *p == '"')) {
			quote = *p;
		}
	}
	return !quote;
}

static bool single_character(const char *text) {
	RzCodePoint cp;
	size_t len = strlen(text);
	return len && rz_utf8_decode((const ut8 *)text, len, &cp, false) == len && cp >= 32;
}

static bool parse_step(char *line, RzTestUiStep *step) {
	char *space = strchr(line, ' ');
	const char *arg = space ? space + 1 : "";
	if (space) {
		*space = 0;
	}
	while (*arg == ' ' || *arg == '\t') {
		arg++;
	}
	if (RZ_STR_EQ(line, "QUIT") || RZ_STR_EQ(line, "CAPTURE")) {
		step->kind = RZ_STR_EQ(line, "QUIT") ? RZ_UI_STEP_QUIT : RZ_UI_STEP_CAPTURE;
		return !*arg;
	}
	if (RZ_STR_EQ(line, "WAIT")) {
		step->kind = RZ_UI_STEP_WAIT;
		return parse_number(&arg, 3600000, &step->arg_n) && !*arg;
	}
	if (RZ_STR_EQ(line, "RESIZE")) {
		step->kind = RZ_UI_STEP_RESIZE;
		char *dims = rz_str_dup(arg);
		if (!dims) {
			return false;
		}
		char *x = strchr(dims, 'x');
		if (x) {
			*x = ' ';
		}
		const char *p = dims;
		ut64 width, height;
		bool ok = parse_number(&p, RZ_TEST_UI_MAX_COLS, &width) && width &&
			parse_number(&p, RZ_TEST_UI_MAX_ROWS, &height) && height && !*p;
		if (ok) {
			step->arg_w = width;
			step->arg_h = height;
		}
		free(dims);
		return ok;
	}
	static const struct {
		const char *name;
		RzTestUiStepKind kind;
		int numbers;
		bool regex;
		bool cell;
	} directives[] = {
		{ "EXPECT_LINE", RZ_UI_STEP_EXPECT_LINE, 1, false, false },
		{ "EXPECT_NOLINE", RZ_UI_STEP_EXPECT_NOLINE, 1, false, false },
		{ "EXPECT_REGEX", RZ_UI_STEP_EXPECT_REGEX, 0, true, false },
		{ "EXPECT_NOREGEX", RZ_UI_STEP_EXPECT_NOREGEX, 0, true, false },
		{ "EXPECT_REGEX_AT", RZ_UI_STEP_EXPECT_REGEX_AT, 1, true, false },
		{ "EXPECT_AT", RZ_UI_STEP_EXPECT_AT, 2, false, false },
		{ "EXPECT_CELL", RZ_UI_STEP_EXPECT_CELL, 2, false, true },
		{ "EXPECT_VLINE", RZ_UI_STEP_EXPECT_VLINE, 3, false, true },
		{ "EXPECT_HLINE", RZ_UI_STEP_EXPECT_HLINE, 3, false, true },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(directives); i++) {
		if (!RZ_STR_EQ(line, directives[i].name)) {
			continue;
		}
		step->kind = directives[i].kind;
		if (directives[i].numbers && !parse_number(&arg, RZ_TEST_UI_MAX_COLS, &step->arg_n)) {
			return false;
		}
		if (directives[i].numbers == 2 && !parse_column(&arg, &step->arg_col)) {
			return false;
		}
		if (directives[i].numbers == 3 &&
			(!parse_number(&arg, RZ_TEST_UI_MAX_COLS, &step->arg_b) ||
				!parse_number(&arg, RZ_TEST_UI_MAX_COLS, &step->arg_e) || step->arg_b > step->arg_e)) {
			return false;
		}
		step->arg_s = rz_str_dup(arg);
		if (!step->arg_s || !*step->arg_s) {
			return false;
		}
		if (directives[i].regex) {
			RzRegex *re = rz_regex_new(arg, RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT, NULL);
			if (!re) {
				return false;
			}
			rz_regex_free(re);
		} else {
			size_t len = strlen(step->arg_s);
			if (len >= 2 && step->arg_s[0] == '"' && step->arg_s[len - 1] == '"') {
				memmove(step->arg_s, step->arg_s + 1, len - 2);
				step->arg_s[len - 2] = 0;
			}
			// Keep escapes literal: screen text is not a C string or a shell command.
			if (directives[i].cell && !single_character(step->arg_s)) {
				return false;
			}
		}
		return true;
	}
	return false;
}

static void step_free(void *ptr) {
	RzTestUiStep *step = ptr;
	if (step) {
		free(step->arg_s);
		free(step);
	}
}

void rz_test_ui_free(RZ_NULLABLE RzTestUi *test) {
	if (!test) {
		return;
	}
	free(test->name);
	free(test->file);
	free(test->args);
	free((char *)test->path);
	rz_pvector_fini(&test->steps);
	free(test);
}

static RzTestUi *test_new(const char *path) {
	RzTestUi *test = RZ_NEW0(RzTestUi);
	if (test) {
		test->cols = RZ_TEST_UI_DEFAULT_COLS;
		test->rows = RZ_TEST_UI_DEFAULT_ROWS;
		test->path = rz_str_dup(path);
		rz_pvector_init(&test->steps, step_free);
		if (!test->path) {
			rz_test_ui_free(test);
			return NULL;
		}
	}
	return test;
}

static char *next_line(char **cursor) {
	char *line = *cursor;
	if (!line) {
		return NULL;
	}
	char *end = strchr(line, '\n');
	*cursor = end ? end + 1 : NULL;
	if (end) {
		*end = 0;
	}
	size_t len = strlen(line);
	if (len && line[len - 1] == '\r') {
		line[len - 1] = 0;
	}
	return line;
}

/** \brief Preserve logical key boundaries, especially a lone Escape key. */
static bool load_keys(RzTestUi *test, const char *keys, ut64 line, bool single) {
	size_t count = 0;
	while (*keys) {
		const char *bytes = keys;
		size_t input_length = 0, output_length = 0;
		for (size_t i = 0; NAMED_KEYS[i].name; i++) {
			size_t len = strlen(NAMED_KEYS[i].name);
			if (!rz_str_ncasecmp(keys, NAMED_KEYS[i].name, len)) {
				input_length = len;
				bytes = NAMED_KEYS[i].seq;
				output_length = strlen(bytes);
				break;
			}
		}
		if (!input_length) {
			RzCodePoint cp;
			input_length = rz_utf8_decode((const ut8 *)keys, strlen(keys), &cp, false);
			if (!input_length || cp < 32 || cp == 127) {
				return false;
			}
			output_length = input_length;
		}
		RzTestUiStep *step = RZ_NEW0(RzTestUiStep);
		if (!step) {
			return false;
		}
		step->kind = RZ_UI_STEP_KEY;
		step->line_begin = step->line_end = line;
		step->arg_s = rz_str_ndup(bytes, output_length);
		if (!step->arg_s || rz_pvector_len(&test->steps) >= RZ_TEST_UI_MAX_STEPS || !rz_pvector_push(&test->steps, step)) {
			step_free(step);
			return false;
		}
		keys += input_length;
		count++;
	}
	return count && (!single || count == 1);
}

static bool load_steps(RzTestUi *test, char **cursor, const char *term, ut64 *line) {
	char *raw;
	bool quit = false;
	if (!*term) {
		return false;
	}
	while ((raw = next_line(cursor))) {
		(*line)++;
		rz_str_trim(raw);
		if (RZ_STR_EQ(raw, term)) {
			return !rz_pvector_empty(&test->steps);
		}
		if (!*raw || *raw == '#') {
			continue;
		}
		if (quit) {
			return false;
		}
		if (rz_str_startswith(raw, "KEY ") || rz_str_startswith(raw, "KEYS ")) {
			bool single = raw[3] == ' ';
			if (!load_keys(test, raw + (single ? 4 : 5), *line, single)) {
				return false;
			}
			continue;
		}
		RzTestUiStep *step = RZ_NEW0(RzTestUiStep);
		if (!step) {
			return false;
		}
		step->line_begin = step->line_end = *line;
		bool ok = false;
		if (rz_str_startswith(raw, "EXPECT_SCREEN <<")) {
			const char *end = raw + strlen("EXPECT_SCREEN <<");
			if (!*end || RZ_STR_EQ(end, term)) {
				step_free(step);
				return false;
			}
			step->kind = RZ_UI_STEP_EXPECT_SCR;
			step->line_begin = *line + 1;
			RzStrBuf screen;
			rz_strbuf_init(&screen);
			while ((raw = next_line(cursor))) {
				(*line)++;
				if (RZ_STR_EQ(raw, end)) {
					ok = true;
					break;
				}
				if (!rz_strbuf_append(&screen, raw) || !rz_strbuf_append(&screen, "\n")) {
					break;
				}
			}
			step->line_end = *line - 1;
			step->arg_s = rz_strbuf_drain_nofree(&screen);
			ok = ok && step->arg_s;
		} else {
			ok = parse_step(raw, step);
		}
		if (!ok || rz_pvector_len(&test->steps) >= RZ_TEST_UI_MAX_STEPS || !rz_pvector_push(&test->steps, step)) {
			step_free(step);
			return false;
		}
		quit = step->kind == RZ_UI_STEP_QUIT;
	}
	return false;
}

/**
 * \brief Parse atomically: a malformed record invalidates the entire file.
 * \return A vector of owned tests, or NULL on error. Each test owns its path.
 */
RZ_OWN RzPVector /*<RzTestUi *>*/ *rz_test_ui_load(RZ_NONNULL const char *path, RZ_NONNULL const char *text) {
	if (strlen(text) > RZ_TEST_UI_MAX_FILE_SIZE) {
		return NULL;
	}
	char *content = rz_str_dup(text);
	RzPVector *tests = rz_pvector_new((RzPVectorFree)rz_test_ui_free);
	RzTestUi *cur = test_new(path);
	ut64 line = 0;
	bool fields[10] = { false };
	if (!content || !tests || !cur) {
		goto invalid;
	}
	char *cursor = content, *raw;
	while ((raw = next_line(&cursor))) {
		line++;
		rz_str_trim(raw);
		if (!*raw || *raw == '#') {
			continue;
		}
		if (RZ_STR_EQ(raw, "RUN")) {
			if (!cur->name || !*cur->name || !fields[9]) {
				goto invalid;
			}
			cur->run_line = line;
			cur->index = rz_pvector_len(tests);
			if (!rz_pvector_push(tests, cur)) {
				goto invalid;
			}
			cur = test_new(path);
			memset(fields, 0, sizeof(fields));
			if (!cur) {
				goto invalid;
			}
			continue;
		}
		char *equal = strchr(raw, '=');
		if (!equal) {
			goto invalid;
		}
		*equal++ = 0;
		static const char *names[] = { "NAME", "FILE", "ARGS", "COLS", "ROWS", "TIMEOUT", "COLOR", "UTF8", "BROKEN", "STEPS" };
		size_t field;
		for (field = 0; field < RZ_ARRAY_SIZE(names); field++) {
			if (RZ_STR_EQ(raw, names[field])) {
				break;
			}
		}
		if (field == RZ_ARRAY_SIZE(names) || fields[field] || fields[9]) {
			goto invalid;
		}
		fields[field] = true;
		if (field < 3) {
			char **target = field == 0 ? &cur->name : field == 1 ? &cur->file
									     : &cur->args;
			*target = rz_str_dup(equal);
			if (!*target || (field == 2 && !args_valid(*target))) {
				goto invalid;
			}
		} else if (field == 9) {
			if (!rz_str_startswith(equal, "<<") || !load_steps(cur, &cursor, equal + 2, &line)) {
				goto invalid;
			}
		} else {
			ut64 value, limit = field == 3 ? RZ_TEST_UI_MAX_COLS : field == 4 ? RZ_TEST_UI_MAX_ROWS
				: field == 5                                              ? 3600
											  : 1;
			const char *p = equal;
			if (!parse_number(&p, limit, &value) || *p || (field <= 5 && !value)) {
				goto invalid;
			}
			switch (field) {
			case 3: cur->cols = value; break;
			case 4: cur->rows = value; break;
			case 5: cur->timeout_ms = value * 1000; break;
			case 6: cur->color = value; break;
			case 7: cur->utf8 = value; break;
			case 8: cur->broken = value; break;
			}
		}
	}
	bool any = false;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(fields); i++) {
		any |= fields[i];
	}
	if (any) {
		if (!cur->name || !*cur->name || !fields[9]) {
			goto invalid;
		}
		cur->index = rz_pvector_len(tests);
		if (!rz_pvector_push(tests, cur)) {
			goto invalid;
		}
		cur = NULL;
	}
	if (rz_pvector_empty(tests)) {
		goto invalid;
	}
	rz_test_ui_free(cur);
	free(content);
	return tests;
invalid:
	eprintf("rz-test-ui: %s:%" PFMT64u ": invalid or incomplete UI test\n", path, line);
	rz_test_ui_free(cur);
	rz_pvector_free(tests);
	free(content);
	return NULL;
}

/**
 * \brief Read text with a hard byte limit, including files that grow while read.
 *
 * Reject embedded NULs and read errors. A separate stat followed by an unbounded
 * slurp cannot enforce the limit on the object actually opened.
 */
RZ_OWN char *rz_test_ui_read_text(RZ_NONNULL const char *path, size_t limit) {
	FILE *file = rz_sys_fopen(path, "rb");
	if (!file) {
		return NULL;
	}
	RzStrBuf text;
	rz_strbuf_init(&text);
	char buffer[4096];
	size_t n, total = 0;
	bool ok = true;
	while ((n = fread(buffer, 1, sizeof(buffer), file))) {
		if (n > limit - total || memchr(buffer, 0, n) || !rz_strbuf_append_n(&text, buffer, n)) {
			ok = false;
			break;
		}
		total += n;
	}
	ok = ok && !ferror(file);
	ok = fclose(file) == 0 && ok;
	if (!ok) {
		rz_strbuf_fini(&text);
		return NULL;
	}
	return rz_strbuf_drain_nofree(&text);
}

RZ_OWN RzPVector /*<RzTestUi *>*/ *rz_test_ui_load_file(RZ_NONNULL const char *path) {
	char *text = rz_test_ui_read_text(path, RZ_TEST_UI_MAX_FILE_SIZE);
	if (!text) {
		eprintf("rz-test-ui: cannot read text test %s\n", path);
		return NULL;
	}
	RzPVector *tests = rz_test_ui_load(path, text);
	free(text);
	return tests;
}
