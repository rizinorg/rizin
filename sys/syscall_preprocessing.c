/* SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re> */
/* SPDX-License-Identifier: LGPL-3.0-only */

/* Portable C reimplementation of sys/syscall_preprocessing.py.
 *
 * It preprocesses syscall/d .sdb.txt files so that they can be compiled by
 * sdb_gen. For every line that does not start with '_' and contains a '=',
 * it splits the line on '=' and ',' (stripping whitespace from each field)
 * and emits two lines:
 *   <field1>.<field2>=<field0>
 *   <field0>=<field1>,<field2>,...   (padded to at least 4 fields)
 * Every other line is copied verbatim.
 *
 * Unlike the Python version this has no external dependencies and is meant to
 * be built as a native build-time helper (like sdb_gen), so the build does
 * not require a Python interpreter. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_ws(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* Append [start,end) with surrounding whitespace stripped to the field list. */
static void push_field(char ***fields, size_t *n, size_t *cap, const char *start, const char *end) {
	while (start < end && is_ws(*start)) {
		start++;
	}
	while (end > start && is_ws(end[-1])) {
		end--;
	}
	size_t len = (size_t)(end - start);
	char *s = (char *)malloc(len + 1);
	if (!s) {
		exit(1);
	}
	memcpy(s, start, len);
	s[len] = '\0';
	if (*n == *cap) {
		*cap = *cap ? *cap * 2 : 8;
		*fields = (char **)realloc(*fields, *cap * sizeof(char *));
		if (!*fields) {
			exit(1);
		}
	}
	(*fields)[(*n)++] = s;
}

static void process_line(FILE *out, const char *line, size_t len) {
	/* Find end of line content (excluding a single trailing '\n'). */
	size_t content_len = len;
	int has_nl = 0;
	if (content_len > 0 && line[content_len - 1] == '\n') {
		content_len--;
		has_nl = 1;
	}

	int starts_underscore = (len > 0 && line[0] == '_');
	int has_eq = 0;
	for (size_t i = 0; i < content_len; i++) {
		if (line[i] == '=') {
			has_eq = 1;
			break;
		}
	}

	if (starts_underscore || !has_eq) {
		/* Copy verbatim (including trailing newline if present). */
		fwrite(line, 1, len, out);
		return;
	}

	/* Split content on '=' and ','. */
	char **fields = NULL;
	size_t n = 0, cap = 0;
	const char *seg = line;
	for (size_t i = 0; i < content_len; i++) {
		if (line[i] == '=' || line[i] == ',') {
			push_field(&fields, &n, &cap, seg, line + i);
			seg = line + i + 1;
		}
	}
	push_field(&fields, &n, &cap, seg, line + content_len);

	/* fields[1].fields[2]=fields[0] */
	fprintf(out, "%s.%s=%s\n", fields[1], fields[2], fields[0]);

	/* fields[0]=fields[1],fields[2],...  padded to at least 4 fields. */
	fprintf(out, "%s=", fields[0]);
	size_t total = n < 4 ? 4 : n;
	for (size_t i = 1; i < total; i++) {
		if (i > 1) {
			fputc(',', out);
		}
		fputs(i < n ? fields[i] : "", out);
	}
	fputc('\n', out);

	for (size_t i = 0; i < n; i++) {
		free(fields[i]);
	}
	free(fields);
	(void)has_nl;
}

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
		return 1;
	}

	FILE *in = fopen(argv[1], "rb");
	if (!in) {
		fprintf(stderr, "%s: cannot open input %s\n", argv[0], argv[1]);
		return 1;
	}
	fseek(in, 0, SEEK_END);
	long size = ftell(in);
	fseek(in, 0, SEEK_SET);
	if (size < 0) {
		fclose(in);
		return 1;
	}
	char *buf = (char *)malloc((size_t)size + 1);
	if (!buf) {
		fclose(in);
		return 1;
	}
	size_t rd = fread(buf, 1, (size_t)size, in);
	buf[rd] = '\0';
	fclose(in);

	FILE *out = fopen(argv[2], "wb");
	if (!out) {
		fprintf(stderr, "%s: cannot open output %s\n", argv[0], argv[2]);
		free(buf);
		return 1;
	}

	size_t start = 0;
	for (size_t i = 0; i < rd; i++) {
		if (buf[i] == '\n') {
			process_line(out, buf + start, i - start + 1);
			start = i + 1;
		}
	}
	if (start < rd) {
		process_line(out, buf + start, rd - start);
	}

	fclose(out);
	free(buf);
	return 0;
}
