/* SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re> */
/* SPDX-License-Identifier: LGPL-3.0-only */

/* Portable C reimplementation of sys/create_tags_rz.py.
 *
 * For each input file it emits a single line:
 *   ft <basename> <file contents with newlines replaced by single spaces>
 *
 * This mirrors Python's str.splitlines() + " ".join(): line boundaries are
 * '\n', '\r' and '\r\n', empty lines are preserved (producing consecutive
 * spaces) and a trailing newline does not add a trailing space. Like the
 * Python version the output is written to stdout. Having this as a native
 * build-time helper removes the build-time dependency on Python. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *basename_portable(const char *path) {
	const char *base = path;
	for (const char *p = path; *p; p++) {
		if (*p == '/' || *p == '\\') {
			base = p + 1;
		}
	}
	return base;
}

static int emit_file(const char *path) {
	FILE *in = fopen(path, "rb");
	if (!in) {
		fprintf(stderr, "create_tags_rz: cannot open %s\n", path);
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

	fputs("ft ", stdout);
	fputs(basename_portable(path), stdout);
	fputc(' ', stdout);

	/* Replicate " ".join(text.splitlines()): print a space before every line
	 * except the first. A line ends at '\n', '\r' or '\r\n'. */
	int first = 1;
	size_t i = 0;
	while (i < rd) {
		size_t start = i;
		while (i < rd && buf[i] != '\n' && buf[i] != '\r') {
			i++;
		}
		if (!first) {
			fputc(' ', stdout);
		}
		first = 0;
		fwrite(buf + start, 1, i - start, stdout);
		if (i < rd) {
			char c = buf[i];
			i++;
			if (c == '\r' && i < rd && buf[i] == '\n') {
				i++;
			}
		}
	}

	fputc('\n', stdout);
	free(buf);
	return 0;
}

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		int rc = emit_file(argv[i]);
		if (rc != 0) {
			return rc;
		}
	}
	return 0;
}
