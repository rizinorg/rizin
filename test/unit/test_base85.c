// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "minunit.h"

static void begin_capture(int pipefd[2], RZ_NONNULL int *saved_fd) {
	// ensure stdout has nothing
	fflush(stdout);

	if (pipe(pipefd) == -1) {
		perror("pipe");
		exit(1);
	}

	// save the real stdout
	*saved_fd = dup(STDOUT_FILENO);
	if (*saved_fd == -1) {
		perror("dup");
		exit(1);
	}

	// stdout --> pipe write end
	if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
		perror("dup2");
		exit(1);
	}

	// fd now held by STDOUT_FILENO
	close(pipefd[1]);
}

static char *end_capture(int pipefd[2], int saved_fd, RZ_NULLABLE size_t *out_len) {
	// flush stdio buffer so everything reaches the pipe
	fflush(stdout);

	// restore original stdout
	if (dup2(saved_fd, STDOUT_FILENO) == -1) {
		perror("dup2‑restore");
		exit(1);
	}
	close(saved_fd);

	// read entire pipe into a dynamically‑grown buffer
	char *buf = NULL;
	size_t cap = 0;
	char tmp[256];
	ssize_t n;
	for (;;) {
		n = read(pipefd[0], tmp, sizeof tmp);
		if (n == 0) {
			break;
		}
		if (n == -1) {
			perror("read(pipe)");
			exit(1);
		}

		char *newbuf = realloc(buf, cap + n + 1);
		if (!newbuf) {
			perror("realloc");
			exit(1);
		}
		buf = newbuf;
		memcpy(buf + cap, tmp, n);
		cap += n;
	}
	close(pipefd[0]);

	if (!buf) {
		buf = malloc(1);
		if (!buf) {
			perror("malloc");
			exit(1);
		}
	}
	buf[cap] = '\0';
	if (out_len)
		*out_len = cap;
	return buf;
}

bool test_rz_base85_encode_nodelims(void) {
	const char plain[] = "hello, ascii85";
	FILE *in = fmemopen((void *)plain, strlen(plain), "r");
	mu_assert_notnull(in, "fmemopen failed");

	int pipefd[2];
	int saved_stdout;
	begin_capture(pipefd, &saved_stdout);
	rz_base85_encode(in, 0, 0, 1);
	char *captured = end_capture(pipefd, saved_stdout, NULL);
	fclose(in);

	mu_assert_streq(captured, "BOu!rD_*#>F(8ou3&L", "ascii85 encode mismatch");
	free(captured);
	mu_end;
}

bool test_rz_base85_encode_delims(void) {
	const char plain[] = "hello, ascii85";
	FILE *in = fmemopen((void *)plain, strlen(plain), "r");
	mu_assert_notnull(in, "fmemopen failed");

	int pipefd[2];
	int saved_stdout;
	begin_capture(pipefd, &saved_stdout);
	rz_base85_encode(in, 1, 0, 1);
	char *captured = end_capture(pipefd, saved_stdout, NULL);
	fclose(in);

	mu_assert_streq(captured, "<~BOu!rD_*#>F(8ou3&L~>", "ascii85 encode mismatch");
	free(captured);
	mu_end;
}

bool test_rz_base85_decode_nodelims(void) {
	const char encoded[] = "BOu!rD_*#>F(8ou3&L";
	FILE *in = fmemopen((void *)encoded, strlen(encoded), "r");
	mu_assert_notnull(in, "fmemopen");

	int p[2], saved;
	begin_capture(p, &saved);
	bool ok = rz_base85_decode(in, 0, 0);
	char *decoded = end_capture(p, saved, NULL);
	fclose(in);

	mu_assert_true(ok, "rz_base85_decode returned false");
	mu_assert_streq(decoded, "hello, ascii85", "decoder output mismatch");
	free(decoded);
	mu_end;
}

bool test_rz_base85_decode_delims(void) {
	const char encoded[] = "<~BOu!rD_*#>F(8ou3&L~>";
	FILE *in = fmemopen((void *)encoded, strlen(encoded), "r");
	mu_assert_notnull(in, "fmemopen failed");

	int pipefd[2], saved;
	begin_capture(pipefd, &saved);
	bool ok = rz_base85_decode(in, 1, 0);
	char *decoded = end_capture(pipefd, saved, NULL);
	fclose(in);

	mu_assert_true(ok, "rz_base85_decode returned false");
	mu_assert_streq(decoded, "hello, ascii85", "ascii85 decode with delimiters mismatch");
	free(decoded);
	mu_end;
}

bool test_rz_base85_encode_decode_wrap10(void) {
	char plain[51];
	memset(plain, 'A', 50);
	plain[50] = '\0';

	FILE *in = fmemopen(plain, 50, "r");
	mu_assert_notnull(in, "fmemopen failed");

	int p[2], saved;
	begin_capture(p, &saved);
	rz_base85_encode(in, 0, 10, 0);
	char *encoded = end_capture(p, saved, NULL);
	fclose(in);

	int col = 0, newlines = 0;
	for (size_t i = 0; encoded[i]; i++) {
		if (encoded[i] == '\n') {
			mu_assert_eq(col, 10, "line length before \\n not 10");
			col = 0;
			newlines++;
		} else {
			col++;
		}
	}
	mu_assert_true(col <= 10, "final line exceeds wrap length");

	char *flat = malloc(strlen(encoded) + 1);
	mu_assert_notnull(flat, "malloc");
	size_t j = 0;
	for (size_t i = 0; encoded[i]; i++) {
		if (encoded[i] != '\n')
			flat[j++] = encoded[i];
	}
	flat[j] = '\0';

	FILE *enc_in = fmemopen(flat, j, "r");
	mu_assert_notnull(enc_in, "fmemopen 2");

	begin_capture(p, &saved);
	bool ok = rz_base85_decode(enc_in, 0, 0);
	char *decoded = end_capture(p, saved, NULL);
	fclose(enc_in);

	mu_assert_true(ok, "rz_base85_decode failed");
	mu_assert_eq(strlen(decoded), 50U, "decoded length mismatch");
	mu_assert_true(memcmp(decoded, plain, 50) == 0, "decoded data mismatch");

	free(encoded);
	free(flat);
	free(decoded);
	mu_end;
}

bool test_rz_base85_encode_decode_z_abbrev(void) {
	const ut8 zeros[4] = { 0, 0, 0, 0 };
	FILE *in = fmemopen((void *)zeros, 4, "r");
	mu_assert_notnull(in, "fmemopen zeros");

	int p[2], saved;
	begin_capture(p, &saved);
	rz_base85_encode(in, 0, 0, 0);
	char *enc = end_capture(p, saved, NULL);
	fclose(in);

	mu_assert_streq(enc, "z", "encode zeros should be 'z'");

	const char zzz[] = "zz";
	FILE *in2 = fmemopen((void *)zzz, strlen(zzz), "r");
	mu_assert_notnull(in2, "fmemopen zz");

	begin_capture(p, &saved);
	bool ok = rz_base85_decode(in2, 0, 0);
	size_t decoded_len;
	char *decoded = end_capture(p, saved, &decoded_len);
	fclose(in2);

	mu_assert_true(ok, "rz_base85_decode returned false");
	mu_assert_eq(decoded_len, 8U, "decoded length != 8");
	for (size_t i = 0; i < 8; i++) {
		mu_assert_eq(decoded[i], '\0', "decoded byte non‑zero");
	}

	free(enc);
	free(decoded);
	mu_end;
}

bool test_rz_base85_decode_invalid_strict_vs_lenient(void) {
	const char bad[] = "FCfN8v";

	FILE *in_strict = fmemopen((void *)bad, strlen(bad), "r");
	mu_assert_notnull(in_strict, "fmemopen strict");

	bool ok_strict = rz_base85_decode(in_strict, 0, 0);
	fclose(in_strict);

	mu_assert_false(ok_strict, "decoder accepted garbage in strict mode");

	FILE *in_lenient = fmemopen((void *)bad, strlen(bad), "r");
	mu_assert_notnull(in_lenient, "fmemopen lenient");

	int p[2], saved;
	begin_capture(p, &saved);
	bool ok_lenient = rz_base85_decode(in_lenient, 0, 1);
	size_t decoded_len;
	char *decoded = end_capture(p, saved, &decoded_len);
	fclose(in_lenient);

	mu_assert_true(ok_lenient, "lenient decode returned false");
	mu_assert_streq(decoded, "test", "lenient decode produced wrong bytes");

	free(decoded);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_base85_encode_nodelims);
	mu_run_test(test_rz_base85_decode_nodelims);
	mu_run_test(test_rz_base85_encode_delims);
	mu_run_test(test_rz_base85_decode_delims);
	mu_run_test(test_rz_base85_encode_decode_wrap10);
	mu_run_test(test_rz_base85_encode_decode_z_abbrev);
	mu_run_test(test_rz_base85_decode_invalid_strict_vs_lenient);

	return tests_passed != tests_run;
}

mu_main(all_tests)
