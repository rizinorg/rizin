// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test_ui.h"
#include <rz_main.h>
#include <errno.h>
#if __WINDOWS__
#include <rz_windows.h>
#endif

#define TESTUI_EXT ".rzt-ui"

static int help(bool verbose) {
	printf("Usage: rz-test-ui [-hvVa] [-r bindir] [-t sec] [path ...]\n");
	if (!verbose) {
		return 1;
	}
	printf("\n"
	       " -h           this help\n"
	       " -v           show version\n"
	       " -V           verbose: print diffs and diagnostics for failures\n"
	       " -a           accept: rewrite EXPECT_SCREEN blocks with what rizin produced\n"
	       " -r bindir    look for the rz-test-ui executable in this directory\n"
	       " -t sec       per-test timeout in seconds (default %d)\n"
	       "\n"
	       "If no path is given, '" TESTUI_EXT "' files are searched under ./test/tui.\n",
		RZ_TEST_UI_TIMEOUT_DEFAULT);
	return 0;
}

static int str_cmp_q(const void *a, const void *b, void *user) {
	return strcmp((const char *)a, (const char *)b);
}

/** \brief Bound recursion so directory links cannot wedge discovery. */
static bool collect(const char *path, RzPVector /*<char *>*/ *files, unsigned depth) {
	if (!depth) {
		eprintf("directory nesting limit at %s\n", path);
		return false;
	}
	if (rz_file_is_directory(path)) {
		RzList *entries = rz_sys_dir(path);
		if (!entries) {
			return false;
		}
		RzListIter *it;
		char *entry;
		bool ok = true;
		rz_list_foreach (entries, it, entry) {
			if (entry[0] == '.') {
				continue;
			}
			char *child = rz_str_newf("%s%s%s", path, RZ_SYS_DIR, entry);
			if (!child || !collect(child, files, depth - 1)) {
				ok = false;
			}
			free(child);
		}
		rz_list_free(entries);
		return ok;
	}
	if (!rz_file_exists(path)) {
		eprintf("path does not exist: %s\n", path);
		return false;
	}
	if (!rz_str_endswith(path, TESTUI_EXT)) {
		return true;
	}
	char *copy = rz_str_dup(path);
	if (!copy || !rz_pvector_push(files, copy)) {
		free(copy);
		return false;
	}
	return true;
}

/**
 * \brief Replace in the same directory, never truncate the source on write failure.
 *
 * The exclusive temporary is removed on every error. Rename/MoveFileEx commits
 * the whole replacement only after its contents have been written and closed.
 */
static bool replace_file(const char *path, const char *text) {
#if !__WINDOWS__
	// Read permissions from the opened source, and apply them to the still-open
	// temporary. Never chmod a pathname that another process could replace.
	int source_fd = rz_sys_open(path, O_RDONLY | O_BINARY, 0);
	struct stat st;
	bool source_ok = source_fd >= 0 && !fstat(source_fd, &st) && S_ISREG(st.st_mode);
	if (source_fd >= 0) {
		close(source_fd);
	}
	if (!source_ok) {
		return false;
	}
#endif
	char *temp = NULL;
	int fd = -1;
	for (unsigned i = 0; i < 32 && fd < 0; i++) {
		free(temp);
		temp = rz_str_newf("%s.ui-%" PFMT64u "-%u.tmp", path, rz_time_now_mono(), i);
		if (!temp) {
			return false;
		}
		fd = rz_sys_open(temp, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
		if (fd < 0 && errno != EEXIST) {
			free(temp);
			return false;
		}
	}
	if (fd < 0) {
		free(temp);
		return false;
	}
	size_t length = strlen(text), written = 0;
	while (written < length) {
		ssize_t n = write(fd, text + written, length - written);
		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n <= 0) {
			break;
		}
		written += n;
	}
	bool ok = written == length;
#if !__WINDOWS__
	ok = ok && !fchmod(fd, st.st_mode & 0777);
#endif
	ok = close(fd) == 0 && ok;
#if __WINDOWS__
	wchar_t *from = rz_utf8_to_utf16(temp), *to = rz_utf8_to_utf16(path);
	ok = ok && from && to && MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING);
	free(from);
	free(to);
#else
	ok = ok && !rename(temp, path);
#endif
	if (!ok) {
		rz_file_rm(temp);
	}
	free(temp);
	return ok;
}

static const char *line_end(const char *line) {
	const char *end = strchr(line, '\n');
	return end ? end + 1 : line + strlen(line);
}

static bool apply_fixups(const char *path, const char *original, RzPVector /*<RzTestUiScreenFixup *>*/ *fixups) {
	if (rz_pvector_empty(fixups)) {
		return true;
	}
	char *current = rz_test_ui_read_text(path, RZ_TEST_UI_MAX_FILE_SIZE);
	bool unchanged = current && !strcmp(current, original);
	free(current);
	if (!unchanged) {
		eprintf("refusing to accept %s: source changed during the run\n", path);
		return false;
	}
	RzStrBuf output;
	rz_strbuf_init(&output);
	const char *at = original;
	ut64 line = 1;
	bool ok = true;
	void **it;
	rz_pvector_foreach (fixups, it) {
		RzTestUiScreenFixup *fix = *it;
		if (fix->line_begin < line) {
			ok = false;
			break;
		}
		while (line < fix->line_begin && *at) {
			const char *next = line_end(at);
			ok &= rz_strbuf_append_n(&output, at, next - at);
			at = next;
			line++;
		}
		while (line <= fix->line_end && *at) {
			at = line_end(at);
			line++;
		}
		if (!*at) {
			ok = false;
			break;
		}
		const char *end = line_end(at);
		size_t delimiter_len = end - at;
		while (delimiter_len && (at[delimiter_len - 1] == '\r' || at[delimiter_len - 1] == '\n')) {
			delimiter_len--;
		}
		bool crlf = end - at >= 2 && end[-2] == '\r';
		const char *capture = fix->text;
		while (*capture) {
			const char *next = strchr(capture, '\n');
			size_t len = next ? (size_t)(next - capture) : strlen(capture);
			if (len == delimiter_len && !memcmp(capture, at, len)) {
				ok = false;
				break;
			}
			ok &= rz_strbuf_append_n(&output, capture, len);
			ok &= rz_strbuf_append(&output, crlf ? "\r\n" : "\n");
			capture += len + (next ? 1 : 0);
		}
	}
	ok &= rz_strbuf_append(&output, at);
	ok &= rz_strbuf_length(&output) <= RZ_TEST_UI_MAX_FILE_SIZE;
	if (ok && strcmp(original, rz_strbuf_get(&output))) {
		ok = replace_file(path, rz_strbuf_get(&output));
	}
	rz_strbuf_fini(&output);
	return ok;
}

static const char *kind_tag(RzTestResult k) {
	switch (k) {
	case RZ_TEST_RESULT_OK: return "OK";
	case RZ_TEST_RESULT_FAILED: return "XX";
	case RZ_TEST_RESULT_BROKEN: return "BR";
	case RZ_TEST_RESULT_FIXED: return "FX";
	}
	return "??";
}

static int ui_main(int argc, const char **argv) {
	if (argc == 5 && !strcmp(argv[1], "--worker")) {
		char *end;
		errno = 0;
		ut64 index = strtoull(argv[3], &end, 10);
		if (errno || !*argv[3] || *end || index > SIZE_MAX) {
			return 2;
		}
		return rz_test_ui_worker(argv[2], index, argv[4]);
	}
	// Windows treats line buffering as full buffering and rejects a zero size.
	setvbuf(stdout, NULL, _IONBF, 0);
	bool verbose = false, accept = false;
	const char *bindir = NULL;
	ut64 timeout_sec = RZ_TEST_UI_TIMEOUT_DEFAULT;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (a[0] != '-' || !strcmp(a, "-")) {
			break;
		}
		if (!strcmp(a, "-h")) {
			return help(true);
		} else if (!strcmp(a, "-v")) {
			printf("rz-test-ui %s\n", RZ_VERSION);
			return 0;
		} else if (!strcmp(a, "-V")) {
			verbose = true;
		} else if (!strcmp(a, "-a")) {
			accept = true;
		} else if (!strcmp(a, "-r")) {
			if (++i >= argc) {
				return help(false);
			}
			bindir = argv[i];
		} else if (!strcmp(a, "-t")) {
			if (++i >= argc) {
				return help(false);
			}
			char *end;
			errno = 0;
			timeout_sec = strtoull(argv[i], &end, 10);
			if (errno || !*argv[i] || *end || !timeout_sec || timeout_sec > 3600) {
				return help(false);
			}
		} else {
			eprintf("unknown option: %s\n", a);
			return help(false);
		}
	}

	if (!rz_subprocess_init()) {
		eprintf("cannot initialise subprocess subsystem\n");
		return 1;
	}

	RzPVector *files = rz_pvector_new(free);
	if (!files) {
		rz_subprocess_fini();
		return 1;
	}
	if (i >= argc) {
		if (!collect(rz_file_is_directory("tui") ? "tui" : "test" RZ_SYS_DIR "tui", files, 16)) {
			rz_pvector_free(files);
			rz_subprocess_fini();
			return 1;
		}
	} else {
		for (; i < argc; i++) {
			if (!collect(argv[i], files, 16)) {
				rz_pvector_free(files);
				rz_subprocess_fini();
				return 1;
			}
		}
	}
	if (rz_pvector_empty(files)) {
		eprintf("no " TESTUI_EXT " files found\n");
		rz_pvector_free(files);
		rz_subprocess_fini();
		return 1;
	}
	rz_pvector_sort(files, str_cmp_q, NULL);

	RzTestUiRunConfig cfg = {
		.bin_path = bindir,
		.worker_exe = bindir ? "rz-test-ui" : argv[0],
		.timeout_ms = timeout_sec * 1000,
	};

	size_t n_ok = 0, n_fail = 0, n_broken = 0, n_fixed = 0, n_total = 0;
	void **fit;
	rz_pvector_foreach (files, fit) {
		const char *path = (const char *)*fit;
		char *original = rz_test_ui_read_text(path, RZ_TEST_UI_MAX_FILE_SIZE);
		RzPVector *tests = original ? rz_test_ui_load(path, original) : NULL;
		if (!tests) {
			free(original);
			eprintf("[%s] could not load\n", path);
			n_fail++;
			n_total++;
			continue;
		}
		RzPVector *file_fixups = accept ? rz_pvector_new(NULL) : NULL;
		if (accept && !file_fixups) {
			eprintf("[%s] cannot allocate snapshot transaction\n", path);
			free(original);
			rz_pvector_free(tests);
			n_fail++;
			n_total++;
			continue;
		}
		bool accept_safe = true;
		size_t file_capture_size = 0;
		void **tit;
		rz_pvector_foreach (tests, tit) {
			RzTestUi *t = (RzTestUi *)*tit;
			RzTestUiResult *res = rz_test_ui_run(&cfg, t);
			n_total++;
			if (!res) {
				n_fail++;
				accept_safe = false;
				continue;
			}
			accept_safe &= res->completed && !res->assertion_failed && !res->run_failed && !res->timeout;
			const char *name = t->name ? t->name : "(unnamed)";
			printf("[%s] %s :: %s\n", kind_tag(res->result), path, name);
			switch (res->result) {
			case RZ_TEST_RESULT_OK: n_ok++; break;
			case RZ_TEST_RESULT_FAILED: n_fail++; break;
			case RZ_TEST_RESULT_BROKEN: n_broken++; break;
			case RZ_TEST_RESULT_FIXED: n_fixed++; break;
			}
			if (res->fail_diag && (verbose || res->result == RZ_TEST_RESULT_FAILED)) {
				printf("---- %s ----\n%s\n", name, res->fail_diag);
				if (verbose && res->actual_screen) {
					printf("---- actual screen ----\n%s\n", res->actual_screen);
				}
			}
			if (accept && accept_safe && res->fixups) {
				void **xit;
				rz_pvector_foreach (res->fixups, xit) {
					RzTestUiScreenFixup *src = *xit;
					size_t capture_size = strlen(src->text);
					if (capture_size > RZ_TEST_UI_MAX_FILE_SIZE - file_capture_size) {
						accept_safe = false;
						break;
					}
					file_capture_size += capture_size;
					RzTestUiScreenFixup *cp = RZ_NEW0(RzTestUiScreenFixup);
					if (!cp) {
						accept_safe = false;
						break;
					}
					cp->line_begin = src->line_begin;
					cp->line_end = src->line_end;
					cp->text = rz_str_dup(src->text);
					if (!cp->text || !rz_pvector_push(file_fixups, cp)) {
						free(cp->text);
						free(cp);
						accept_safe = false;
						break;
					}
				}
			}
			rz_test_ui_result_free(res);
		}
		if (accept && file_fixups) {
			if (!rz_pvector_empty(file_fixups)) {
				if (accept_safe && apply_fixups(path, original, file_fixups)) {
					printf("  (updated EXPECT_SCREEN blocks in %s)\n", path);
				} else {
					eprintf("  (refused or failed to update %s)\n", path);
					n_fail++;
				}
			}
			void **xit;
			rz_pvector_foreach (file_fixups, xit) {
				RzTestUiScreenFixup *fx = *xit;
				free(fx->text);
				free(fx);
			}
			rz_pvector_free(file_fixups);
		}
		free(original);
		rz_pvector_free(tests);
	}

	printf("\n%zu tests: %zu ok, %zu failed, %zu broken, %zu fixed\n",
		n_total, n_ok, n_fail, n_broken, n_fixed);

	rz_pvector_free(files);
	rz_subprocess_fini();
	// fixed (a BROKEN test now passing) is also a signal worth a non-zero exit
	return (n_fail || n_fixed) ? 1 : 0;
}

int MAIN_NAME(int argc, const ARGV_TYPE **argv) {
	char **utf8 = ARGV_TYPE_TO_UTF8(argc, argv);
	if (!utf8) {
		return 1;
	}
	int result = ui_main(argc, (const char **)utf8);
	FREE_UTF8_ARGV(argc, utf8);
	return result;
}
