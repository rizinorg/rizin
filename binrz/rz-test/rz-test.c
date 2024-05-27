// SPDX-FileCopyrightText: 2020-2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test.h"
#include <assert.h>
#include <rz_cons.h>
#include <rz_main.h>
#include <rz_windows.h>
#include <rz_util/rz_print.h>

#define Color_INSERT   Color_BGREEN
#define Color_DELETE   Color_BRED
#define Color_BGINSERT "\x1b[48;5;22m"
#define Color_BGDELETE "\x1b[48;5;52m"
#define Color_HLINSERT Color_BGINSERT Color_INSERT
#define Color_HLDELETE Color_BGDELETE Color_DELETE

#define RIZIN_CMD_DEFAULT      "rizin"
#define RZ_ASM_CMD_DEFAULT     "rz-asm"
#define JSON_TEST_FILE_DEFAULT "bins/elf/crackme0x00b"
#define TIMEOUT_DEFAULT        960

#define STRV(x)             #x
#define STR(x)              STRV(x)
#define WORKERS_DEFAULT_STR STR(WORKERS_DEFAULT)
#define TIMEOUT_DEFAULT_STR STR(TIMEOUT_DEFAULT)

typedef struct test_counter_t {
	size_t n_tests; ///< Total number of tests
	size_t n_handled; ///< Tests that has been handled
	size_t ok; ///< Tests that succeeded
	size_t xx; ///< Tests that failed
	size_t fx; ///< Tests that succeeded but also marked as broken
	size_t br; ///< Tests that failed but also marked as broken
} TestCounter;

typedef struct test_return_t {
	size_t max_path;
	ut64 time_start; ///< Start time of the tests
	bool interactive; ///< When true allows to review the tests interactively
	st64 expected_succ; ///< Changes the return code if this value mismatches the actual total OK number
	st64 expected_fail; ///< Changes the return code if this value mismatches the actual total XX number
	int return_val; ///< Main return value
	HtSP *path_counter; ///< Hashmap<const char*, TestCounter*> which is initialized when log_mode is true
	RzAtomicBool *running; ///< Atomic boolean to stop result_thread
} ResultThreadData;

typedef struct rz_test_state_t {
	RzTestRunConfig run_config;
	bool verbose;
	RzTestDatabase *db;
	PJ *pj;
	ResultThreadData data; ///< Thread context for result_thread
	RzThreadQueue *results; ///< Results of the executed tests.
} RzTestState;

static void worker_thread(void *element, void *user);
static void *result_thread(void *user);
static void handle_result(RzTestState *state, RzTestResultInfo *result, TestCounter *counter);
static void print_counter(RzTestState *state, TestCounter *cnt);
static void interact(RzTestState *state, RzPVector /*<RzTestResultInfo *>*/ *failed_results);
static bool interact_fix(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results);
static void interact_break(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results);
static void interact_commands(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results);

static int help(bool verbose) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-test [-qvVnL] [-j threads] [test file/dir | @test-type]\n");
	if (verbose) {
		const char *options[] = {
			// clang-format off
			"-h",           "",               "Show this help",
			"-v",           "",               "Show version information",
			"-q",           "",               "Quiet mode",
			"-V",           "",               "Be verbose",
			"-i",           "",               "Interactive mode",
			"-n",           "",               "Do nothing (don't run any test, just load/parse them)",
			"-L",           "",               "Log mode (better printing for CI, logfiles, etc.)",
			"-F",           "[dir]",          "Run fuzz tests (open and default analysis) on all files in the given dir",
			"-j",           "[threads]",      "How many threads to use for running tests concurrently (default is " WORKERS_DEFAULT_STR ")",
			"-r",           "[rizin]",        "Path to rizin executable (default is " RIZIN_CMD_DEFAULT ")",
			"-m",           "[rz-asm]",       "Path to rz-asm executable (default is " RZ_ASM_CMD_DEFAULT ")",
			"-f",           "[file]",         "File to use for JSON tests (default is " JSON_TEST_FILE_DEFAULT ")",
			"-C",           "[dir]",          "Chdir before running rz-test (default follows executable symlink + test/new)",
			"-t",           "[seconds]",      "Timeout per test (default is " TIMEOUT_DEFAULT_STR " seconds)",
			"-o",           "[file]",         "Output test run information in JSON format to file",
			"-e",           "[dir]",          "Exclude a particular directory while testing (this option can appear many times)",
			"-s",           "[num]",          "Number of expected successful tests",
			"-x",           "[num]",          "Number of expected failed tests",
			// clang-format on
		};
		size_t maxOptionAndArgLength = 0;
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			size_t optionLength = strlen(options[i]);
			size_t argLength = strlen(options[i + 1]);
			size_t totalLength = optionLength + argLength;
			if (totalLength > maxOptionAndArgLength) {
				maxOptionAndArgLength = totalLength;
			}
		}
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			if (i + 1 < sizeof(options) / sizeof(options[0])) {
				rz_print_colored_help_option(options[i], options[i + 1], options[i + 2], maxOptionAndArgLength);
			}
		}
		printf("Supported test types: @json @unit @fuzz @cmds\n"
		       "OS/Arch for archos tests: " RZ_TEST_ARCH_OS "\n");
	}
	return 1;
}

static bool rz_test_chdir(const char *argv0) {
#if __UNIX__
	if (rz_file_is_directory("db")) {
		return true;
	}
	char src_path[PATH_MAX];
	char *rz_test_path = rz_file_path(argv0);
	bool found = false;

	ssize_t linklen = readlink(rz_test_path, src_path, sizeof(src_path) - 1);
	if (linklen != -1) {
		src_path[linklen] = '\0';
		char *p = strstr(src_path, RZ_SYS_DIR "binrz" RZ_SYS_DIR "rz-test" RZ_SYS_DIR "rz-test");
		if (p) {
			*p = 0;
			strcat(src_path, RZ_SYS_DIR "test" RZ_SYS_DIR);
			if (rz_file_is_directory(src_path)) {
				if (chdir(src_path) != -1) {
					eprintf("Running from %s\n", src_path);
					found = true;
				} else {
					eprintf("Cannot find '%s' directory\n", src_path);
				}
			}
		}
	} else {
		eprintf("Cannot follow the link %s\n", src_path);
	}
	free(rz_test_path);
	return found;
#else
	return false;
#endif
}

static bool rz_test_test_run_unit(void) {
	return rz_sys_system("make -C unit all run") == 0;
}

static bool rz_test_chdir_fromtest(const char *test_path) {
	if (!test_path || *test_path == '@') {
		test_path = "";
	}
	char *abs_test_path = rz_file_abspath(test_path);
	if (!rz_file_is_directory(abs_test_path)) {
		char *last_slash = (char *)rz_str_lchr(abs_test_path, RZ_SYS_DIR[0]);
		if (last_slash) {
			*last_slash = 0;
		}
	}
	if (chdir(abs_test_path) == -1) {
		free(abs_test_path);
		return false;
	}
	free(abs_test_path);
	bool found = false;
	char *cwd = NULL;
	char *old_cwd = NULL;
	while (true) {
		cwd = rz_sys_getdir();
		if (old_cwd && !strcmp(old_cwd, cwd)) {
			break;
		}
		if (rz_file_is_directory("test")) {
			rz_sys_chdir("test");
			if (rz_file_is_directory("db")) {
				found = true;
				eprintf("Running from %s\n", cwd);
				break;
			}
			rz_sys_chdir("..");
		}
		if (rz_file_is_directory("db")) {
			found = true;
			eprintf("Running from %s\n", cwd);
			break;
		}
		free(old_cwd);
		old_cwd = cwd;
		cwd = NULL;
		if (chdir("..") == -1) {
			break;
		}
	}
	free(old_cwd);
	free(cwd);
	return found;
}

int rz_test_main(int argc, const char **argv) {
	size_t n_threads = RZ_THREAD_POOL_ALL_CORES;
	bool verbose = false;
	bool nothing = false;
	bool quiet = false;
	char *rizin_cmd = NULL;
	char *rz_asm_cmd = NULL;
	char *json_test_file = NULL;
	char *output_file = NULL;
	char *fuzz_dir = NULL;
	bool log_mode = false;
	RzTestState state = { 0 };
	ut64 timeout_sec = TIMEOUT_DEFAULT;
	const char *rz_test_dir = NULL;
	RzPVector *except_dir = rz_pvector_new(free);
	if (!except_dir) {
		RZ_LOG_ERROR("Fail to create RzPVector\n");
		return -1;
	}

	state.data.expected_succ = -1;
	state.data.expected_fail = -1;

#if __WINDOWS__
	UINT old_cp = GetConsoleOutputCP();
	{
		HANDLE streams[] = { GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE) };
		DWORD mode;
		int i;
		for (i = 0; i < RZ_ARRAY_SIZE(streams); i++) {
			GetConsoleMode(streams[i], &mode);
			SetConsoleMode(streams[i],
				mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		}
	}
#endif

	RzGetopt opt;
	rz_getopt_init(&opt, argc, (const char **)argv, "hqvj:r:m:f:C:LnVt:F:io:e:s:x:");

	int c;
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'h':
			state.data.return_val = help(true);
			goto beach;
		case 'q':
			quiet = true;
			break;
		case 'v':
			if (quiet) {
				printf(RZ_VERSION "\n");
			} else {
				char *s = rz_version_str("rz-test");
				printf("%s\n", s);
				free(s);
			}
			state.data.return_val = 0;
			goto beach;
		case 'V':
			verbose = true;
			break;
		case 'i':
			state.data.interactive = true;
			break;
		case 'L':
			log_mode = true;
			break;
		case 'F':
			free(fuzz_dir);
			fuzz_dir = strdup(opt.arg);
			break;
		case 'j':
			n_threads = atoi(opt.arg);
			if (n_threads <= 0) {
				eprintf("Invalid thread count (must be positive)\n");
				state.data.return_val = help(false);
				goto beach;
			}
			break;
		case 'r':
			free(rizin_cmd);
			rizin_cmd = strdup(opt.arg);
			break;
		case 'C':
			rz_test_dir = opt.arg;
			break;
		case 'n':
			nothing = true;
			break;
		case 'm':
			free(rz_asm_cmd);
			rz_asm_cmd = strdup(opt.arg);
			break;
		case 'f':
			free(json_test_file);
			json_test_file = strdup(opt.arg);
			break;
		case 't':
			timeout_sec = strtoull(opt.arg, NULL, 0);
			if (!timeout_sec) {
				timeout_sec = UT64_MAX;
			}
			break;
		case 'o':
			free(output_file);
			output_file = strdup(opt.arg);
			break;
		case 'e':
			rz_pvector_push(except_dir, strdup(opt.arg));
			break;
		case 's':
			// rz_num_math returns 0 for both '0' and invalid str
			state.data.expected_succ = rz_num_math(NULL, opt.arg);
			if (!rz_num_is_valid_input(NULL, opt.arg) || state.data.expected_succ < 0) {
				RZ_LOG_ERROR("Number of expected successful tests is invalid\n");
				goto beach;
			}
			break;
		case 'x':
			state.data.expected_fail = rz_num_math(NULL, opt.arg);
			if (!rz_num_is_valid_input(NULL, opt.arg) || state.data.expected_fail < 0) {
				RZ_LOG_ERROR("Number of expected failed tests is invalid\n");
				goto beach;
			}
			break;
		default:
			state.data.return_val = help(false);
			goto beach;
		}
	}

	char *cwd = rz_sys_getdir();
	if (rz_test_dir) {
		if (chdir(rz_test_dir) == -1) {
			eprintf("Cannot find %s directory.\n", rz_test_dir);
			state.data.return_val = -1;
			goto beach;
		}
	} else {
		bool dir_found = (opt.ind < argc && argv[opt.ind][0] != '.')
			? rz_test_chdir_fromtest(argv[opt.ind])
			: rz_test_chdir(argv[0]);
		if (!dir_found) {
			eprintf("Cannot find db/ directory related to the given test.\n");
			state.data.return_val = -1;
			goto beach;
		}
	}

	if (fuzz_dir) {
		char *tmp = fuzz_dir;
		fuzz_dir = rz_file_abspath_rel(cwd, fuzz_dir);
		free(tmp);
	}

	if (!rz_subprocess_init()) {
		eprintf("Subprocess init failed\n");
		state.data.return_val = -1;
		goto beach;
	}
	atexit(rz_subprocess_fini);

	rz_sys_setenv("TZ", "UTC");
	// Avoid PATH search for each process launched
	if (!rizin_cmd) {
		rizin_cmd = rz_file_path(RIZIN_CMD_DEFAULT);
	}
	if (!rz_asm_cmd) {
		rz_asm_cmd = rz_file_path(RZ_ASM_CMD_DEFAULT);
	}
	state.run_config.rz_cmd = rizin_cmd;
	state.run_config.rz_asm_cmd = rz_asm_cmd;
	state.run_config.json_test_file = json_test_file ? json_test_file : JSON_TEST_FILE_DEFAULT;
	state.run_config.timeout_ms = timeout_sec > UT64_MAX / 1000 ? UT64_MAX : timeout_sec * 1000;
	state.verbose = verbose;
	state.db = rz_test_test_database_new();
	if (!state.db) {
		state.data.return_val = -1;
		goto beach;
	}

	if (output_file) {
		state.pj = pj_new();
		pj_a(state.pj);
	}

	if (opt.ind < argc) {
		// Manually specified path(s)
		int i;
		for (i = opt.ind; i < argc; i++) {
			const char *arg = argv[i];
			char *alloc_arg = NULL;
			if (*arg == '@') {
				arg++;
				eprintf("Category: %s\n", arg);
				if (!strcmp(arg, "unit")) {
					if (!rz_test_test_run_unit()) {
						state.data.return_val = -1;
						goto beach;
					}
					continue;
				} else if (!strcmp(arg, "fuzz")) {
					if (!fuzz_dir) {
						eprintf("No fuzz dir given. Use -F [dir]\n");
						state.data.return_val = -1;
						goto beach;
					}
					if (!rz_test_test_database_load_fuzz(state.db, fuzz_dir)) {
						eprintf("Failed to load fuzz tests from \"%s\"\n", fuzz_dir);
					}
					continue;
				} else if (!strcmp(arg, "json")) {
					arg = "db/json";
				} else if (!strcmp(arg, "dasm")) {
					arg = "db/asm";
				} else if (!strcmp(arg, "cmds")) {
					arg = "db";
				} else {
					arg = alloc_arg = rz_str_newf("db/%s", arg + 1);
				}
			}
			char *tf = rz_file_abspath_rel(cwd, arg);
			if (!tf || !rz_test_test_database_load(state.db, tf)) {
				eprintf("Failed to load tests from \"%s\"\n", tf);
				rz_test_test_database_free(state.db);
				free(tf);
				free(alloc_arg);
				state.data.return_val = -1;
				goto beach;
			}
			RZ_FREE(alloc_arg);
			free(tf);
		}
	} else {
		// Default db path
		if (!rz_test_test_database_load(state.db, "db")) {
			eprintf("Failed to load tests from ./db\n");
			rz_test_test_database_free(state.db);
			state.data.return_val = -1;
			goto beach;
		}
		if (fuzz_dir && !rz_test_test_database_load_fuzz(state.db, fuzz_dir)) {
			eprintf("Failed to load fuzz tests from \"%s\"\n", fuzz_dir);
		}
	}

	// filter out except_dir
	if (!rz_pvector_empty(except_dir)) {
		void **it;
		rz_pvector_foreach (except_dir, it) {
			const char *p = rz_file_abspath_rel(cwd, (char *)*it), *tp;
			for (ut32 i = 0; i < rz_pvector_len(&state.db->tests); i++) {
				RzTest *test = rz_pvector_at(&state.db->tests, i);
				if (rz_file_is_abspath(test->path)) {
					tp = strdup(test->path);
				} else {
					tp = rz_file_abspath_rel(cwd, test->path);
				}
				if (rz_str_startswith(tp, p)) {
					rz_test_test_free(test);
					rz_pvector_remove_at(&state.db->tests, i--);
				}
				RZ_FREE(tp);
			}
			RZ_FREE(p);
		}
	}

	if (log_mode) {
		// Log mode prints the state after every completed file.
		// The count of tests left per file is stored in a ht.
		HtSP *path_counter = ht_sp_new(HT_STR_DUP, NULL, free);
		state.data.max_path = 0;
		if (path_counter) {
			void **it;
			rz_pvector_foreach (&state.db->tests, it) {
				RzTest *test = *it;
				TestCounter *cnt = ht_sp_find(path_counter, test->path, NULL);
				if (!cnt) {
					size_t path_len = strlen(test->path);
					if (path_len > state.data.max_path) {
						state.data.max_path = path_len;
					}
					cnt = RZ_NEW0(TestCounter);
					ht_sp_insert(path_counter, test->path, cnt);
				}
				cnt->n_tests++;
			}
		}
		state.data.path_counter = path_counter;
	}

	RZ_FREE(cwd);
	uint32_t loaded_tests = rz_pvector_len(&state.db->tests);
	printf("Loaded %u tests.\n", loaded_tests);
	if (nothing) {
		goto coast;
	}

	bool jq_available = rz_test_check_jq_available();
	if (!jq_available) {
		eprintf("Skipping json tests because jq is not available.\n");
		size_t i;
		for (i = 0; i < rz_pvector_len(&state.db->tests);) {
			RzTest *test = rz_pvector_at(&state.db->tests, i);
			if (test->type == RZ_TEST_TYPE_JSON) {
				rz_test_test_free(test);
				rz_pvector_remove_at(&state.db->tests, i);
				continue;
			}
			i++;
		}
	}

	if (rz_pvector_len(&state.db->tests) < 1) {
		eprintf("No tests discovered\n");
		goto coast;
	}

	state.results = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_test_result_info_free);
	if (!state.results) {
		eprintf("Failed to create result queue.\n");
		goto coast;
	}

	state.data.running = rz_atomic_bool_new(true);
	if (!state.data.running) {
		eprintf("Failed to create atomic boolean.\n");
		goto coast;
	}

	RzThread *rth = rz_th_new(result_thread, &state);
	if (!rth) {
		eprintf("Failed to start the result thread.\n");
		return -1;
	}

	eprintf("Using %" PFMTSZu " threads\n", rz_th_request_physical_cores(n_threads));

	state.data.time_start = rz_time_now_mono();
	rz_th_iterate_pvector(&state.db->tests, worker_thread, n_threads, &state);

	// notify the result thread that we finished running all tests.
	rz_atomic_bool_set(state.data.running, false);

	// wait for the result thread to empty the queue.
	rz_th_wait(rth);
	rz_th_free(rth);

	if (output_file) {
		pj_end(state.pj);
		char *results = pj_drain(state.pj);
		rz_file_dump(output_file, (ut8 *)results, strlen(results), false);
		free(results);
	}

coast:
	ht_sp_free(state.data.path_counter);
	rz_atomic_bool_free(state.data.running);
	rz_th_queue_free(state.results);
beach:
	free(output_file);
	free(rizin_cmd);
	free(rz_asm_cmd);
	free(json_test_file);
	free(fuzz_dir);
	rz_pvector_free(except_dir);
#if __WINDOWS__
	if (old_cp) {
		(void)SetConsoleOutputCP(old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)rz_sys_cmdf("chcp %u > NUL", old_cp);
	}
#endif
	return state.data.return_val;
}

static void result_to_json(RzTestState *state, RzTestResultInfo *result) {
	rz_return_if_fail(result);

	PJ *pj = state->pj;
	pj_o(pj);
	pj_k(pj, "type");
	RzTest *test = result->test;
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		pj_s(pj, "cmd");
		pj_ks(pj, "name", test->cmd_test->name.value ? test->cmd_test->name.value : "missing name");
		break;
	case RZ_TEST_TYPE_ASM:
		pj_s(pj, "asm");
		pj_ks(pj, "arch", test->asm_test->arch);
		pj_ki(pj, "bits", test->asm_test->bits);
		pj_kn(pj, "line", test->asm_test->line);
		break;
	case RZ_TEST_TYPE_JSON:
		pj_s(pj, "json");
		pj_ks(pj, "cmd", test->json_test->cmd);
		break;
	case RZ_TEST_TYPE_FUZZ:
		pj_s(pj, "fuzz");
		pj_ks(pj, "file", test->fuzz_test->file);
		break;
	}
	pj_k(pj, "result");
	switch (result->result) {
	case RZ_TEST_RESULT_OK:
		pj_s(pj, "ok");
		break;
	case RZ_TEST_RESULT_FAILED:
		pj_s(pj, "failed");
		break;
	case RZ_TEST_RESULT_BROKEN:
		pj_s(pj, "broken");
		break;
	case RZ_TEST_RESULT_FIXED:
		pj_s(pj, "fixed");
		break;
	}
	pj_kb(pj, "run_failed", result->run_failed);
	pj_kn(pj, "time_elapsed", result->time_elapsed);
	pj_kb(pj, "timeout", result->timeout);
	pj_end(pj);
}

static void worker_thread(void *element, void *user) {
	RzTest *test = (RzTest *)element;
	RzTestState *state = (RzTestState *)user;
	RzTestResultInfo *result = rz_test_run_test(&state->run_config, test);
	rz_th_queue_push(state->results, result, true);
}

static void *result_thread(void *user) {
	TestCounter counter = { 0 };
	RzTestState *state = (RzTestState *)user;
	RzTestResultInfo *result = NULL;
	RzPVector failed_results = { 0 };

	counter.n_tests = rz_pvector_len(&state->db->tests);
	rz_pvector_init(&failed_results, (RzPVectorFree)rz_test_result_info_free);

	while (true) {
		if (!(result = rz_th_queue_pop(state->results, false))) {
			if (rz_atomic_bool_get(state->data.running)) {
				rz_sys_usleep(250);
				continue;
			}
			// queue is empty and there is nothing
			// else to do. we terminate the loop
			break;
		}

		handle_result(state, result, &counter);
		if (state->data.interactive && result->result == RZ_TEST_RESULT_FAILED) {
			rz_pvector_push(&failed_results, result);
		} else {
			rz_test_result_info_free(result);
		}
	}
	ut64 seconds = (rz_time_now_mono() - state->data.time_start) / 1000000;

	print_counter(state, &counter);
	printf("\nFinished in");
	if (seconds > 60) {
		ut64 minutes = seconds / 60;
		printf(" %" PFMT64u " minutes and", minutes);
		seconds -= (minutes * 60);
	}
	printf(" %" PFMT64u " seconds.\n", seconds % 60);

	if (state->data.interactive) {
		interact(state, &failed_results);
		rz_pvector_clear(&failed_results);
	}

	if (state->data.expected_succ > 0 && state->data.expected_succ != counter.ok) {
		state->data.return_val = 1;
	}

	if (state->data.expected_fail > 0 && state->data.expected_fail != counter.xx) {
		state->data.return_val = 1;
	}

	if (state->data.expected_fail < 0 && state->data.expected_succ < 0 && counter.xx) {
		state->data.return_val = 1;
	}

	return NULL;
}

static void print_diff(const char *actual, const char *expected, const char *regexp) {
	RzDiff *d = NULL;
	char *uni = NULL;
	const char *output = actual;

	if (regexp) {
		RzStrBuf *match_str = rz_regex_full_match_str(regexp, actual, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT, "\n");
		output = rz_strbuf_drain(match_str);
	}

	d = rz_diff_lines_new(expected, output, NULL);
	if (!d) {
		goto cleanup;
	}

	uni = rz_diff_unified_text(d, "expected", "actual", false, true);
	if (!uni) {
		goto cleanup;
	}
	puts(uni);
	free(uni);

cleanup:
	rz_diff_free(d);
	if (regexp) {
		free((char *)output);
	}
}

static RzSubprocessOutput *print_runner(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	size_t i;
	for (i = 0; i < env_size; i++) {
		printf("%s=%s ", envvars[i], envvals[i]);
	}
	printf("%s", file);
	for (i = 0; i < args_size; i++) {
		const char *str = args[i];
		if (strpbrk(str, "\n \'\"")) {
			printf(" '%s'", str); // TODO: escape
		} else {
			printf(" %s", str);
		}
	}
	printf("\n");
	return NULL;
}

static void print_result_diff(RzTestRunConfig *config, RzTestResultInfo *result) {
	if (result->run_failed) {
		printf(Color_RED "RUN FAILED (e.g. wrong rizin path)" Color_RESET "\n");
		return;
	}
	switch (result->test->type) {
	case RZ_TEST_TYPE_CMD: {
		rz_test_run_cmd_test(config, result->test->cmd_test, print_runner, NULL);
		const char *expect = result->test->cmd_test->expect.value;
		const char *out = (const char *)result->proc_out->out;
		const char *regexp_out = result->test->cmd_test->regexp_out.value;
		if (expect && !rz_test_cmp_cmd_output(out, expect, regexp_out)) {
			printf("-- stdout\n");
			print_diff(out, expect, regexp_out);
		}
		expect = result->test->cmd_test->expect_err.value;
		const char *err = (const char *)result->proc_out->err;
		const char *regexp_err = result->test->cmd_test->regexp_err.value;
		if (expect && !rz_test_cmp_cmd_output(err, expect, regexp_err)) {
			printf("-- stderr\n");
			print_diff(err, expect, regexp_err);
		} else if (*err) {
			printf("-- stderr\n%s\n", err);
		}
		if (result->proc_out->ret != 0) {
			printf("-- exit status: " Color_RED "%d" Color_RESET "\n", result->proc_out->ret);
		}
		break;
	}
	case RZ_TEST_TYPE_ASM: {
		RzAsmTest *test = result->test->asm_test;
		RzAsmTestOutput *out = result->asm_out;
		char *expect_hex = rz_hex_bin2strdup(test->bytes, test->bytes_size);
		printf("-- <asm> " Color_YELLOW "%s %c--%c %s%s" Color_RESET "\n",
			test->disasm,
			test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE ? '<' : '-',
			test->mode & RZ_ASM_TEST_MODE_ASSEMBLE ? '>' : '-',
			expect_hex ? expect_hex : "",
			test->il ? " ---> <IL>" : "");
		if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
			const char *expect = test->disasm;
			const char *actual = out->disasm;
			if (expect && actual && strcmp(actual, expect)) {
				printf("-- disassembly\n");
				print_diff(actual, expect, NULL);
			}
		}
		if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
			printf("-- assembly\n");
			if (out->bytes && (out->bytes_size != test->bytes_size || memcmp(out->bytes, test->bytes, out->bytes_size))) {
				char *actual = rz_hex_bin2strdup(out->bytes, out->bytes_size);
				print_diff(actual ? actual : "", expect_hex ? expect_hex : "", NULL);
				free(actual);
			}
		}
		if (test->il) {
			const char *expect = test->il;
			const char *actual = out->il;
			const char *report = out->il_report;
			bool il_printed = false;
			const char *hdr = "-- IL\n";
			if (expect && actual && strcmp(actual, expect)) {
				printf("%s", hdr);
				il_printed = true;
				print_diff(actual, expect, NULL);
			}
			if (report) {
				if (!il_printed) {
					printf("%s", hdr);
					if (actual) {
						printf("%s\n", actual);
					}
				}
				printf(Color_RED "%s" Color_RESET "\n", report);
			}
		}
		free(expect_hex);
		break;
	}
	case RZ_TEST_TYPE_JSON:
		break;
	case RZ_TEST_TYPE_FUZZ:
		rz_test_run_fuzz_test(config, result->test->fuzz_test, print_runner, NULL);
		printf("-- stdout\n%s\n", (const char *)result->proc_out->out);
		printf("-- stderr\n%s\n", (const char *)result->proc_out->err);
		printf("-- exit status: " Color_RED "%d" Color_RESET "\n", result->proc_out->ret);
		break;
	}
}

static void print_path_completion(RzTestState *state, RzTestResultInfo *result) {
	if (!state->data.path_counter) {
		return;
	}

	const char *path = result->test->path;
	if (!path) {
		rz_warn_if_reached();
		return;
	}

	TestCounter *cnt = ht_sp_find(state->data.path_counter, path, NULL);
	if (!cnt) {
		rz_warn_if_reached();
		return;
	}

	cnt->n_handled++;
	switch (result->result) {
	case RZ_TEST_RESULT_OK:
		cnt->ok++;
		break;
	case RZ_TEST_RESULT_FAILED:
		cnt->xx++;
		break;
	case RZ_TEST_RESULT_BROKEN:
		cnt->br++;
		break;
	case RZ_TEST_RESULT_FIXED:
		cnt->fx++;
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	if (cnt->n_handled < cnt->n_tests) {
		return;
	}

	const int max_path = state->data.max_path;

	if (cnt->xx > 0) {
		printf(Color_RED "[XX]" Color_RESET " %-*s %8" PFMTSZu " OK  %8" PFMTSZu " BR %8" PFMTSZu " XX %8" PFMTSZu " FX\n",
			max_path, path, cnt->ok, cnt->br, cnt->xx, cnt->fx);
	} else {
		printf(Color_GREEN "[OK]" Color_RESET " %-*s %8" PFMTSZu " OK  %8" PFMTSZu " BR %8" PFMTSZu " XX %8" PFMTSZu " FX\n",
			max_path, path, cnt->ok, cnt->br, cnt->xx, cnt->fx);
	}

	// free the counter.
	ht_sp_delete(state->data.path_counter, path);
}

static void print_counter(RzTestState *state, TestCounter *cnt) {
	printf(RZ_CONS_CLEAR_LINE "[%" PFMTSZu "/%" PFMTSZu "]", cnt->n_tests, cnt->n_handled);
	printf(" %8" PFMTSZu " OK  %8" PFMTSZu " BR %8" PFMTSZu " XX %8" PFMTSZu " FX", cnt->ok, cnt->br, cnt->xx, cnt->fx);
}

static void print_result(RzTestState *state, RzTestResultInfo *result) {
	if (!state->verbose && result->result != RZ_TEST_RESULT_FAILED) {
		return;
	}
	char *name = rz_test_test_name(result->test);
	if (!name) {
		return;
	}
	printf("\n" RZ_CONS_CURSOR_UP RZ_CONS_CLEAR_LINE);
	switch (result->result) {
	case RZ_TEST_RESULT_OK:
		printf(Color_GREEN "[OK]" Color_RESET);
		break;
	case RZ_TEST_RESULT_FAILED:
		printf(Color_RED "[XX]" Color_RESET);
		break;
	case RZ_TEST_RESULT_BROKEN:
		printf(Color_BLUE "[BR]" Color_RESET);
		break;
	case RZ_TEST_RESULT_FIXED:
		printf(Color_CYAN "[FX]" Color_RESET);
		break;
	}
	if (result->timeout) {
		printf(Color_CYAN " TIMEOUT" Color_RESET);
	}
	printf(" %s " Color_YELLOW "%s" Color_RESET "\n", result->test->path, name);
	if (result->result == RZ_TEST_RESULT_FAILED || (state->verbose && result->result == RZ_TEST_RESULT_BROKEN)) {
		print_result_diff(&state->run_config, result);
	}
	free(name);
}

static void handle_result(RzTestState *state, RzTestResultInfo *result, TestCounter *counter) {
#if __WINDOWS__
	setvbuf(stdout, NULL, _IOFBF, 8192);
#endif

	counter->n_handled++;
	switch (result->result) {
	case RZ_TEST_RESULT_OK:
		counter->ok++;
		break;
	case RZ_TEST_RESULT_FAILED:
		counter->xx++;
		break;
	case RZ_TEST_RESULT_BROKEN:
		counter->br++;
		break;
	case RZ_TEST_RESULT_FIXED:
		counter->fx++;
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	if (state->pj) {
		result_to_json(state, result);
	}

	print_result(state, result);
	print_path_completion(state, result);
	if (!state->data.path_counter) {
		print_counter(state, counter);
	}

	// ensure to flush stdout
	fflush(stdout);

#if __WINDOWS__
	setvbuf(stdout, NULL, _IONBF, 0);
#endif
}

static void interact(RzTestState *state, RzPVector /*<RzTestResultInfo *>*/ *failed_results) {
	if (rz_pvector_empty(failed_results)) {
		return;
	}

#if __WINDOWS__
	(void)SetConsoleOutputCP(65001); // UTF-8
#endif
	printf("\n");
	printf("#####################\n");
	printf(" %" PFMT64u " failed test(s) " UTF8_POLICE_CARS_REVOLVING_LIGHT "\n",
		(ut64)rz_pvector_len(failed_results));

	void **it;
	ut32 cnt = 0;
	rz_pvector_foreach (failed_results, it) {
		cnt++;
		RzTestResultInfo *result = *it;
		if (result->test->type != RZ_TEST_TYPE_CMD && result->test->type != RZ_TEST_TYPE_ASM) {
			continue;
		}

		printf("#####################\n\n");
		char *name = rz_test_test_name(result->test);
		if (name) {
			printf(Color_RED "[XX]" Color_RESET " %s " Color_YELLOW "%s" Color_RESET " (%d/%zu)\n", result->test->path, name, cnt, rz_pvector_len(failed_results));
			free(name);
		}
		print_result_diff(&state->run_config, result);
		bool have_commands = result->test->type == RZ_TEST_TYPE_CMD;
	menu:
		printf("Wat do?    "
		       "(f)ix " UTF8_WHITE_HEAVY_CHECK_MARK UTF8_VS16 UTF8_VS16 UTF8_VS16 "    "
		       "(i)gnore " UTF8_SEE_NO_EVIL_MONKEY "    "
		       "(b)roken " UTF8_SKULL_AND_CROSSBONES UTF8_VS16 UTF8_VS16 UTF8_VS16 "    "
		       "%s"
		       "(q)uit " UTF8_DOOR "\n",
			have_commands ? "(c)ommands " UTF8_KEYBOARD UTF8_VS16 "    " : "");
		printf("> ");
		char buf[0x30];
		if (!fgets(buf, sizeof(buf), stdin)) {
			break;
		}
		if (strlen(buf) != 2) {
			goto menu;
		}
		switch (buf[0]) {
		case 'f':
			if (!interact_fix(result, failed_results)) {
				printf("This test has failed too hard to be fixed.\n");
				goto menu;
			}
			break;
		case 'i':
			break;
		case 'b':
			interact_break(result, failed_results);
			break;
		case 'c':
			if (have_commands) {
				interact_commands(result, failed_results);
				break;
			}
			goto menu;
		case 'q':
			return;
		default:
			goto menu;
		}
	}
}

static char *format_cmd_kv(const char *key, const char *val) {
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_strbuf_appendf(&buf, "%s=", key);
	if (strchr(val, '\n')) {
		rz_strbuf_appendf(&buf, "<<EOF\n%sEOF", val);
	} else {
		rz_strbuf_append(&buf, val);
	}
	return rz_strbuf_drain_nofree(&buf);
}

static char *replace_lines(const char *src, size_t from, size_t to, const char *news) {
	const char *begin = src;
	size_t line = 1;
	while (line < from) {
		begin = strchr(begin, '\n');
		if (!begin) {
			break;
		}
		begin++;
		line++;
	}
	if (!begin) {
		return NULL;
	}

	const char *end = begin;
	while (line < to) {
		end = strchr(end, '\n');
		if (!end) {
			break;
		}
		end++;
		line++;
	}

	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_strbuf_append_n(&buf, src, begin - src);
	rz_strbuf_append(&buf, news);
	rz_strbuf_append(&buf, "\n");
	if (end) {
		rz_strbuf_append(&buf, end);
	}
	return rz_strbuf_drain_nofree(&buf);
}

// After editing a test, fix the line numbers previously saved for all the other tests
static void fixup_tests(RzPVector /*<RzTestResultInfo *>*/ *results, const char *edited_file, ut64 start_line, st64 delta) {
	void **it;
	rz_pvector_foreach (results, it) {
		RzTestResultInfo *result = *it;
		if (result->test->type != RZ_TEST_TYPE_CMD) {
			continue;
		}
		if (result->test->path != edited_file) { // this works because all the paths come from the string pool
			continue;
		}
		RzCmdTest *test = result->test->cmd_test;
		test->run_line += delta;

#define DO_KEY_STR(key, field) \
	if (test->field.value) { \
		if (test->field.line_begin >= start_line) { \
			test->field.line_begin += delta; \
		} \
		if (test->field.line_end >= start_line) { \
			test->field.line_end += delta; \
		} \
	}

#define DO_KEY_BOOL(key, field) \
	if (test->field.set && test->field.line >= start_line) { \
		test->field.line += delta; \
	}

#define DO_KEY_NUM(key, field) \
	if (test->field.set && test->field.line >= start_line) { \
		test->field.line += delta; \
	}

		RZ_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, DO_KEY_BOOL, DO_KEY_NUM)
#undef DO_KEY_STR
#undef DO_KEY_BOOL
#undef DO_KEY_NUM
	}
}

static char *read_test_file_for_fix(const char *path) {
	char *content = rz_file_slurp(path, NULL);
	if (!content) {
		eprintf("Failed to read file \"%s\"\n", path);
	}
	return content;
}

static void save_test_file_for_fix(const char *path, const char *newc) {
	if (rz_file_dump(path, (const ut8 *)newc, -1, false)) {
#if __UNIX__
		sync();
#endif
	} else {
		eprintf("Failed to write file \"%s\"\n", path);
	}
}

static char *replace_cmd_kv(const char *path, const char *content, size_t line_begin, size_t line_end, const char *key, const char *value, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	char *kv = format_cmd_kv(key, value);
	if (!kv) {
		return NULL;
	}
	size_t kv_lines = rz_str_char_count(kv, '\n') + 1;
	char *newc = replace_lines(content, line_begin, line_end, kv);
	free(kv);
	if (!newc) {
		return NULL;
	}
	size_t lines_before = line_end - line_begin;
	st64 delta = (st64)kv_lines - (st64)lines_before;
	if (line_end == line_begin) {
		delta++;
	}
	fixup_tests(fixup_results, path, line_end, delta);
	return newc;
}

static void replace_cmd_kv_file(const char *path, ut64 line_begin, ut64 line_end, const char *key, const char *value, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	char *content = read_test_file_for_fix(path);
	if (!content) {
		return;
	}
	char *newc = replace_cmd_kv(path, content, line_begin, line_end, key, value, fixup_results);
	free(content);
	if (!newc) {
		return;
	}
	save_test_file_for_fix(path, newc);
	free(newc);
}

static bool interact_fix_cmd(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	assert(result->test->type == RZ_TEST_TYPE_CMD);
	if (result->run_failed || result->proc_out->ret != 0) {
		return false;
	}
	RzCmdTest *test = result->test->cmd_test;
	RzSubprocessOutput *out = result->proc_out;
	if (test->expect.value && out->out) {
		replace_cmd_kv_file(result->test->path, test->expect.line_begin, test->expect.line_end, "EXPECT", (char *)out->out, fixup_results);
	}
	if (test->expect_err.value && out->err) {
		replace_cmd_kv_file(result->test->path, test->expect_err.line_begin, test->expect_err.line_end, "EXPECT_ERR", (char *)out->err, fixup_results);
	}
	return true;
}

static void replace_file_line(const char *path, ut64 line_idx, const char *line_new) {
	char *content = read_test_file_for_fix(path);
	if (!content) {
		return;
	}
	char *newc = replace_lines(content, line_idx, line_idx + 1, line_new);
	free(content);
	if (!newc) {
		return;
	}
	save_test_file_for_fix(path, newc);
	free(newc);
}

static void replace_asm_test(RZ_NONNULL const char *path, ut64 line_idx,
	int mode, RZ_NONNULL const char *disasm, RZ_NONNULL const ut8 *bytes, size_t bytes_sz, ut64 offset, RZ_NULLABLE const char *il) {
	char *hex = rz_hex_bin2strdup(bytes, bytes_sz);
	if (!hex) {
		return;
	}
	char offset_str[0x20];
	if ((!offset && !il) || snprintf(offset_str, sizeof(offset_str), " 0x%" PFMT64x, offset) < 0) {
		*offset_str = '\0';
	}
	char *line = rz_str_newf("%s%s%s%s \"%s\" %s%s%s%s",
		(mode & RZ_ASM_TEST_MODE_ASSEMBLE) ? "a" : "",
		(mode & RZ_ASM_TEST_MODE_DISASSEMBLE) ? "d" : "",
		(mode & RZ_ASM_TEST_MODE_BIG_ENDIAN) ? "E" : "",
		(mode & RZ_ASM_TEST_MODE_BROKEN) ? "B" : "",
		disasm, hex, offset_str, il ? " " : "", il ? il : "");
	free(hex);
	if (!line) {
		return;
	}
	replace_file_line(path, line_idx, line);
	free(line);
}

/**
 * Check if both assembly and disassembly passes failed,
 * making it non-trivial to repair automatically.
 */
static bool asm_test_failed_both_ways(RzAsmTest *test, RzAsmTestOutput *out) {
	// check that both ways are requested
	if (!(test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) || !(test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE)) {
		return false;
	}
	// check that disasm is wrong
	if (out->disasm && !strcmp(test->disasm, out->disasm)) {
		return false;
	}
	// check that asm is wrong too
	if (out->bytes && out->bytes_size == test->bytes_size && !memcmp(out->bytes, test->bytes, test->bytes_size)) {
		return false;
	}
	// determined that both ways are broken
	return true;
}

static bool interact_fix_asm(RzTestResultInfo *result) {
	assert(result->test->type == RZ_TEST_TYPE_ASM);
	RzAsmTest *test = result->test->asm_test;
	RzAsmTestOutput *out = result->asm_out;

	const char *disasm = test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE ? out->disasm : test->disasm;
	if (!disasm) {
		return false;
	}

	const ut8 *bytes;
	size_t bytes_sz;
	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		bytes = out->bytes;
		bytes_sz = out->bytes_size;
	} else {
		bytes = test->bytes;
		bytes_sz = test->bytes_size;
	}
	if (!bytes) {
		return false;
	}

	if (asm_test_failed_both_ways(test, out)) {
		// both disasm and asm failed, so trying to fix here would likely only make things worse
		return false;
	}

	if (test->il && (out->il_failed || !out->il)) {
		// IL wasn't lifted or validation failed, this can only be fixed in code
		return false;
	}

	replace_asm_test(result->test->path, test->line, test->mode, disasm, bytes, bytes_sz, test->offset, out->il);
	return true;
}

static bool interact_fix(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	switch (result->test->type) {
	case RZ_TEST_TYPE_CMD:
		return interact_fix_cmd(result, fixup_results);
	case RZ_TEST_TYPE_ASM:
		return interact_fix_asm(result);
	default:
		return false;
	}
}

static void interact_break_cmd(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	assert(result->test->type == RZ_TEST_TYPE_CMD);
	RzCmdTest *test = result->test->cmd_test;
	ut64 line_begin;
	ut64 line_end;
	if (test->broken.set) {
		line_begin = test->broken.set;
		line_end = line_begin + 1;
	} else {
		line_begin = line_end = test->run_line;
	}
	replace_cmd_kv_file(result->test->path, line_begin, line_end, "BROKEN", "1", fixup_results);
}

static void interact_break_asm(RzTestResultInfo *result) {
	assert(result->test->type == RZ_TEST_TYPE_ASM);
	RzAsmTest *test = result->test->asm_test;
	replace_asm_test(result->test->path, test->line,
		test->mode | RZ_ASM_TEST_MODE_BROKEN, test->disasm, test->bytes, test->bytes_size, test->offset, test->il);
}

static void interact_break(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	switch (result->test->type) {
	case RZ_TEST_TYPE_CMD:
		interact_break_cmd(result, fixup_results);
		break;
	case RZ_TEST_TYPE_ASM:
		interact_break_asm(result);
		break;
	default:
		break;
	}
}

static void interact_commands(RzTestResultInfo *result, RzPVector /*<RzTestResultInfo *>*/ *fixup_results) {
	assert(result->test->type == RZ_TEST_TYPE_CMD);
	RzCmdTest *test = result->test->cmd_test;
	if (!test->cmds.value) {
		return;
	}
	char *name = NULL;
	int fd = rz_file_mkstemp("rz-test-cmds", &name);
	if (fd == -1) {
		free(name);
		eprintf("Failed to open tmp file\n");
		return;
	}
	size_t cmds_sz = strlen(test->cmds.value);
	if (write(fd, test->cmds.value, cmds_sz) != cmds_sz) {
		eprintf("Failed to write to tmp file\n");
		free(name);
		close(fd);
		return;
	}
	close(fd);

	char *editor = rz_sys_getenv("EDITOR");
	if (!editor || !*editor) {
		free(editor);
		editor = strdup("vim");
		if (!editor) {
			free(name);
			return;
		}
	}
	rz_sys_cmdf("%s '%s'", editor, name);
	free(editor);

	char *newcmds = rz_file_slurp(name, NULL);
	if (!newcmds) {
		eprintf("Failed to read edited command file\n");
		free(name);
		return;
	}
	rz_str_trim(newcmds);

	// if it's multiline we want exactly one trailing newline
	if (strchr(newcmds, '\n')) {
		char *tmp = newcmds;
		newcmds = rz_str_newf("%s\n", newcmds);
		free(tmp);
		if (!newcmds) {
			free(name);
			return;
		}
	}

	replace_cmd_kv_file(result->test->path, test->cmds.line_begin, test->cmds.line_end, "CMDS", newcmds, fixup_results);
	free(name);
	free(newcmds);
}

int MAIN_NAME(int argc, const ARGV_TYPE **argv) {
	char **utf8_argv = ARGV_TYPE_TO_UTF8(argc, argv);
	int ret = rz_test_main(argc, (const char **)utf8_argv);
	FREE_UTF8_ARGV(argc, utf8_argv);
	return ret;
}
