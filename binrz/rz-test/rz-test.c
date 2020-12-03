// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test.h"
#include <assert.h>

#define WORKERS_DEFAULT        8
#define RIZIN_CMD_DEFAULT    "rizin"
#define RZ_ASM_CMD_DEFAULT      "rz-asm"
#define JSON_TEST_FILE_DEFAULT "bins/elf/crackme0x00b"
#define TIMEOUT_DEFAULT        960

#define STRV(x) #x
#define STR(x) STRV(x)
#define WORKERS_DEFAULT_STR STR(WORKERS_DEFAULT)
#define TIMEOUT_DEFAULT_STR STR(TIMEOUT_DEFAULT)

typedef struct rz_test_state_t {
	RzTestRunConfig run_config;
	bool verbose;
	RzTestDatabase *db;
	PJ *test_results;

	RzThreadCond *cond; // signaled from workers to main thread to update status
	RzThreadLock *lock; // protects everything below
	HtPP *path_left; // char * (path to test file) => ut64 * (count of remaining tests)
	RzPVector completed_paths;
	ut64 ok_count;
	ut64 xx_count;
	ut64 br_count;
	ut64 fx_count;
	RzPVector queue;
	RzPVector results;
} RzTestState;

static RzThreadFunctionRet worker_th(RzThread *th);
static void print_state(RzTestState *state, ut64 prev_completed);
static void print_log(RzTestState *state, ut64 prev_completed, ut64 prev_paths_completed);
static void interact(RzTestState *state);
static void interact_fix(RzTestResultInfo *result, RzPVector *fixup_results);
static void interact_break(RzTestResultInfo *result, RzPVector *fixup_results);
static void interact_commands(RzTestResultInfo *result, RzPVector *fixup_results);
static void interact_diffchar(RzTestResultInfo *result);

static int help(bool verbose) {
	printf ("Usage: rz-test [-qvVnL] [-j threads] [test file/dir | @test-type]\n");
	if (verbose) {
		printf (
		" -h           print this help\n"
		" -v           show version\n"
		" -q           quiet\n"
		" -V           verbose\n"
		" -i           interactive mode\n"
		" -n           do nothing (don't run any test, just load/parse them)\n"
		" -L           log mode (better printing for CI, logfiles, etc.)\n"
		" -F [dir]     run fuzz tests (open and default analysis) on all files in the given dir\n"
		" -j [threads] how many threads to use for running tests concurrently (default is "WORKERS_DEFAULT_STR")\n"
		" -r [rizin] path to rizin executable (default is "RIZIN_CMD_DEFAULT")\n"
		" -m [rz-asm]   path to rz-asm executable (default is "RZ_ASM_CMD_DEFAULT")\n"
		" -f [file]    file to use for json tests (default is "JSON_TEST_FILE_DEFAULT")\n"
		" -C [dir]     chdir before running rz_test (default follows executable symlink + test/new\n"
		" -t [seconds] timeout per test (default is "TIMEOUT_DEFAULT_STR")\n"
		" -o [file]    output test run information in JSON format to file"
		"\n"
		"Supported test types: @json @unit @fuzz @cmds\n"
		"OS/Arch for archos tests: "RZ_TEST_ARCH_OS"\n");
	}
	return 1;
}

static void path_left_free_kv(HtPPKv *kv) {
	free (kv->value);
}

static bool rz_test_chdir(const char *argv0) {
#if __UNIX__
	if (rz_file_is_directory ("db")) {
		return true;
	}
	char src_path[PATH_MAX];
	char *rz_test_path = rz_file_path (argv0);
	bool found = false;
	if (readlink (rz_test_path, src_path, sizeof (src_path)) != -1) {
		char *p = strstr (src_path, RZ_SYS_DIR "binrz"RZ_SYS_DIR"rz_test"RZ_SYS_DIR"rz_test");
		if (p) {
			*p = 0;
			strcat (src_path, RZ_SYS_DIR"test"RZ_SYS_DIR);
			if (rz_file_is_directory (src_path)) {
				if (chdir (src_path) != -1) {
					eprintf ("Running from %s\n", src_path);
					found = true;
				} else {
					eprintf ("Cannot find '%s' directory\n", src_path);
				}
			}
		}
	}
	free (rz_test_path);
	return found;
#else
	return false;
#endif
}

static bool rz_test_test_run_unit(void) {
	return rz_sandbox_system ("make -C unit all run", 1) == 0;
}

static bool rz_test_chdir_fromtest(const char *test_path) {
	if (*test_path == '@') {
		test_path = "";
	}
	char *abs_test_path = rz_file_abspath (test_path);
	if (!rz_file_is_directory (abs_test_path)) {
		char *last_slash = (char *)rz_str_lchr (abs_test_path, RZ_SYS_DIR[0]);
		if (last_slash) {
			*last_slash = 0;
		}
	}
	if (chdir (abs_test_path) == -1) {
		free (abs_test_path);
		return false;
	}
	free (abs_test_path);
	bool found = false;
	char *cwd = NULL;
	char *old_cwd = NULL;
	while (true) {
		cwd = rz_sys_getdir ();
		if (old_cwd && !strcmp (old_cwd, cwd)) {
			break;
		}
		if (rz_file_is_directory ("test")) {
			rz_sys_chdir ("test");
			if (rz_file_is_directory ("db")) {
				found = true;
				eprintf ("Running from %s\n", cwd);
				break;
			}
			rz_sys_chdir ("..");
		}
		if (rz_file_is_directory ("db")) {
			found = true;
			eprintf ("Running from %s\n", cwd);
			break;
		}
		free (old_cwd);
		old_cwd = cwd;
		cwd = NULL;
		if (chdir ("..") == -1) {
			break;
		}
	}
	free (old_cwd);
	free (cwd);
	return found;
}

int main(int argc, char **argv) {
	int workers_count = WORKERS_DEFAULT;
	bool verbose = false;
	bool nothing = false;
	bool quiet = false;
	bool log_mode = false;
	bool interactive = false;
	char *rizin_cmd = NULL;
	char *rz_asm_cmd = NULL;
	char *json_test_file = NULL;
	char *output_file = NULL;
	char *fuzz_dir = NULL;
	const char *rz_test_dir = NULL;
	ut64 timeout_sec = TIMEOUT_DEFAULT;
	int ret = 0;

#if __WINDOWS__
	UINT old_cp = GetConsoleOutputCP ();
	{
		HANDLE streams[] = { GetStdHandle (STD_OUTPUT_HANDLE), GetStdHandle (STD_ERROR_HANDLE) };
		DWORD mode;
		int i;
		for (i = 0; i < RZ_ARRAY_SIZE (streams); i++) {
			GetConsoleMode (streams[i], &mode);
			SetConsoleMode (streams[i],
			                mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		}
	}
#endif

	RzGetopt opt;
	rz_getopt_init (&opt, argc, (const char **)argv, "hqvj:r:m:f:C:LnVt:F:io:");

	int c;
	while ((c = rz_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'h':
			ret = help (true);
			goto beach;
		case 'q':
			quiet = true;
			break;
		case 'v':
			if (quiet) {
				printf (RZ_VERSION "\n");
			} else {
				char *s = rz_str_version ("rz_test");
				printf ("%s\n", s);
				free (s);
			}
			return 0;
		case 'V':
			verbose = true;
			break;
		case 'i':
			interactive = true;
			break;
		case 'L':
			log_mode = true;
			break;
		case 'F':
			free (fuzz_dir);
			fuzz_dir = strdup (opt.arg);
			break;
		case 'j':
			workers_count = atoi (opt.arg);
			if (workers_count <= 0) {
				eprintf ("Invalid thread count\n");
				ret = help (false);
				goto beach;
			}
			break;
		case 'r':
			free (rizin_cmd);
			rizin_cmd = strdup (opt.arg);
			break;
		case 'C':
			rz_test_dir = opt.arg;
			break;
		case 'n':
			nothing = true;
			break;
		case 'm':
			free (rz_asm_cmd);
			rz_asm_cmd = strdup (opt.arg);
			break;
		case 'f':
			free (json_test_file);
			json_test_file = strdup (opt.arg);
			break;
		case 't':
			timeout_sec = strtoull (opt.arg, NULL, 0);
			if (!timeout_sec) {
				timeout_sec = UT64_MAX;
			}
			break;
		case 'o':
			free (output_file);
			output_file = strdup (opt.arg);
			break;
		default:
			ret = help (false);
			goto beach;
		}
	}

	char *cwd = rz_sys_getdir ();
	if (rz_test_dir) {
		if (chdir (rz_test_dir) == -1) {
			eprintf ("Cannot find %s directory.\n", rz_test_dir);
			return -1;
		}
	} else {
		bool dir_found = (opt.ind < argc && argv[opt.ind][0] != '.')
			? rz_test_chdir_fromtest (argv[opt.ind])
			: rz_test_chdir (argv[0]);
		if (!dir_found) {
			eprintf ("Cannot find db/ directory related to the given test.\n");
			return -1;
		}
	}

	if (fuzz_dir) {
		char *tmp = fuzz_dir;
		fuzz_dir = rz_file_abspath_rel (cwd, fuzz_dir);
		free (tmp);
	}

	if (!rz_subprocess_init ()) {
		eprintf ("Subprocess init failed\n");
		return -1;
	}
	atexit (rz_subprocess_fini);

	ut64 time_start = rz_time_now_mono ();
	RzTestState state = {{0}};
	state.run_config.rz_cmd = rizin_cmd ? rizin_cmd : RIZIN_CMD_DEFAULT;
	state.run_config.rz_asm_cmd = rz_asm_cmd ? rz_asm_cmd : RZ_ASM_CMD_DEFAULT;
	state.run_config.json_test_file = json_test_file ? json_test_file : JSON_TEST_FILE_DEFAULT;
	state.run_config.timeout_ms = timeout_sec > UT64_MAX / 1000 ? UT64_MAX : timeout_sec * 1000;
	state.verbose = verbose;
	state.db = rz_test_test_database_new ();
	if (!state.db) {
		return -1;
	}
	rz_pvector_init (&state.queue, NULL);
	rz_pvector_init (&state.results, (RzPVectorFree)rz_test_test_result_info_free);
	rz_pvector_init (&state.completed_paths, NULL);
	if (output_file) {
		state.test_results = pj_new ();
		pj_a (state.test_results);
	}
	state.lock = rz_th_lock_new (false);
	if (!state.lock) {
		return -1;
	}
	state.cond = rz_th_cond_new ();
	if (!state.cond) {
		return -1;
	}

	if (opt.ind < argc) {
		// Manually specified path(s)
		int i;
		for (i = opt.ind; i < argc; i++) {
			const char *arg = argv[i];
			if (*arg == '@') {
				arg++;
				eprintf ("Category: %s\n", arg);
				if (!strcmp (arg, "unit")) {
					if (!rz_test_test_run_unit ()) {
						return -1;
					}
					continue;
				} else if (!strcmp (arg, "fuzz")) {
					if (!fuzz_dir) {
						eprintf ("No fuzz dir given. Use -F [dir]\n");
						return -1;
					}
					if (!rz_test_test_database_load_fuzz (state.db, fuzz_dir)) {
						eprintf ("Failed to load fuzz tests from \"%s\"\n", fuzz_dir);
					}
					continue;
				} else if (!strcmp (arg, "json")) {
					arg = "db/json";
				} else if (!strcmp (arg, "dasm")) {
					arg = "db/asm";
				} else if (!strcmp (arg, "cmds")) {
					arg = "db";
				} else {
					arg = rz_str_newf ("db/%s", arg + 1);
				}
			}
			char *tf = rz_file_abspath_rel (cwd, arg);
			if (!tf || !rz_test_test_database_load (state.db, tf)) {
				eprintf ("Failed to load tests from \"%s\"\n", tf);
				rz_test_test_database_free (state.db);
				free (tf);
				return -1;
			}
			free (tf);
		}
	} else {
		// Default db path
		if (!rz_test_test_database_load (state.db, "db")) {
			eprintf ("Failed to load tests from ./db\n");
			rz_test_test_database_free (state.db);
			return -1;
		}
		if (fuzz_dir && !rz_test_test_database_load_fuzz (state.db, fuzz_dir)) {
			eprintf ("Failed to load fuzz tests from \"%s\"\n", fuzz_dir);
		}
	}

	RZ_FREE (cwd);
	uint32_t loaded_tests = rz_pvector_len (&state.db->tests);
	printf ("Loaded %u tests.\n", loaded_tests);
	if (nothing) {
		goto coast;
	}

	bool jq_available = rz_test_check_jq_available ();
	if (!jq_available) {
		eprintf ("Skipping json tests because jq is not available.\n");
		size_t i;
		for (i = 0; i < rz_pvector_len (&state.db->tests);) {
			RzTest *test = rz_pvector_at (&state.db->tests, i);
			if (test->type == RZ_TEST_TYPE_JSON) {
				rz_test_test_free (test);
				rz_pvector_remove_at (&state.db->tests, i);
				continue;
			}
			i++;
		}
	}

	rz_pvector_insert_range (&state.queue, 0, state.db->tests.v.a, rz_pvector_len (&state.db->tests));

	if (log_mode) {
		// Log mode prints the state after every completed file.
		// The count of tests left per file is stored in a ht.
		state.path_left = ht_pp_new (NULL, path_left_free_kv, NULL);
		if (state.path_left) {
			void **it;
			rz_pvector_foreach (&state.queue, it) {
				RzTest *test = *it;
				ut64 *count = ht_pp_find (state.path_left, test->path, NULL);
				if (!count) {
					count = malloc (sizeof (ut64));
					*count = 0;
					ht_pp_insert (state.path_left, test->path, count);
				}
				(*count)++;
			}
		}
	}

	rz_th_lock_enter (state.lock);

	RzPVector workers;
	rz_pvector_init (&workers, NULL);
	int i;
	for (i = 0; i < workers_count; i++) {
		RzThread *th = rz_th_new (worker_th, &state, 0);
		if (!th) {
			eprintf ("Failed to start thread.\n");
			exit (-1);
		}
		rz_pvector_push (&workers, th);
	}

	ut64 prev_completed = UT64_MAX;
	ut64 prev_paths_completed = 0;
	while (true) {
		ut64 completed = (ut64)rz_pvector_len (&state.results);
		if (log_mode) {
			print_log (&state, prev_completed, prev_paths_completed);
		} else if (completed != prev_completed) {
			print_state (&state, prev_completed);
		}
		prev_completed = completed;
		prev_paths_completed = (ut64)rz_pvector_len (&state.completed_paths);
		if (completed == rz_pvector_len (&state.db->tests)) {
			break;
		}
		rz_th_cond_wait (state.cond, state.lock);
	}

	rz_th_lock_leave (state.lock);

	printf ("\n");

	void **it;
	rz_pvector_foreach (&workers, it) {
		RzThread *th = *it;
		rz_th_wait (th);
		rz_th_free (th);
	}
	rz_pvector_clear (&workers);

	ut64 seconds = (rz_time_now_mono () - time_start) / 1000000;
	printf ("Finished in");
	if (seconds > 60) {
		ut64 minutes = seconds / 60;
		printf (" %"PFMT64d" minutes and", seconds / 60);
		seconds -= (minutes * 60);
	}
	printf (" %"PFMT64d" seconds.\n", seconds % 60);

	if (output_file) {
		pj_end (state.test_results);
		char *results = pj_drain (state.test_results);
		rz_file_dump (output_file, (ut8 *)results, strlen (results), false);
		free (results);
	}

	if (interactive) {
		interact (&state);
	}

	if (state.xx_count) {
		ret = 1;
	}

coast:
	rz_pvector_clear (&state.queue);
	rz_pvector_clear (&state.results);
	rz_pvector_clear (&state.completed_paths);
	rz_test_test_database_free (state.db);
	rz_th_lock_free (state.lock);
	rz_th_cond_free (state.cond);
beach:
	free (rizin_cmd);
	free (rz_asm_cmd);
	free (json_test_file);
	free (fuzz_dir);
#if __WINDOWS__
	if (old_cp) {
		(void)SetConsoleOutputCP (old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)rz_sys_cmdf ("chcp %u > NUL", old_cp);
	}
#endif
	return ret;
}

static void test_result_to_json(PJ *pj, RzTestResultInfo *result) {
	rz_return_if_fail (pj && result);
	pj_o (pj);
	pj_k (pj, "type");
	RzTest *test = result->test;
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		pj_s (pj, "cmd");
		pj_ks (pj, "name", test->cmd_test->name.value);
		break;
	case RZ_TEST_TYPE_ASM:
		pj_s (pj, "asm");
		pj_ks (pj, "arch", test->asm_test->arch);
		pj_ki (pj, "bits", test->asm_test->bits);
		pj_kn (pj, "line", test->asm_test->line);
		break;
	case RZ_TEST_TYPE_JSON:
		pj_s (pj, "json");
		pj_ks (pj, "cmd", test->json_test->cmd);
		break;
	case RZ_TEST_TYPE_FUZZ:
		pj_s (pj, "fuzz");
		pj_ks (pj, "file", test->fuzz_test->file);
		break;
	}
	pj_k (pj, "result");
	switch (result->result) {
	case RZ_TEST_RESULT_OK:
		pj_s (pj, "ok");
		break;
	case RZ_TEST_RESULT_FAILED:
		pj_s (pj, "failed");
		break;
	case RZ_TEST_RESULT_BROKEN:
		pj_s (pj, "broken");
		break;
	case RZ_TEST_RESULT_FIXED:
		pj_s (pj, "fixed");
		break;
	}
	pj_kb (pj, "run_failed", result->run_failed);
	pj_kn (pj, "time_elapsed", result->time_elapsed);
	pj_kb (pj, "timeout", result->timeout);
	pj_end (pj);
}

static RzThreadFunctionRet worker_th(RzThread *th) {
	RzTestState *state = th->user;
	rz_th_lock_enter (state->lock);
	while (true) {
		if (rz_pvector_empty (&state->queue)) {
			break;
		}
		RzTest *test = rz_pvector_pop (&state->queue);
		rz_th_lock_leave (state->lock);

		RzTestResultInfo *result = rz_test_run_test (&state->run_config, test);

		rz_th_lock_enter (state->lock);
		rz_pvector_push (&state->results, result);
		switch (result->result) {
		case RZ_TEST_RESULT_OK:
			state->ok_count++;
			break;
		case RZ_TEST_RESULT_FAILED:
			state->xx_count++;
			break;
		case RZ_TEST_RESULT_BROKEN:
			state->br_count++;
			break;
		case RZ_TEST_RESULT_FIXED:
			state->fx_count++;
			break;
		}
		if (state->path_left) {
			ut64 *count = ht_pp_find (state->path_left, test->path, NULL);
			if (count) {
				(*count)--;
				if (!*count) {
					rz_pvector_push (&state->completed_paths, (void *)test->path);
				}
			}
		}
		rz_th_cond_signal (state->cond);
	}
	rz_th_lock_leave (state->lock);
	return RZ_TH_STOP;
}

static void print_diff(const char *actual, const char *expected, bool diffchar) {
	RzDiff *d = rz_diff_new ();
#ifdef __WINDOWS__
	d->diff_cmd = "git diff --no-index";
#endif
	if (diffchar) {
		RzDiffChar *diff = rz_diffchar_new ((const ut8 *)expected, (const ut8 *)actual);
		if (diff) {
			rz_diff_free (d);
			rz_diffchar_print (diff);
			rz_diffchar_free (diff);
			return;
		}
		d->diff_cmd = "git diff --no-index --word-diff=porcelain --word-diff-regex=.";
	}
	rz_subprocess_lock (); // diffing may fork(), potentially preventing pipes from other subprocs to be closed completely
	char *uni = rz_diff_buffers_to_string (d, (const ut8 *)expected, (int)strlen (expected),
	                                      (const ut8 *)actual, (int)strlen (actual));
	rz_subprocess_unlock ();
	rz_diff_free (d);

	RzList *lines = rz_str_split_duplist (uni, "\n", false);
	RzListIter *it;
	char *line;
	bool header_found = false;
	rz_list_foreach (lines, it, line) {
		if (!header_found) {
			if (rz_str_startswith (line, "+++ ")) {
				header_found = true;
			}
			continue;
		}
		if (rz_str_startswith (line, "@@ ") && rz_str_endswith (line, " @@")) {
			printf ("%s%s%s\n", Color_CYAN, line, Color_RESET);
			continue;
		}
		bool color = true;
		char c = *line;
		switch (c) {
		case '+':
			printf ("%s"Color_INSERT, diffchar ? Color_BGINSERT : "");
			break;
		case '-':
			printf ("%s"Color_DELETE, diffchar ? Color_BGDELETE : "");
			break;
		case '~': // can't happen if !diffchar
			printf ("\n");
			continue;
		default:
			color = false;
			break;
		}
		if (diffchar) {
			printf ("%s", *line ? line + 1 : "");
		} else {
			printf ("%s\n", line);
		}
		if (color) {
			printf ("%s", Color_RESET);
		}
	}
	rz_list_free (lines);
	free (uni);
	printf ("\n");
}

static RzSubprocessOutput *print_runner(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	size_t i;
	for (i = 0; i < env_size; i++) {
		printf ("%s=%s ", envvars[i], envvals[i]);
	}
	printf ("%s", file);
	for (i = 0; i < args_size; i++) {
		const char *str = args[i];
		if (strpbrk (str, "\n \'\"")) {
			printf (" '%s'", str); // TODO: escape
		} else {
			printf (" %s", str);
		}
	}
	printf ("\n");
	return NULL;
}

static void print_result_diff(RzTestRunConfig *config, RzTestResultInfo *result) {
	if (result->run_failed) {
		printf (Color_RED "RUN FAILED (e.g. wrong rizin path)" Color_RESET "\n");
		return;
	}
	switch (result->test->type) {
	case RZ_TEST_TYPE_CMD: {
		rz_test_run_cmd_test (config, result->test->cmd_test, print_runner, NULL);
		const char *expect = result->test->cmd_test->expect.value;
		if (expect && strcmp (result->proc_out->out, expect)) {
			printf ("-- stdout\n");
			print_diff (result->proc_out->out, expect, false);
		}
		expect = result->test->cmd_test->expect_err.value;
		const char *err = result->proc_out->err;
		if (expect && strcmp (err, expect)) {
			printf ("-- stderr\n");
			print_diff (err, expect, false);
		} else if (*err) {
			printf ("-- stderr\n%s\n", err);
		}
		if (result->proc_out->ret != 0) {
			printf ("-- exit status: "Color_RED"%d"Color_RESET"\n", result->proc_out->ret);
		}
		break;
	}
	case RZ_TEST_TYPE_ASM:
		if (result->test->asm_test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
			const char *expect = result->test->asm_test->disasm;
			const char *actual = result->asm_out->disasm;
			if (expect && actual && strcmp (actual, expect)) {
				printf ("-- disassembly\n");
				print_diff (actual, expect, false);
			}
		}
		// TODO: assembly
		break;
	case RZ_TEST_TYPE_JSON:
		break;
	case RZ_TEST_TYPE_FUZZ:
		rz_test_run_fuzz_test (config, result->test->fuzz_test, print_runner, NULL);
		printf ("-- stdout\n%s\n", result->proc_out->out);
		printf ("-- stderr\n%s\n", result->proc_out->err);
		printf ("-- exit status: "Color_RED"%d"Color_RESET"\n", result->proc_out->ret);
		break;
	}
}

static void print_new_results(RzTestState *state, ut64 prev_completed) {
	// Detailed test result (with diff if necessary)
	ut64 completed = (ut64)rz_pvector_len (&state->results);
	ut64 i;
	for (i = prev_completed; i < completed; i++) {
		RzTestResultInfo *result = rz_pvector_at (&state->results, (size_t)i);
		if (state->test_results) {
			test_result_to_json (state->test_results, result);
		}
		if (!state->verbose && (result->result == RZ_TEST_RESULT_OK || result->result == RZ_TEST_RESULT_FIXED || result->result == RZ_TEST_RESULT_BROKEN)) {
			continue;
		}
		char *name = rz_test_test_name (result->test);
		if (!name) {
			continue;
		}
		printf ("\n"RZ_CONS_CURSOR_UP RZ_CONS_CLEAR_LINE);
		switch (result->result) {
		case RZ_TEST_RESULT_OK:
			printf (Color_GREEN"[OK]"Color_RESET);
			break;
		case RZ_TEST_RESULT_FAILED:
			printf (Color_RED"[XX]"Color_RESET);
			break;
		case RZ_TEST_RESULT_BROKEN:
			printf (Color_BLUE"[BR]"Color_RESET);
			break;
		case RZ_TEST_RESULT_FIXED:
			printf (Color_CYAN"[FX]"Color_RESET);
			break;
		}
		if (result->timeout) {
			printf (Color_CYAN" TIMEOUT"Color_RESET);
		}
		printf (" %s "Color_YELLOW"%s"Color_RESET"\n", result->test->path, name);
		if (result->result == RZ_TEST_RESULT_FAILED || (state->verbose && result->result == RZ_TEST_RESULT_BROKEN)) {
			print_result_diff (&state->run_config, result);
		}
		free (name);
	}
}

static void print_state_counts(RzTestState *state) {
	printf ("%8"PFMT64u" OK  %8"PFMT64u" BR %8"PFMT64u" XX %8"PFMT64u" FX",
			state->ok_count, state->br_count, state->xx_count, state->fx_count);
}

static void print_state(RzTestState *state, ut64 prev_completed) {
#if __WINDOWS__
	setvbuf (stdout, NULL, _IOFBF, 8192);
#endif
	print_new_results (state, prev_completed);

	// [x/x] OK  42 BR  0 ...
	printf (RZ_CONS_CLEAR_LINE);
	int w = printf ("[%"PFMT64u"/%"PFMT64u"]", (ut64)rz_pvector_len (&state->results), (ut64)rz_pvector_len (&state->db->tests));
	while (w >= 0 && w < 20) {
		printf (" ");
		w++;
	}
	printf (" ");
	print_state_counts (state);
	fflush (stdout);
#if __WINDOWS__
	setvbuf (stdout, NULL, _IONBF, 0);
#endif
}

static void print_log(RzTestState *state, ut64 prev_completed, ut64 prev_paths_completed) {
	print_new_results (state, prev_completed);
	ut64 paths_completed = rz_pvector_len (&state->completed_paths);
	for (; prev_paths_completed < paths_completed; prev_paths_completed++) {
		printf ("[**] %50s ", (const char *)rz_pvector_at (&state->completed_paths, prev_paths_completed));
		print_state_counts (state);
		printf ("\n");
		fflush (stdout);
	}
}

static void interact(RzTestState *state) {
	void **it;
	RzPVector failed_results;
	rz_pvector_init (&failed_results, NULL);
	rz_pvector_foreach (&state->results, it) {
		RzTestResultInfo *result = *it;
		if (result->result == RZ_TEST_RESULT_FAILED) {
			rz_pvector_push (&failed_results, result);
		}
	}
	if (rz_pvector_empty (&failed_results)) {
		goto beach;
	}

#if __WINDOWS__
	(void)SetConsoleOutputCP (65001); // UTF-8
#endif
	printf ("\n");
	printf ("#####################\n");
	printf (" %"PFMT64u" failed test(s) "UTF8_POLICE_CARS_REVOLVING_LIGHT"\n",
	        (ut64)rz_pvector_len (&failed_results));

	rz_pvector_foreach (&failed_results, it) {
		RzTestResultInfo *result = *it;
		if (result->test->type != RZ_TEST_TYPE_CMD) {
			// TODO: other types of tests
			continue;
		}

		printf ("#####################\n\n");
		print_result_diff (&state->run_config, result);
menu:
		printf ("Wat do?    "
				"(f)ix "UTF8_WHITE_HEAVY_CHECK_MARK UTF8_VS16 UTF8_VS16 UTF8_VS16"    "
				"(i)gnore "UTF8_SEE_NO_EVIL_MONKEY"    "
				"(b)roken "UTF8_SKULL_AND_CROSSBONES UTF8_VS16 UTF8_VS16 UTF8_VS16"    "
				"(c)ommands "UTF8_KEYBOARD UTF8_VS16"    "
				"(d)iffchar "UTF8_LEFT_POINTING_MAGNIFYING_GLASS"    "
				"(q)uit "UTF8_DOOR"\n");
		printf ("> ");
		char buf[0x30];
		if (!fgets (buf, sizeof (buf), stdin)) {
			break;
		}
		if (strlen (buf) != 2) {
			goto menu;
		}
		switch (buf[0]) {
		case 'f':
			if (result->run_failed || result->proc_out->ret != 0) {
				printf ("This test has failed too hard to be fixed.\n");
				goto menu;
			}
			interact_fix (result, &failed_results);
			break;
		case 'i':
			break;
		case 'b':
			interact_break (result, &failed_results);
			break;
		case 'c':
			interact_commands (result, &failed_results);
			break;
		case 'd':
			interact_diffchar (result);
			goto menu;
		case 'q':
			goto beach;
		default:
			goto menu;
		}
	}

beach:
	rz_pvector_clear (&failed_results);
}

static char *format_cmd_kv(const char *key, const char *val) {
	RzStrBuf buf;
	rz_strbuf_init (&buf);
	rz_strbuf_appendf (&buf, "%s=", key);
	if (strchr (val, '\n')) {
		rz_strbuf_appendf (&buf, "<<EOF\n%sEOF", val);
	} else {
		rz_strbuf_append (&buf, val);
	}
	return rz_strbuf_drain_nofree (&buf);
}

static char *replace_lines(const char *src, size_t from, size_t to, const char *news) {
	const char *begin = src;
	size_t line = 1;
	while (line < from) {
		begin = strchr (begin, '\n');
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
		end = strchr (end, '\n');
		if (!end) {
			break;
		}
		end++;
		line++;
	}

	RzStrBuf buf;
	rz_strbuf_init (&buf);
	rz_strbuf_append_n (&buf, src, begin - src);
	rz_strbuf_append (&buf, news);
	rz_strbuf_append (&buf, "\n");
	if (end) {
		rz_strbuf_append (&buf, end);
	}
	return rz_strbuf_drain_nofree (&buf);
}

// After editing a test, fix the line numbers previously saved for all the other tests
static void fixup_tests(RzPVector *results, const char *edited_file, ut64 start_line, st64 delta) {
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

static char *replace_cmd_kv(const char *path, const char *content, size_t line_begin, size_t line_end, const char *key, const char *value, RzPVector *fixup_results) {
	char *kv = format_cmd_kv (key, value);
	if (!kv) {
		return NULL;
	}
	size_t kv_lines = rz_str_char_count (kv, '\n') + 1;
	char *newc = replace_lines (content, line_begin, line_end, kv);
	free (kv);
	if (!newc) {
		return NULL;
	}
	size_t lines_before = line_end - line_begin;
	st64 delta = (st64)kv_lines - (st64)lines_before;
	if (line_end == line_begin) {
		delta++;
	}
	fixup_tests (fixup_results, path, line_end, delta);
	return newc;
}

static void replace_cmd_kv_file(const char *path, ut64 line_begin, ut64 line_end, const char *key, const char *value, RzPVector *fixup_results) {
	char *content = rz_file_slurp (path, NULL);
	if (!content) {
		eprintf ("Failed to read file \"%s\"\n", path);
		return;
	}
	char *newc = replace_cmd_kv (path, content, line_begin, line_end, key, value, fixup_results);
	free (content);
	if (!newc) {
		return;
	}
	if (rz_file_dump (path, (const ut8 *)newc, -1, false)) {
#if __UNIX__
		sync ();
#endif
	} else {
		eprintf ("Failed to write file \"%s\"\n", path);
	}
	free (newc);
}

static void interact_fix(RzTestResultInfo *result, RzPVector *fixup_results) {
	assert (result->test->type == RZ_TEST_TYPE_CMD);
	RzCmdTest *test = result->test->cmd_test;
	RzSubprocessOutput *out = result->proc_out;
	if (test->expect.value && out->out) {
		replace_cmd_kv_file (result->test->path, test->expect.line_begin, test->expect.line_end, "EXPECT", out->out, fixup_results);
	}
	if (test->expect_err.value && out->err) {
		replace_cmd_kv_file (result->test->path, test->expect_err.line_begin, test->expect_err.line_end, "EXPECT_ERR", out->err, fixup_results);
	}
}

static void interact_break(RzTestResultInfo *result, RzPVector *fixup_results) {
	assert (result->test->type == RZ_TEST_TYPE_CMD);
	RzCmdTest *test = result->test->cmd_test;
	ut64 line_begin;
	ut64 line_end;
	if (test->broken.set) {
		line_begin = test->broken.set;
		line_end = line_begin + 1;
	} else {
		line_begin = line_end = test->run_line;
	}
	replace_cmd_kv_file (result->test->path, line_begin, line_end, "BROKEN", "1", fixup_results);
}

static void interact_commands(RzTestResultInfo *result, RzPVector *fixup_results) {
	assert (result->test->type == RZ_TEST_TYPE_CMD);
	RzCmdTest *test = result->test->cmd_test;
	if (!test->cmds.value) {
		return;
	}
	char *name = NULL;
	int fd = rz_file_mkstemp ("rz_test-cmds", &name);
	if (fd == -1) {
		free (name);
		eprintf ("Failed to open tmp file\n");
		return;
	}
	size_t cmds_sz = strlen (test->cmds.value);
	if (write (fd, test->cmds.value, cmds_sz) != cmds_sz) {
		eprintf ("Failed to write to tmp file\n");
		free (name);
		close (fd);
		return;
	}
	close (fd);

	char *editor = rz_sys_getenv ("EDITOR");
	if (!editor || !*editor) {
		free (editor);
		editor = strdup ("vim");
		if (!editor) {
			free (name);
			return;
		}
	}
	rz_sys_cmdf ("%s '%s'", editor, name);
	free (editor);

	char *newcmds = rz_file_slurp (name, NULL);
	if (!newcmds) {
		eprintf ("Failed to read edited command file\n");
		free (name);
		return;
	}
	rz_str_trim (newcmds);

	// if it's multiline we want exactly one trailing newline
	if (strchr (newcmds, '\n')) {
		char *tmp = newcmds;
		newcmds = rz_str_newf ("%s\n", newcmds);
		free (tmp);
		if (!newcmds) {
			free (name);
			return;
		}
	}

	replace_cmd_kv_file (result->test->path, test->cmds.line_begin, test->cmds.line_end, "CMDS", newcmds, fixup_results);
	free (name);
	free (newcmds);
}

static void interact_diffchar(RzTestResultInfo *result) {
	const char *actual = result->proc_out->out;
	const char *expected = result->test->cmd_test->expect.value;
	printf ("-- stdout\n");
	print_diff (actual, expected, true);
}
