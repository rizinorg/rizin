// SPDX-FileCopyrightText: 2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test.h"
#include <rz_util/rz_str.h>
#include <rz_util/rz_regex.h>
#include <rz_cons.h>
#if __WINDOWS__
#include <io.h>
#endif

#if __WINDOWS__
static ut8 *crlf2lf(ut8 *str) {
	char *src = (char *)str;
	char *dest = src;
	while (*src) {
		*dest = *src;
		if (src[0] == '\r' && src[1] == '\n') {
			// dest does not move
		} else {
			dest++;
		}
		src++;
	}
	*dest = '\0';
	return str;
}
#else
#define crlf2lf(x) (x)
#endif

static RzSubprocessOutput *subprocess_runner(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	RzSubprocess *proc = rz_subprocess_start(file, args, args_size, envvars, envvals, env_size);
	if (!proc) {
		return NULL;
	}
	RzSubprocessWaitReason r = rz_subprocess_wait(proc, timeout_ms);
	if (r == RZ_SUBPROCESS_TIMEDOUT) {
		rz_subprocess_kill(proc);
	}
	RzSubprocessOutput *out = rz_subprocess_drain(proc);
	if (out) {
		out->timeout = r == RZ_SUBPROCESS_TIMEDOUT;
		out->out = crlf2lf(out->out);
		out->err = crlf2lf(out->err);
	}
	rz_subprocess_free(proc);
	return out;
}

#if __WINDOWS__
static char *convert_win_cmds(const char *cmds) {
	if (RZ_STR_ISEMPTY(cmds)) {
		return NULL;
	}
	char *r = malloc(strlen(cmds) + 1);
	if (!r) {
		return NULL;
	}
	char *p = r;
	while (*cmds) {
		if (*cmds == '!' || (*cmds == '\"' && cmds[1] == '!')) {
			// Adjust shell syntax for Windows,
			// only for lines starting with ! or "!
			char c;
			for (; c = *cmds, c; cmds++) {
				if (c == '\\') {
					// replace \$ by $
					c = *++cmds;
					if (c == '$') {
						*p++ = '$';
					} else {
						*p++ = '\\';
						*p++ = c;
					}
				} else if (c == '$') {
					// replace ${VARNAME} by %VARNAME%
					c = *++cmds;
					if (c == '{') {
						*p++ = '%';
						cmds++;
						for (; c = *cmds, c && c != '}'; cmds++) {
							*p++ = c;
						}
						if (c) { // must check c to prevent overflow
							*p++ = '%';
						}
					} else {
						*p++ = '$';
						*p++ = c;
					}
				} else {
					*p++ = c;
					if (c == '\n') {
						cmds++;
						break;
					}
				}
			}
			continue;
		}

		// Nothing to do, just copy the line
		char *lend = strchr(cmds, '\n');
		size_t llen;
		if (lend) {
			llen = lend - cmds + 1;
		} else {
			llen = strlen(cmds);
		}
		memcpy(p, cmds, llen);
		cmds += llen;
		p += llen;
	}
	*p = '\0';
	return rz_str_replace(r, "/dev/null", "nul", true);
}
#endif

typedef struct run_rz_test_s {
	RzTestRunConfig *config; ///< Global configuration
	ut64 timeout_ms; ///< Test timeout in millisec
	const char *bin_path; ///< Path of the bin directory (can be null)
	const char *tool; ///< When set executes a different tool rather than the default exe
	const char *cmds; ///< Rizin command line passed as value of `-c` (-q will be added unless TOOL= is defined)
	RzList /*<char *>*/ *envs; ///< Additional environment variables
	RzList /*<char *>*/ *files; ///< Additional files or tool inputs
	RzList /*<char *>*/ *extra_args; ///< Additional arguments
	bool load_plugins; ///< When true, allows to load external plugins (RZ_NOPLUGINS=0)
	bool color; ///< When true sets RZ_COLOR=1, otherwise RZ_COLOR=0 (default)
	bool utf8; ///< When true sets RZ_UTF8=1, otherwise RZ_UTF8=0 (default)
	RzTestCmdRunner runner; ///< Function to call to execute the test
	void *user; ///< Additional user data passed to `runner`.
} RunRzTest;

static inline bool run_rz_test_is_custom(const RunRzTest *rrt) {
	return RZ_STR_ISNOTEMPTY(rrt->tool);
}

static void run_rz_test_add_args_from_list(RzPVector /*<const char *>*/ *args, RzList /*<char *>*/ *list) {
	RzListIter *it = NULL;
	char *arg = NULL;
	rz_list_foreach (list, it, arg) {
		if (RZ_STR_ISEMPTY(arg)) {
			continue;
		}
		rz_pvector_push(args, arg);
	}
}

static void run_rz_test_init_args(const RunRzTest *rrt, const char *rizin_cmd, RzPVector /*<const char *>*/ *args) {
	rz_pvector_init(args, NULL);

	if (run_rz_test_is_custom(rrt)) {
		// the test runs with custom args and may exec a different tool.
		run_rz_test_add_args_from_list(args, rrt->extra_args);
		if (rizin_cmd) {
			rz_pvector_push(args, "-c");
			rz_pvector_push(args, (void *)rizin_cmd);
		}
		run_rz_test_add_args_from_list(args, rrt->files);
		return;
	}

	// the test runs in a normal rizin test environment.
	rz_pvector_push(args, "-escr.utf8=0");
	rz_pvector_push(args, "-escr.color=0");
	rz_pvector_push(args, "-escr.interactive=0");
	rz_pvector_push(args, "-eflirt.sigdb.load.system=false");
	rz_pvector_push(args, "-esearch.show_progress=false");
	rz_pvector_push(args, "-eflirt.sigdb.load.home=false");
	rz_pvector_push(args, "-N");
	run_rz_test_add_args_from_list(args, rrt->extra_args);
	rz_pvector_push(args, "-qc");
	rz_pvector_push(args, (void *)rizin_cmd);
	run_rz_test_add_args_from_list(args, rrt->files);
}

static void run_rz_test_init_envs(const RunRzTest *rrt, const char ***envvars_o, const char ***envvals_o, size_t *env_size_o) {
	RzListIter *it = NULL;
	char *env = NULL;
	size_t env_size = 0;
	const size_t reserve = 4 + rz_list_length(rrt->envs);
	const char **envvars = RZ_NEWS0(const char *, reserve);
	const char **envvals = RZ_NEWS0(const char *, reserve);

#define RUN_RZ_TEST_ENV_SET(k, v) \
	do { \
		envvars[env_size] = k; \
		envvals[env_size] = v; \
		env_size++; \
	} while (0)

#if __WINDOWS__
	RUN_RZ_TEST_ENV_SET("ANSICON", "1");
#endif
	RUN_RZ_TEST_ENV_SET("RZ_COLOR", rrt->color ? "1" : "0");
	RUN_RZ_TEST_ENV_SET("RZ_UTF8", rrt->utf8 ? "1" : "0");
	if (!rrt->load_plugins) {
		RUN_RZ_TEST_ENV_SET("RZ_NOPLUGINS", "1");
	}

	rz_list_foreach (rrt->envs, it, env) {
		if (RZ_STR_ISEMPTY(env)) {
			continue;
		}

		const char *key = env;
		char *value = strchr(env, '=');
		if (value) {
			*value = 0;
			RUN_RZ_TEST_ENV_SET(key, value + 1);
		} else {
			RUN_RZ_TEST_ENV_SET(key, "");
		}
	}
#undef RUN_RZ_TEST_ENV_SET

	*envvars_o = envvars;
	*envvals_o = envvals;
	*env_size_o = env_size;
}

RZ_API RZ_OWN char *rz_test_find_executable(RZ_NULLABLE const char *exec, RZ_NULLABLE const char *bin_path) {
	if (RZ_STR_ISEMPTY(exec)) {
		return NULL;
	} else if (RZ_STR_ISEMPTY(bin_path)) {
		return rz_file_path(exec);
	}

#if __WINDOWS__
	char *exe_path = rz_str_newf(RZ_JOIN_2_PATHS("%s", "%s.exe"), bin_path, exec);
#else
	char *exe_path = rz_str_newf(RZ_JOIN_2_PATHS("%s", "%s"), bin_path, exec);
#endif

	if (rz_file_exists(exe_path)) {
		return exe_path;
	}

	free(exe_path);
	return rz_str_dup(exec);
}

static char *run_rz_test_find_executable(const RunRzTest *rrt, const char *default_exe) {
	const char *exec = default_exe;
	if (RZ_STR_ISNOTEMPTY(rrt->tool)) {
		exec = rrt->tool;
	}

	return rz_test_find_executable(exec, rrt->bin_path);
}

static RzSubprocessOutput *run_rz_test(const RunRzTest *rrt, const char *default_exe) {
	const char **envvars = NULL;
	const char **envvals = NULL;
	size_t env_size = 0;
	RzPVector args;
#if __WINDOWS__
	char *wcmds = convert_win_cmds(rrt->cmds);
	run_rz_test_init_args(rrt, wcmds, &args);
#else
	run_rz_test_init_args(rrt, rrt->cmds, &args);
#endif

	run_rz_test_init_envs(rrt, &envvars, &envvals, &env_size);
	char *executable = run_rz_test_find_executable(rrt, default_exe);

	RzSubprocessOutput *out = rrt->runner(executable, args.v.a, rz_pvector_len(&args), envvars, envvals, env_size, rrt->timeout_ms, rrt->user);
	rz_pvector_clear(&args);

	free(envvals);
	free(envvars);

	free(executable);
#if __WINDOWS__
	free(wcmds);
#endif
	return out;
}

RZ_API RzSubprocessOutput *rz_test_run_cmd_test(RzTestRunConfig *config, RzCmdTest *test, RzTestCmdRunner runner, void *user) {
	RzList *extra_args = test->args.value ? rz_str_split_duplist(test->args.value, " ", true) : NULL;
	RzList *files = test->file.value ? rz_str_split_duplist(test->file.value, "\n", true) : NULL;
	RzList *envs = test->envs.value ? rz_str_split_duplist(test->envs.value, "\n", true) : NULL;
	RzListIter *it;
	RzListIter *tmpit;
	char *token;
	rz_list_foreach_safe (extra_args, it, tmpit, token) {
		if (!*token) {
			rz_list_delete(extra_args, it);
		}
	}
	rz_list_foreach_safe (files, it, tmpit, token) {
		if (!*token) {
			rz_list_delete(files, it);
		}
	}
	if (rz_list_empty(files) && RZ_STR_ISEMPTY(test->tool.value)) {
		if (!files) {
			files = rz_list_new();
		} else {
			files->free = NULL;
		}
		rz_list_push(files, "=");
	}
	ut64 timeout_ms = test->timeout.set ? test->timeout.value * 1000 : config->timeout_ms;

	RunRzTest normal_rrt = {
		.config = config,
		.timeout_ms = timeout_ms,
		.bin_path = config->bin_path,
		.tool = test->tool.value,
		.cmds = test->cmds.value,
		.envs = envs,
		.files = files,
		.extra_args = extra_args,
		.load_plugins = test->load_plugins,
		.color = test->color.value,
		.utf8 = test->utf8.value,
		.runner = runner,
		.user = user,
	};

	RzSubprocessOutput *out = run_rz_test(&normal_rrt, "rizin");
	rz_list_free(extra_args);
	rz_list_free(files);
	rz_list_free(envs);
	return out;
}

RZ_API RZ_OWN RzStrBuf *rz_test_regex_full_match_str(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text) {
	return rz_regex_full_match_str(pattern, text, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		"\n");
}

RZ_API bool rz_test_cmp_cmd_output(const char *output, const char *expect, const char *regexp) {
	if (regexp) {
		RzStrBuf *match_str = rz_test_regex_full_match_str(regexp, output);
		bool equal = false;
		size_t expect_len = strlen(expect);
		if (expect_len && expect[expect_len - 1] == '\n') {
			// Ignore newline in expect
			expect_len--;
			size_t match_str_len = rz_strbuf_length(match_str);
			if (match_str_len && rz_strbuf_get(match_str)[match_str_len - 1] == '\n') {
				// Ignore newline in match_str
				match_str_len--;
			}
			if (expect_len != match_str_len) {
				rz_strbuf_free(match_str);
				return false;
			}
			equal = !rz_str_cmp(expect, rz_strbuf_get(match_str), expect_len);
		} else {
			equal = RZ_STR_EQ(expect, rz_strbuf_get(match_str));
		}
		rz_strbuf_free(match_str);
		return equal;
	}
	return !strcmp(expect, output);
}

RZ_API bool rz_test_check_cmd_test(RzSubprocessOutput *out, RzCmdTest *test) {
	if (!out || out->ret != test->exit_status.value || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *expect_out = test->expect.value;
	const char *regexp_out = test->regexp_out.value;
	if (expect_out && !rz_test_cmp_cmd_output((char *)out->out, expect_out, regexp_out)) {
		return false;
	}
	const char *expect_err = test->expect_err.value;
	const char *regexp_err = test->regexp_err.value;
	if (expect_err && !rz_test_cmp_cmd_output((char *)out->err, expect_err, regexp_err)) {
		return false;
	}
	return true;
}

#define JQ_CMD "jq"

RZ_API bool rz_test_check_jq_available(void) {
	const char *args[] = { "." };
	const char *invalid_json = "this is not json lol";
	char *jq_path = rz_file_path(JQ_CMD);
	RzSubprocess *proc = rz_subprocess_start(jq_path, args, 1, NULL, NULL, 0);
	if (proc) {
		rz_subprocess_stdin_write(proc, (const ut8 *)invalid_json, strlen(invalid_json));
		rz_subprocess_wait(proc, UT64_MAX);
	}
	bool invalid_detected = proc && rz_subprocess_ret(proc) != 0;
	rz_subprocess_free(proc);

	const char *valid_json = "{\"this is\":\"valid json\",\"lol\":true}";
	proc = rz_subprocess_start(jq_path, args, 1, NULL, NULL, 0);
	if (proc) {
		rz_subprocess_stdin_write(proc, (const ut8 *)valid_json, strlen(valid_json));
		rz_subprocess_wait(proc, UT64_MAX);
	}
	bool valid_detected = proc && rz_subprocess_ret(proc) == 0;
	rz_subprocess_free(proc);
	free(jq_path);
	return invalid_detected && valid_detected;
}

/**
 * \brief Checks if the tool \p exec is available by running it with -v.
 *
 * NOTE: If the tool is built with LSAN enabled and LSAN returns a
 * code !=0 on `exec -v` due to a leak, this function will report the tool as broken!
 *
 * \param exec The tool to check.
 *
 * \return True if the tool existed with return code 0, false otherwise.
 */
RZ_API bool rz_test_check_tool_available(RZ_NULLABLE const char *exec) {
	if (RZ_STR_ISEMPTY(exec)) {
		return false;
	}

	const char *args[] = { "-v" };
	RzSubprocess *proc = rz_subprocess_start(exec, args, 1, NULL, NULL, 0);
	if (!proc) {
		return false;
	}
	rz_subprocess_wait(proc, UT64_MAX);
	bool return_zero = rz_subprocess_ret(proc) == 0;
	rz_subprocess_free(proc);

	return return_zero;
}

RZ_API RzSubprocessOutput *rz_test_run_json_test(RzTestRunConfig *config, RzJsonTest *test, RzTestCmdRunner runner, void *user) {
	RzList *files = rz_list_new();
	rz_list_push(files, (void *)config->json_test_file);

	RunRzTest json_rrt = {
		.config = config,
		.timeout_ms = config->timeout_ms,
		.bin_path = config->bin_path,
		.tool = NULL,
		.cmds = test->cmd,
		.files = files,
		.extra_args = NULL,
		.load_plugins = test->load_plugins,
		.color = false,
		.utf8 = false,
		.runner = runner,
		.user = user,
	};

	RzSubprocessOutput *ret = run_rz_test(&json_rrt, "rizin");
	rz_list_free(files);
	return ret;
}

RZ_API bool rz_test_check_json_test(RzSubprocessOutput *out, RzJsonTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *args[] = { "." };
	char *jq_path = rz_file_path(JQ_CMD);
	RzSubprocess *proc = rz_subprocess_start(jq_path, args, 1, NULL, NULL, 0);
	rz_subprocess_stdin_write(proc, (const ut8 *)out->out, strlen((char *)out->out));
	rz_subprocess_wait(proc, UT64_MAX);
	bool ret = rz_subprocess_ret(proc) == 0;
	rz_subprocess_free(proc);
	free(jq_path);
	return ret;
}

#define ASM_BATCH_BEGIN_MARKER "\n\x1eRZ_ASM_BATCH_BEGIN\n"
#define ASM_BATCH_ITEM_PREFIX  "\n\x1eRZ_ASM_BATCH_ITEM "

typedef enum {
	ASM_BATCH_OP_ASM = 0,
	ASM_BATCH_OP_DISASM,
	ASM_BATCH_OP_IL,
} AsmBatchOpKind;

typedef struct {
	size_t test_idx;
	AsmBatchOpKind kind;
} AsmBatchReq;

typedef struct {
	char *data;
	int ret;
} AsmBatchItemSlice;

static void asm_batch_slices_fini(AsmBatchItemSlice *slices, size_t n) {
	if (!slices) {
		return;
	}
	for (size_t i = 0; i < n; i++) {
		free(slices[i].data);
	}
	free(slices);
}

/**
 * \brief Split a framed rz-asm batch stdout or stderr stream into per-request slices.
 * \param stream      Raw captured stdout/stderr string from `rz-asm -t`.
 * \param n_reqs      Expected number of batch request items.
 * \param preamble_o  Optional output receiving text emitted before the batch begin marker.
 * \return Array of \p n_reqs slices to free with asm_batch_slices_fini(), or NULL on mismatch.
 */
static RZ_OWN AsmBatchItemSlice *rz_test_parse_asm_batch_stream(RZ_NONNULL const char *stream, size_t n_reqs, RZ_NULLABLE RZ_OUT char **preamble_o) {
	if (preamble_o) {
		*preamble_o = NULL;
	}
	const char *begin = strstr(stream, ASM_BATCH_BEGIN_MARKER);
	if (!begin) {
		return NULL;
	}
	if (preamble_o && begin > stream) {
		*preamble_o = rz_str_ndup(stream, (size_t)(begin - stream));
		if (!*preamble_o) {
			return NULL;
		}
	}
	AsmBatchItemSlice *slices = RZ_NEWS0(AsmBatchItemSlice, n_reqs);
	if (!slices) {
		if (preamble_o) {
			RZ_FREE(*preamble_o);
		}
		return NULL;
	}
	const char *cur = begin + strlen(ASM_BATCH_BEGIN_MARKER);
	const size_t prefix_len = strlen(ASM_BATCH_ITEM_PREFIX);
	for (size_t i = 0; i < n_reqs; i++) {
		const char *marker = strstr(cur, ASM_BATCH_ITEM_PREFIX);
		if (!marker) {
			goto fail;
		}
		const char *meta = marker + prefix_len;
		char *end_idx = NULL;
		unsigned long long parsed_idx = strtoull(meta, &end_idx, 10);
		if (!end_idx || end_idx == meta || *end_idx != ' ' || (size_t)parsed_idx != i) {
			goto fail;
		}
		char *end_ret = NULL;
		long parsed_ret = strtol(end_idx + 1, &end_ret, 10);
		if (!end_ret || end_ret == end_idx + 1 || *end_ret != '\n') {
			goto fail;
		}
		slices[i].data = rz_str_ndup(cur, (size_t)(marker - cur));
		if (!slices[i].data) {
			goto fail;
		}
		slices[i].ret = (int)parsed_ret;
		cur = end_ret + 1;
	}
	if (*cur != '\0') {
		goto fail;
	}
	return slices;
fail:
	asm_batch_slices_fini(slices, n_reqs);
	if (preamble_o) {
		RZ_FREE(*preamble_o);
	}
	return NULL;
}

static char *asm_batch_join_err(RZ_NULLABLE const char *preamble, RZ_NONNULL const char *err) {
	char *joined = RZ_STR_ISNOTEMPTY(preamble)
		? rz_str_newf("%s%s", preamble, err)
		: rz_str_dup(err);
	if (joined) {
		rz_str_trim(joined);
	}
	return joined;
}

static void asm_push_common_args(RzPVector /*<const char *>*/ *args, const RzAsmTest *test, char *bits_buf, size_t bits_sz) {
	if (test->arch) {
		rz_pvector_push(args, "-a");
		rz_pvector_push(args, (void *)test->arch);
	}
	if (test->cpu) {
		rz_pvector_push(args, "-c");
		rz_pvector_push(args, (void *)test->cpu);
	}
	if (test->bits) {
		snprintf(bits_buf, bits_sz, "%d", test->bits);
		rz_pvector_push(args, "-b");
		rz_pvector_push(args, bits_buf);
	}
	if (test->mode & RZ_ASM_TEST_MODE_BIG_ENDIAN) {
		rz_pvector_push(args, "-e");
	}
}

RZ_API RzAsmTestOutput *rz_test_run_asm_test(RzTestRunConfig *config, RzAsmTest *test) {
	RzAsmTestOutput *out = RZ_NEW0(RzAsmTestOutput);
	if (!out) {
		return NULL;
	}
	out->as_ret = out->disas_ret = out->il_ret = INT_MAX;
	char *rz_asm_exe = rz_test_find_executable("rz-asm", config->bin_path);
	const char *envvars[] = { "RZ_NOPLUGINS" };
	const char *envvals[] = { "1" };
	size_t env_size = test->load_plugins ? 0 : 1;

	RzPVector args;
	rz_pvector_init(&args, NULL);

	char bits[0x20];
	asm_push_common_args(&args, test, bits, sizeof(bits));

	char offset[0x20];
	if (test->offset) {
		rz_snprintf(offset, sizeof(offset), "0x%" PFMT64x, test->offset);
		rz_pvector_push(&args, "-o");
		rz_pvector_push(&args, offset);
	}

	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		rz_pvector_push(&args, test->disasm);
		RzSubprocess *proc = rz_subprocess_start(rz_asm_exe, args.v.a, rz_pvector_len(&args),
			env_size ? envvars : NULL, env_size ? envvals : NULL, env_size);
		if (!proc) {
			goto rip;
		}
		if (rz_subprocess_wait(proc, config->timeout_ms) == RZ_SUBPROCESS_TIMEDOUT) {
			rz_subprocess_kill(proc);
			out->as_timeout = true;
			goto rip;
		}
		char *as_err = (char *)crlf2lf(rz_subprocess_err(proc, NULL));
		rz_str_trim(as_err);
		out->as_err = as_err;
		out->as_ret = rz_subprocess_ret(proc);
		if (out->as_ret != 0) {
			goto rip;
		}
		char *hex = (char *)crlf2lf(rz_subprocess_out(proc, NULL));
		size_t hexlen = strlen(hex);
		if (!hexlen) {
			free(hex);
			goto rip;
		}
		ut8 *bytes = malloc(hexlen);
		int byteslen = rz_hex_str2bin(hex, bytes);
		free(hex);
		if (byteslen <= 0) {
			free(bytes);
			goto rip;
		}
		out->bytes = bytes;
		out->bytes_size = (size_t)byteslen;
	rip:
		rz_pvector_pop(&args);
		rz_subprocess_free(proc);
	}
	if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
		char *hex = rz_hex_bin2strdup(test->bytes, test->bytes_size);
		if (!hex) {
			goto beach;
		}
		rz_pvector_push(&args, "-d");
		rz_pvector_push(&args, hex);
		RzSubprocess *proc = rz_subprocess_start(rz_asm_exe, args.v.a, rz_pvector_len(&args),
			env_size ? envvars : NULL, env_size ? envvals : NULL, env_size);
		if (!proc) {
			goto ship;
		}
		if (rz_subprocess_wait(proc, config->timeout_ms) == RZ_SUBPROCESS_TIMEDOUT) {
			rz_subprocess_kill(proc);
			out->disas_timeout = true;
			goto ship;
		}
		char *disas_err = (char *)crlf2lf(rz_subprocess_err(proc, NULL));
		rz_str_trim(disas_err);
		out->disas_err = disas_err;
		out->disas_ret = rz_subprocess_ret(proc);
		if (out->disas_ret != 0) {
			goto ship;
		}
		char *disasm = (char *)crlf2lf(rz_subprocess_out(proc, NULL));
		rz_str_trim(disasm);
		rz_str_replace_char(disasm, '\n', ';');
		out->disasm = disasm;
	ship:
		free(hex);
		rz_pvector_pop(&args);
		rz_pvector_pop(&args);
		rz_subprocess_free(proc);
	}
	if (test->il) {
		char *hex = rz_hex_bin2strdup(test->bytes, test->bytes_size);
		if (!hex) {
			goto beach;
		}
		rz_pvector_push(&args, "-I");
		rz_pvector_push(&args, hex);
		RzSubprocess *proc = rz_subprocess_start(rz_asm_exe, args.v.a, rz_pvector_len(&args),
			env_size ? envvars : NULL, env_size ? envvals : NULL, env_size);
		if (!proc) {
			free(hex);
			rz_pvector_pop(&args);
			rz_pvector_pop(&args);
			goto beach;
		}
		if (rz_subprocess_wait(proc, config->timeout_ms) == RZ_SUBPROCESS_TIMEDOUT) {
			rz_subprocess_kill(proc);
			out->il_timeout = true;
		} else {
			char *il = (char *)crlf2lf(rz_subprocess_out(proc, NULL));
			rz_str_trim(il);
			rz_str_replace_char(il, '\n', ';');
			char *il_err = (char *)crlf2lf(rz_subprocess_err(proc, NULL));
			rz_str_trim(il_err);
			out->il = il;
			out->il_err = il_err;
			out->il_ret = rz_subprocess_ret(proc);
			out->il_failed = out->il_ret != 0;
		}
		free(hex);
		rz_pvector_pop(&args);
		rz_pvector_pop(&args);
		rz_subprocess_free(proc);
	}

beach:
	free(rz_asm_exe);
	rz_pvector_clear(&args);
	return out;
}

static RZ_OWN RzPVector /*<RzTestResultInfo *>*/ *rz_test_run_asm_batch_fallback(RZ_NONNULL RzTestRunConfig *config, RZ_NONNULL RzTest **tests, size_t n_tests) {
	RzPVector *results = rz_pvector_new((RzPVectorFree)rz_test_test_result_info_free);
	if (!results) {
		return NULL;
	}
	for (size_t i = 0; i < n_tests; i++) {
		RzTestResultInfo *res = rz_test_run_test(config, tests[i]);
		if (res) {
			rz_pvector_push(results, res);
		}
	}
	return results;
}

/**
 * \brief Run a batch of RZ_TEST_TYPE_ASM tests sharing (arch, cpu, bits, endian, load_plugins) in one rz-asm process.
 * Falls back to running each test individually if the batch process crashes, times out, or mismatches framing.
 */
RZ_API RZ_OWN RzPVector /*<RzTestResultInfo *>*/ *rz_test_run_asm_batch(RZ_NONNULL RzTestRunConfig *config, RZ_NONNULL RzTest **tests, size_t n_tests) {
	rz_return_val_if_fail(config && tests, NULL);
	if (!n_tests) {
		return rz_pvector_new((RzPVectorFree)rz_test_test_result_info_free);
	}
	if (n_tests == 1) {
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}

	ut64 start_time = rz_time_now_mono();
	RzStrBuf batch_in;
	rz_strbuf_init(&batch_in);
	RzVector reqs;
	rz_vector_init(&reqs, sizeof(AsmBatchReq), NULL, NULL);

	for (size_t i = 0; i < n_tests; i++) {
		RzAsmTest *t = tests[i]->asm_test;
		if (t->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
			AsmBatchReq req = { .test_idx = i, .kind = ASM_BATCH_OP_ASM };
			rz_vector_push(&reqs, &req);
			rz_strbuf_appendf(&batch_in, "a %" PFMT64x " %s\n", t->offset, t->disasm);
		}
		if ((t->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) || t->il) {
			char *hex = rz_hex_bin2strdup(t->bytes, t->bytes_size);
			if (!hex) {
				rz_strbuf_fini(&batch_in);
				rz_vector_fini(&reqs);
				return rz_test_run_asm_batch_fallback(config, tests, n_tests);
			}
			if (t->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
				AsmBatchReq req = { .test_idx = i, .kind = ASM_BATCH_OP_DISASM };
				rz_vector_push(&reqs, &req);
				rz_strbuf_appendf(&batch_in, "d %" PFMT64x " %s\n", t->offset, hex);
			}
			if (t->il) {
				AsmBatchReq req = { .test_idx = i, .kind = ASM_BATCH_OP_IL };
				rz_vector_push(&reqs, &req);
				rz_strbuf_appendf(&batch_in, "I %" PFMT64x " %s\n", t->offset, hex);
			}
			free(hex);
		}
	}

	size_t n_reqs = rz_vector_len(&reqs);
	if (!n_reqs) {
		rz_strbuf_fini(&batch_in);
		rz_vector_fini(&reqs);
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}

	char *tmp_path = NULL;
	int fd = rz_file_mkstemp("rz-test-asm-batch", &tmp_path);
	if (fd != -1) {
#if __WINDOWS__
		_close(fd);
#else
		close(fd);
#endif
	}
	if (fd == -1 || !tmp_path) {
		free(tmp_path);
		rz_strbuf_fini(&batch_in);
		rz_vector_fini(&reqs);
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}

	bool dumped = rz_file_dump(tmp_path, (const ut8 *)rz_strbuf_get(&batch_in), (int)rz_strbuf_length(&batch_in), false);
	rz_strbuf_fini(&batch_in);
	if (!dumped) {
		rz_file_rm(tmp_path);
		free(tmp_path);
		rz_vector_fini(&reqs);
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}

	char *rz_asm_exe = rz_test_find_executable("rz-asm", config->bin_path);
	const char *envvars[] = { "RZ_NOPLUGINS" };
	const char *envvals[] = { "1" };
	size_t env_size = tests[0]->asm_test->load_plugins ? 0 : 1;
	RzPVector args;
	rz_pvector_init(&args, NULL);
	char bits[0x20];
	asm_push_common_args(&args, tests[0]->asm_test, bits, sizeof(bits));
	rz_pvector_push(&args, "-t");
	rz_pvector_push(&args, tmp_path);

	RzSubprocessOutput *proc_out = subprocess_runner(rz_asm_exe, args.v.a, rz_pvector_len(&args),
		env_size ? envvars : NULL, env_size ? envvals : NULL, env_size, config->timeout_ms, NULL);
	rz_pvector_clear(&args);
	free(rz_asm_exe);
	rz_file_rm(tmp_path);
	free(tmp_path);

	if (!proc_out || proc_out->timeout || proc_out->ret != 0 || !proc_out->out || !proc_out->err) {
		rz_subprocess_output_free(proc_out);
		rz_vector_fini(&reqs);
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}

	char *out_preamble = NULL;
	char *err_preamble = NULL;
	AsmBatchItemSlice *out_slices = rz_test_parse_asm_batch_stream((const char *)proc_out->out, n_reqs, &out_preamble);
	AsmBatchItemSlice *err_slices = (out_slices && RZ_STR_ISEMPTY(out_preamble))
		? rz_test_parse_asm_batch_stream((const char *)proc_out->err, n_reqs, &err_preamble)
		: NULL;
	rz_subprocess_output_free(proc_out);

	if (!out_slices || !err_slices || RZ_STR_ISNOTEMPTY(out_preamble)) {
		asm_batch_slices_fini(out_slices, n_reqs);
		asm_batch_slices_fini(err_slices, n_reqs);
		free(out_preamble);
		free(err_preamble);
		rz_vector_fini(&reqs);
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}
	free(out_preamble);

	RzAsmTestOutput **outs = RZ_NEWS0(RzAsmTestOutput *, n_tests);
	if (!outs) {
		asm_batch_slices_fini(out_slices, n_reqs);
		asm_batch_slices_fini(err_slices, n_reqs);
		free(err_preamble);
		rz_vector_fini(&reqs);
		return rz_test_run_asm_batch_fallback(config, tests, n_tests);
	}
	for (size_t i = 0; i < n_tests; i++) {
		outs[i] = RZ_NEW0(RzAsmTestOutput);
		if (!outs[i]) {
			for (size_t j = 0; j < i; j++) {
				rz_test_asm_test_output_free(outs[j]);
			}
			free(outs);
			asm_batch_slices_fini(out_slices, n_reqs);
			asm_batch_slices_fini(err_slices, n_reqs);
			free(err_preamble);
			rz_vector_fini(&reqs);
			return rz_test_run_asm_batch_fallback(config, tests, n_tests);
		}
		outs[i]->as_ret = outs[i]->disas_ret = outs[i]->il_ret = INT_MAX;
	}

	for (size_t r = 0; r < n_reqs; r++) {
		if (out_slices[r].ret != err_slices[r].ret) {
			for (size_t j = 0; j < n_tests; j++) {
				rz_test_asm_test_output_free(outs[j]);
			}
			free(outs);
			asm_batch_slices_fini(out_slices, n_reqs);
			asm_batch_slices_fini(err_slices, n_reqs);
			free(err_preamble);
			rz_vector_fini(&reqs);
			return rz_test_run_asm_batch_fallback(config, tests, n_tests);
		}
		AsmBatchReq *req = rz_vector_index_ptr(&reqs, r);
		RzAsmTestOutput *out = outs[req->test_idx];
		int ret_code = out_slices[r].ret;
		switch (req->kind) {
		case ASM_BATCH_OP_ASM: {
			out->as_err = asm_batch_join_err(err_preamble, err_slices[r].data);
			out->as_ret = ret_code;
			if (ret_code == 0) {
				const char *hex = out_slices[r].data;
				size_t hexlen = strlen(hex);
				if (hexlen > 0) {
					ut8 *bytes = malloc(hexlen);
					if (bytes) {
						int byteslen = rz_hex_str2bin(hex, bytes);
						if (byteslen > 0) {
							out->bytes = bytes;
							out->bytes_size = (size_t)byteslen;
						} else {
							free(bytes);
						}
					}
				}
			}
			break;
		}
		case ASM_BATCH_OP_DISASM: {
			out->disas_err = asm_batch_join_err(err_preamble, err_slices[r].data);
			out->disas_ret = ret_code;
			if (ret_code == 0) {
				char *disasm = rz_str_dup(out_slices[r].data);
				if (disasm) {
					rz_str_trim(disasm);
					rz_str_replace_char(disasm, '\n', ';');
				}
				out->disasm = disasm;
			}
			break;
		}
		case ASM_BATCH_OP_IL: {
			char *il = rz_str_dup(out_slices[r].data);
			if (il) {
				rz_str_trim(il);
				rz_str_replace_char(il, '\n', ';');
			}
			out->il = il;
			out->il_err = asm_batch_join_err(err_preamble, err_slices[r].data);
			out->il_ret = ret_code;
			out->il_failed = ret_code != 0;
			break;
		}
		}
	}

	asm_batch_slices_fini(out_slices, n_reqs);
	asm_batch_slices_fini(err_slices, n_reqs);
	free(err_preamble);
	rz_vector_fini(&reqs);

	ut64 elapsed = rz_time_now_mono() - start_time;
	ut64 per_test_elapsed = elapsed / n_tests;
	RzPVector *results = rz_pvector_new((RzPVectorFree)rz_test_test_result_info_free);
	if (!results) {
		for (size_t i = 0; i < n_tests; i++) {
			rz_test_asm_test_output_free(outs[i]);
		}
		free(outs);
		return NULL;
	}
	for (size_t i = 0; i < n_tests; i++) {
		RzTestResultInfo *res = RZ_NEW0(RzTestResultInfo);
		if (!res) {
			rz_test_asm_test_output_free(outs[i]);
			continue;
		}
		res->test = tests[i];
		res->asm_out = outs[i];
		res->time_elapsed = per_test_elapsed;
		bool success = rz_test_check_asm_test(outs[i], tests[i]->asm_test);
		bool broken = rz_test_broken(tests[i]);
		if (!success) {
			res->result = broken ? RZ_TEST_RESULT_BROKEN : RZ_TEST_RESULT_FAILED;
		} else {
			res->result = broken ? RZ_TEST_RESULT_FIXED : RZ_TEST_RESULT_OK;
		}
		rz_pvector_push(results, res);
	}
	free(outs);
	return results;
}

RZ_API bool rz_test_check_asm_test(RzAsmTestOutput *out, RzAsmTest *test) {
	if (!out) {
		return false;
	}
	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		if (!out->bytes || !test->bytes || out->bytes_size != test->bytes_size || out->as_timeout) {
			return false;
		}
		if (memcmp(out->bytes, test->bytes, test->bytes_size) != 0) {
			return false;
		}
	}
	if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
		if (!out->disasm || !test->disasm || out->disas_timeout) {
			return false;
		}
		if (strcmp(out->disasm, test->disasm) != 0) {
			return false;
		}
	}
	if (test->il) {
		// expect some IL, no failure, no report and no timeout
		if (!out->il || out->il_failed || RZ_STR_ISNOTEMPTY(out->il_err) || out->il_timeout) {
			return false;
		}
		// IL must also be correct
		if (strcmp(out->il, test->il) != 0) {
			return false;
		}
	}
	return true;
}

RZ_API void rz_test_asm_test_output_free(RzAsmTestOutput *out) {
	if (!out) {
		return;
	}
	free(out->disasm);
	free(out->bytes);
	free(out->il);
	free(out->as_err);
	free(out->disas_err);
	free(out->il_err);
	free(out);
}

RZ_API RzSubprocessOutput *rz_test_run_fuzz_test(RzTestRunConfig *config, RzFuzzTest *test, RzTestCmdRunner runner, void *user) {
	const char *cmd = "e analysis.nopskip=0; aaa";
	RzList *files = rz_list_new();
	rz_list_push(files, test->file);
#if ASAN
	if (rz_str_endswith(test->file, "/swift_read")) {
		cmd = "?F";
	}
#endif

	RunRzTest fuzzer_rrt = {
		.config = config,
		.timeout_ms = config->timeout_ms,
		.bin_path = config->bin_path,
		.tool = NULL,
		.cmds = cmd,
		.files = files,
		.extra_args = NULL,
		.load_plugins = false,
		.color = false,
		.utf8 = false,
		.runner = runner,
		.user = user,
	};

	RzSubprocessOutput *ret = run_rz_test(&fuzzer_rrt, "rizin");
	rz_list_free(files);
	return ret;
}

RZ_API bool rz_test_check_fuzz_test(RzSubprocessOutput *out) {
	return out && out->ret == 0 && out->out && out->err && !out->timeout;
}

RZ_API char *rz_test_test_name(RzTest *test) {
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		if (test->cmd_test->name.value) {
			return strdup(test->cmd_test->name.value);
		}
		return strdup("<unnamed>");
	case RZ_TEST_TYPE_ASM:
		return rz_str_newf("<asm> %s", test->asm_test->disasm ? test->asm_test->disasm : "");
	case RZ_TEST_TYPE_JSON:
		return rz_str_newf("<json> %s", test->json_test->cmd ? test->json_test->cmd : "");
	case RZ_TEST_TYPE_FUZZ:
		return rz_str_newf("<fuzz> %s", test->fuzz_test->file);
	}
	return NULL;
}

RZ_API bool rz_test_broken(RzTest *test) {
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		return test->cmd_test->broken.value;
	case RZ_TEST_TYPE_ASM:
		return test->asm_test->mode & RZ_ASM_TEST_MODE_BROKEN ? true : false;
	case RZ_TEST_TYPE_JSON:
		return test->json_test->broken;
	case RZ_TEST_TYPE_FUZZ:
		return false;
	}
	return false;
}

RZ_API RzTestResultInfo *rz_test_run_test(RzTestRunConfig *config, RzTest *test) {
	RzTestResultInfo *ret = RZ_NEW0(RzTestResultInfo);
	if (!ret) {
		return NULL;
	}
	ret->test = test;
	bool success = false;
	ut64 start_time = rz_time_now_mono();
	switch (test->type) {
	case RZ_TEST_TYPE_CMD: {
		RzCmdTest *cmd_test = test->cmd_test;
		RzSubprocessOutput *out = rz_test_run_cmd_test(config, cmd_test, subprocess_runner, NULL);
		success = rz_test_check_cmd_test(out, cmd_test);
		ret->proc_out = out;
		ret->timeout = out && out->timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_ASM: {
		RzAsmTest *asm_test = test->asm_test;
		RzAsmTestOutput *out = rz_test_run_asm_test(config, asm_test);
		success = rz_test_check_asm_test(out, asm_test);
		ret->asm_out = out;
		if (out) {
			ret->timeout = out->as_timeout || out->disas_timeout || out->il_timeout;
		}
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_JSON: {
		RzJsonTest *json_test = test->json_test;
		RzSubprocessOutput *out = rz_test_run_json_test(config, json_test, subprocess_runner, NULL);
		success = rz_test_check_json_test(out, json_test);
		ret->proc_out = out;
		if (out) {
			ret->timeout = out->timeout;
		}
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_FUZZ: {
		RzFuzzTest *fuzz_test = test->fuzz_test;
		RzSubprocessOutput *out = rz_test_run_fuzz_test(config, fuzz_test, subprocess_runner, NULL);
		success = rz_test_check_fuzz_test(out);
		ret->proc_out = out;
		if (out) {
			ret->timeout = out->timeout;
		}
		ret->run_failed = !out;
	}
	}
	ret->time_elapsed = rz_time_now_mono() - start_time;
	bool broken = rz_test_broken(test);
	if (!success) {
		ret->result = broken ? RZ_TEST_RESULT_BROKEN : RZ_TEST_RESULT_FAILED;
	} else {
		ret->result = broken ? RZ_TEST_RESULT_FIXED : RZ_TEST_RESULT_OK;
	}
	return ret;
}

RZ_API void rz_test_test_result_info_free(RzTestResultInfo *result) {
	if (!result) {
		return;
	}
	if (result->test) {
		switch (result->test->type) {
		case RZ_TEST_TYPE_CMD:
		case RZ_TEST_TYPE_JSON:
		case RZ_TEST_TYPE_FUZZ:
			rz_subprocess_output_free(result->proc_out);
			break;
		case RZ_TEST_TYPE_ASM:
			rz_test_asm_test_output_free(result->asm_out);
			break;
		}
	}
	free(result);
}
