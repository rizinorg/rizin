// SPDX-FileCopyrightText: 2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test.h"
#include <rz_util/rz_str.h>
#include <rz_util/rz_regex.h>
#include <rz_cons.h>
#if __WINDOWS__
#include <io.h>
#else
#include <unistd.h>
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

static size_t crlf2lf_len(ut8 *str, size_t len) {
	size_t r = 0, w = 0;
	while (r < len) {
		if (r + 1 < len && str[r] == '\r' && str[r + 1] == '\n') {
			r++;
			continue;
		}
		str[w++] = str[r++];
	}
	str[w] = '\0';
	return w;
}
#else
#define crlf2lf(x)        (x)
#define crlf2lf_len(x, l) (l)
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

static bool cmds_contain_process_mutating_op(const char *cmds) {
	if (RZ_STR_ISEMPTY(cmds)) {
		return false;
	}
	const char *p = cmds;
	bool at_cmd_start = true;
	while (*p) {
		if (at_cmd_start) {
			while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ';') {
				p++;
			}
			if (!*p) {
				break;
			}
			if (*p == '!') {
				return true;
			}
			if (p[0] == '#' && p[1] == '!') {
				return true;
			}
			if (p[0] == 'R' && p[1] == '+') {
				return true;
			}
			if (p[0] == '=' && (p[1] == 'h' || p[1] == 'H' || p[1] == '&')) {
				return true;
			}
			if (p[0] == 'q' && p[1] == '!') {
				return true;
			}
			if (p[0] == 'c' && p[1] == 'd' && (!p[2] || p[2] == ' ' || p[2] == '\t' || p[2] == '\n' || p[2] == ';')) {
				return true;
			}
			if (p[0] == 'e' && p[1] == 'n' && p[2] == 'v' && (!p[3] || p[3] == ' ' || p[3] == '\t' || p[3] == '\n' || p[3] == ';')) {
				return true;
			}
			at_cmd_start = false;
		}
		if (*p == '\n' || *p == ';') {
			at_cmd_start = true;
		}
		p++;
	}
	return false;
}

static bool args_contain_unsafe_batch_flag(const char *args_str) {
	if (RZ_STR_ISEMPTY(args_str)) {
		return false;
	}
	const char *p = args_str;
	while (*p) {
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (!*p) {
			break;
		}
		const char *tok = p;
		while (*p && *p != ' ' && *p != '\t') {
			p++;
		}
		size_t len = (size_t)(p - tok);
		if (len >= 2 && tok[0] == '-') {
			if (tok[1] == '-') {
				return true;
			}
			// Check short option cluster for flags mutating fds, debugger, remote, or pipes.
			for (size_t i = 1; i < len; i++) {
				char ch = tok[i];
				if (ch == 'd' || ch == 'D' || ch == '1' || ch == '2' || ch == '0' || ch == 'C' || ch == '=') {
					return true;
				}
				// Stop scanning once a flag that consumes the rest of the token as its value is reached.
				if (ch == 'a' || ch == 'b' || ch == 'B' || ch == 'c' || ch == 'e' || ch == 'E' ||
					ch == 'F' || ch == 'H' || ch == 'i' || ch == 'I' || ch == 'k' || ch == 'l' ||
					ch == 'm' || ch == 'p' || ch == 'r' || ch == 'R' || ch == 's') {
					break;
				}
			}
		}
	}
	return false;
}

static bool files_contain_unsafe_batch_target(const char *file_str) {
	if (RZ_STR_ISEMPTY(file_str)) {
		return false;
	}
	const char *p = file_str;
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);
		if (len == 1 && p[0] == '-') {
			return true;
		}
		if ((len >= 6 && !strncmp(p, "dbg://", 6)) ||
			(len >= 6 && !strncmp(p, "gdb://", 6)) ||
			(len >= 9 && !strncmp(p, "ptrace://", 9)) ||
			(len >= 7 && !strncmp(p, "self://", 7)) ||
			(len >= 10 && !strncmp(p, "winedbg://", 10))) {
			return true;
		}
		if (!nl) {
			break;
		}
		p = nl + 1;
	}
	return false;
}

/**
 * \brief Return true if a cmd test can safely run inside a batched rizin worker.
 */
RZ_API bool rz_test_cmd_test_batchable(RZ_NONNULL const RzCmdTest *test) {
	rz_return_val_if_fail(test, false);
	if (RZ_STR_ISNOTEMPTY(test->tool.value) || RZ_STR_ISNOTEMPTY(test->envs.value) ||
		test->load_plugins || test->color.value || test->utf8.value || test->timeout.set) {
		return false;
	}
	if (args_contain_unsafe_batch_flag(test->args.value)) {
		return false;
	}
	if (files_contain_unsafe_batch_target(test->file.value)) {
		return false;
	}
	if (cmds_contain_process_mutating_op(test->cmds.value)) {
		return false;
	}
	return true;
}

static bool parse_worker_result_header(const char *line, int *rc_out, size_t *out_len_out, size_t *err_len_out) {
	if (!line || strncmp(line, "RESULT ", 7) != 0) {
		return false;
	}
	char *end1 = NULL;
	char *end2 = NULL;
	char *end3 = NULL;
	long rc = strtol(line + 7, &end1, 10);
	if (!end1 || *end1 != ' ') {
		return false;
	}
	unsigned long long olen = strtoull(end1 + 1, &end2, 10);
	if (!end2 || *end2 != ' ') {
		return false;
	}
	unsigned long long elen = strtoull(end2 + 1, &end3, 10);
	if (!end3 || *end3 != '\0') {
		return false;
	}
	*rc_out = (int)rc;
	*out_len_out = (size_t)olen;
	*err_len_out = (size_t)elen;
	return true;
}

static bool append_batch_item_args(RzStrBuf *sb, const RzPVector /*<const char *>*/ *args) {
	size_t n = rz_pvector_len(args);
	if (!n) {
		return false;
	}
	rz_strbuf_appendf(sb, "ITEM %" PFMTSZu "\n", n);
	for (size_t i = 0; i < n; i++) {
		const char *arg = rz_pvector_at(args, i);
		if (!arg) {
			arg = "";
		}
		size_t alen = strlen(arg);
		rz_strbuf_appendf(sb, "ARG %" PFMTSZu "\n", alen);
		rz_strbuf_append_n(sb, arg, alen);
		rz_strbuf_append_n(sb, "\n", 1);
	}
	return true;
}

struct rz_test_rizin_worker_t {
	RzSubprocess *proc;
};

static bool worker_write_all(RzSubprocess *proc, const ut8 *buf, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t w = rz_subprocess_stdin_write(proc, buf + off, len - off);
		if (w <= 0) {
			return false;
		}
		off += (size_t)w;
	}
	return true;
}

static bool worker_read_exact(RzSubprocess *proc, ut8 *dst, size_t want, ut64 deadline_us, bool *timedout) {
	size_t got = 0;
	while (got < want) {
		ut64 now = rz_time_now_mono();
		if (deadline_us != UT64_MAX && now >= deadline_us) {
			*timedout = true;
			return false;
		}
		ut64 rem_ms = deadline_us == UT64_MAX ? UT64_MAX : ((deadline_us - now + 999) / 1000);
		if (rem_ms == 0) {
			rem_ms = 1;
		}
		RzStrBuf *sb = rz_subprocess_stdout_read(proc, want - got, rem_ms);
		size_t n = sb ? rz_strbuf_length(sb) : 0;
		if (!n) {
			if (deadline_us != UT64_MAX && rz_time_now_mono() >= deadline_us) {
				*timedout = true;
			}
			return false;
		}
		memcpy(dst + got, rz_strbuf_get(sb), n);
		got += n;
	}
	return true;
}

static bool worker_read_line(RzSubprocess *proc, char *buf, size_t cap, ut64 deadline_us, bool *timedout) {
	size_t len = 0;
	while (len + 1 < cap) {
		ut8 ch = 0;
		if (!worker_read_exact(proc, &ch, 1, deadline_us, timedout)) {
			return false;
		}
		if (ch == '\n') {
			buf[len] = '\0';
			if (len > 0 && buf[len - 1] == '\r') {
				buf[len - 1] = '\0';
			}
			return true;
		}
		buf[len++] = (char)ch;
	}
	return false;
}

/**
 * \brief Spawn a persistent rizin --batch-worker subprocess for a worker thread.
 */
RZ_API RZ_OWN RzTestRizinWorker *rz_test_rizin_worker_new(RZ_NONNULL RzTestRunConfig *config) {
	rz_return_val_if_fail(config, NULL);
	char *exe = rz_test_find_executable("rizin", config->bin_path);
	if (!exe) {
		return NULL;
	}
	const char *args[] = { "--batch-worker" };
	const char *envvars[] = {
#if __WINDOWS__
		"ANSICON",
#endif
		"RZ_COLOR",
		"RZ_UTF8",
		"RZ_NOPLUGINS",
	};
	const char *envvals[] = {
#if __WINDOWS__
		"1",
#endif
		"0",
		"0",
		"1",
	};
	RzSubprocessOpt opt = {
		.file = exe,
		.args = args,
		.args_size = RZ_ARRAY_SIZE(args),
		.envvars = envvars,
		.envvals = envvals,
		.env_size = RZ_ARRAY_SIZE(envvars),
		.stdin_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stdout_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stderr_pipe = RZ_SUBPROCESS_PIPE_NONE,
	};
	RzSubprocess *proc = rz_subprocess_start_opt(&opt);
	free(exe);
	if (!proc) {
		return NULL;
	}
	RzTestRizinWorker *w = RZ_NEW0(RzTestRizinWorker);
	if (!w) {
		rz_subprocess_kill(proc);
		rz_subprocess_free(proc);
		return NULL;
	}
	w->proc = proc;
	return w;
}

/**
 * \brief Gracefully stop and free a persistent rizin worker subprocess.
 */
RZ_API void rz_test_rizin_worker_free(RZ_NULLABLE RzTestRizinWorker *worker) {
	if (!worker) {
		return;
	}
	if (worker->proc) {
		if (rz_subprocess_wait(worker->proc, 5000) == RZ_SUBPROCESS_TIMEDOUT) {
			rz_subprocess_kill(worker->proc);
		}
		rz_subprocess_free(worker->proc);
	}
	free(worker);
}

static void rz_test_rizin_worker_kill(RzTestRizinWorker **worker_slot) {
	if (!worker_slot || !*worker_slot) {
		return;
	}
	RzTestRizinWorker *w = *worker_slot;
	if (w->proc) {
		rz_subprocess_kill(w->proc);
		rz_subprocess_wait(w->proc, 1000);
		rz_subprocess_free(w->proc);
	}
	free(w);
	*worker_slot = NULL;
}

static RzSubprocessOutput *run_test_in_worker(RzTestRunConfig *config, RzTest *test, RzTestRizinWorker **worker_slot, bool *proto_ok) {
	*proto_ok = false;
	RzList /*<char *>*/ *extra_args = NULL;
	RzList /*<char *>*/ *files = NULL;
	const char *cmds = NULL;
	if (test->type == RZ_TEST_TYPE_CMD) {
		RzCmdTest *ct = test->cmd_test;
		extra_args = ct->args.value ? rz_str_split_duplist(ct->args.value, " ", true) : NULL;
		files = ct->file.value ? rz_str_split_duplist(ct->file.value, "\n", true) : NULL;
		RzListIter *it, *tmpit;
		char *tok;
		rz_list_foreach_safe (extra_args, it, tmpit, tok) {
			if (!*tok) {
				rz_list_delete(extra_args, it);
			}
		}
		rz_list_foreach_safe (files, it, tmpit, tok) {
			if (!*tok) {
				rz_list_delete(files, it);
			}
		}
		if (rz_list_empty(files)) {
			if (!files) {
				files = rz_list_new();
			} else {
				files->free = NULL;
			}
			rz_list_push(files, "=");
		}
		cmds = ct->cmds.value;
	} else if (test->type == RZ_TEST_TYPE_JSON) {
		files = rz_list_new();
		rz_list_push(files, (void *)config->json_test_file);
		cmds = test->json_test->cmd;
	} else {
		return NULL;
	}

	RunRzTest rrt = {
		.config = config,
		.timeout_ms = config->timeout_ms,
		.bin_path = config->bin_path,
		.tool = NULL,
		.cmds = cmds,
		.envs = NULL,
		.files = files,
		.extra_args = extra_args,
		.load_plugins = false,
		.color = false,
		.utf8 = false,
		.runner = NULL,
		.user = NULL,
	};
	RzPVector /*<const char *>*/ args;
#if __WINDOWS__
	char *wcmds = convert_win_cmds(rrt.cmds);
	run_rz_test_init_args(&rrt, wcmds, &args);
#else
	run_rz_test_init_args(&rrt, rrt.cmds, &args);
#endif
	RzStrBuf req;
	rz_strbuf_init(&req);
	bool req_ok = append_batch_item_args(&req, &args);
	rz_pvector_clear(&args);
#if __WINDOWS__
	free(wcmds);
#endif
	rz_list_free(extra_args);
	rz_list_free(files);
	if (!req_ok) {
		rz_strbuf_fini(&req);
		return NULL;
	}

	if (!*worker_slot) {
		*worker_slot = rz_test_rizin_worker_new(config);
		if (!*worker_slot) {
			rz_strbuf_fini(&req);
			return NULL;
		}
	}

	RzSubprocess *proc = (*worker_slot)->proc;
	bool sent = worker_write_all(proc, (const ut8 *)rz_strbuf_get(&req), rz_strbuf_length(&req));
	rz_strbuf_fini(&req);
	if (!sent) {
		rz_test_rizin_worker_kill(worker_slot);
		return NULL;
	}

	ut64 deadline_us = config->timeout_ms == UT64_MAX
		? UT64_MAX
		: rz_time_now_mono() + config->timeout_ms * 1000;
	bool timedout = false;
	char hdr[128];
	int item_rc = 0;
	size_t out_len = 0;
	size_t err_len = 0;
	if (!worker_read_line(proc, hdr, sizeof(hdr), deadline_us, &timedout) ||
		!parse_worker_result_header(hdr, &item_rc, &out_len, &err_len)) {
		rz_test_rizin_worker_kill(worker_slot);
		return NULL;
	}

	ut8 *out_buf = malloc(out_len + 1);
	ut8 *err_buf = malloc(err_len + 1);
	if (!out_buf || !err_buf ||
		!worker_read_exact(proc, out_buf, out_len, deadline_us, &timedout) ||
		!worker_read_exact(proc, err_buf, err_len, deadline_us, &timedout)) {
		free(out_buf);
		free(err_buf);
		rz_test_rizin_worker_kill(worker_slot);
		return NULL;
	}
	out_buf[out_len] = '\0';
	err_buf[err_len] = '\0';
	out_len = crlf2lf_len(out_buf, out_len);
	err_len = crlf2lf_len(err_buf, err_len);

	RzSubprocessOutput *out = RZ_NEW0(RzSubprocessOutput);
	if (!out) {
		free(out_buf);
		free(err_buf);
		return NULL;
	}
	out->out = out_buf;
	out->out_len = (int)out_len;
	out->err = err_buf;
	out->err_len = (int)err_len;
	out->ret = item_rc;
	out->timeout = false;
	*proto_ok = true;
	return out;
}

/**
 * \brief Run a single test using a persistent rizin worker when eligible, with fallback.
 */
RZ_API RZ_OWN RzTestResultInfo *rz_test_run_test_with_worker(RzTestRunConfig *config, RzTest *test, RzTestRizinWorker **worker_slot) {
	bool eligible = worker_slot &&
		((test->type == RZ_TEST_TYPE_CMD && rz_test_cmd_test_batchable(test->cmd_test)) ||
			(test->type == RZ_TEST_TYPE_JSON && !test->json_test->load_plugins));
	if (!eligible) {
		return rz_test_run_test(config, test);
	}

	ut64 start_time = rz_time_now_mono();
	bool proto_ok = false;
	RzSubprocessOutput *out = run_test_in_worker(config, test, worker_slot, &proto_ok);
	if (!proto_ok || !out) {
		rz_subprocess_output_free(out);
		return rz_test_run_test(config, test);
	}

	RzTestResultInfo *ret = RZ_NEW0(RzTestResultInfo);
	if (!ret) {
		rz_subprocess_output_free(out);
		return NULL;
	}
	ret->test = test;
	ret->proc_out = out;
	ret->timeout = false;
	ret->run_failed = false;
	ret->time_elapsed = rz_time_now_mono() - start_time;

	bool success = false;
	bool broken = false;
	if (test->type == RZ_TEST_TYPE_CMD) {
		success = rz_test_check_cmd_test(out, test->cmd_test);
		broken = test->cmd_test->broken.value;
	} else if (test->type == RZ_TEST_TYPE_JSON) {
		success = rz_test_check_json_test(out, test->json_test);
		broken = test->json_test->broken;
	}
	if (!success) {
		ret->result = broken ? RZ_TEST_RESULT_BROKEN : RZ_TEST_RESULT_FAILED;
	} else {
		ret->result = broken ? RZ_TEST_RESULT_FIXED : RZ_TEST_RESULT_OK;
	}
	return ret;
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

RZ_API RzAsmTestOutput *rz_test_run_asm_test(RzTestRunConfig *config, RzAsmTest *test) {
	RzAsmTestOutput *out = RZ_NEW0(RzAsmTestOutput);
	if (!out) {
		return NULL;
	}
	out->as_ret = out->disas_ret = out->il_ret = INT_MAX;
	char *rz_asm_exe = rz_file_path("rz-asm");

	RzPVector args;
	rz_pvector_init(&args, NULL);

	if (test->arch) {
		rz_pvector_push(&args, "-a");
		rz_pvector_push(&args, (void *)test->arch);
	}

	if (test->cpu) {
		rz_pvector_push(&args, "-c");
		rz_pvector_push(&args, (void *)test->cpu);
	}

	char bits[0x20];
	if (test->bits) {
		snprintf(bits, sizeof(bits), "%d", test->bits);
		rz_pvector_push(&args, "-b");
		rz_pvector_push(&args, bits);
	}

	if (test->mode & RZ_ASM_TEST_MODE_BIG_ENDIAN) {
		rz_pvector_push(&args, "-e");
	}

	char offset[0x20];
	if (test->offset) {
		rz_snprintf(offset, sizeof(offset), "0x%" PFMT64x, test->offset);
		rz_pvector_push(&args, "-o");
		rz_pvector_push(&args, offset);
	}

	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		rz_pvector_push(&args, test->disasm);
		RzSubprocess *proc = rz_subprocess_start(rz_asm_exe, args.v.a, rz_pvector_len(&args), NULL, NULL, 0);
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
		RzSubprocess *proc = rz_subprocess_start(rz_asm_exe, args.v.a, rz_pvector_len(&args), NULL, NULL, 0);
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
		RzSubprocess *proc = rz_subprocess_start(rz_asm_exe, args.v.a, rz_pvector_len(&args), NULL, NULL, 0);
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
		if (!out->disasm || !test->disasm || out->as_timeout) {
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
