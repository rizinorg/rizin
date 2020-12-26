// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test.h"

static RzSubprocessOutput *subprocess_runner(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	RzSubprocess *proc = rz_subprocess_start (file, args, args_size, envvars, envvals, env_size);
	if (!proc) {
		return NULL;
	}
	bool timeout = !rz_subprocess_wait (proc, timeout_ms);
	if (timeout) {
		rz_subprocess_kill (proc);
	}
	RzSubprocessOutput *out = rz_subprocess_drain (proc);
	if (out) {
		out->timeout = timeout;
	}
	rz_subprocess_free (proc);
	return out;
}

#if __WINDOWS__
static char *convert_win_cmds(const char *cmds) {
	char *r = malloc (strlen (cmds) + 1);
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
						for (; c = *cmds, c && c != '}'; *cmds++) {
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
		char *lend = strchr (cmds, '\n');
		size_t llen;
		if (lend) {
			llen = lend - cmds + 1;
		} else {
			llen = strlen (cmds);
		}
		memcpy (p, cmds, llen);
		cmds += llen;
		p += llen;
	}
	*p = '\0';
	return rz_str_replace (r, "/dev/null", "nul", true);
}
#endif

static RzSubprocessOutput *run_rz_test(RzTestRunConfig *config, ut64 timeout_ms, const char *cmds, RzList *files, RzList *extra_args, bool load_plugins, RzTestCmdRunner runner, void *user) {
	RzPVector args;
	rz_pvector_init (&args, NULL);
	rz_pvector_push (&args, "-escr.utf8=0");
	rz_pvector_push (&args, "-escr.color=0");
	rz_pvector_push (&args, "-escr.interactive=0");
	rz_pvector_push (&args, "-N");
	RzListIter *it;
	void *extra_arg, *file_arg;
	rz_list_foreach (extra_args, it, extra_arg) {
		rz_pvector_push (&args, extra_arg);
	}
	rz_pvector_push (&args, "-Qc");
#if __WINDOWS__
	char *wcmds = convert_win_cmds (cmds);
	rz_pvector_push (&args, wcmds);
#else
	rz_pvector_push (&args, (void *)cmds);
#endif
	rz_list_foreach (files, it, file_arg) {
		rz_pvector_push (&args, file_arg);
	}

	const char *envvars[] = {
#if __WINDOWS__
		"ANSICON",
#endif
		"RZ_NOPLUGINS"
	};
	const char *envvals[] = {
#if __WINDOWS__
		"1",
#endif
		"1"
	};
#if __WINDOWS__
	size_t env_size = load_plugins ? 1 : 2;
#else
	size_t env_size = load_plugins ? 0 : 1;
#endif
	RzSubprocessOutput *out = runner (config->rz_cmd, args.v.a, rz_pvector_len (&args), envvars, envvals, env_size, timeout_ms, user);
	rz_pvector_clear (&args);
#if __WINDOWS__
	free (wcmds);
#endif
	return out;
}

RZ_API RzSubprocessOutput *rz_test_run_cmd_test(RzTestRunConfig *config, RzCmdTest *test, RzTestCmdRunner runner, void *user) {
	RzList *extra_args = test->args.value ? rz_str_split_duplist (test->args.value, " ", true) : NULL;
	RzList *files = test->file.value? rz_str_split_duplist (test->file.value, "\n", true): NULL;
	RzListIter *it;
	RzListIter *tmpit;
	char *token;
	rz_list_foreach_safe (extra_args, it, tmpit, token) {
		if (!*token) {
			rz_list_delete (extra_args, it);
		}
	}
	rz_list_foreach_safe (files, it, tmpit, token) {
		if (!*token) {
			rz_list_delete (files, it);
		}
	}
	if (rz_list_empty (files)) {
		if (!files) {
			files = rz_list_new ();
		} else {
			files->free = NULL;
		}
		rz_list_push (files, "-");
	}
	ut64 timeout_ms = test->timeout.set? test->timeout.value * 1000: config->timeout_ms;
	RzSubprocessOutput *out = run_rz_test (config, timeout_ms, test->cmds.value, files, extra_args, test->load_plugins, runner, user);
	rz_list_free (extra_args);
	rz_list_free (files);
	return out;
}

RZ_API bool rz_test_check_cmd_test(RzSubprocessOutput *out, RzCmdTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *expect_out = test->expect.value;
	if (expect_out && strcmp (out->out, expect_out) != 0) {
		return false;
	}
	const char *expect_err = test->expect_err.value;
	if (expect_err && strcmp (out->err, expect_err) != 0) {
		return false;
	}
	return true;
}

#define JQ_CMD "jq"

RZ_API bool rz_test_check_jq_available(void) {
	const char *args[] = {"."};
	const char *invalid_json = "this is not json lol";
	RzSubprocess *proc = rz_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		rz_subprocess_stdin_write (proc, (const ut8 *)invalid_json, strlen (invalid_json));
		rz_subprocess_wait (proc, UT64_MAX);
	}
	bool invalid_detected = proc && rz_subprocess_ret (proc) != 0;
	rz_subprocess_free (proc);

	const char *valid_json = "{\"this is\":\"valid json\",\"lol\":true}";
	proc = rz_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		rz_subprocess_stdin_write (proc, (const ut8 *)valid_json, strlen (valid_json));
		rz_subprocess_wait (proc, UT64_MAX);
	}
	bool valid_detected = proc && rz_subprocess_ret (proc) == 0;
	rz_subprocess_free (proc);

	return invalid_detected && valid_detected;
}

RZ_API RzSubprocessOutput *rz_test_run_json_test(RzTestRunConfig *config, RzJsonTest *test, RzTestCmdRunner runner, void *user) {
	RzList *files = rz_list_new ();
	rz_list_push (files, (void *)config->json_test_file);
	RzSubprocessOutput *ret = run_rz_test (config, config->timeout_ms, test->cmd, files, NULL, test->load_plugins, runner, user);
	rz_list_free (files);
	return ret;
}

RZ_API bool rz_test_check_json_test(RzSubprocessOutput *out, RzJsonTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *args[] = {"."};
	RzSubprocess *proc = rz_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	rz_subprocess_stdin_write (proc, (const ut8 *)out->out, strlen (out->out));
	rz_subprocess_wait (proc, UT64_MAX);
	bool ret = rz_subprocess_ret (proc) == 0;
	rz_subprocess_free (proc);
	return ret;
}

RZ_API RzAsmTestOutput *rz_test_run_asm_test(RzTestRunConfig *config, RzAsmTest *test) {
	RzAsmTestOutput *out = RZ_NEW0 (RzAsmTestOutput);
	if (!out) {
		return NULL;
	}

	RzPVector args;
	rz_pvector_init (&args, NULL);

	if (test->arch) {
		rz_pvector_push (&args, "-a");
		rz_pvector_push (&args, (void *)test->arch);
	}

	if (test->cpu) {
		rz_pvector_push (&args, "-c");
		rz_pvector_push (&args, (void *)test->cpu);
	}

	char bits[0x20];
	if (test->bits) {
		snprintf (bits, sizeof (bits), "%d", test->bits);
		rz_pvector_push (&args, "-b");
		rz_pvector_push (&args, bits);
	}

	if (test->mode & RZ_ASM_TEST_MODE_BIG_ENDIAN) {
		rz_pvector_push (&args, "-e");
	}

	char offset[0x20];
	if (test->offset) {
		rz_snprintf (offset, sizeof (offset), "0x%"PFMT64x, test->offset);
		rz_pvector_push (&args, "-o");
		rz_pvector_push (&args, offset);
	}

	RzStrBuf cmd_buf;
	rz_strbuf_init (&cmd_buf);
	if (test->mode & RZ_ASM_TEST_MODE_ASSEMBLE) {
		rz_pvector_push (&args, test->disasm);
		RzSubprocess *proc = rz_subprocess_start (config->rz_asm_cmd, args.v.a, rz_pvector_len (&args), NULL, NULL, 0);
		if (!rz_subprocess_wait (proc, config->timeout_ms)) {
			rz_subprocess_kill (proc);
			out->as_timeout = true;
			goto rip;
		}
		if (rz_subprocess_ret (proc) != 0) {
			goto rip;
		}
		char *hex = rz_subprocess_out (proc);
		size_t hexlen = strlen (hex);
		if (!hexlen) {
			goto rip;
		}
		ut8 *bytes = malloc (hexlen);
		int byteslen = rz_hex_str2bin (hex, bytes);
		free (hex);
		if (byteslen <= 0) {
			free (bytes);
			goto rip;
		}
		out->bytes = bytes;
		out->bytes_size = (size_t)byteslen;
rip:
		rz_pvector_pop (&args);
		rz_subprocess_free (proc);
	}
	if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
		char *hex = rz_hex_bin2strdup (test->bytes, test->bytes_size);
		if (!hex) {
			goto beach;
		}
		rz_pvector_push (&args, "-d");
		rz_pvector_push (&args, hex);
		RzSubprocess *proc = rz_subprocess_start (config->rz_asm_cmd, args.v.a, rz_pvector_len (&args), NULL, NULL, 0);
		if (!rz_subprocess_wait (proc, config->timeout_ms)) {
			rz_subprocess_kill (proc);
			out->disas_timeout = true;
			goto ship;
		}
		if (rz_subprocess_ret (proc) != 0) {
			goto ship;
		}
		free (hex);
		char *disasm = rz_subprocess_out (proc);
		rz_str_trim (disasm);
		out->disasm = disasm;
ship:
		rz_pvector_pop (&args);
		rz_pvector_pop (&args);
		rz_subprocess_free (proc);
	}

beach:
	rz_pvector_clear (&args);
	rz_strbuf_fini (&cmd_buf);
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
		if (memcmp (out->bytes, test->bytes, test->bytes_size) != 0) {
			return false;
		}
	}
	if (test->mode & RZ_ASM_TEST_MODE_DISASSEMBLE) {
		if (!out->disasm || !test->disasm || out->as_timeout) {
			return false;
		}
		if (strcmp (out->disasm, test->disasm) != 0) {
			return false;
		}
	}
	return true;
}

RZ_API void rz_test_asm_test_output_free(RzAsmTestOutput *out) {
	if (!out) {
		return;
	}
	free (out->disasm);
	free (out->bytes);
	free (out);
}

RZ_API RzSubprocessOutput *rz_test_run_fuzz_test(RzTestRunConfig *config, RzFuzzTest *test, RzTestCmdRunner runner, void *user) {
	const char *cmd = "aaa";
	RzList *files = rz_list_new ();
	rz_list_push (files, test->file);
#if ASAN
	if (rz_str_endswith (test->file, "/swift_read")) {
		cmd = "?F";
	}
#endif
	RzSubprocessOutput *ret = run_rz_test (config, config->timeout_ms, cmd, files, NULL, false, runner, user);
	rz_list_free (files);
	return ret;
}

RZ_API bool rz_test_check_fuzz_test(RzSubprocessOutput *out) {
	return out && out->ret == 0 && out->out && out->err && !out->timeout;
}

RZ_API char *rz_test_test_name(RzTest *test) {
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		if (test->cmd_test->name.value) {
			return strdup (test->cmd_test->name.value);
		}
		return strdup ("<unnamed>");
	case RZ_TEST_TYPE_ASM:
		return rz_str_newf ("<asm> %s", test->asm_test->disasm ? test->asm_test->disasm : "");
	case RZ_TEST_TYPE_JSON:
		return rz_str_newf ("<json> %s", test->json_test->cmd ? test->json_test->cmd: "");
	case RZ_TEST_TYPE_FUZZ:
		return rz_str_newf ("<fuzz> %s", test->fuzz_test->file);
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
	RzTestResultInfo *ret = RZ_NEW0 (RzTestResultInfo);
	if (!ret) {
		return NULL;
	}
	ret->test = test;
	bool success = false;
	ut64 start_time = rz_time_now_mono ();
	switch (test->type) {
	case RZ_TEST_TYPE_CMD: {
		RzCmdTest *cmd_test = test->cmd_test;
		RzSubprocessOutput *out = rz_test_run_cmd_test (config, cmd_test, subprocess_runner, NULL);
		success = rz_test_check_cmd_test (out, cmd_test);
		ret->proc_out = out;
		ret->timeout = out && out->timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_ASM: {
		RzAsmTest *asm_test = test->asm_test;
		RzAsmTestOutput *out = rz_test_run_asm_test (config, asm_test);
		success = rz_test_check_asm_test (out, asm_test);
		ret->asm_out = out;
		ret->timeout = out->as_timeout || out->disas_timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_JSON: {
		RzJsonTest *json_test = test->json_test;
		RzSubprocessOutput *out = rz_test_run_json_test (config, json_test, subprocess_runner, NULL);
		success = rz_test_check_json_test (out, json_test);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		ret->run_failed = !out;
		break;
	}
	case RZ_TEST_TYPE_FUZZ: {
		RzFuzzTest *fuzz_test = test->fuzz_test;
		RzSubprocessOutput *out = rz_test_run_fuzz_test (config, fuzz_test, subprocess_runner, NULL);
		success = rz_test_check_fuzz_test (out);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		ret->run_failed = !out;
	}
	}
	ret->time_elapsed = rz_time_now_mono () - start_time;
	bool broken = rz_test_broken (test);
#if ASAN
# if !RZ_ASSERT_STDOUT
# error RZ_ASSERT_STDOUT undefined or 0
# endif
	RzSubprocessOutput *out = ret->proc_out;
	if (!success && test->type == RZ_TEST_TYPE_CMD && strstr (test->path, "/dbg")
	    && (!out->out ||
	        (!strstr (out->out, "WARNING:") && !strstr (out->out, "ERROR:") && !strstr (out->out, "FATAL:")))
	    && (!out->err ||
	        (!strstr (out->err, "Sanitizer") && !strstr (out->err, "runtime error:")))) {
		broken = true;
	}
#endif
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
			rz_subprocess_output_free (result->proc_out);
			break;
		case RZ_TEST_TYPE_ASM:
			rz_test_asm_test_output_free (result->asm_out);
			break;
		}
	}
	free (result);
}
