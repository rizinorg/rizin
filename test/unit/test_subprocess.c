// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_cons.h>
#include "minunit.h"

#define UT_TIMEOUT 100000000

static char tmp_path[1000];

#if __WINDOWS__
static char *remove_cr(ut8 *str) {
	char *s = (char *)str;
	char *start = s;
	while (*s) {
		if (s[0] == '\r' &&
			!(s - start >= 4 && !strncmp(s - 4, RZ_CONS_CLEAR_SCREEN, 4))) {
			memmove(s, s + 1, strlen(s + 1) + 1);
			continue;
		}
		s++;
	}
	return start;
}
#else
#define remove_cr(x) ((char *)(x))
#endif

const char *get_auxiliary_path(const char *s) {
	char *p = rz_sys_pid_to_path(rz_sys_getpid());
	char *pp = (char *)rz_str_lchr(p, RZ_SYS_DIR[0]);
	if (pp) {
		*pp = '\0';
	}
	snprintf(tmp_path, sizeof(tmp_path), "%s%s%s%s%s", p, RZ_SYS_DIR, "auxiliary", RZ_SYS_DIR, s);
	free(p);
	return tmp_path;
}

bool test_noargs_noinput_outerr(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	RzSubprocess *sp = rz_subprocess_start(exe_path, NULL, 0, NULL, NULL, 0);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Hello World\n", "hello world string should be print on stdout");
	mu_assert_streq(remove_cr(spo->err), "This is on err\n", "stderr should be found");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_args(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	const char *args[] = { "rizin" };
	RzSubprocess *sp = rz_subprocess_start(exe_path, args, 1, NULL, NULL, 0);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Hello rizin\n", "rizin arg should be passed and printed");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_env(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	const char *envvars[] = { "YOUVAR" };
	const char *envvals[] = { "Rizin Project" };
	RzSubprocess *sp = rz_subprocess_start(exe_path, NULL, 0, envvars, envvals, 1);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Hello Rizin Project\n", "YOUVAR env var should be passed and printed on stdout");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_stdin(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-stdin");
	RzSubprocess *sp = rz_subprocess_start(exe_path, NULL, 0, NULL, NULL, 0);
	mu_assert_notnull(sp, "the subprocess should be created");
	const char *input = "3\n10\n";
	rz_subprocess_stdin_write(sp, (const ut8 *)input, strlen(input));
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "13\n", "the sum should be printed on stdout");
	mu_assert_eq(spo->ret, 13, "return value is the sum, 13");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_multi(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-stdin");
	RzSubprocess *sp1 = rz_subprocess_start(exe_path, NULL, 0, NULL, NULL, 0);
	RzSubprocess *sp2 = rz_subprocess_start(exe_path, NULL, 0, NULL, NULL, 0);
	RzSubprocess *sp3 = rz_subprocess_start(exe_path, NULL, 0, NULL, NULL, 0);
	const char *input1 = "3\n10\n";
	const char *input2 = "1\n2\n";
	const char *input3 = "5\n7\n";
	rz_subprocess_stdin_write(sp1, (const ut8 *)input1, strlen(input1));
	rz_subprocess_wait(sp1, UT_TIMEOUT);
	rz_subprocess_stdin_write(sp2, (const ut8 *)input2, strlen(input2));
	rz_subprocess_stdin_write(sp3, (const ut8 *)input3, strlen(input3));
	rz_subprocess_wait(sp2, UT_TIMEOUT);
	rz_subprocess_wait(sp3, UT_TIMEOUT);
	RzSubprocessOutput *spo1 = rz_subprocess_drain(sp1);
	mu_assert_eq(spo1->ret, 13, "return value is the sum");
	RzSubprocessOutput *spo2 = rz_subprocess_drain(sp2);
	mu_assert_eq(spo2->ret, 3, "return value is the sum");
	RzSubprocessOutput *spo3 = rz_subprocess_drain(sp3);
	mu_assert_eq(spo3->ret, 12, "return value is the sum");
	rz_subprocess_output_free(spo1);
	rz_subprocess_output_free(spo2);
	rz_subprocess_output_free(spo3);
	rz_subprocess_free(sp1);
	rz_subprocess_free(sp2);
	rz_subprocess_free(sp3);
	rz_subprocess_fini();
	mu_end;
}

bool test_specialchar_args(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-multiargs");
	const char *args[] = { "ri$in", " awesome project ", "'single $quoted'", "\"double $quoted\"", "{", "(", "]", "[" };
	RzSubprocess *sp = rz_subprocess_start(exe_path, args, RZ_ARRAY_SIZE(args), NULL, NULL, 0);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Hello ri$in  awesome project  'single $quoted' \"double $quoted\" { ( ] [\n", "all args should be correctly printed");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_nopipes(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_NONE;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_NONE;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_NONE;
	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "", "hello world string should be not intercepted on stdout");
	mu_assert_streq(remove_cr(spo->err), "", "stderr should not be intercepted");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_stdoutonly(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_NONE;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_CREATE;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_NONE;
	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Hello World\n", "hello world string should be on stdout");
	mu_assert_streq(remove_cr(spo->err), "", "stderr should not be intercepted");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_stderronly(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_NONE;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_NONE;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_CREATE;
	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "", "stdout should not be intercepted");
	mu_assert_streq(remove_cr(spo->err), "This is on err\n", "stderr should not be intercepted");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_stdoutstderr(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-helloworld");
	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_NONE;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_CREATE;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_STDOUT;
	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_strcontains(remove_cr(spo->out), "Hello World\n", "stdout should be captured in out");
	mu_assert_strcontains(remove_cr(spo->out), "This is on err\n", "stderr should be captured in out");
	mu_assert_streq(remove_cr(spo->err), "", "stderr should not be intercepted");
	mu_assert_eq(spo->ret, 0, "return value is 0");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_interactive(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-interactive");
	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_CREATE;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_CREATE;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_NONE;
	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_stdin_write(sp, (const ut8 *)"3\n", strlen("3\n"));
	rz_subprocess_stdin_write(sp, (const ut8 *)"5\n", strlen("5\n"));
	RzStrBuf *sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	int c = atoi(rz_strbuf_get(sb));
	char buf[100];
	snprintf(buf, sizeof(buf), "%d\n", 3 + 5 + c);
	rz_subprocess_stdin_write(sp, (const ut8 *)buf, strlen(buf));
	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Right\n", "A Good message should be returned");
	mu_assert_eq(spo->ret, 0, "subprocess exited in the right way");
	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

#if HAVE_FORKPTY && HAVE_OPENPTY && HAVE_LOGIN_TTY
bool test_interactive_pty(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-interactive");

	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	/* Try all PTY */
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_PTY;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_PTY;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_PTY;
	opt.make_raw = true;

	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_stdin_write(sp, (const ut8 *)"3\n", strlen("3\n"));
	rz_subprocess_stdin_write(sp, (const ut8 *)"5\n", strlen("5\n"));

	RzStrBuf *sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	int c = atoi(rz_strbuf_get(sb));
	char buf[100];
	snprintf(buf, sizeof(buf), "%d\n", 3 + 5 + c);
	rz_subprocess_stdin_write(sp, (const ut8 *)buf, strlen(buf));

	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Right\n", "A Good message should be returned");
	mu_assert_eq(spo->ret, 0, "subprocess exited in the right way");

	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}

bool test_interactive_custom_pty(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-interactive");

	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_CREATE;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_PTY;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_STDOUT;
	opt.make_raw = true;
	opt.pty = rz_subprocess_openpty(NULL, NULL, NULL);

	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_stdin_write(sp, (const ut8 *)"3\n", strlen("3\n"));
	rz_subprocess_stdin_write(sp, (const ut8 *)"5\n", strlen("5\n"));

	RzStrBuf *sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	int c = atoi(rz_strbuf_get(sb));
	char buf[100];
	snprintf(buf, sizeof(buf), "%d\n", 3 + 5 + c);
	rz_subprocess_stdin_write(sp, (const ut8 *)buf, strlen(buf));

	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Right\n", "A Good message should be returned");
	mu_assert_eq(spo->ret, 0, "subprocess exited in the right way");

	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	rz_subprocess_pty_free(opt.pty);
	mu_end;
}

bool test_interactive_not_raw_pty(void) {
	rz_subprocess_init();
	const char *exe_path = get_auxiliary_path("subprocess-interactive");

	RzSubprocessOpt opt = { 0 };
	opt.file = exe_path;
	opt.stdin_pipe = RZ_SUBPROCESS_PIPE_PTY;
	opt.stdout_pipe = RZ_SUBPROCESS_PIPE_PTY;
	opt.stderr_pipe = RZ_SUBPROCESS_PIPE_PTY;
	/* Not raw, so all input will be echoe-ed */
	opt.make_raw = false;

	RzSubprocess *sp = rz_subprocess_start_opt(&opt);
	mu_assert_notnull(sp, "the subprocess should be created");
	rz_subprocess_stdin_write(sp, (const ut8 *)"3\n", strlen("3\n"));
	rz_subprocess_stdin_write(sp, (const ut8 *)"5\n", strlen("5\n"));

	/* CRLF is returned, can be changed by using custom PTY with custom term params
	Not necessary for testing here though */
	RzStrBuf *sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	mu_assert_streq(remove_cr(rz_strbuf_get(sb)), "3\r\n", "No 3");
	sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	mu_assert_streq(remove_cr(rz_strbuf_get(sb)), "5\r\n", "No 5");

	sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	int c = atoi(rz_strbuf_get(sb));
	char buf[100];
	snprintf(buf, sizeof(buf), "%d\n", 3 + 5 + c);
	rz_subprocess_stdin_write(sp, (const ut8 *)buf, strlen(buf));

	sb = rz_subprocess_stdout_readline(sp, UT_TIMEOUT);
	mu_assert_eq(atoi(rz_strbuf_get(sb)), 3 + 5 + c, "No 3 + 5 + c");

	rz_subprocess_wait(sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain(sp);
	mu_assert_streq(remove_cr(spo->out), "Right\r\n", "A Good message should be returned");
	mu_assert_eq(spo->ret, 0, "subprocess exited in the right way");

	rz_subprocess_output_free(spo);
	rz_subprocess_free(sp);
	rz_subprocess_fini();
	mu_end;
}
#else
bool test_interactive_pty(void) {
	mu_end;
}
bool test_interactive_custom_pty(void) {
	mu_end;
}
bool test_interactive_not_raw_pty(void) {
	mu_end;
}
#endif // PTY functions

bool all_tests() {
	mu_run_test(test_noargs_noinput_outerr);
	mu_run_test(test_args);
	mu_run_test(test_env);
	mu_run_test(test_stdin);
	mu_run_test(test_multi);
	mu_run_test(test_specialchar_args);
	mu_run_test(test_nopipes);
	mu_run_test(test_stdoutonly);
	mu_run_test(test_stderronly);
	mu_run_test(test_stdoutstderr);
	mu_run_test(test_interactive);
	mu_run_test(test_interactive_pty);
	mu_run_test(test_interactive_custom_pty);
	mu_run_test(test_interactive_not_raw_pty);
	return tests_passed != tests_run;
}

mu_main(all_tests)
