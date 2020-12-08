#include <rz_util.h>
#include "minunit.h"

#define UT_TIMEOUT 1000

static char tmp_path[1000];

const char *get_auxiliary_path(const char *s) {
	char *p = rz_sys_pid_to_path (rz_sys_getpid ());
	char *pp = (char *)rz_str_lchr (p, RZ_SYS_DIR[0]);
	if (pp) {
		*pp = '\0';
	}
	snprintf (tmp_path, sizeof (tmp_path), "%s%s%s%s%s", p, RZ_SYS_DIR, "auxiliary", RZ_SYS_DIR, s);
	free (p);
	return tmp_path;
}

bool test_noargs_noinput_outerr(void) {
	rz_subprocess_init ();
	const char *exe_path = get_auxiliary_path ("subprocess-helloworld");
	RzSubprocess *sp = rz_subprocess_start (exe_path, NULL, 0, NULL, NULL, 0);
	mu_assert_notnull (sp, "the subprocess should be created");
	rz_subprocess_wait (sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain (sp);
	mu_assert_streq (spo->out, "Hello World\n", "hello world string should be print on stdout");
	mu_assert_streq (spo->err, "This is on err\n", "stderr should be found");
	mu_assert_eq (spo->ret, 0, "return value is 0");
	rz_subprocess_output_free (spo);
	rz_subprocess_free (sp);
	rz_subprocess_fini ();
	mu_end;
}

bool test_args(void) {
	rz_subprocess_init ();
	const char *exe_path = get_auxiliary_path ("subprocess-helloworld");
	const char *args[] = { "rizin" };
	RzSubprocess *sp = rz_subprocess_start (exe_path, args, 1, NULL, NULL, 0);
	mu_assert_notnull (sp, "the subprocess should be created");
	rz_subprocess_wait (sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain (sp);
	mu_assert_streq (spo->out, "Hello rizin\n", "rizin arg should be passed and printed");
	mu_assert_eq (spo->ret, 0, "return value is 0");
	rz_subprocess_output_free (spo);
	rz_subprocess_free (sp);
	rz_subprocess_fini ();
	mu_end;
}

bool test_env(void) {
	rz_subprocess_init ();
	const char *exe_path = get_auxiliary_path ("subprocess-helloworld");
	const char *envvars[] = { "YOUVAR" };
	const char *envvals[] = { "Rizin Project" };
	RzSubprocess *sp = rz_subprocess_start (exe_path, NULL, 0, envvars, envvals, 1);
	mu_assert_notnull (sp, "the subprocess should be created");
	rz_subprocess_wait (sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain (sp);
	mu_assert_streq (spo->out, "Hello Rizin Project\n", "YOUVAR env var should be passed and printed on stdout");
	mu_assert_eq (spo->ret, 0, "return value is 0");
	rz_subprocess_output_free (spo);
	rz_subprocess_free (sp);
	rz_subprocess_fini ();
	mu_end;
}

bool test_stdin(void) {
	rz_subprocess_init ();
	const char *exe_path = get_auxiliary_path ("subprocess-stdin");
	RzSubprocess *sp = rz_subprocess_start (exe_path, NULL, 0, NULL, NULL, 0);
	mu_assert_notnull (sp, "the subprocess should be created");
	const char *input = "3\n10\n";
	rz_subprocess_stdin_write (sp, (const ut8 *)input, strlen (input));
	rz_subprocess_wait (sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain (sp);
	mu_assert_streq (spo->out, "13\n", "the sum should be printed on stdout");
	mu_assert_eq (spo->ret, 13, "return value is the sum, 13");
	rz_subprocess_output_free (spo);
	rz_subprocess_free (sp);
	rz_subprocess_fini ();
	mu_end;
}

bool test_multi(void) {
	rz_subprocess_init ();
	const char *exe_path = get_auxiliary_path ("subprocess-stdin");
	RzSubprocess *sp1 = rz_subprocess_start (exe_path, NULL, 0, NULL, NULL, 0);
	RzSubprocess *sp2 = rz_subprocess_start (exe_path, NULL, 0, NULL, NULL, 0);
	RzSubprocess *sp3 = rz_subprocess_start (exe_path, NULL, 0, NULL, NULL, 0);
	const char *input1 = "3\n10\n";
	const char *input2 = "1\n2\n";
	const char *input3 = "5\n7\n";
	rz_subprocess_stdin_write (sp1, (const ut8 *)input1, strlen (input1));
	rz_subprocess_wait (sp1, UT_TIMEOUT);
	rz_subprocess_stdin_write (sp2, (const ut8 *)input2, strlen (input2));
	rz_subprocess_stdin_write (sp3, (const ut8 *)input3, strlen (input3));
	rz_subprocess_wait (sp2, UT_TIMEOUT);
	rz_subprocess_wait (sp3, UT_TIMEOUT);
	RzSubprocessOutput *spo1 = rz_subprocess_drain (sp1);
	mu_assert_eq (spo1->ret, 13, "return value is the sum");
	RzSubprocessOutput *spo2 = rz_subprocess_drain (sp2);
	mu_assert_eq (spo2->ret, 3, "return value is the sum");
	RzSubprocessOutput *spo3 = rz_subprocess_drain (sp3);
	mu_assert_eq (spo3->ret, 12, "return value is the sum");
	rz_subprocess_output_free (spo1);
	rz_subprocess_output_free (spo2);
	rz_subprocess_output_free (spo3);
	rz_subprocess_free (sp1);
	rz_subprocess_free (sp2);
	rz_subprocess_free (sp3);
	rz_subprocess_fini ();
	mu_end;
}

bool test_specialchar_args(void) {
	rz_subprocess_init ();
	const char *exe_path = get_auxiliary_path ("subprocess-multiargs");
	const char *args[] = { "ri$in", " awesome project ", "'single $quoted'", "\"double $quoted\"", "{", "(", "]", "[" };
	RzSubprocess *sp = rz_subprocess_start (exe_path, args, RZ_ARRAY_SIZE (args), NULL, NULL, 0);
	mu_assert_notnull (sp, "the subprocess should be created");
	rz_subprocess_wait (sp, UT_TIMEOUT);
	RzSubprocessOutput *spo = rz_subprocess_drain (sp);
	mu_assert_streq (spo->out, "Hello ri$in  awesome project  'single $quoted' \"double $quoted\" { ( ] [\n", "all args should be correctly printed");
	mu_assert_eq (spo->ret, 0, "return value is 0");
	rz_subprocess_output_free (spo);
	rz_subprocess_free (sp);
	rz_subprocess_fini ();
	mu_end;
}

bool all_tests () {
	// TODO: use rz_subprocess in cmd_system (!)
	mu_run_test (test_noargs_noinput_outerr);
	mu_run_test (test_args);
	mu_run_test (test_env);
	mu_run_test (test_stdin);
	mu_run_test (test_multi);
	mu_run_test (test_specialchar_args);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}