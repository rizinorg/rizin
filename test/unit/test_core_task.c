#include <rz_core.h>
#include "minunit.h"

static void *my_function(RzCore *core, void *user) {
	size_t val = (size_t)user;
	int i;
	for (i = 0; i < 5; i++) {
		rz_cons_printf ("%u, %d\n", (unsigned int)val, i);
		rz_core_task_yield (&core->tasks);
	}
	return strdup (rz_cons_get_buffer ());
}

static bool test_core_task(void) {
	RzCore *core = rz_core_new ();
	rz_core_task_sync_begin (&core->tasks);

	RzCoreTask *a = rz_core_cmd_task_new (core, "?e hello; ?e world; ?e from; ?e a; ?e task");
	rz_core_task_enqueue (&core->tasks, a);

	RzCoreTask *b = rz_core_function_task_new (core, my_function, (void *)(size_t)1337);
	rz_core_task_enqueue (&core->tasks, b);

	rz_cons_printf ("Hello\n");
	rz_cons_printf ("this\n");
	rz_cons_printf ("is\n");
	rz_cons_printf ("the\n");
	rz_cons_printf ("main\n");
	rz_cons_printf ("task!\n");

	rz_core_task_join (&core->tasks, rz_core_task_self (&core->tasks), a->id);
	rz_core_task_join (&core->tasks, rz_core_task_self (&core->tasks), b->id);

	void *fcn_result = rz_core_function_task_get_result (a);
	mu_assert_null (fcn_result, "fcn result");
	const char *cmd_result = rz_core_cmd_task_get_result (a);
	mu_assert_streq (cmd_result, "hello\nworld\nfrom\na\ntask\n", "cmd result");

	fcn_result = rz_core_function_task_get_result (b);
	mu_assert_streq ((const char *)fcn_result, "1337, 0\n1337, 1\n1337, 2\n1337, 3\n1337, 4\n", "fcn result");
	free (fcn_result);
	cmd_result = rz_core_cmd_task_get_result (b);
	mu_assert_null (cmd_result, "cmd result");

	rz_core_task_del (&core->tasks, a->id);
	rz_core_task_del (&core->tasks, b->id);

	mu_assert_streq (rz_cons_get_buffer (), "Hello\nthis\nis\nthe\nmain\ntask!\n", "main buffer");

	rz_core_task_sync_end (&core->tasks);
	rz_core_free (core);
	mu_end;
}

// This test is best served with helgrind
static int all_tests(void) {
	mu_run_test (test_core_task);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
