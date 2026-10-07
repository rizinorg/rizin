// SPDX-FileCopyrightText: 2026 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_interrupt.h>
#include "../unit/minunit.h"

#if __UNIX__
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#elif __WINDOWS__
#include <windows.h>
#include <stdlib.h>
#endif

static bool test_rz_interrupt_sigint_handling(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new failed");

	intr->hook_signals = true;
	rz_interrupt_break_push(intr, NULL, NULL);

	mu_assert_false(rz_interrupt_is_breaked(intr), "should not be breaked initially");

	rz_interrupt_raise_sigint();

	mu_assert_true(rz_interrupt_is_breaked(intr), "should be breaked after signal");

	rz_interrupt_break_pop(intr);
	rz_interrupt_free(intr);
	mu_end;
}

static bool test_rz_interrupt_process_signal(void) {
#if __WINDOWS__
	if (__argc > 1 && strcmp(__argv[1], "--child") == 0) {
		RzInterrupt *intr = rz_interrupt_new();
		if (!intr) {
			ExitProcess(1);
		}
		intr->hook_signals = true;
		rz_interrupt_break_push(intr, NULL, NULL);

		for (int i = 0; i < 50; i++) {
			if (rz_interrupt_is_breaked(intr)) {
				rz_interrupt_break_pop(intr);
				rz_interrupt_free(intr);
				ExitProcess(0);
			}
			rz_sys_usleep(10000);
		}

		rz_interrupt_break_pop(intr);
		rz_interrupt_free(intr);
		ExitProcess(2);
	}

	char exe_path[MAX_PATH];
	GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));

	char cmd[MAX_PATH + 16];
	snprintf(cmd, sizeof(cmd), "\"%s\" --child", exe_path);

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL created = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);
	mu_assert("CreateProcess failed", created);

	rz_sys_usleep(50000);
	GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId);

	WaitForSingleObject(pi.hProcess, 5000);

	DWORD exit_code = 1;
	GetExitCodeProcess(pi.hProcess, &exit_code);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	mu_assert_eq(exit_code, 0, "child caught signal via rz_interrupt");
#elif __UNIX__
	pid_t pid = fork();
	mu_assert("fork failed", pid >= 0);

	if (pid == 0) {
		RzInterrupt *intr = rz_interrupt_new();
		if (!intr) {
			exit(1);
		}
		intr->hook_signals = true;
		rz_interrupt_break_push(intr, NULL, NULL);

		for (int i = 0; i < 50; i++) {
			if (rz_interrupt_is_breaked(intr)) {
				rz_interrupt_break_pop(intr);
				rz_interrupt_free(intr);
				exit(0);
			}
			rz_sys_usleep(10000);
		}

		rz_interrupt_break_pop(intr);
		rz_interrupt_free(intr);
		exit(2);
	} else {
		rz_sys_usleep(20000);
		kill(pid, SIGINT);

		int status = 0;
		waitpid(pid, &status, 0);

		mu_assert_true(WIFEXITED(status), "child exited normally");
		mu_assert_eq(WEXITSTATUS(status), 0, "child caught SIGINT via rz_interrupt");
	}
#else
	mu_test_status = MU_TEST_BROKEN;
#endif
	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_rz_interrupt_sigint_handling);
	mu_run_test(test_rz_interrupt_process_signal);
	return tests_passed != tests_run;
}

mu_main(all_tests)