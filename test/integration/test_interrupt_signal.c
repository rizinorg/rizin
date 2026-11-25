// SPDX-FileCopyrightText: 2026 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_interrupt.h>
#include "../unit/minunit.h"

#if __UNIX__
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#elif __WINDOWS__
#include <windows.h>
#include <stdlib.h>
#endif

#if __WINDOWS__
static UINT run_windows_child(const char *event_name) {
	RzInterrupt *intr = rz_interrupt_new();
	if (!intr) {
		return 1;
	}
	intr->hook_signals = true;
	rz_interrupt_break_push(intr, NULL, NULL);

	HANDLE ready_evt = OpenEventA(EVENT_MODIFY_STATE, FALSE, event_name);
	if (!ready_evt) {
		rz_interrupt_break_pop(intr);
		rz_interrupt_free(intr);
		return 3;
	}
	SetEvent(ready_evt);
	CloseHandle(ready_evt);

	for (int i = 0; i < 500; i++) {
		if (rz_interrupt_is_breaked(intr)) {
			rz_interrupt_break_pop(intr);
			rz_interrupt_free(intr);
			return 0;
		}
		rz_sys_usleep(10000);
	}

	rz_interrupt_break_pop(intr);
	rz_interrupt_free(intr);
	return 2;
}
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
	char exe_path[MAX_PATH];
	DWORD path_len = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
	mu_assert("GetModuleFileNameA failed", path_len > 0 && path_len < sizeof(exe_path));

	char event_name[64];
	snprintf(event_name, sizeof(event_name), "Local\\rz_test_intr_%lu", (unsigned long)GetCurrentProcessId());
	HANDLE ready_evt = CreateEventA(NULL, TRUE, FALSE, event_name);
	mu_assert_notnull(ready_evt, "CreateEventA failed");

	char cmd[MAX_PATH + 96];
	snprintf(cmd, sizeof(cmd), "\"%s\" --child %s", exe_path, event_name);

	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	BOOL created = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);
	if (!created) {
		CloseHandle(ready_evt);
		mu_fail("CreateProcess failed");
	}

	HANDLE waits[2] = { ready_evt, pi.hProcess };
	DWORD ready_wait = WaitForMultipleObjects(2, waits, FALSE, 5000);
	BOOL sent = FALSE;
	if (ready_wait == WAIT_OBJECT_0) {
		sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId);
	}

	DWORD proc_wait = WaitForSingleObject(pi.hProcess, 5000);
	if (proc_wait != WAIT_OBJECT_0) {
		TerminateProcess(pi.hProcess, 1);
		WaitForSingleObject(pi.hProcess, 1000);
	}

	DWORD exit_code = 1;
	GetExitCodeProcess(pi.hProcess, &exit_code);
	CloseHandle(ready_evt);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	mu_assert_eq(ready_wait, WAIT_OBJECT_0, "child signaled handler ready");
	mu_assert("GenerateConsoleCtrlEvent failed", sent);
	mu_assert_eq(proc_wait, WAIT_OBJECT_0, "child exited in time");
	mu_assert_eq(exit_code, 0, "child caught signal via rz_interrupt");
#elif __UNIX__
	int ready_pipe[2] = { -1, -1 };
	mu_assert("pipe failed", pipe(ready_pipe) == 0);

	pid_t pid = fork();
	if (pid < 0) {
		close(ready_pipe[0]);
		close(ready_pipe[1]);
	}
	mu_assert("fork failed", pid >= 0);

	if (pid == 0) {
		close(ready_pipe[0]);
		RzInterrupt *intr = rz_interrupt_new();
		if (!intr) {
			close(ready_pipe[1]);
			_exit(1);
		}
		intr->hook_signals = true;
		rz_interrupt_break_push(intr, NULL, NULL);

		char ready = 1;
		ssize_t nwritten;
		do {
			nwritten = write(ready_pipe[1], &ready, 1);
		} while (nwritten < 0 && errno == EINTR);
		close(ready_pipe[1]);
		if (nwritten != 1) {
			rz_interrupt_break_pop(intr);
			rz_interrupt_free(intr);
			_exit(3);
		}

		for (int i = 0; i < 500; i++) {
			if (rz_interrupt_is_breaked(intr)) {
				rz_interrupt_break_pop(intr);
				rz_interrupt_free(intr);
				_exit(0);
			}
			rz_sys_usleep(10000);
		}

		rz_interrupt_break_pop(intr);
		rz_interrupt_free(intr);
		_exit(2);
	} else {
		close(ready_pipe[1]);
		char ready = 0;
		ssize_t nread;
		do {
			nread = read(ready_pipe[0], &ready, 1);
		} while (nread < 0 && errno == EINTR);
		close(ready_pipe[0]);
		if (nread != 1) {
			kill(pid, SIGKILL);
			int status = 0;
			pid_t wpid;
			do {
				wpid = waitpid(pid, &status, 0);
			} while (wpid < 0 && errno == EINTR);
			mu_assert_eq(nread, 1, "child signaled readiness");
		}

		kill(pid, SIGINT);

		int status = 0;
		pid_t wpid;
		do {
			wpid = waitpid(pid, &status, 0);
		} while (wpid < 0 && errno == EINTR);

		mu_assert_eq(wpid, pid, "waitpid succeeded");
		mu_assert_true(WIFEXITED(status), "child exited normally");
		mu_assert_eq(WEXITSTATUS(status), 0, "child caught SIGINT via rz_interrupt");
	}
#else
	mu_test_status = MU_TEST_BROKEN;
#endif
	mu_end;
}

static int all_tests(void) {
#if __WINDOWS__
	if (__argc > 2 && strcmp(__argv[1], "--child") == 0) {
		ExitProcess(run_windows_child(__argv[2]));
	}
#endif
	mu_run_test(test_rz_interrupt_sigint_handling);
	mu_run_test(test_rz_interrupt_process_signal);
	return tests_passed != tests_run;
}

mu_main(all_tests)