// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_socket.h>
#include "minunit.h"

static void *ping_back_th(void *user) {
	rz_sys_usleep(10000);
	RzSocket *sock = rz_socket_new(false);
	if (!sock) {
		eprintf("ping back: !sock\n");
		return NULL;
	}
	sock->local = true;
	rz_sys_usleep(10000);
	bool succ = rz_socket_connect_tcp(sock, "127.0.0.1", user, 1);
	if (!succ) {
		eprintf("ping back: connect failed\n");
		return NULL;
	}
	rz_sys_usleep(10000);
	char *data = "hello";
	int r = rz_socket_write(sock, data, strlen(data));
	if (r != strlen(data)) {
		eprintf("ping back: write failed\n");
		return NULL;
	}
	rz_sys_usleep(10000);
	rz_socket_close(sock);
	rz_socket_free(sock);
	return (void *)(size_t)1;
}

bool test_socket_tcp() {
	char *port = "42587"; // arbitrary

	RzSocket *sock = rz_socket_new(false);
	sock->local = true;
	mu_assert_notnull(sock, "rz_socket_new()");
	bool succ = rz_socket_listen(sock, port, NULL);
	mu_assert_true(succ, "rz_socket_listen()");

	RzThread *th = rz_th_new(ping_back_th, port);

	RzSocket *ch = rz_socket_accept(sock);
	mu_assert_notnull(ch, "accept");
	char buf[6] = { 0 };
	int r = rz_socket_read_block(ch, (ut8 *)buf, sizeof(buf));
	mu_assert_eq(r, sizeof(buf) - 1, "read");
	mu_assert_streq(buf, "hello", "read contents");
	rz_socket_close(ch);
	rz_socket_free(ch);

	rz_socket_close(sock);
	rz_socket_free(sock);

	rz_th_wait(th);
	mu_assert_notnull(rz_th_get_retv(th), "ping back");
	rz_th_free(th);
	mu_end;
}

bool test_stop_pipe_nostop() {
	char *port = "42588"; // arbitrary

	RzStopPipe *sp = rz_stop_pipe_new();
	mu_assert_notnull(sp, "rz_stop_pipe_new()");

	RzSocket *sock = rz_socket_new(false);
	sock->local = true;
	mu_assert_notnull(sock, "rz_socket_new()");
	bool succ = rz_socket_listen(sock, port, NULL);
	mu_assert_true(succ, "rz_socket_listen()");

	RzThread *th = rz_th_new(ping_back_th, port);

	RzStopPipeSelectResult spr = rz_stop_pipe_select_single(sp, sock, false, UT64_MAX);
	mu_assert_eq(spr, RZ_STOP_PIPE_SOCKET_READY, "stop pipe select");

	RzSocket *ch = rz_socket_accept(sock);
	mu_assert_notnull(ch, "accept");
	char buf[6] = { 0 };
	int r_sz = 0;
	while (r_sz < sizeof(buf) - 1) {
		spr = rz_stop_pipe_select_single(sp, ch, false, UT64_MAX);
		mu_assert_eq(spr, RZ_STOP_PIPE_SOCKET_READY, "stop pipe select");
		int r = rz_socket_read(ch, (ut8 *)buf + r_sz, sizeof(buf));
		if (r <= 0) {
			break;
		}
		r_sz += r;
	}
	mu_assert_eq(r_sz, sizeof(buf) - 1, "read");
	mu_assert_streq(buf, "hello", "read contents");
	rz_socket_close(ch);
	rz_socket_free(ch);

	rz_socket_close(sock);
	rz_socket_free(sock);

	rz_th_wait(th);
	mu_assert_notnull(rz_th_get_retv(th), "ping back");
	rz_th_free(th);

	rz_stop_pipe_free(sp);
	mu_end;
}

bool test_stop_pipe_stop() {
	char *port = "42589"; // arbitrary

	RzStopPipe *sp = rz_stop_pipe_new();
	mu_assert_notnull(sp, "rz_stop_pipe_new()");

	RzSocket *sock = rz_socket_new(false);
	sock->local = true;
	mu_assert_notnull(sock, "rz_socket_new()");
	bool succ = rz_socket_listen(sock, port, NULL);
	mu_assert_true(succ, "rz_socket_listen()");

	rz_stop_pipe_stop(sp);

	RzStopPipeSelectResult spr = rz_stop_pipe_select_single(sp, sock, false, UT64_MAX);
	mu_assert_eq(spr, RZ_STOP_PIPE_STOPPED, "stop pipe select");

	rz_socket_close(sock);
	rz_socket_free(sock);
	rz_stop_pipe_free(sp);
	mu_end;
}

bool test_stop_pipe_timeout() {
	char *port = "42590"; // arbitrary

	RzStopPipe *sp = rz_stop_pipe_new();
	mu_assert_notnull(sp, "rz_stop_pipe_new()");

	RzSocket *sock = rz_socket_new(false);
	sock->local = true;
	mu_assert_notnull(sock, "rz_socket_new()");
	bool succ = rz_socket_listen(sock, port, NULL);
	mu_assert_true(succ, "rz_socket_listen()");

	RzStopPipeSelectResult spr = rz_stop_pipe_select_single(sp, sock, false, 10);
	mu_assert_eq(spr, RZ_STOP_PIPE_TIMEOUT, "stop pipe select");

	rz_socket_close(sock);
	rz_socket_free(sock);
	rz_stop_pipe_free(sp);
	mu_end;
}

#define USE_PERTURBATOR !__WINDOWS__

#if USE_PERTURBATOR
/*
 * Run a thread that will spam our test process with (caught) signals,
 * so EINTRs are very likely to occur and we can test for them.
 */
static pid_t my_pid;
static bool perturbator_stop = false;
static RzThreadLock *perturbator_stop_lock;

static void *perturbator_th(void *user) {
	while (true) {
		rz_th_lock_enter(perturbator_stop_lock);
		bool stop = perturbator_stop;
		rz_th_lock_leave(perturbator_stop_lock);
		if (stop) {
			break;
		}
		kill(my_pid, SIGUSR1);
		usleep(20);
	}
	return NULL;
}

static void signal_handler(int sig) {}
#endif

bool all_tests() {
#if USE_PERTURBATOR
	my_pid = getpid();
	perturbator_stop_lock = rz_th_lock_new(false);
	rz_sys_signal(SIGUSR1, signal_handler);
	RzThread *pert = rz_th_new(perturbator_th, NULL);
#endif

	mu_run_test(test_socket_tcp);
	mu_run_test(test_stop_pipe_nostop);
	mu_run_test(test_stop_pipe_stop);
	mu_run_test(test_stop_pipe_timeout);

#if USE_PERTURBATOR
	rz_th_lock_enter(perturbator_stop_lock);
	perturbator_stop = true;
	rz_th_lock_leave(perturbator_stop_lock);
	rz_th_wait(pert);
	rz_th_free(pert);
	rz_th_lock_free(perturbator_stop_lock);
#endif
	return tests_passed != tests_run;
}

mu_main(all_tests)
