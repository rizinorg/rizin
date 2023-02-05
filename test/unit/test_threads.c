// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_util/rz_time.h>
#include <rz_util/rz_sys.h>
#include "minunit.h"

bool test_thread_pool_cores(void) {
	size_t cores = rz_th_physical_core_number();

	RzThreadPool *pool = rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES);
	mu_assert_notnull(pool, "rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES) null check");
	size_t pool_size = rz_th_pool_size(pool);
	mu_assert_eq(pool_size, cores, "rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES) core count check");
	rz_th_pool_free(pool);

	if (cores > 1) {
		/* this can be tested only when cores are more than 1 */
		pool = rz_th_pool_new(cores - 1);
		mu_assert_notnull(pool, "rz_th_pool_new(cores - 1) null check");
		pool_size = rz_th_pool_size(pool);
		mu_assert_eq(pool_size, cores - 1, "rz_th_pool_new(cores - 1) core count check");
		rz_th_pool_free(pool);
	}

	mu_end;
}

void *thread_queue_push_timed(RzThreadQueue *queue) {
	rz_sys_sleep(2);
	return rz_th_queue_push(queue, queue, true) ? queue : NULL;
}

bool test_thread_queue(void) {
	// test limited queue
	void *head = (void *)"aaaaaa";
	void *tail = (void *)"bbbbbb";
	RzThreadQueue *queue = rz_th_queue_new(3, NULL);
	mu_assert_notnull(queue, "rz_th_queue_new(3) null check");
	mu_assert_true(rz_th_queue_is_empty(queue), "queue is empty");
	mu_assert_true(rz_th_queue_push(queue, "cccccc", true), "queue pushed new element");
	mu_assert_true(rz_th_queue_push(queue, head, false), "queue pushed head new element");
	mu_assert_true(rz_th_queue_push(queue, tail, true), "queue pushed tail new element");
	mu_assert_true(rz_th_queue_is_full(queue), "queue is full");
	mu_assert_false(rz_th_queue_push(queue, "kkkkkk", true), "queue cannot push a new element");
	mu_assert_ptreq(rz_th_queue_pop(queue, false), head, "queue can pop head and is that element");
	mu_assert_ptreq(rz_th_queue_pop(queue, true), tail, "queue can pop tail and is that element");
	mu_assert_false(rz_th_queue_is_empty(queue), "queue is empty");
	mu_assert_false(rz_th_queue_is_full(queue), "queue is not full");
	rz_th_queue_free(queue);

	// test unlimited queue
	queue = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	mu_assert_notnull(queue, "rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED) null check");
	mu_assert_true(rz_th_queue_push(queue, "aaaaa", false), "queue can push a new element");
	mu_assert_true(rz_th_queue_push(queue, "aaaaa", true), "queue can push a new element");
	mu_assert_true(rz_th_queue_push(queue, "aaaaa", false), "queue can push a new element");
	mu_assert_true(rz_th_queue_push(queue, "aaaaa", true), "queue can push a new element");
	mu_assert_true(rz_th_queue_push(queue, "aaaaa", false), "queue can push a new element");
	mu_assert_true(rz_th_queue_push(queue, "aaaaa", true), "queue can push a new element");
	mu_assert_false(rz_th_queue_is_empty(queue), "queue is not empty");
	mu_assert_false(rz_th_queue_is_full(queue), "queue is not full");
	rz_th_queue_free(queue);

	// test queue
	queue = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	RzThread *th = rz_th_new((RzThreadFunction)thread_queue_push_timed, queue);
	mu_assert_notnull(th, "rz_th_new(thread_queue_push_timed, queue) null check");
	ut64 start = rz_time_now();
	tail = rz_th_queue_wait_pop(queue, true);
	ut64 diff = rz_time_now() - start;
	rz_th_wait(th);
	mu_assert_ptreq(tail, queue, "rz_th_queue_wait_pop(queue, true) is queue");
	mu_assert_true(diff >= 1500000, "queue did wait for value.");
	mu_assert_ptreq(rz_th_get_retv(th), queue, "verify it returned queue");
	rz_th_free(th);
	rz_th_queue_free(queue);

	mu_end;
}

int all_tests() {
	mu_run_test(test_thread_pool_cores);
	mu_run_test(test_thread_queue);
	return tests_passed != tests_run;
}

mu_main(all_tests)
