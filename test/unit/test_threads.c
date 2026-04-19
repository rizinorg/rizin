// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_util/rz_time.h>
#include <rz_util/rz_sys.h>
#include <rz_userconf.h>
#include "minunit.h"
#include "rz_types.h"

bool test_thread_limit(void) {
	const RzThreadNCores n_thread_limit = N_THREAD_LIMIT;
	const RzThreadNCores n_cores = rz_th_physical_core_number();

	// ensure the core count is returned.
	RzThreadNCores requested = rz_th_max_threads(RZ_THREAD_N_CORES_ALL_AVAILABLE);
	mu_assert_eq(requested, n_cores, "RZ_THREAD_N_CORES_ALL_AVAILABLE == rz_th_physical_core_number");

	// ensure the thread limit is returned.
	requested = rz_th_max_threads(n_thread_limit + 1);
	mu_assert_eq(requested, n_thread_limit, "N_THREAD_LIMIT == rz_th_max_threads(LIMIT + 1)");

	mu_end;
}

bool test_thread_pool_cores(void) {
	RzThreadNCores cores = rz_th_physical_core_number();

	RzThreadPool *pool = rz_th_pool_new(RZ_THREAD_N_CORES_ALL_AVAILABLE);
	mu_assert_notnull(pool, "rz_th_pool_new(RZ_THREAD_N_CORES_ALL_AVAILABLE) null check");
	size_t pool_size = rz_th_pool_size(pool);
	mu_assert_eq(pool_size, cores, "rz_th_pool_new(RZ_THREAD_N_CORES_ALL_AVAILABLE) core count check");
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

#define THREAD_WAIT_AT_LEAST_MICROSEC 1500000

void *thread_queue_push_timed(RzThreadQueue *queue) {
	void *data = NULL;
	ut64 start = rz_time_now();
	if (!rz_th_queue_pop(queue, true, &data)) {
		return NULL;
	}
	ut64 diff = rz_time_now() - start;
	if (diff < THREAD_WAIT_AT_LEAST_MICROSEC) {
		return "did not wait for " RZ_STR(THREAD_WAIT_AT_LEAST_MICROSEC) " microsec";
	} else if (!strcmp((const char *)data, "rizin")) {
		return "OK";
	}
	return "did not receive 'rizin'";
}

bool test_thread_queue(void) {
	// test limited queue
	void *head = (void *)"aaaaaa";
	void *tail = (void *)"bbbbbb";
	void *pop_data = NULL;
	RzThreadQueue *queue = rz_th_queue_new(3, NULL);
	mu_assert_notnull(queue, "rz_th_queue_new(3) null check");
	mu_assert_true(rz_th_queue_is_empty(queue), "queue is empty");
	mu_assert_true(rz_th_queue_push(queue, "cccccc", true), "queue pushed new element");
	mu_assert_true(rz_th_queue_push(queue, head, false), "queue pushed head new element");
	mu_assert_true(rz_th_queue_push(queue, tail, true), "queue pushed tail new element");
	mu_assert_true(rz_th_queue_is_full(queue), "queue is full");
	mu_assert_false(rz_th_queue_push(queue, "kkkkkk", true), "queue cannot push a new element");
	mu_assert_true(rz_th_queue_pop(queue, false, &pop_data), "queue can pop head");
	mu_assert_ptreq(pop_data, head, "queue popped head and is head");
	pop_data = NULL;
	mu_assert_true(rz_th_queue_pop(queue, true, &pop_data), "queue can pop tail");
	mu_assert_ptreq(pop_data, tail, "queue popped tail and is tail");
	mu_assert_false(rz_th_queue_is_empty(queue), "queue is empty");
	mu_assert_false(rz_th_queue_is_closed(queue), "queue is not closed");
	mu_assert_false(rz_th_queue_is_full(queue), "queue is not full");
	// close queue, so no read/writes can happen
	pop_data = NULL;
	rz_th_queue_close(queue);
	mu_assert_true(rz_th_queue_is_closed(queue), "queue is closed");
	mu_assert_false(rz_th_queue_push(queue, "cccccc", true), "closed queue cannot push new data");
	mu_assert_false(rz_th_queue_pop(queue, false, &pop_data), "closed queue cannot pop new data");
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
	mu_assert_false(rz_th_terminated(th), "Thread should still sleep and count as running.");
	mu_assert_notnull(th, "rz_th_new(thread_queue_push_timed, queue) null check");

	rz_sys_sleep(2);
	mu_assert_true(rz_th_queue_push(queue, "rizin", true), "queue can push an element after 2 sec of waiting");
	// we wait for the queue to be empty
	rz_th_queue_close_when_empty(queue);
	rz_th_wait(th);

	const char *thread_string = rz_th_get_retv(th);
	mu_assert_notnull(thread_string, "thread retuned non-null value");
	mu_assert_streq(thread_string, "OK", "thread retuned the 'OK' string");
	mu_assert_true(rz_th_terminated(th), "Thread should count as terminated.");
	mu_assert_true(rz_th_queue_is_closed(queue), "verify the queue is closed");
	rz_th_free(th);
	rz_th_queue_free(queue);

	mu_end;
}

bool test_thread_ht(void) {
	bool v_boolean = false;
	const char *element = NULL;

	HtSS *tab = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	RzThreadHtSS *ht = rz_th_ht_ss_new(tab);
	mu_assert_notnull(ht, "rz_th_ht_ss_new() null check");

	v_boolean = true;
	element = rz_th_ht_ss_find(ht, "not found", &v_boolean);
	mu_assert_false(v_boolean, "the search must say not found");
	mu_assert_null(element, "the search must return NULL");

	v_boolean = rz_th_ht_ss_insert(ht, "foo", "bar");
	mu_assert_true(v_boolean, "the insert must succeed");

	v_boolean = false;
	element = rz_th_ht_ss_find(ht, "foo", &v_boolean);
	mu_assert_true(v_boolean, "the search must say found");
	mu_assert_notnull(element, "the search must NOT return NULL");
	mu_assert_streq(element, "bar", "expecting to find 'bar' when searching for 'foo'");

	element = rz_th_ht_ss_find(ht, "foo", NULL);
	mu_assert_notnull(element, "the search must NOT return NULL");
	mu_assert_streq(element, "bar", "expecting to find 'bar' when searching for 'foo'");

	v_boolean = rz_th_ht_ss_delete(ht, "not found");
	mu_assert_false(v_boolean, "the delete must fail");

	v_boolean = rz_th_ht_ss_delete(ht, "foo");
	mu_assert_true(v_boolean, "the delete must succeed");

	v_boolean = true;
	element = rz_th_ht_ss_find(ht, "foo", &v_boolean);
	mu_assert_false(v_boolean, "the search must say not found");
	mu_assert_null(element, "the search must return NULL");

	rz_th_ht_ss_free(ht);
	mu_end;
}

bool thread_set_bool_arg(bool *value, bool *user) {
	*value = true;
	*user = true;
	return true;
}

bool test_thread_iterator_list(void) {
	bool bool0 = false;
	bool bool1 = false;
	bool bool2 = false;
	bool bool3 = false;
	bool bool4 = false;
	bool bool_user = false;

	// test empty list
	RzList *list = rz_list_new();
	mu_assert_notnull(list, "rz_list_new() null check");
	bool res = rz_th_iterate_list(list, (RzThreadIterator)thread_set_bool_arg, 1, NULL);
	mu_assert_true(res, "list is empty and must return true");

	rz_list_append(list, &bool0);
	rz_list_append(list, &bool1);
	rz_list_append(list, &bool2);
	rz_list_append(list, &bool3);
	rz_list_append(list, &bool4);

	// test values are accessed
	res = rz_th_iterate_list(list, (RzThreadIterator)thread_set_bool_arg, RZ_THREAD_N_CORES_ALL_AVAILABLE, &bool_user);
	mu_assert_true(res, "list is not empty and must return true");
	mu_assert_true(bool_user, "bool_user must be true");
	mu_assert_true(bool0, "bool0 must be true");
	mu_assert_true(bool1, "bool1 must be true");
	mu_assert_true(bool2, "bool2 must be true");
	mu_assert_true(bool3, "bool3 must be true");
	mu_assert_true(bool4, "bool4 must be true");

	// test skip null pointers
	rz_list_free(list);
	list = rz_list_new();
	mu_assert_notnull(list, "rz_list_new() null check");

	bool_user = false;
	rz_list_append(list, NULL);
	rz_list_append(list, NULL);
	rz_list_append(list, NULL);
	rz_list_append(list, NULL);
	rz_list_append(list, NULL);
	res = rz_th_iterate_list(list, (RzThreadIterator)thread_set_bool_arg, RZ_THREAD_N_CORES_ALL_AVAILABLE, &bool_user);
	mu_assert_true(res, "pvec is not empty and must return true");
	mu_assert_false(bool_user, "bool_user must be false");

	rz_list_free(list);
	mu_end;
}

bool test_thread_iterator_pvec(void) {
	bool bool0 = false;
	bool bool1 = false;
	bool bool2 = false;
	bool bool3 = false;
	bool bool4 = false;
	bool bool_user = false;

	// test empty pvec
	RzPVector *pvec = rz_pvector_new(NULL);
	mu_assert_notnull(pvec, "rz_pvector_new() null check");
	rz_pvector_reserve(pvec, 5);

	bool res = rz_th_iterate_pvector(pvec, (RzThreadIterator)thread_set_bool_arg, 1, NULL);
	mu_assert_true(res, "pvec is empty and must return true");

	rz_pvector_push(pvec, &bool0);
	rz_pvector_push(pvec, &bool1);
	rz_pvector_push(pvec, &bool2);
	rz_pvector_push(pvec, &bool3);
	rz_pvector_push(pvec, &bool4);

	// test values are accessed
	res = rz_th_iterate_pvector(pvec, (RzThreadIterator)thread_set_bool_arg, RZ_THREAD_N_CORES_ALL_AVAILABLE, &bool_user);
	mu_assert_true(res, "pvec is not empty and must return true");
	mu_assert_true(bool_user, "bool_user must be true");
	mu_assert_true(bool0, "bool0 must be true");
	mu_assert_true(bool1, "bool1 must be true");
	mu_assert_true(bool2, "bool2 must be true");
	mu_assert_true(bool3, "bool3 must be true");
	mu_assert_true(bool4, "bool4 must be true");

	// test skip null pointers
	bool_user = false;
	rz_pvector_set(pvec, 0, NULL);
	rz_pvector_set(pvec, 1, NULL);
	rz_pvector_set(pvec, 2, NULL);
	rz_pvector_set(pvec, 3, NULL);
	rz_pvector_set(pvec, 4, NULL);
	res = rz_th_iterate_pvector(pvec, (RzThreadIterator)thread_set_bool_arg, RZ_THREAD_N_CORES_ALL_AVAILABLE, &bool_user);
	mu_assert_true(res, "pvec is not empty and must return true");
	mu_assert_false(bool_user, "bool_user must be false");

	rz_pvector_free(pvec);
	mu_end;
}

bool test_thread_ring_buf_seq(void) {
	// Full buffer + read 1 -> Signaling waiting
	// Full buffer + clear -> Signaling waiting
	ut64 in_1 = 1;
	ut64 in_2 = 2;
	ut64 in_3 = 3;
	ut64 out = 0;
	RzThreadRingBuf *rbuf = rz_th_ring_buf_new(3, sizeof(ut64));
	mu_assert_true(rz_th_ring_buf_is_open(rbuf), "is open");
	mu_assert_eq(rz_th_ring_buf_is_empty(rbuf), RZ_THREAD_RING_BUF_OK, "empty");
	mu_assert_eq(rz_th_ring_buf_is_full(rbuf), RZ_THREAD_RING_BUF_FAIL, "full");

	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_is_empty(rbuf), RZ_THREAD_RING_BUF_FAIL, "empty");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_2), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_3), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_is_full(rbuf), RZ_THREAD_RING_BUF_OK, "full check");
	mu_assert_eq(rz_th_ring_buf_is_empty(rbuf), RZ_THREAD_RING_BUF_FAIL, "empty");

	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_1, "Take mismatch");
	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_2, "Take mismatch");
	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_3, "Take mismatch");
	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_FAIL, "take on empty");

	rz_th_ring_buf_free(rbuf);

	mu_end;
}

utptr thread_queue_put_99(RzThreadRingBuf *rbuf) {
	ut64 in_99 = 99;
	return (utptr)rz_th_ring_buf_put(rbuf, &in_99);
}

utptr thread_queue_put_98(RzThreadRingBuf *rbuf) {
	ut64 in_98 = 98;
	return (utptr)rz_th_ring_buf_put(rbuf, &in_98);
}

utptr thread_queue_put_97(RzThreadRingBuf *rbuf) {
	ut64 in_97 = 97;
	return (utptr)rz_th_ring_buf_put(rbuf, &in_97);
}

utptr thread_queue_put_100(RzThreadRingBuf *rbuf) {
	ut64 in_100 = 100;
	return (utptr)rz_th_ring_buf_put(rbuf, &in_100);
}

bool test_thread_ring_buf_writer_cond(void) {
	// Full buffer + clear -> Signaling waiting
	ut64 in_1 = 1;
	ut64 in_2 = 2;
	ut64 in_3 = 3;
	ut64 out = 0;
	RzThreadRingBuf *rbuf = rz_th_ring_buf_new(3, sizeof(ut64));

	// Test wake up of writers.
	// Fill buffer.
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_2), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_3), RZ_THREAD_RING_BUF_OK, "put");

	// Start writers waiting on condition.
	RzThread *th_97 = rz_th_new((RzThreadFunction)thread_queue_put_97, rbuf);
	mu_assert_notnull(th_97, "rz_th_new 97 null check");
	RzThread *th_98 = rz_th_new((RzThreadFunction)thread_queue_put_98, rbuf);
	mu_assert_notnull(th_98, "rz_th_new 98 null check");

	// Take elements out of the buffer ensure they
	// the write threads terminate in the right order.
	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_1, "Take mismatch");
	rz_sys_sleep(1);

	int termed = 0;
	if (rz_th_terminated(th_97)) {
		printf("Thread 97 terminated\n");
		mu_assert_eq(rz_th_get_retv(th_97), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		termed++;
	}
	if (rz_th_terminated(th_98)) {
		printf("Thread 98 terminated\n");
		mu_assert_eq(rz_th_get_retv(th_98), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		termed++;
	}
	mu_assert_eq(termed, 1, "Incorrect number of threads terminated");

	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_2, "Take mismatch");
	rz_sys_sleep(1);

	mu_assert_true(rz_th_terminated(th_97) && rz_th_terminated(th_98), "Both threads should be termined by now");
	mu_assert_eq(rz_th_get_retv(th_97), RZ_THREAD_RING_BUF_OK, "Wrong return value");
	mu_assert_eq(rz_th_get_retv(th_98), RZ_THREAD_RING_BUF_OK, "Wrong return value");

	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_3, "Take mismatch");

	// Check writers values
	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	if (out == 97) {
		mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
		mu_assert_eq(out, 98, "Should be 98, 97 was already taken");
	} else {
		mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
		mu_assert_eq(out, 97, "Should be 97, 98 was already taken");
	}

	rz_th_free(th_97);
	rz_th_free(th_98);
	rz_th_ring_buf_free(rbuf);

	mu_end;
}

bool test_thread_ring_buf_writer_clear(void) {
	ut64 in_1 = 1;
	ut64 in_2 = 2;
	ut64 in_3 = 3;
	ut64 out = 0;
	RzThreadRingBuf *rbuf = rz_th_ring_buf_new(3, sizeof(ut64));

	// Test wake up of writers.
	// Fill buffer.
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_2), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_3), RZ_THREAD_RING_BUF_OK, "put");

	// Start writers waiting on condition.
	RzThread *th_97 = rz_th_new((RzThreadFunction)thread_queue_put_97, rbuf);
	mu_assert_notnull(th_97, "rz_th_new 97 null check");
	RzThread *th_98 = rz_th_new((RzThreadFunction)thread_queue_put_98, rbuf);
	mu_assert_notnull(th_98, "rz_th_new 98 null check");
	RzThread *th_99 = rz_th_new((RzThreadFunction)thread_queue_put_99, rbuf);
	mu_assert_notnull(th_99, "rz_th_new 99 null check");
	RzThread *th_100 = rz_th_new((RzThreadFunction)thread_queue_put_100, rbuf);
	mu_assert_notnull(th_100, "rz_th_new 100 null check");

	// Clear buffer signaling n writers.
	mu_assert_eq(rz_th_ring_buf_clear(rbuf), RZ_THREAD_RING_BUF_OK, "clear");
	rz_sys_sleep(1);
	// Check return value of the thread which terminated
	// (Order is not guaranteed so check any of them).
	int termed = 0;
	if (rz_th_terminated(th_97)) {
		printf("Thread 97 terminated\n");
		mu_assert_eq(rz_th_get_retv(th_97), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		termed++;
	}
	if (rz_th_terminated(th_98)) {
		printf("Thread 98 terminated\n");
		mu_assert_eq(rz_th_get_retv(th_98), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		termed++;
	}
	if (rz_th_terminated(th_99)) {
		printf("Thread 99 terminated\n");
		mu_assert_eq(rz_th_get_retv(th_99), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		termed++;
	}
	if (rz_th_terminated(th_100)) {
		printf("Thread 100 terminated\n");
		mu_assert_eq(rz_th_get_retv(th_100), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		termed++;
	}
	mu_assert_eq(termed, 3, "Exactly 3 threads should have been woken up and terminated.");

	ut64 cand[] = { 97, 98, 99, 100 };
	int written = 0;
	for (int k = 0; k < 3; ++k) {
		mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
		printf("took: %" PFMT64d "\n", out);
		for (int i = 0; i < RZ_ARRAY_SIZE(cand); ++i) {
			if (out == cand[i]) {
				printf("mark: %" PFMT64d "\n", out);
				cand[i] = 0;
				written++;
			}
		}
	}

	mu_assert_eq(written, 3, "invalid number of values written.");

	rz_sys_sleep(1);

	// Now the last one should be done
	mu_assert_true(rz_th_terminated(th_97) &&
			rz_th_terminated(th_98) &&
			rz_th_terminated(th_99) &&
			rz_th_terminated(th_100),
		"All terminated");

	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	written = 0;
	for (int i = 0; i < RZ_ARRAY_SIZE(cand); ++i) {
		if (cand[i] == 0) {
			continue;
		} else if (cand[i] == out) {
			printf("taken: %" PFMT64d "\n", out);
			written++;
		}
	}
	mu_assert_eq(written, 1, "Last thread didn't write.");

	rz_th_free(th_97);
	rz_th_free(th_98);
	rz_th_free(th_99);
	rz_th_free(th_100);
	rz_th_ring_buf_free(rbuf);

	mu_end;
}

bool test_thread_ring_buf_writer_close(void) {
	ut64 in_1 = 1;
	ut64 in_2 = 2;
	ut64 in_3 = 3;
	ut64 out;
	RzThreadRingBuf *rbuf = rz_th_ring_buf_new(3, sizeof(ut64));
	mu_assert_true(rz_th_ring_buf_is_open(rbuf), "is open");
	mu_assert_eq(rz_th_ring_buf_open(rbuf), RZ_THREAD_RING_BUF_FAIL, "already open");

	// Test wake up of writers.
	// Fill buffer.
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_2), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_3), RZ_THREAD_RING_BUF_OK, "put");

	// Start writers waiting on condition.
	RzThread *th_97 = rz_th_new((RzThreadFunction)thread_queue_put_97, rbuf);
	mu_assert_notnull(th_97, "rz_th_new 97 null check");
	RzThread *th_98 = rz_th_new((RzThreadFunction)thread_queue_put_98, rbuf);
	mu_assert_notnull(th_98, "rz_th_new 98 null check");
	RzThread *th_99 = rz_th_new((RzThreadFunction)thread_queue_put_99, rbuf);
	mu_assert_notnull(th_99, "rz_th_new 99 null check");
	RzThread *th_100 = rz_th_new((RzThreadFunction)thread_queue_put_100, rbuf);
	mu_assert_notnull(th_100, "rz_th_new 100 null check");

	// Close buffers
	mu_assert_eq(rz_th_ring_buf_close(rbuf), RZ_THREAD_RING_BUF_OK, "close");
	mu_assert_eq(rz_th_ring_buf_close(rbuf), RZ_THREAD_RING_BUF_CLOSED, "close");

	rz_sys_sleep(1);

	mu_assert_true(rz_th_terminated(th_97), "Write thread 97 terminated");
	mu_assert_eq(rz_th_get_retv(th_97), RZ_THREAD_RING_BUF_CLOSED, "Wrong return value");
	mu_assert_true(rz_th_terminated(th_98), "Write thread 98 terminated");
	mu_assert_eq(rz_th_get_retv(th_98), RZ_THREAD_RING_BUF_CLOSED, "Wrong return value");
	mu_assert_true(rz_th_terminated(th_99), "Write thread 99 terminated");
	mu_assert_eq(rz_th_get_retv(th_99), RZ_THREAD_RING_BUF_CLOSED, "Wrong return value");
	mu_assert_true(rz_th_terminated(th_100), "Write thread 100 still waiting");
	mu_assert_eq(rz_th_get_retv(th_100), RZ_THREAD_RING_BUF_CLOSED, "Wrong return value");

	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_CLOSED, "take failed");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &out), RZ_THREAD_RING_BUF_CLOSED, "put");
	mu_assert_eq(rz_th_ring_buf_is_full(rbuf), RZ_THREAD_RING_BUF_CLOSED, "full check");
	mu_assert_eq(rz_th_ring_buf_is_empty(rbuf), RZ_THREAD_RING_BUF_CLOSED, "empty");
	mu_assert_false(rz_th_ring_buf_is_open(rbuf), "is open");

	mu_assert_eq(rz_th_ring_buf_open(rbuf), RZ_THREAD_RING_BUF_OK, "opens");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_take(rbuf, &out), RZ_THREAD_RING_BUF_OK, "take failed");
	mu_assert_eq(out, in_1, "Wrong element taken");
	mu_assert_eq(rz_th_ring_buf_close(rbuf), RZ_THREAD_RING_BUF_OK, "close");

	rz_th_free(th_97);
	rz_th_free(th_98);
	rz_th_free(th_99);
	rz_th_free(th_100);
	rz_th_ring_buf_free(rbuf);

	mu_end;
}

utptr thread_rbuf_take_blocking_1(RzThreadRingBuf *rbuf) {
	ut64 out;
	RzThreadRingBufResult r = rz_th_ring_buf_take_blocking(rbuf, &out);
	assert(out == 1 && "wrong val taken");
	return (utptr)r;
}

utptr thread_rbuf_take_blocking_2(RzThreadRingBuf *rbuf) {
	ut64 out;
	RzThreadRingBufResult r = rz_th_ring_buf_take_blocking(rbuf, &out);
	assert(out == 2 && "wrong val taken");
	return (utptr)r;
}

utptr thread_rbuf_take_blocking(RzThreadRingBuf *rbuf) {
	ut64 out;
	RzThreadRingBufResult r = rz_th_ring_buf_take_blocking(rbuf, &out);
	return (utptr)r;
}

bool test_thread_ring_buf_reader_cond(void) {
	ut64 in_1 = 1;
	ut64 in_2 = 2;
	RzThreadRingBuf *rbuf = rz_th_ring_buf_new(3, sizeof(ut64));

	RzThread *rblock_1 = rz_th_new((RzThreadFunction)thread_rbuf_take_blocking_1, rbuf);
	mu_assert_notnull(rblock_1, "rz_th_new 1 null check");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	rz_sys_sleep(1);
	mu_assert_true(rz_th_terminated(rblock_1), "Didn't terminated");
	mu_assert_eq(rz_th_get_retv(rblock_1), RZ_THREAD_RING_BUF_OK, "Wrong return code");

	RzThread *rblock_2 = rz_th_new((RzThreadFunction)thread_rbuf_take_blocking_2, rbuf);
	mu_assert_notnull(rblock_2, "rz_th_new 2 null check");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_2), RZ_THREAD_RING_BUF_OK, "put");
	rz_sys_sleep(1);
	mu_assert_true(rz_th_terminated(rblock_2), "Didn't terminated");
	mu_assert_eq(rz_th_get_retv(rblock_2), RZ_THREAD_RING_BUF_OK, "Wrong return code");

	// Spawn many
	RzThread *rblock_n1 = rz_th_new((RzThreadFunction)thread_rbuf_take_blocking, rbuf);
	RzThread *rblock_n2 = rz_th_new((RzThreadFunction)thread_rbuf_take_blocking, rbuf);
	RzThread *rblock_n3 = rz_th_new((RzThreadFunction)thread_rbuf_take_blocking, rbuf);
	RzThread *rblock_n4 = rz_th_new((RzThreadFunction)thread_rbuf_take_blocking, rbuf);
	RzThread *ths[] = { rblock_n1, rblock_n2, rblock_n3, rblock_n4 };

	// Write two
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");
	mu_assert_eq(rz_th_ring_buf_put(rbuf, &in_1), RZ_THREAD_RING_BUF_OK, "put");

	rz_sys_sleep(1);

	size_t n_term = 0;
	if (rz_th_terminated(rblock_n1)) {
		printf("rblock_n1 terminated\n");
		mu_assert_eq(rz_th_get_retv(rblock_n1), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		ths[0] = NULL;
		n_term++;
	}
	if (rz_th_terminated(rblock_n2)) {
		printf("rblock_n2 terminated\n");
		mu_assert_eq(rz_th_get_retv(rblock_n2), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		ths[1] = NULL;
		n_term++;
	}
	if (rz_th_terminated(rblock_n3)) {
		printf("rblock_n3 terminated\n");
		mu_assert_eq(rz_th_get_retv(rblock_n3), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		ths[2] = NULL;
		n_term++;
	}
	if (rz_th_terminated(rblock_n4)) {
		printf("rblock_n4 terminated\n");
		mu_assert_eq(rz_th_get_retv(rblock_n4), RZ_THREAD_RING_BUF_OK, "Wrong return value");
		ths[3] = NULL;
		n_term++;
	}
	mu_assert_eq(n_term, 2, "two should have terminated, two still waiting.");

	rz_th_ring_buf_close(rbuf);
	rz_sys_sleep(1);

	for (size_t i = 0; i < 4; ++i) {
		if (!ths[i]) {
			continue;
		}
		mu_assert_true(rz_th_terminated(ths[i]), "Should have terminated after close.");
		mu_assert_eq(rz_th_get_retv(ths[i]), RZ_THREAD_RING_BUF_CLOSED, "Wrong return value.");
	}

	rz_th_ring_buf_free(rbuf);
	rz_th_free(rblock_1);
	rz_th_free(rblock_2);
	rz_th_free(rblock_n1);
	rz_th_free(rblock_n2);
	rz_th_free(rblock_n3);
	rz_th_free(rblock_n4);

	mu_end;
}

int all_tests() {
	mu_run_test(test_thread_limit);
	mu_run_test(test_thread_pool_cores);
	mu_run_test(test_thread_queue);
	mu_run_test(test_thread_ht);
	mu_run_test(test_thread_iterator_list);
	mu_run_test(test_thread_iterator_pvec);
	mu_run_test(test_thread_ring_buf_seq);
	mu_run_test(test_thread_ring_buf_writer_cond);
	mu_run_test(test_thread_ring_buf_writer_clear);
	mu_run_test(test_thread_ring_buf_writer_close);
	mu_run_test(test_thread_ring_buf_reader_cond);
	return tests_passed != tests_run;
}

mu_main(all_tests)
