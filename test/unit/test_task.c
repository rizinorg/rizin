// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

typedef struct shared_ctx_t {
	RzStrBuf log;
	RzThreadLock *free_lock;
} SharedCtx;

typedef struct local_ctx_t {
	SharedCtx *shared;
	int id;
	int freed;
	unsigned int want_to_consume;
	bool breaked;
} LocalCtx;

static void ctx_switch(RzCoreTask *next, void *user) {
	SharedCtx *ctx = user;
	LocalCtx *local_ctx = next->runner_user;
	if (local_ctx) {
		rz_strbuf_appendf(&ctx->log, "Context switch to %d\n", local_ctx->id);
	} else {
		rz_strbuf_appendf(&ctx->log, "Context switch to main\n");
	}
}

static void task_break(RzCoreTask *task, void *user) {
	LocalCtx *ctx = task->runner_user;
	ctx->breaked = true;
}

static void runner(RzCoreTaskScheduler *sched, void *user) {
	LocalCtx *ctx = user;
	rz_strbuf_appendf(&ctx->shared->log, "Runner %d start\n", ctx->id);
	while (ctx->want_to_consume) {
		if (ctx->breaked) {
			rz_strbuf_appendf(&ctx->shared->log, "Runner %d was breaked!\n", ctx->id);
			break;
		}
		rz_strbuf_appendf(&ctx->shared->log, "Runner %d consume %u\n", ctx->id, ctx->want_to_consume);
		ctx->want_to_consume--;
		rz_core_task_yield(sched);
	}
	rz_strbuf_appendf(&ctx->shared->log, "Runner %d done\n", ctx->id);
}

static void local_ctx_free(void *user) {
	LocalCtx *ctx = user;
	SharedCtx *shared_ctx = ctx->shared;
	rz_th_lock_enter(shared_ctx->free_lock);
	ctx->freed++;
	rz_th_lock_leave(shared_ctx->free_lock);
}

// Busy-wait for task threads to be started and in the queue
static void wait_for_tasks_enqueued(RzCoreTaskScheduler *sched, size_t count) {
	while (true) {
		rz_th_lock_enter(sched->lock);
		size_t queued = rz_list_length(sched->tasks_queue);
		rz_th_lock_leave(sched->lock);
		if (queued == count) {
			break;
		}
		rz_sys_usleep(1000);
	}
}

static bool test_task(void) {
	SharedCtx shared_ctx = { 0 };
	rz_strbuf_init(&shared_ctx.log);
	shared_ctx.free_lock = rz_th_lock_new(false);

	RzCoreTaskScheduler sched;
	rz_core_task_scheduler_init(&sched, ctx_switch, &shared_ctx, task_break, &shared_ctx);
	rz_core_task_sync_begin(&sched);

	LocalCtx a_ctx = {
		.shared = &shared_ctx,
		.id = 1,
		.want_to_consume = 3
	};
	RzCoreTask *a = rz_core_task_new(&sched, runner, local_ctx_free, &a_ctx);
	int a_id = a->id;
	rz_core_task_enqueue(&sched, a);
	a = NULL; // ownership moved to the scheduler, don't touch anymore!
	wait_for_tasks_enqueued(&sched, 1);

	LocalCtx b_ctx = {
		.shared = &shared_ctx,
		.id = 2,
		.want_to_consume = 3
	};
	RzCoreTask *b = rz_core_task_new(&sched, runner, local_ctx_free, &b_ctx);
	b->transient = true;
	int b_id = b->id;
	rz_core_task_enqueue(&sched, b);
	b = NULL; // ownership moved to the scheduler, don't touch anymore!
	wait_for_tasks_enqueued(&sched, 2);

	mu_assert_streq(rz_strbuf_get(&shared_ctx.log), "Context switch to main\n", "log");

	// The scheduler uses very primitive round-robin scheduling, which is why it is completely deterministic
	// after the queue has been filled and we can test it well.
	// In case the scheduling scheme changes in the future, these tests are allowed to be changed for it.

	rz_core_task_yield(&sched);
	mu_assert_streq(rz_strbuf_get(&shared_ctx.log),
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 start\n"
		"Runner 1 consume 3\n"
		"Context switch to 2\n"
		"Runner 2 start\n"
		"Runner 2 consume 3\n"
		"Context switch to main\n",
		"log");
	rz_core_task_break(&sched, b_id);

	rz_th_lock_enter(shared_ctx.free_lock);
	mu_assert_eq(a_ctx.freed, 0, "freed");
	mu_assert_eq(b_ctx.freed, 0, "freed");
	rz_th_lock_leave(shared_ctx.free_lock);

	rz_core_task_yield(&sched);
	mu_assert_streq(rz_strbuf_get(&shared_ctx.log),
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 start\n"
		"Runner 1 consume 3\n"
		"Context switch to 2\n"
		"Runner 2 start\n"
		"Runner 2 consume 3\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 2\n"
		"Context switch to 2\n"
		"Runner 2 was breaked!\n"
		"Runner 2 done\n"
		"Context switch to main\n",
		"log");

	rz_th_lock_enter(shared_ctx.free_lock);
	mu_assert_eq(a_ctx.freed, 0, "freed");
	mu_assert_eq(b_ctx.freed, 1, "freed"); // this one is transient and should now have been freed automatically
	rz_th_lock_leave(shared_ctx.free_lock);

	rz_core_task_yield(&sched);
	mu_assert_streq(rz_strbuf_get(&shared_ctx.log),
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 start\n"
		"Runner 1 consume 3\n"
		"Context switch to 2\n"
		"Runner 2 start\n"
		"Runner 2 consume 3\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 2\n"
		"Context switch to 2\n"
		"Runner 2 was breaked!\n"
		"Runner 2 done\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 1\n"
		"Context switch to main\n",
		"log");

	rz_core_task_yield(&sched);
	mu_assert_streq(rz_strbuf_get(&shared_ctx.log),
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 start\n"
		"Runner 1 consume 3\n"
		"Context switch to 2\n"
		"Runner 2 start\n"
		"Runner 2 consume 3\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 2\n"
		"Context switch to 2\n"
		"Runner 2 was breaked!\n"
		"Runner 2 done\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 1\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 done\n"
		"Context switch to main\n",
		"log");

	// everything done now and no new logs should happen

	rz_core_task_yield(&sched);
	mu_assert_streq(rz_strbuf_get(&shared_ctx.log),
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 start\n"
		"Runner 1 consume 3\n"
		"Context switch to 2\n"
		"Runner 2 start\n"
		"Runner 2 consume 3\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 2\n"
		"Context switch to 2\n"
		"Runner 2 was breaked!\n"
		"Runner 2 done\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 consume 1\n"
		"Context switch to main\n"
		"Context switch to 1\n"
		"Runner 1 done\n"
		"Context switch to main\n",
		"log");

	rz_th_lock_enter(shared_ctx.free_lock);
	mu_assert_eq(a_ctx.freed, 0, "freed"); // this one isn't transient so need to free it manually
	mu_assert_eq(b_ctx.freed, 1, "freed");
	rz_th_lock_leave(shared_ctx.free_lock);
	rz_core_task_del(&sched, a_id);
	rz_th_lock_enter(shared_ctx.free_lock);
	mu_assert_eq(a_ctx.freed, 1, "freed");
	mu_assert_eq(b_ctx.freed, 1, "freed");
	rz_th_lock_leave(shared_ctx.free_lock);

	rz_core_task_sync_end(&sched);
	rz_core_task_join(&sched, NULL, -1);
	rz_core_task_scheduler_fini(&sched);

	rz_th_lock_free(shared_ctx.free_lock);
	rz_strbuf_fini(&shared_ctx.log);

	mu_end;
}

// This test is best served with helgrind
static int all_tests(void) {
	mu_run_test(test_task);
	return tests_passed != tests_run;
}

mu_main(all_tests)