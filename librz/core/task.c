// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API void rz_core_task_scheduler_init(RzCoreTaskScheduler *sched,
	RzCoreTaskContextSwitch ctx_switch, void *ctx_switch_user,
	RzCoreTaskBreak break_cb, void *break_cb_user) {
	sched->ctx_switch = ctx_switch;
	sched->ctx_switch_user = ctx_switch_user;
	sched->break_cb = break_cb;
	sched->break_cb_user = break_cb_user;
	sched->task_id_next = 0;
	sched->tasks = rz_list_newf((RzListFree)rz_core_task_decref);
	sched->tasks_queue = rz_list_new();
	sched->oneshot_queue = rz_list_newf(free);
	sched->oneshots_enqueued = 0;
	sched->lock = rz_th_lock_new(true);
	sched->tasks_running = 0;
	sched->oneshot_running = false;
	sched->main_task = rz_core_task_new(sched, NULL, NULL, NULL);
	rz_list_append(sched->tasks, sched->main_task);
	sched->current_task = NULL;
}

RZ_API void rz_core_task_scheduler_fini(RzCoreTaskScheduler *tasks) {
	rz_list_free(tasks->tasks);
	rz_list_free(tasks->tasks_queue);
	rz_list_free(tasks->oneshot_queue);
	rz_th_lock_free(tasks->lock);
}

#if HAVE_PTHREAD
#define TASK_SIGSET_T sigset_t
static void tasks_lock_block_signals(sigset_t *old_sigset) {
	sigset_t block_sigset;
	sigemptyset(&block_sigset);
	sigaddset(&block_sigset, SIGWINCH);
	rz_signal_sigmask(SIG_BLOCK, &block_sigset, old_sigset);
}

static void tasks_lock_block_signals_reset(sigset_t *old_sigset) {
	rz_signal_sigmask(SIG_SETMASK, old_sigset, NULL);
}
#else
#define TASK_SIGSET_T void *
static void tasks_lock_block_signals(TASK_SIGSET_T *old_sigset) {
	(void)old_sigset;
}
static void tasks_lock_block_signals_reset(TASK_SIGSET_T *old_sigset) {
	(void)old_sigset;
}
#endif

static void tasks_lock_enter(RzCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	tasks_lock_block_signals(old_sigset);
	rz_th_lock_enter(scheduler->lock);
}

static void tasks_lock_leave(RzCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	rz_th_lock_leave(scheduler->lock);
	tasks_lock_block_signals_reset(old_sigset);
}

typedef struct oneshot_t {
	RzCoreTaskOneShot func;
	void *user;
} OneShot;

RZ_API int rz_core_task_running_tasks_count(RzCoreTaskScheduler *scheduler) {
	RzListIter *iter;
	RzCoreTask *task;
	int count = 0;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task != scheduler->main_task && task->state != RZ_CORE_TASK_STATE_DONE) {
			count++;
		}
	}
	tasks_lock_leave(scheduler, &old_sigset);
	return count;
}

static bool task_join(RzCoreTask *task) {
	RzThreadSemaphore *sem = task->running_sem;
	if (!sem) {
		return false;
	}

	rz_th_sem_wait(sem);
	rz_th_sem_post(sem);
	return true;
}

RZ_API RzCoreTaskJoinErr rz_core_task_join(RzCoreTaskScheduler *scheduler, RzCoreTask *current, int id) {
	RzCoreTaskJoinErr ret = RZ_CORE_TASK_JOIN_ERR_SUCCESS;
	if (current && id == current->id) {
		return RZ_CORE_TASK_JOIN_ERR_CURRENT;
	}
	if (id >= 0) {
		RzCoreTask *task = rz_core_task_get_incref(scheduler, id);
		if (!task) {
			return RZ_CORE_TASK_JOIN_ERR_NO_TASK;
		}
		if (current) {
			rz_core_task_sleep_begin(current);
		}
		if (!task_join(task)) {
			ret = RZ_CORE_TASK_JOIN_ERR_ONE_NO_SEM;
		}
		if (current) {
			rz_core_task_sleep_end(current);
		}
		rz_core_task_decref(task);
	} else {
		TASK_SIGSET_T old_sigset;
		tasks_lock_enter(scheduler, &old_sigset);
		RzList *tasks = rz_list_clone(scheduler->tasks);
		RzListIter *iter;
		RzCoreTask *task;
		rz_list_foreach (tasks, iter, task) {
			if (current == task) {
				continue;
			}
			rz_core_task_incref(task);
		}
		tasks_lock_leave(scheduler, &old_sigset);

		rz_list_foreach (tasks, iter, task) {
			if (current == task) {
				continue;
			}
			if (current) {
				rz_core_task_sleep_begin(current);
			}
			if (!task_join(task)) {
				ret = RZ_CORE_TASK_JOIN_ERR_ALL_NO_SEM;
			}
			if (current) {
				rz_core_task_sleep_end(current);
			}
			rz_core_task_decref(task);
		}
		rz_list_free(tasks);
	}
	return ret;
}

static void task_free(RzCoreTask *task) {
	if (!task) {
		return;
	}
	if (task->runner_free) {
		task->runner_free(task->runner_user);
	}
	if (task->thread) {
		rz_th_wait(task->thread);
		rz_th_free(task->thread);
	}
	rz_th_sem_free(task->running_sem);
	rz_th_cond_free(task->dispatch_cond);
	rz_th_lock_free(task->dispatch_lock);
	free(task);
}

RZ_API RzCoreTask *rz_core_task_new(RzCoreTaskScheduler *sched, RzCoreTaskRunner runner, RzCoreTaskRunnerFree runner_free, void *runner_user) {
	RzCoreTask *task = RZ_NEW0(RzCoreTask);
	if (!task) {
		goto fail;
	}

	task->sched = sched;
	task->thread = NULL;
	task->running_sem = NULL;
	task->dispatched = false;
	task->dispatch_cond = rz_th_cond_new();
	task->dispatch_lock = rz_th_lock_new(false);
	if (!task->dispatch_cond || !task->dispatch_lock) {
		goto fail;
	}
	task->runner = runner;
	task->runner_free = runner_free;
	task->runner_user = runner_user;
	task->id = sched->task_id_next++;
	task->state = RZ_CORE_TASK_STATE_BEFORE_START;
	task->refcount = 1;
	task->transient = false;
	return task;

fail:
	task_free(task);
	return NULL;
}

RZ_API void rz_core_task_incref(RzCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(task->sched, &old_sigset);
	task->refcount++;
	tasks_lock_leave(task->sched, &old_sigset);
}

RZ_API void rz_core_task_decref(RzCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	RzCoreTaskScheduler *sched = task->sched;
	tasks_lock_enter(sched, &old_sigset);
	task->refcount--;
	if (task->refcount <= 0) {
		task_free(task);
	}
	tasks_lock_leave(sched, &old_sigset);
}

/**
 * Delete all done, transient, non-current jobs that have not been deleted yet.
 */
static void cleanup_transient(RzCoreTaskScheduler *sched, RzCoreTask *exclude) {
	RzCoreTask *ltask;
	RzListIter *iter;
	RzListIter *iter_tmp;
	rz_list_foreach_safe (sched->tasks, iter, iter_tmp, ltask) {
		if (ltask == exclude) {
			continue;
		}
		if (ltask->transient && ltask->state == RZ_CORE_TASK_STATE_DONE) {
			rz_list_delete(sched->tasks, iter);
		}
	}
}

RZ_API void rz_core_task_schedule(RzCoreTask *current, RzTaskState next_state) {
	RzCoreTaskScheduler *sched = current->sched;
	bool stop = next_state != RZ_CORE_TASK_STATE_RUNNING;

	if (sched->oneshot_running || (!stop && sched->tasks_running == 1 && sched->oneshots_enqueued == 0)) {
		return;
	}

	sched->current_task = NULL;

	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(sched, &old_sigset);

	current->state = next_state;

	if (stop) {
		sched->tasks_running--;
	}

	cleanup_transient(sched, current);

	// oneshots always have priority.
	// if there are any queued, run them immediately.
	OneShot *oneshot;
	while ((oneshot = rz_list_pop_head(sched->oneshot_queue))) {
		sched->oneshots_enqueued--;
		sched->oneshot_running = true;
		oneshot->func(oneshot->user);
		sched->oneshot_running = false;
		free(oneshot);
	}

	RzCoreTask *next = rz_list_pop_head(sched->tasks_queue);

	if (next && !stop) {
		rz_list_append(sched->tasks_queue, current);
		rz_th_lock_enter(current->dispatch_lock);
	}

	tasks_lock_leave(sched, &old_sigset);

	if (next) {
		rz_th_lock_enter(next->dispatch_lock);
		next->dispatched = true;
		rz_th_lock_leave(next->dispatch_lock);
		rz_th_cond_signal(next->dispatch_cond);
		if (!stop) {
			while (!current->dispatched) {
				rz_th_cond_wait(current->dispatch_cond, current->dispatch_lock);
			}
			current->dispatched = false;
			rz_th_lock_leave(current->dispatch_lock);

			tasks_lock_enter(sched, &old_sigset);
			cleanup_transient(sched, current);
			tasks_lock_leave(sched, &old_sigset);
		}
	}

	if (!stop) {
		sched->current_task = current;
		if (sched->ctx_switch) {
			sched->ctx_switch(current, sched->ctx_switch_user);
		}
	}
}

static void task_wakeup(RzCoreTask *current) {
	RzCoreTaskScheduler *sched = current->sched;

	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(sched, &old_sigset);

	sched->tasks_running++;
	current->state = RZ_CORE_TASK_STATE_RUNNING;

	// check if there are other tasks running
	bool single = sched->tasks_running == 1 || sched->tasks_running == 0;

	rz_th_lock_enter(current->dispatch_lock);

	// if we are not the only task, we must wait until another task signals us.

	if (!single) {
		rz_list_append(sched->tasks_queue, current);
	}

	tasks_lock_leave(sched, &old_sigset);

	if (!single) {
		while (!current->dispatched) {
			rz_th_cond_wait(current->dispatch_cond, current->dispatch_lock);
		}
		current->dispatched = false;
	}

	rz_th_lock_leave(current->dispatch_lock);

	sched->current_task = current;

	if (sched->ctx_switch) {
		sched->ctx_switch(current, sched->ctx_switch_user);
	}
}

RZ_API void rz_core_task_yield(RzCoreTaskScheduler *scheduler) {
	RzCoreTask *task = rz_core_task_self(scheduler);
	if (!task) {
		return;
	}
	rz_core_task_schedule(task, RZ_CORE_TASK_STATE_RUNNING);
}

static void task_end(RzCoreTask *t) {
	rz_core_task_schedule(t, RZ_CORE_TASK_STATE_DONE);
}

static void *task_run_thread(RzCoreTask *task) {
	RzCoreTaskScheduler *sched = task->sched;

	task_wakeup(task);

	if (task->breaked) {
		// breaked in RZ_CORE_TASK_STATE_BEFORE_START
		goto nonstart;
	}

	task->runner(sched, task->runner_user);

	TASK_SIGSET_T old_sigset;
nonstart:
	tasks_lock_enter(sched, &old_sigset);

	task_end(task);

	if (task->running_sem) {
		rz_th_sem_post(task->running_sem);
	}

	tasks_lock_leave(sched, &old_sigset);
	return NULL;
}

RZ_API void rz_core_task_enqueue(RzCoreTaskScheduler *scheduler, RzCoreTask *task) {
	if (!scheduler || !task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	if (!task->running_sem) {
		task->running_sem = rz_th_sem_new(0);
	}
	rz_list_append(scheduler->tasks, task);
	task->thread = rz_th_new((RzThreadFunction)task_run_thread, task);
	tasks_lock_leave(scheduler, &old_sigset);
}

RZ_API void rz_core_task_enqueue_oneshot(RzCoreTaskScheduler *scheduler, RzCoreTaskOneShot func, void *user) {
	if (!scheduler || !func) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	if (scheduler->tasks_running == 0) {
		// nothing is running right now and no other task can be scheduled
		// while core->tasks_lock is locked => just run it
		scheduler->oneshot_running = true;
		func(user);
		scheduler->oneshot_running = false;
	} else {
		OneShot *oneshot = RZ_NEW(OneShot);
		if (oneshot) {
			oneshot->func = func;
			oneshot->user = user;
			rz_list_append(scheduler->oneshot_queue, oneshot);
			scheduler->oneshots_enqueued++;
		}
	}
	tasks_lock_leave(scheduler, &old_sigset);
}

RZ_API int rz_core_task_run_sync(RzCoreTaskScheduler *scheduler, RzCoreTask *task) {
	task->thread = NULL;
	return task_run_thread(task) != NULL;
}

/* begin running stuff synchronously on the main task */
RZ_API void rz_core_task_sync_begin(RzCoreTaskScheduler *scheduler) {
	RzCoreTask *task = scheduler->main_task;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	task->thread = NULL;
	task->state = RZ_CORE_TASK_STATE_BEFORE_START;
	tasks_lock_leave(scheduler, &old_sigset);
	task_wakeup(task);
}

/* end running stuff synchronously, initially started with rz_core_task_sync_begin() */
RZ_API void rz_core_task_sync_end(RzCoreTaskScheduler *scheduler) {
	task_end(scheduler->main_task);
}

/* To be called from within a task.
 * Begin sleeping and schedule other tasks until rz_core_task_sleep_end() is called. */
RZ_API void rz_core_task_sleep_begin(RzCoreTask *task) {
	rz_core_task_schedule(task, RZ_CORE_TASK_STATE_SLEEPING);
}

RZ_API void rz_core_task_sleep_end(RzCoreTask *task) {
	task_wakeup(task);
}

RZ_API RzCoreTask *rz_core_task_self(RzCoreTaskScheduler *scheduler) {
	return scheduler->current_task ? scheduler->current_task : scheduler->main_task;
}

static RzCoreTask *task_get(RzCoreTaskScheduler *scheduler, int id) {
	RzCoreTask *task;
	RzListIter *iter;
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task->id == id) {
			return task;
		}
	}
	return NULL;
}

RZ_API RzCoreTask *rz_core_task_get_incref(RzCoreTaskScheduler *scheduler, int id) {
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	RzCoreTask *task = task_get(scheduler, id);
	if (task) {
		rz_core_task_incref(task);
	}
	tasks_lock_leave(scheduler, &old_sigset);
	return task;
}

/**
 * break without locking, don't call directly and use public api instead!
 */
static void task_break(RzCoreTask *task) {
	RzCoreTaskScheduler *sched = task->sched;
	task->breaked = true;
	if (sched->break_cb) {
		sched->break_cb(task, sched->break_cb_user);
	}
}

RZ_API void rz_core_task_break(RzCoreTaskScheduler *scheduler, int id) {
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	RzCoreTask *task = task_get(scheduler, id);
	if (!task || task->state == RZ_CORE_TASK_STATE_DONE) {
		tasks_lock_leave(scheduler, &old_sigset);
		return;
	}
	task_break(task);
	tasks_lock_leave(scheduler, &old_sigset);
}

RZ_API void rz_core_task_break_all(RzCoreTaskScheduler *scheduler) {
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	RzCoreTask *task;
	RzListIter *iter;
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task->state != RZ_CORE_TASK_STATE_DONE) {
			task_break(task);
		}
	}
	tasks_lock_leave(scheduler, &old_sigset);
}

RZ_API int rz_core_task_del(RzCoreTaskScheduler *scheduler, int id) {
	RzCoreTask *task;
	RzListIter *iter;
	bool ret = false;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(scheduler, &old_sigset);
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task->id == id) {
			if (task == scheduler->main_task) {
				break;
			}
			if (task->state == RZ_CORE_TASK_STATE_DONE) {
				rz_list_delete(scheduler->tasks, iter);
			} else {
				task->transient = true;
			}
			ret = true;
			break;
		}
	}
	tasks_lock_leave(scheduler, &old_sigset);
	return ret;
}

// above here is for agnostic RzTask api later
// -------------------------------------------
// below here is for RzCore-specific tasks

/**
 * Common base for all contexts of tasks in core.
 * Must be the first member of every task context!
 */
typedef struct core_task_ctx_t {
	RzCore *core;
	RzConsContext *cons_context;
} CoreTaskCtx;

static bool core_task_ctx_init(CoreTaskCtx *ctx, RzCore *core) {
	ctx->core = core;
	ctx->cons_context = rz_cons_context_new(rz_cons_singleton()->context);
	if (!ctx->cons_context) {
		return false;
	}
	ctx->cons_context->cmd_depth = core->max_cmd_depth;
	rz_cons_context_break_push(ctx->cons_context, NULL, NULL, false);
	return true;
}

static void core_task_ctx_fini(CoreTaskCtx *ctx) {
	if (ctx->cons_context && ctx->cons_context->break_stack) {
		rz_cons_context_break_pop(ctx->cons_context, false);
	}
	rz_cons_context_free(ctx->cons_context);
}

/**
 * Context for (user-visible) command tasks
 */
typedef struct cmd_task_ctx_t {
	CoreTaskCtx core_ctx;
	char *cmd;
	bool cmd_log;
	char *res;
	RzCoreCmdTaskFinished finished_cb;
	void *finished_cb_user;
} CmdTaskCtx;

static CmdTaskCtx *cmd_task_ctx_new(RzCore *core, const char *cmd, RzCoreCmdTaskFinished finished_cb, void *finished_cb_user) {
	rz_return_val_if_fail(cmd, NULL);
	CmdTaskCtx *ctx = RZ_NEW(CmdTaskCtx);
	if (!ctx) {
		return NULL;
	}
	if (!core_task_ctx_init(&ctx->core_ctx, core)) {
		free(ctx);
		return NULL;
	}
	ctx->cmd = strdup(cmd);
	ctx->cmd_log = false;
	ctx->res = NULL;
	ctx->finished_cb = finished_cb;
	ctx->finished_cb_user = finished_cb_user;
	return ctx;
}

static void cmd_task_runner(RzCoreTaskScheduler *sched, void *user) {
	CmdTaskCtx *ctx = user;
	RzCore *core = ctx->core_ctx.core;
	RzCoreTask *task = rz_core_task_self(sched);
	char *res_str;
	if (task == sched->main_task) {
		rz_core_cmd(core, ctx->cmd, ctx->cmd_log);
		res_str = NULL;
	} else {
		res_str = rz_core_cmd_str(core, ctx->cmd);
	}
	ctx->res = res_str;

	if (ctx->finished_cb) {
		ctx->finished_cb(res_str, ctx->finished_cb_user);
	}

	if (task != sched->main_task && rz_cons_default_context_is_interactive()) {
		eprintf("\nTask %d finished\n", task->id);
	}
}

static void cmd_task_free(CmdTaskCtx *ctx) {
	if (!ctx) {
		return;
	}
	free(ctx->cmd);
	free(ctx->res);
	core_task_ctx_fini(&ctx->core_ctx);
	free(ctx);
}

/**
 * Create a new task that runs a command and saves its result.
 * These tasks are user-visible under the & command family.
 */
RZ_API RzCoreTask *rz_core_cmd_task_new(RzCore *core, const char *cmd, RzCoreCmdTaskFinished finished_cb, void *finished_cb_user) {
	CmdTaskCtx *ctx = cmd_task_ctx_new(core, cmd, finished_cb, finished_cb_user);
	if (!ctx) {
		return NULL;
	}
	RzCoreTask *task = rz_core_task_new(&core->tasks, cmd_task_runner, (RzCoreTaskRunnerFree)cmd_task_free, ctx);
	if (!task) {
		cmd_task_free(ctx);
		return NULL;
	}
	return task;
}

/**
 * Get the result of the command that was run in a task created with rz_core_cmd_task_new.
 * If the task is not a command task, returns NULL.
 */
RZ_API const char *rz_core_cmd_task_get_result(RzCoreTask *task) {
	// Check if this is really a command task
	if (!task->runner_user || task->runner != cmd_task_runner) {
		return NULL;
	}
	CmdTaskCtx *ctx = task->runner_user;
	return ctx->res;
}

/**
 * Context for (user-invisible) function tasks
 */
typedef struct function_task_ctx_t {
	CoreTaskCtx core_ctx;
	RzCoreTaskFunction fcn;
	void *fcn_user;
	void *res;
} FunctionTaskCtx;

static FunctionTaskCtx *function_task_ctx_new(RzCore *core, RzCoreTaskFunction fcn, void *fcn_user) {
	FunctionTaskCtx *ctx = RZ_NEW(FunctionTaskCtx);
	if (!ctx) {
		return NULL;
	}
	if (!core_task_ctx_init(&ctx->core_ctx, core)) {
		free(ctx);
		return NULL;
	}
	ctx->fcn = fcn;
	ctx->fcn_user = fcn_user;
	ctx->res = NULL;
	return ctx;
}

static void function_task_runner(RzCoreTaskScheduler *sched, void *user) {
	FunctionTaskCtx *ctx = user;
	RzCore *core = ctx->core_ctx.core;
	rz_cons_push();
	ctx->res = ctx->fcn(core, ctx->fcn_user);
	rz_cons_pop();
}

static void function_task_free(FunctionTaskCtx *ctx) {
	if (!ctx) {
		return;
	}
	core_task_ctx_fini(&ctx->core_ctx);
	free(ctx);
}

/**
 * Create a new task that runs a custom function and saves its result.
 * These tasks are not user-visible.
 */
RZ_API RzCoreTask *rz_core_function_task_new(RzCore *core, RzCoreTaskFunction fcn, void *fcn_user) {
	FunctionTaskCtx *ctx = function_task_ctx_new(core, fcn, fcn_user);
	if (!ctx) {
		return NULL;
	}
	RzCoreTask *task = rz_core_task_new(&core->tasks, function_task_runner,
		(RzCoreTaskRunnerFree)function_task_free, ctx);
	if (!task) {
		function_task_free(ctx);
		return NULL;
	}
	return task;
}

/**
 * Get the return value of the function that was run in a task created with rz_core_function_task_new.
 * If the task is not a function task, returns NULL.
 */
RZ_API void *rz_core_function_task_get_result(RzCoreTask *task) {
	// Check if this is really a command task
	if (!task->runner_user || task->runner != function_task_runner) {
		return NULL;
	}
	FunctionTaskCtx *ctx = task->runner_user;
	return ctx->res;
}

RZ_IPI void rz_core_task_ctx_switch(RzCoreTask *next, void *user) {
	if (next->runner_user) {
		CoreTaskCtx *ctx = next->runner_user;
		if (ctx->cons_context) {
			rz_cons_context_load(ctx->cons_context);
			return;
		}
	}
	rz_cons_context_reset();
}

RZ_IPI void rz_core_task_break_cb(RzCoreTask *task, void *user) {
	CoreTaskCtx *ctx = task->runner_user;
	rz_cons_context_break(ctx ? ctx->cons_context : NULL);
}

RZ_API const char *rz_core_task_status(RzCoreTask *task) {
	switch (task->state) {
	case RZ_CORE_TASK_STATE_RUNNING:
		return "running";
	case RZ_CORE_TASK_STATE_SLEEPING:
		return "sleeping";
	case RZ_CORE_TASK_STATE_DONE:
		return "done";
	case RZ_CORE_TASK_STATE_BEFORE_START:
		return "before start";
	default:
		return "unknown";
	}
}

RZ_API void rz_core_task_print(RzCore *core, RzCoreTask *task, int mode, PJ *j) {
	rz_return_if_fail(mode != 'j' || j);
	if (task != core->tasks.main_task && task->runner != cmd_task_runner) {
		// don't print tasks that are custom function-runners, which come from internal code.
		// only main and command ones, which should be user-visible.
		return;
	}
	const char *cmd = NULL;
	if (task != core->tasks.main_task) {
		cmd = ((CmdTaskCtx *)task->runner_user)->cmd;
	}
	switch (mode) {
	case 'j': {
		pj_o(j);
		pj_ki(j, "id", task->id);
		const char *state;
		// This is NOT the same as rz_core_task_status()!
		// rz_core_task_status() is meant to be readable and may be changed.
		// These are meant to be stable for scripting.
		switch (task->state) {
		case RZ_CORE_TASK_STATE_BEFORE_START:
			state = "before_start";
			break;
		case RZ_CORE_TASK_STATE_RUNNING:
			state = "running";
			break;
		case RZ_CORE_TASK_STATE_SLEEPING:
			state = "sleeping";
			break;
		case RZ_CORE_TASK_STATE_DONE:
			state = "done";
			break;
		default:
			state = "invalid";
		}
		pj_ks(j, "state", state);
		pj_kb(j, "transient", task->transient);
		if (cmd) {
			pj_ks(j, "cmd", cmd);
		}
		pj_end(j);
		break;
	default: {
		rz_cons_printf("%3d %3s %12s  %s\n",
			task->id,
			task->transient ? "(t)" : "",
			rz_core_task_status(task),
			cmd ? cmd : "-- MAIN TASK --");
	} break;
	}
	}
}

RZ_API void rz_core_task_list(RzCore *core, int mode) {
	RzListIter *iter;
	RzCoreTask *task;
	PJ *j = NULL;
	if (mode == 'j') {
		j = pj_new();
		pj_a(j);
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(&core->tasks, &old_sigset);
	rz_list_foreach (core->tasks.tasks, iter, task) {
		rz_core_task_print(core, task, mode, j);
	}
	if (j) {
		pj_end(j);
		rz_cons_println(pj_string(j));
		pj_free(j);
	} else {
		rz_cons_printf("--\ntotal running: %d\n", core->tasks.tasks_running);
	}
	tasks_lock_leave(&core->tasks, &old_sigset);
}

RZ_API bool rz_core_task_is_cmd(RzCore *core, int id) {
	RzCoreTask *task = rz_core_task_get_incref(&core->tasks, id);
	if (!task) {
		return false;
	}
	bool r = task->runner == cmd_task_runner;
	rz_core_task_decref(task);
	return r;
}

RZ_API void rz_core_task_del_all_done(RzCore *core) {
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter(&core->tasks, &old_sigset);
	RzCoreTaskScheduler *sched = &core->tasks;
	RzCoreTask *task;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (sched->tasks, iter, iter2, task) {
		if (task != sched->main_task && task->state == RZ_CORE_TASK_STATE_DONE && task->runner == cmd_task_runner) {
			rz_list_delete(sched->tasks, iter);
		}
	}
	tasks_lock_leave(&core->tasks, &old_sigset);
}
