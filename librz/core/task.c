/* radare - LGPL - Copyright 2014-2019 - pancake, thestr4ng3r */

#include <rz_core.h>

RZ_API void rz_core_task_scheduler_init (RzCoreTaskScheduler *tasks, RzCore *core) {
	tasks->task_id_next = 0;
	tasks->tasks = rz_list_newf ((RzListFree)rz_core_task_decref);
	tasks->tasks_queue = rz_list_new ();
	tasks->oneshot_queue = rz_list_newf (free);
	tasks->oneshots_enqueued = 0;
	tasks->lock = rz_th_lock_new (true);
	tasks->tasks_running = 0;
	tasks->oneshot_running = false;
	tasks->main_task = rz_core_task_new (core, false, NULL, NULL, NULL);
	rz_list_append (tasks->tasks, tasks->main_task);
	tasks->current_task = NULL;
}

RZ_API void rz_core_task_scheduler_fini (RzCoreTaskScheduler *tasks) {
	rz_list_free (tasks->tasks);
	rz_list_free (tasks->tasks_queue);
	rz_list_free (tasks->oneshot_queue);
	rz_th_lock_free (tasks->lock);
}

#if HAVE_PTHREAD
#define TASK_SIGSET_T sigset_t
static void tasks_lock_block_signals(sigset_t *old_sigset) {
	sigset_t block_sigset;
	sigemptyset (&block_sigset);
	sigaddset (&block_sigset, SIGWINCH);
	rz_signal_sigmask (SIG_BLOCK, &block_sigset, old_sigset);
}

static void tasks_lock_block_signals_reset(sigset_t *old_sigset) {
	rz_signal_sigmask (SIG_SETMASK, old_sigset, NULL);
}
#else
#define TASK_SIGSET_T void *
static void tasks_lock_block_signals(TASK_SIGSET_T *old_sigset) { (void)old_sigset; }
static void tasks_lock_block_signals_reset(TASK_SIGSET_T *old_sigset) { (void)old_sigset; }
#endif

static void tasks_lock_enter(RzCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	tasks_lock_block_signals (old_sigset);
	rz_th_lock_enter (scheduler->lock);
}

static void tasks_lock_leave(RzCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	rz_th_lock_leave (scheduler->lock);
	tasks_lock_block_signals_reset (old_sigset);
}

typedef struct oneshot_t {
	RzCoreTaskOneShot func;
	void *user;
} OneShot;

RZ_API void rz_core_task_print (RzCore *core, RzCoreTask *task, int mode) {
	switch (mode) {
	case 'j':
		{
		rz_cons_printf ("{\"id\":%d,\"state\":\"", task->id);
		switch (task->state) {
		case RZ_CORE_TASK_STATE_BEFORE_START:
			rz_cons_print ("before_start");
			break;
		case RZ_CORE_TASK_STATE_RUNNING:
			rz_cons_print ("running");
			break;
		case RZ_CORE_TASK_STATE_SLEEPING:
			rz_cons_print ("sleeping");
			break;
		case RZ_CORE_TASK_STATE_DONE:
			rz_cons_print ("done");
			break;
		}
		rz_cons_printf ("\",\"transient\":%s,\"cmd\":", task->transient ? "true" : "false");
		if (task->cmd) {
			rz_cons_printf ("\"%s\"}", task->cmd);
		} else {
			rz_cons_printf ("null}");
		}
		}
		break;
	default: {
		const char *info = task->cmd;
		if (task == core->tasks.main_task) {
			info = "-- MAIN TASK --";
		}
		rz_cons_printf ("%3d %3s %12s  %s\n",
					   task->id,
					   task->transient ? "(t)" : "",
					   rz_core_task_status (task),
					   info ? info : "");
		}
		break;
	}
}

RZ_API void rz_core_task_list(RzCore *core, int mode) {
	RzListIter *iter;
	RzCoreTask *task;
	if (mode == 'j') {
		rz_cons_printf ("[");
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (&core->tasks, &old_sigset);
	rz_list_foreach (core->tasks.tasks, iter, task) {
		rz_core_task_print (core, task, mode);
		if (mode == 'j' && iter->n) {
			rz_cons_printf (",");
		}
	}
	if (mode == 'j') {
		rz_cons_printf ("]\n");
	} else {
		rz_cons_printf ("--\ntotal running: %d\n", core->tasks.tasks_running);
	}
	tasks_lock_leave (&core->tasks, &old_sigset);
}

RZ_API int rz_core_task_running_tasks_count(RzCoreTaskScheduler *scheduler) {
	RzListIter *iter;
	RzCoreTask *task;
	int count = 0;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task != scheduler->main_task && task->state != RZ_CORE_TASK_STATE_DONE) {
			count++;
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
	return count;
}

static void task_join(RzCoreTask *task) {
	RzThreadSemaphore *sem = task->running_sem;
	if (!sem) {
		return;
	}

	rz_th_sem_wait (sem);
	rz_th_sem_post (sem);
}

RZ_API void rz_core_task_join(RzCoreTaskScheduler *scheduler, RzCoreTask *current, int id) {
	if (current && id == current->id) {
		return;
	}
	if (id >= 0) {
		RzCoreTask *task = rz_core_task_get_incref (scheduler, id);
		if (!task) {
			return;
		}
		if (current) {
			rz_core_task_sleep_begin (current);
		}
		task_join (task);
		if (current) {
			rz_core_task_sleep_end (current);
		}
		rz_core_task_decref (task);
	} else {
		TASK_SIGSET_T old_sigset;
		tasks_lock_enter (scheduler, &old_sigset);
		RzList *tasks = rz_list_clone (scheduler->tasks);
		RzListIter *iter;
		RzCoreTask *task;
		rz_list_foreach (tasks, iter, task) {
			if (current == task) {
				continue;
			}
			rz_core_task_incref (task);
		}
		tasks_lock_leave (scheduler, &old_sigset);

		rz_list_foreach (tasks, iter, task) {
			if (current == task) {
				continue;
			}
			if (current) {
				rz_core_task_sleep_begin (current);
			}
			task_join (task);
			if (current) {
				rz_core_task_sleep_end (current);
			}
			rz_core_task_decref (task);
		}
		rz_list_free (tasks);
	}
}

static void task_free (RzCoreTask *task) {
	if (!task) {
		return;
	}
	free (task->cmd);
	free (task->res);
	rz_th_free (task->thread);
	rz_th_sem_free (task->running_sem);
	rz_th_cond_free (task->dispatch_cond);
	rz_th_lock_free (task->dispatch_lock);
	rz_cons_context_free (task->cons_context);
	free (task);
}

RZ_API RzCoreTask *rz_core_task_new(RzCore *core, bool create_cons, const char *cmd, RzCoreTaskCallback cb, void *user) {
	RzCoreTask *task = RZ_NEW0 (RzCoreTask);
	if (!task) {
		goto hell;
	}

	task->thread = NULL;
	task->cmd = cmd ? strdup (cmd) : NULL;
	task->cmd_log = false;
	task->res = NULL;
	task->running_sem = NULL;
	task->dispatched = false;
	task->dispatch_cond = rz_th_cond_new ();
	task->dispatch_lock = rz_th_lock_new (false);
	if (!task->dispatch_cond || !task->dispatch_lock) {
		goto hell;
	}

	if (create_cons) {
		task->cons_context = rz_cons_context_new (rz_cons_singleton ()->context);
		if (!task->cons_context) {
			goto hell;
		}
		task->cons_context->cmd_depth = core->max_cmd_depth;
	}

	task->id = core->tasks.task_id_next++;
	task->state = RZ_CORE_TASK_STATE_BEFORE_START;
	task->refcount = 1;
	task->transient = false;
	task->core = core;
	task->user = user;
	task->cb = cb;

	return task;

hell:
	task_free (task);
	return NULL;
}

RZ_API void rz_core_task_incref (RzCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (&task->core->tasks, &old_sigset);
	task->refcount++;
	tasks_lock_leave (&task->core->tasks, &old_sigset);
}

RZ_API void rz_core_task_decref (RzCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	RzCoreTaskScheduler *scheduler = &task->core->tasks;
	tasks_lock_enter (scheduler, &old_sigset);
	task->refcount--;
	if (task->refcount <= 0) {
		task_free (task);
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

RZ_API void rz_core_task_schedule(RzCoreTask *current, RTaskState next_state) {
	RzCore *core = current->core;
	RzCoreTaskScheduler *scheduler = &core->tasks;
	bool stop = next_state != RZ_CORE_TASK_STATE_RUNNING;

	if (scheduler->oneshot_running || (!stop && scheduler->tasks_running == 1 && scheduler->oneshots_enqueued == 0)) {
		return;
	}

	scheduler->current_task = NULL;

	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);

	current->state = next_state;

	if (stop) {
		scheduler->tasks_running--;
	}

	// oneshots always have priority.
	// if there are any queued, run them immediately.
	OneShot *oneshot;
	while ((oneshot = rz_list_pop_head (scheduler->oneshot_queue))) {
		scheduler->oneshots_enqueued--;
		scheduler->oneshot_running = true;
		oneshot->func (oneshot->user);
		scheduler->oneshot_running = false;
		free (oneshot);
	}

	RzCoreTask *next = rz_list_pop_head (scheduler->tasks_queue);

	if (next && !stop) {
		rz_list_append (scheduler->tasks_queue, current);
		rz_th_lock_enter (current->dispatch_lock);
	}

	tasks_lock_leave (scheduler, &old_sigset);

	if (next) {
		rz_cons_context_reset ();
		rz_th_lock_enter (next->dispatch_lock);
		next->dispatched = true;
		rz_th_lock_leave (next->dispatch_lock);
		rz_th_cond_signal (next->dispatch_cond);
		if (!stop) {
			while (!current->dispatched) {
				rz_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
			}
			current->dispatched = false;
			rz_th_lock_leave (current->dispatch_lock);
		}
	}

	if (!stop) {
		scheduler->current_task = current;
		if (current->cons_context) {
			rz_cons_context_load (current->cons_context);
		} else {
			rz_cons_context_reset ();
		}
	}
}

static void task_wakeup(RzCoreTask *current) {
	RzCore *core = current->core;
	RzCoreTaskScheduler *scheduler = &core->tasks;

	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);

	scheduler->tasks_running++;
	current->state = RZ_CORE_TASK_STATE_RUNNING;

	// check if there are other tasks running
	bool single = scheduler->tasks_running == 1 || scheduler->tasks_running == 0;

	rz_th_lock_enter (current->dispatch_lock);

	// if we are not the only task, we must wait until another task signals us.

	if (!single) {
		rz_list_append (scheduler->tasks_queue, current);
	}

	tasks_lock_leave (scheduler, &old_sigset);

	if (!single) {
		while (!current->dispatched) {
			rz_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
		}
		current->dispatched = false;
	}

	rz_th_lock_leave (current->dispatch_lock);

	scheduler->current_task = current;

	if (current->cons_context) {
		rz_cons_context_load (current->cons_context);
	} else {
		rz_cons_context_reset ();
	}
}

RZ_API void rz_core_task_yield(RzCoreTaskScheduler *scheduler) {
	RzCoreTask *task = rz_core_task_self (scheduler);
	if (!task) {
		return;
	}
	rz_core_task_schedule (task, RZ_CORE_TASK_STATE_RUNNING);
}

static void task_end(RzCoreTask *t) {
	rz_core_task_schedule (t, RZ_CORE_TASK_STATE_DONE);
}

static RzThreadFunctionRet task_run(RzCoreTask *task) {
	RzCore *core = task->core;
	RzCoreTaskScheduler *scheduler = &task->core->tasks;

	task_wakeup (task);

	if (task->cons_context && task->cons_context->breaked) {
		// breaked in RZ_CORE_TASK_STATE_BEFORE_START
		goto stillbirth;
	}

	char *res_str;
	if (task == scheduler->main_task) {
		rz_core_cmd (core, task->cmd, task->cmd_log);
		res_str = NULL;
	} else {
		res_str = rz_core_cmd_str (core, task->cmd);
	}

	free (task->res);
	task->res = res_str;

	if (task != scheduler->main_task && rz_cons_default_context_is_interactive ()) {
		eprintf ("\nTask %d finished\n", task->id);
	}

	TASK_SIGSET_T old_sigset;
stillbirth:
	tasks_lock_enter (scheduler, &old_sigset);

	task_end (task);

	if (task->cb) {
		task->cb (task->user, task->res);
	}

	if (task->running_sem) {
		rz_th_sem_post (task->running_sem);
	}

	if (task->cons_context && task->cons_context->break_stack) {
		rz_cons_context_break_pop (task->cons_context, false);
	}

	int ret = RZ_TH_STOP;
	if (task->transient) {
		RzCoreTask *ltask;
		RzListIter *iter;
		rz_list_foreach (scheduler->tasks, iter, ltask) {
			if (ltask == task) {
				rz_list_delete (scheduler->tasks, iter);
				ret = RZ_TH_FREED;
				break;
			}
		}
	}

	tasks_lock_leave (scheduler, &old_sigset);
	return ret;
}

static RzThreadFunctionRet task_run_thread(RzThread *th) {
	RzCoreTask *task = (RzCoreTask *)th->user;
	return task_run (task);
}

RZ_API void rz_core_task_enqueue(RzCoreTaskScheduler *scheduler, RzCoreTask *task) {
	if (!scheduler || !task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	if (!task->running_sem) {
		task->running_sem = rz_th_sem_new (1);
	}
	if (task->running_sem) {
		rz_th_sem_wait (task->running_sem);
	}
	if (task->cons_context) {
		rz_cons_context_break_push (task->cons_context, NULL, NULL, false);
	}
	rz_list_append (scheduler->tasks, task);
	task->thread = rz_th_new (task_run_thread, task, 0);
	tasks_lock_leave (scheduler, &old_sigset);
}

RZ_API void rz_core_task_enqueue_oneshot(RzCoreTaskScheduler *scheduler, RzCoreTaskOneShot func, void *user) {
	if (!scheduler || !func) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	if (scheduler->tasks_running == 0) {
		// nothing is running right now and no other task can be scheduled
		// while core->tasks_lock is locked => just run it
		scheduler->oneshot_running = true;
		func (user);
		scheduler->oneshot_running = false;
	} else {
		OneShot *oneshot = RZ_NEW (OneShot);
		if (oneshot) {
			oneshot->func = func;
			oneshot->user = user;
			rz_list_append (scheduler->oneshot_queue, oneshot);
			scheduler->oneshots_enqueued++;
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

RZ_API int rz_core_task_run_sync(RzCoreTaskScheduler *scheduler, RzCoreTask *task) {
	task->thread = NULL;
	return task_run (task);
}

/* begin running stuff synchronously on the main task */
RZ_API void rz_core_task_sync_begin(RzCoreTaskScheduler *scheduler) {
	RzCoreTask *task = scheduler->main_task;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	task->thread = NULL;
	task->cmd = NULL;
	task->cmd_log = false;
	task->state = RZ_CORE_TASK_STATE_BEFORE_START;
	tasks_lock_leave (scheduler, &old_sigset);
	task_wakeup (task);
}

/* end running stuff synchronously, initially started with rz_core_task_sync_begin() */
RZ_API void rz_core_task_sync_end(RzCoreTaskScheduler *scheduler) {
	task_end (scheduler->main_task);
}

/* To be called from within a task.
 * Begin sleeping and schedule other tasks until rz_core_task_sleep_end() is called. */
RZ_API void rz_core_task_sleep_begin(RzCoreTask *task) {
	rz_core_task_schedule (task, RZ_CORE_TASK_STATE_SLEEPING);
}

RZ_API void rz_core_task_sleep_end(RzCoreTask *task) {
	task_wakeup (task);
}

RZ_API const char *rz_core_task_status (RzCoreTask *task) {
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

RZ_API RzCoreTask *rz_core_task_self (RzCoreTaskScheduler *scheduler) {
	return scheduler->current_task ? scheduler->current_task : scheduler->main_task;
}

static RzCoreTask *task_get (RzCoreTaskScheduler *scheduler, int id) {
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
	tasks_lock_enter (scheduler, &old_sigset);
	RzCoreTask *task = task_get (scheduler, id);
	if (task) {
		rz_core_task_incref (task);
	}
	tasks_lock_leave (scheduler, &old_sigset);
	return task;
}

RZ_API void rz_core_task_break(RzCoreTaskScheduler *scheduler, int id) {
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RzCoreTask *task = task_get (scheduler, id);
	if (!task || task->state == RZ_CORE_TASK_STATE_DONE) {
		tasks_lock_leave (scheduler, &old_sigset);
		return;
	}
	if (task->cons_context) {
		rz_cons_context_break (task->cons_context);
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

RZ_API void rz_core_task_break_all(RzCoreTaskScheduler *scheduler) {
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RzCoreTask *task;
	RzListIter *iter;
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task->state != RZ_CORE_TASK_STATE_DONE) {
			rz_cons_context_break (task->cons_context);
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

RZ_API int rz_core_task_del (RzCoreTaskScheduler *scheduler, int id) {
	RzCoreTask *task;
	RzListIter *iter;
	bool ret = false;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	rz_list_foreach (scheduler->tasks, iter, task) {
		if (task->id == id) {
			if (task == scheduler->main_task) {
				break;
			}
			if (task->state == RZ_CORE_TASK_STATE_DONE) {
				rz_list_delete (scheduler->tasks, iter);
			} else {
				task->transient = true;
			}
			ret = true;
			break;
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
	return ret;
}

RZ_API void rz_core_task_del_all_done (RzCoreTaskScheduler *scheduler) {
	RzCoreTask *task;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (scheduler->tasks, iter, iter2, task) {
		if (task != scheduler->main_task && task->state == RZ_CORE_TASK_STATE_DONE) {
			rz_list_delete (scheduler->tasks, iter);
		}
	}
}
