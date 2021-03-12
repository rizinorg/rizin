// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_core.h>
#include "cmd_descs/cmd_descs.h"

static int task_enqueue(RzCore *core, const char *cmd, bool transient) {
	RzCoreTask *task = rz_core_cmd_task_new(core, cmd, NULL, NULL);
	if (!task) {
		return -1;
	}
	task->transient = transient;
	rz_core_task_enqueue(&core->tasks, task);
	return 0;
}

static int task_output(RzCore *core, int tid) {
	if (!tid) {
		return -1;
	}
	RzCoreTask *task = rz_core_task_get_incref(&core->tasks, tid);
	if (task) {
		const char *res = rz_core_cmd_task_get_result(task);
		if (res) {
			rz_cons_println(res);
		}
		rz_core_task_decref(task);
	} else {
		eprintf("Cannot find task\n");
		return -1;
	}
	return 0;
}

static int task_break(RzCore *core, int tid) {
	if (!tid) {
		return -1;
	}
	if (!rz_core_task_is_cmd(core, tid)) {
		return -1;
	}
	rz_core_task_break(&core->tasks, tid);
	return 0;
}

RZ_IPI RzCmdStatus rz_tasks_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc == 1) {
		rz_core_task_list(core, mode == RZ_OUTPUT_MODE_STANDARD ? '\0' : 'j');
		return RZ_CMD_STATUS_OK;
	} else if (argc == 2) {
		return rz_cmd_int2status(task_enqueue(core, argv[1], false));
	}
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_tasks_transient_handler(RzCore *core, int argc, const char **argv) {
	return rz_cmd_int2status(task_enqueue(core, argv[1], true));
}

RZ_IPI RzCmdStatus rz_tasks_output_handler(RzCore *core, int argc, const char **argv) {
	int tid = rz_num_math(core->num, argv[1]);
	return rz_cmd_int2status(task_output(core, tid));
}

RZ_IPI RzCmdStatus rz_tasks_break_handler(RzCore *core, int argc, const char **argv) {
	int tid = rz_num_math(core->num, argv[1]);
	return rz_cmd_int2status(task_break(core, tid));
}

RZ_IPI RzCmdStatus rz_tasks_delete_handler(RzCore *core, int argc, const char **argv) {
	int tid = rz_num_math(core->num, argv[1]);
	if (!rz_core_task_is_cmd(core, tid)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return rz_core_task_del(&core->tasks, tid) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_tasks_delete_all_handler(RzCore *core, int argc, const char **argv) {
	rz_core_task_del_all_done(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_tasks_wait_handler(RzCore *core, int argc, const char **argv) {
	int tid = 0;
	if (argc == 2) {
		tid = rz_num_math(core->num, argv[1]);
	}
	if (!rz_core_task_is_cmd(core, tid)) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_task_join(&core->tasks, core->tasks.current_task, tid ? tid : -1);
	return RZ_CMD_STATUS_OK;
}
