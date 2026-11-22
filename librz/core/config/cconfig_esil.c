// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#define CCONFIG_TYP_ESIL_DECL_BIND_FCN(name, ctype, var) \
	static bool cconfig_##name##_get(void *user, void *data) { \
		ctype *value = data; \
		RzCore *core = user; \
		const RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis); \
		*value = config->var; \
		return true; \
	} \
	static bool cconfig_##name##_set(void *user, const void *data) { \
		const ctype *value = data; \
		RzCore *core = user; \
		RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis); \
		config->var = *value; \
		return true; \
	}

#define CCONFIG_CMD_ESIL_DECL_BIND_FCN(name, var) \
	static bool cconfig_##name##_get(void *user, void *data) { \
		const char **value = data; \
		RzCore *core = user; \
		const RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis); \
		*value = config->var; \
		return true; \
	} \
	static bool cconfig_##name##_set(void *user, const void *data) { \
		const char *value = data; \
		RzCore *core = user; \
		RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis); \
		free(config->var); \
		config->var = rz_str_dup(value); \
		RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis); \
		if (esil) { \
			esil->cmd = rz_core_esil_cmd; \
		} \
		return true; \
	}

CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_prestep, bool, prestep);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_verbose, ut64, verbose);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_gotolimit, ut64, gotolimit);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_stack_size, ut64, stack_size);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_stack_addr, ut64, stack_addr);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_addr_size, ut64, addr_size);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_breakoninvalid, bool, breakoninvalid);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_timeout_sec, ut64, timeout_sec);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_exectrap, bool, exectrap);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_iotrap, bool, iotrap);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_romem, bool, romem);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_stats, bool, stats);
CCONFIG_TYP_ESIL_DECL_BIND_FCN(esil_no_null, bool, no_null);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(esil_mdev_range, mdev_range);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_step, cmd_step);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_stepout, cmd_stepout);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_mdev, cmd_mdev);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_intr, cmd_intr);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_trap, cmd_trap);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_todo, cmd_todo);
CCONFIG_CMD_ESIL_DECL_BIND_FCN(cmd_esil_ioer, cmd_ioer);

static bool cconfig_esil_stack_depth_get(void *user, void *data) {
	ut64 *value = data;
	RzCore *core = user;
	const RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis);
	*value = config->stack_depth;
	return true;
}

static bool cconfig_esil_stack_depth_set(void *user, const void *data) {
	const ut64 *value = data;
	if (*value < 3) {
		RZ_LOG_ERROR("esil.stack.depth: value cannot be < 3\n");
		return false;
	}

	RzCore *core = user;
	RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis);
	config->stack_depth = *value;
	return true;
}

static bool cconfig_esil_fillstack_get(void *user, void *data) {
	const char **value = data;
	RzCore *core = user;
	const RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis);
	switch (config->fillstack) {
	case 'd':
		*value = "debrujn";
		break;
	case 's':
		*value = "seq";
		break;
	case 'r':
		*value = "random";
		break;
	case 'z':
		*value = "zero";
		break;
	default:
		*value = "";
		break;
	}
	return true;
}

static bool cconfig_esil_fillstack_set(void *user, const void *data) {
	const char *value = data;
	RzCore *core = user;
	RzEsilConfig *config = rz_analysis_get_esil_config(core->analysis);
	config->fillstack = *value;
	return true;
}

static bool core_config_init_esil(RzCore *core) {
	RzConfig *cfg = core->config;

	return rz_config_add_bool_bind(cfg, "esil.prestep", "Step before esil evaluation in `de` commands", cconfig_esil_prestep_get, cconfig_esil_prestep_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "esil.fillstack", "Initialize ESIL stack with (random, debrujn, sequence, zeros, ...)", cconfig_esil_fillstack_get, cconfig_esil_fillstack_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.verbose", "Show ESIL verbose level (0, 1, 2)", cconfig_esil_verbose_get, cconfig_esil_verbose_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.gotolimit", "Maximum number of gotos per ESIL expression", cconfig_esil_gotolimit_get, cconfig_esil_gotolimit_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.stack.depth", "Number of elements that can be pushed on the esilstack", cconfig_esil_stack_depth_get, cconfig_esil_stack_depth_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.stack.size", "Set stack size in ESIL VM", cconfig_esil_stack_size_get, cconfig_esil_stack_size_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.stack.addr", "Set stack address in ESIL VM", cconfig_esil_stack_addr_get, cconfig_esil_stack_addr_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.addr.size", "Maximum address size in accessed by the ESIL VM", cconfig_esil_addr_size_get, cconfig_esil_addr_size_set, NULL, core) &&
		rz_config_add_bool_bind(cfg, "esil.breakoninvalid", "Break esil execution when instruction is invalid", cconfig_esil_breakoninvalid_get, cconfig_esil_breakoninvalid_set, NULL, core) &&
		rz_config_add_integer_bind(cfg, "esil.timeout", "A timeout (in seconds) for when we should give up emulating", cconfig_esil_timeout_sec_get, cconfig_esil_timeout_sec_set, NULL, core) &&
		rz_config_add_bool_bind(cfg, "esil.exectrap", "trap when executing code in non-executable memory", cconfig_esil_exectrap_get, cconfig_esil_exectrap_set, NULL, core) &&
		rz_config_add_bool_bind(cfg, "esil.iotrap", "invalid read or writes produce a trap exception", cconfig_esil_iotrap_get, cconfig_esil_iotrap_set, NULL, core) &&
		rz_config_add_bool_bind(cfg, "esil.romem", "Set memory as read-only for ESIL", cconfig_esil_romem_get, cconfig_esil_romem_set, NULL, core) &&
		rz_config_add_bool_bind(cfg, "esil.stats", "Statistics from ESIL emulation stored in sdb", cconfig_esil_stats_get, cconfig_esil_stats_set, NULL, core) &&
		rz_config_add_bool_bind(cfg, "esil.noNULL", "Prevent memory read, memory write at null pointer", cconfig_esil_no_null_get, cconfig_esil_no_null_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "esil.mdev.range", "Specify a range of memory to be handled by cmd.esil.mdev", cconfig_esil_mdev_range_get, cconfig_esil_mdev_range_set, NULL, core) &&

		/* related to esil and moved here */
		rz_config_add_string_bind(cfg, "cmd.esil.step", "Command to run before performing a step in the emulator", cconfig_cmd_esil_step_get, cconfig_cmd_esil_step_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "cmd.esil.stepout", "Command to run after performing a step in the emulator", cconfig_cmd_esil_stepout_get, cconfig_cmd_esil_stepout_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "cmd.esil.mdev", "Command to run when memory device address is accessed", cconfig_cmd_esil_mdev_get, cconfig_cmd_esil_mdev_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "cmd.esil.intr", "Command to run when an esil interrupt happens", cconfig_cmd_esil_intr_get, cconfig_cmd_esil_intr_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "cmd.esil.trap", "Command to run when an esil trap happens", cconfig_cmd_esil_trap_get, cconfig_cmd_esil_trap_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "cmd.esil.todo", "Command to run when the esil instruction contains TODO", cconfig_cmd_esil_todo_get, cconfig_cmd_esil_todo_set, NULL, core) &&
		rz_config_add_string_bind(cfg, "cmd.esil.ioer", "Command to run when esil fails to IO (invalid read/write)", cconfig_cmd_esil_ioer_get, cconfig_cmd_esil_ioer_set, NULL, core) &&

		/* Add options and validators */
		rz_config_set_options2(cfg, "esil.fillstack", "", "d", "debrujn", "s", "seq", "r", "random", "z", "zero", NULL);
}

#undef CCONFIG_ESIL_DECL_BIND_FCN
#undef CCONFIG_CMD_ESIL_DECL_BIND_FCN
