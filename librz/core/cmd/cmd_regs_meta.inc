// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 *
 * Common code for both ar and dr commands
 * Requires the following defines:
 *   CMD_REGS_PREFIX     Path inside RzCore to the RzReg *
 *   CMD_REGS_REG_PATH   Function/Symbol prefix
 *   CMD_REGS_SYNC       RzCmdRegSync function or NULL
 */

#define HANDLER__(prefix, name) rz_##prefix##_##name##_handler
#define HANDLER_(prefix, name)  HANDLER__(prefix, name)
#define HANDLER(name)           HANDLER_(CMD_REGS_PREFIX, name)

RZ_IPI RzCmdStatus HANDLER(regs)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_regs_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv, state);
}

RZ_IPI RzCmdStatus HANDLER(regs_columns)(RzCore *core, int argc, const char **argv) {
	return rz_regs_columns_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(regs_references)(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return rz_regs_references_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv, mode);
}

RZ_IPI RzCmdStatus HANDLER(regs_valgroup)(RzCore *core, int argc, const char **argv) {
	return rz_regs_valgroup_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_push)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_push_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_pop)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_pop_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_swap)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_swap_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_zero)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_zero_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_hexdump)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_hexdump_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_stack_size)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_stack_size_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_arenas_write_hex)(RzCore *core, int argc, const char **argv) {
	return rz_reg_arenas_write_hex_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(regs_args)(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return rz_regs_args_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv, mode);
}

RZ_IPI RzCmdStatus HANDLER(reg_types)(RzCore *core, int argc, const char **argv) {
	return rz_reg_types_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_roles)(RzCore *core, int argc, const char **argv) {
	return rz_reg_roles_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_flags)(RzCore *core, int argc, const char **argv) {
	return rz_reg_flags_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv, false);
}

RZ_IPI RzCmdStatus HANDLER(reg_flags_unset)(RzCore *core, int argc, const char **argv) {
	return rz_reg_flags_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv, true);
}

RZ_IPI RzCmdStatus HANDLER(reg_profile)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_reg_profile_handler(core, core->CMD_REGS_REG_PATH, argc, argv, state);
}

RZ_IPI RzCmdStatus HANDLER(reg_profile_comments)(RzCore *core, int argc, const char **argv) {
	return rz_reg_profile_comments_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_profile_open)(RzCore *core, int argc, const char **argv) {
	return rz_reg_profile_open_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_profile_gdb)(RzCore *core, int argc, const char **argv) {
	return rz_reg_profile_gdb_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_cond)(RzCore *core, int argc, const char **argv) {
	return rz_reg_cond_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(reg_cc)(RzCore *core, int argc, const char **argv) {
	return rz_reg_cc_handler(core, core->CMD_REGS_REG_PATH, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(regs_diff)(RzCore *core, int argc, const char **argv) {
	return rz_regs_diff_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

RZ_IPI RzCmdStatus HANDLER(regs_prev)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_regs_prev_handler(core, core->CMD_REGS_REG_PATH, argc, argv, state);
}

RZ_IPI RzCmdStatus HANDLER(regs_fpu)(RzCore *core, int argc, const char **argv) {
	return rz_regs_fpu_handler(core, core->CMD_REGS_REG_PATH, CMD_REGS_SYNC, argc, argv);
}

#undef HANDLER
#undef HANDLER_
#undef HANDLER__
