// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

static bool core_config_init_elf(RzCore *core) {
	RzConfig *cfg = core->config;

	return rz_config_add_bool(cfg, "elf.checks.sections", "Check elf sections during loading", true) &&
		rz_config_add_bool(cfg, "elf.checks.segments", "Check elf segments during loading", true) &&
		rz_config_add_bool(cfg, "elf.load.sections", "Automatically load elf sections", true);
}
