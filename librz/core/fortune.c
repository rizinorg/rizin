// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

static const char *fortunes[] = {
	"tips", "fun"
};

static char *rizin_fortune_file(RZ_BORROW RZ_NONNULL RzPath *sys_path, const char *type) {
	rz_return_val_if_fail(sys_path, NULL);
	if (!strncmp(type, "tips", 4) || !strncmp(type, "fun", 3)) {
		char *fortunes_dir = rz_path_system(sys_path, RZ_FORTUNES);
		if (!fortunes_dir) {
			return NULL;
		}
		char buf[100];
		char *res = rz_file_path_join(fortunes_dir, rz_strf(buf, "fortunes.%s", type));
		free(fortunes_dir);
		return res;
	}
	return RZ_STR_DUP(type);
}

RZ_API void rz_core_fortune_list_types(void) {
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(fortunes); i++) {
		rz_cons_printf("%s\n", fortunes[i]);
	}
}

RZ_API void rz_core_fortune_list(RzCore *core) {
	const char *types = (char *)rz_config_get(core->config, "cfg.fortunes.file");

	char *file = rizin_fortune_file(core->sys_path, types);
	char *str = rz_file_slurp(file, NULL);
	if (!str) {
		free(file);
		return;
	}
	size_t j, beg;
	for (j = 0, beg = 0; str[j]; j++) {
		if (str[j] == '\n') {
			str[j] = '\0';
			rz_cons_printf("%s\n", str + beg);
			beg = j + 1;
		}
	}
	free(str);
	free(file);
}

RZ_API RZ_OWN char *rz_core_fortune_get_random(RzCore *core) {
	int lines = 0;
	const char *types = (char *)rz_config_get(core->config, "cfg.fortunes.file");

	char *file = rizin_fortune_file(core->sys_path, types);
	char *line = rz_file_slurp_random_line_count(file, &lines);

	free(file);
	return line;
}

RZ_API void rz_core_fortune_print_random(RzCore *core) {
	char *line = rz_core_fortune_get_random(core);
	if (!line) {
		line = rz_core_fortune_get_random(core);
	}
	if (line) {
		if (rz_config_get_i(core->config, "cfg.fortunes.clippy")) {
			rz_core_clippy_print(core, line);
		} else {
			rz_cons_printf(" -- %s\n", line);
		}
		free(line);
	}
}
