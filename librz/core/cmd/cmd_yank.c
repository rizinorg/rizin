// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_core.h>
#include "../core_private.h"

RZ_IPI RzCmdStatus rz_yank_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		st64 len = rz_num_math(core->num, argv[1]);
		if (len < 0) {
			RZ_LOG_ERROR("Yank length cannot be negative\n");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_core_yank(core, core->offset, len);
	} else {
		rz_core_yank_dump(core, 0, state);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_yank_editor_handler(RzCore *core, int argc, const char **argv) {
	char *src = rz_core_yank_as_string(core, 0);
	if (!src) {
		return RZ_CMD_STATUS_ERROR;
	}
	char *new = rz_core_editor(core, NULL, src);
	if (!new) {
		free(src);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_core_yank_hexpair(core, src)) {
		free(src);
		free(new);
		return RZ_CMD_STATUS_ERROR;
	}
	free(src);
	free(new);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_yank_file_handler(RzCore *core, int argc, const char **argv) {
	st64 len = rz_num_math(core->num, argv[1]);
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return rz_core_yank_file(core, len, core->offset, argv[2]);
}

RZ_IPI RzCmdStatus rz_yank_whole_file_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_yank_file_all(core, argv[1]);
}

RZ_IPI RzCmdStatus rz_yank_print_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_yank_print(core, len));
}

RZ_IPI RzCmdStatus rz_yank_string_print_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_yank_print_string(core, len));
}

RZ_IPI RzCmdStatus rz_yank_hex_print_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_yank_print_hexdump(core, len));
}

RZ_IPI RzCmdStatus rz_yank_string_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_yank_string(core, core->offset, len));
}

RZ_IPI RzCmdStatus rz_yank_to_handler(RzCore *core, int argc, const char **argv) {
	st64 len = rz_num_math(core->num, argv[1]);
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = rz_num_math(core->num, argv[2]);
	return bool2status(rz_core_yank_to(core, len, addr));
}

RZ_IPI RzCmdStatus rz_yank_hexpairs_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_yank_hexpair(core, argv[1]));
}

RZ_IPI RzCmdStatus rz_yank_paste_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (len < 0) {
		RZ_LOG_ERROR("Yank length cannot be negative\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_yank_paste(core, core->offset, len));
}
