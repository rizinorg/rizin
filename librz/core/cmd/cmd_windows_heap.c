// SPDX-FileCopyrightText: 2021 Pulak Malhotra <pulakmalhotra2000@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../core_private.h"

#define NOT_SUPPORTED_ERROR_MESSAGE \
	RZ_LOG_ERROR("core: Windows heap parsing is not supported on this platform\n"); \
	return RZ_CMD_STATUS_ERROR;

#if __WINDOWS__
RZ_IPI RzCmdStatus rz_cmd_debug_process_heaps_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_heap_list_w32(core, mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heap_block_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc == 2) {
		rz_heap_debug_block_win(core, argv[1], mode, false);
	} else {
		rz_heap_debug_block_win(core, NULL, mode, false);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_heap_block_flag_handler(RzCore *core, int argc, const char **argv) {
	rz_heap_debug_block_win(core, NULL, RZ_OUTPUT_MODE_STANDARD, true);
	return RZ_CMD_STATUS_OK;
}

#else
RZ_IPI RzCmdStatus rz_cmd_debug_heap_block_flag_handler(RzCore *core, int argc, const char **argv) {
	NOT_SUPPORTED_ERROR_MESSAGE;
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heaps_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	NOT_SUPPORTED_ERROR_MESSAGE;
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heap_block_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	NOT_SUPPORTED_ERROR_MESSAGE;
}
#endif
