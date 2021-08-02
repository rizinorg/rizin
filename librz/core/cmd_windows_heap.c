#include <rz_core.h>
#define NOT_SUPPORTED_ERROR_MESSAGE \
	eprintf("Windows heap parsing is not supported on this platform\n"); \
	return RZ_CMD_STATUS_ERROR;

#if __WINDOWS__
RZ_IPI RzCmdStatus rz_cmd_debug_process_heaps_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	w32_list_heaps(core, mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heap_block_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc == 2) {
		cmd_debug_map_heap_block_win(core, argv[1], mode, false);
	} else {
		cmd_debug_map_heap_block_win(core, NULL, mode, false);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_heap_block_flag_handler(RzCore *core, int argc, const char **argv) {
	cmd_debug_map_heap_block_win(core, NULL, RZ_OUTPUT_MODE_STANDARD, true);
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