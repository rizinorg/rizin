#include <rz_core.h>

RZ_IPI RzCmdStatus rz_cmd_debug_process_heaps_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
#if __WINDOWS__
	w32_list_heaps(core, mode);
	return RZ_CMD_STATUS_OK;
#else
	eprintf("Windows heap parsing is not supported on this platform\n");
	return RZ_CMD_STATUS_ERROR;
#endif
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heap_block_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
#if __WINDOWS__
	if (argc == 2) {
		cmd_debug_map_heap_block_win(core, argv[1], mode, false);
	} else {
		cmd_debug_map_heap_block_win(core, NULL, mode, false);
	}
	return RZ_CMD_STATUS_OK;
#else
	eprintf("Windows heap parsing is not supported on this platform\n");
	return RZ_CMD_STATUS_ERROR;
#endif
}

RZ_IPI RzCmdStatus rz_cmd_debug_heap_block_flag_handler(RzCore *core, int argc, const char **argv) {
#if __WINDOWS__
	cmd_debug_map_heap_block_win(core, NULL, RZ_OUTPUT_MODE_STANDARD, true);
	return RZ_CMD_STATUS_OK;
#else
	eprintf("Windows heap parsing is not supported on this platform\n");
	return RZ_CMD_STATUS_ERROR;
#endif
}