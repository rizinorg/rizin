// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cmd.h"
#include "rz_core.h"
#include <rz_util/rz_num.h>

// "Rh"
RZ_IPI RzCmdStatus rz_remote_webserver_start_fg_handler(RzCore *core, int argc, const char **argv) {
	bool open_browser = RZ_STR_EQ(argv[1], "yes");
	if (!rz_core_rtr_http(core, open_browser)) {
		RZ_LOG_ERROR("Webserver exited with an error.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

// "Rh*"
RZ_IPI RzCmdStatus rz_remote_webserver_restart_fg_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_ERROR("Rh* is only handled by the HTTP server.\n");
	return RZ_CMD_STATUS_ERROR;
}

// "Rh--"
RZ_IPI RzCmdStatus rz_remote_webserver_stop_fg_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_ERROR("Rh-- is only handled by the HTTP server.\n");
	return RZ_CMD_STATUS_ERROR;
}

// "R"
RZ_IPI RzCmdStatus rz_remote_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		rz_core_rtr_list(core);
		return RZ_CMD_STATUS_OK;
	} else if (argc == 3) {
		char *args = rz_str_array_join(argv + 1, argc - 1, " ");
		rz_core_rtr_cmd(core, args);
		free(args);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

// "Rg"
RZ_IPI RzCmdStatus rz_remote_gdb_handler(RzCore *core, int argc, const char **argv) {
	ut32 port = rz_num_math(core->num, argv[1]);
	if (!rz_core_rtr_gdb(core, port, argv[2], argc > 3 ? argv[3] : NULL, false)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

// "Rg!"
RZ_IPI RzCmdStatus rz_remote_gdb_debug_handler(RzCore *core, int argc, const char **argv) {
	ut32 port = rz_num_math(core->num, argv[1]);
	if (!rz_core_rtr_gdb(core, port, argv[2], argc > 3 ? argv[3] : NULL, true)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

// R!
RZ_IPI RzCmdStatus rz_remote_io_system_run_cmd_handler(RzCore *core, int argc, const char **argv) {
	char *res = rz_io_system(core->io, argv[1]);
	if (res) {
		rz_cons_printf("%s\n", res);
		free(res);
	}
	return RZ_CMD_STATUS_OK;
}

// "R<"
RZ_IPI RzCmdStatus rz_remote_send_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_pushout(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

// "R+"
RZ_IPI RzCmdStatus rz_remote_add_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_add(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

// "R-"
RZ_IPI RzCmdStatus rz_remote_del_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_remove(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

// "R="
RZ_IPI RzCmdStatus rz_remote_open_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_session(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

// "R!="
RZ_IPI RzCmdStatus rz_remote_mode_enable_handler(RzCore *core, int argc, const char **argv) {
	const char *cmdremote = rz_str_trim_dup(argc > 1 ? argv[1] : "0");
	rz_core_rtr_enable(core, cmdremote);
	RZ_FREE(cmdremote);
	return RZ_CMD_STATUS_OK;
}

// "R=!"
RZ_IPI RzCmdStatus rz_remote_mode_disable_handler(RzCore *core, int argc, const char **argv) {
	RZ_FREE(core->cmdremote);
	return RZ_CMD_STATUS_OK;
}

// "Rt"
RZ_IPI RzCmdStatus rz_remote_tcp_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 2) {
		rz_core_rtr_cmds(core, argv[1]);
		return RZ_CMD_STATUS_OK;
	} else if (argc == 3) {
		char *host, *port = strchr(argv[1], ':');
		if (port) {
			host = rz_str_ndup(argv[1], port - argv[1]);
			port = rz_str_dup(port + 1);
		} else {
			host = rz_str_dup("localhost");
			port = rz_str_dup(argv[1]);
		}
		char *rbuf = rz_core_rtr_cmds_query(core, host, port, argv[2]);
		if (rbuf) {
			rz_cons_print(rbuf);
			free(rbuf);
		}
		free(host);
		free(port);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

RZ_API void rz_core_rtr_enable(RZ_NONNULL RzCore *core, const char *cmdremote) {
	rz_return_if_fail(core && cmdremote);

	RZ_FREE(core->cmdremote);
	core->cmdremote = rz_str_dup(cmdremote);
}
