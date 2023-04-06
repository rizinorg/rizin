// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cmd.h"
#include "rz_core.h"

static int getArg(char ch, int def) {
	switch (ch) {
	case '&':
	case '-':
		return ch;
	}
	return def;
}

RZ_IPI int rz_equal_g_handler_old(void *data, const char *input) {
	return 0;
}

RZ_IPI int rz_equal_h_handler_old(void *data, const char *input) {
	return 0;
}

RZ_IPI int rz_equal_H_handler_old(void *data, const char *input) {
	return 0;
}

RZ_IPI int rz_cmd_remote(void *data, const char *input) {
	return 0;
}

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

RZ_IPI RzCmdStatus rz_remote_send_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_pushout(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI int rz_io_system_run_oldhandler(void *data, const char *input) {
	return 0;
}

RZ_IPI RzCmdStatus rz_remote_add_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_add(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_del_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_remove(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_open_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_rtr_session(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_mode_enable_handler(RzCore *core, int argc, const char **argv) {
	const char *cmdremote = rz_str_trim_dup(argc > 1 ? argv[1] : "0");
	rz_core_rtr_enable(core, cmdremote);
	RZ_FREE(cmdremote);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_mode_disable_handler(RzCore *core, int argc, const char **argv) {
	RZ_FREE(core->cmdremote);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_rap_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	args = rz_str_prepend(args, ":");
	rz_core_rtr_cmd(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_rap_bg_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	args = rz_str_prepend(args, "&:");
	rz_core_rtr_cmd(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_remote_tcp_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 2) {
		rz_core_rtr_cmds(core, argv[1]);
		return RZ_CMD_STATUS_OK;
	} else if (argc == 3) {
		char *host, *port = strchr(argv[1], ':');
		if (port) {
			host = rz_str_ndup(argv[1], port - argv[1]);
			port = strdup(port + 1);
		} else {
			host = strdup("localhost");
			port = strdup(argv[1]);
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
	core->cmdremote = strdup(cmdremote);
}
