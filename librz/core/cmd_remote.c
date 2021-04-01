// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cmd.h"
#include "rz_core.h"

static const char *help_msg_equal[] = {
	"Usage:", " =[:!+-=ghH] [...]", " # connect with other instances of rizin",
	"\nremote commands:", "", "",
	"=", "", "list all open connections",
	"=<", "[fd] cmd", "send output of local command to remote fd", // XXX may not be a special char
	"=", "[fd] cmd", "exec cmd at remote 'fd' (last open is default one)",
	"=!", " cmd", "run command via rz_io_system",
	"=+", " [proto://]host:port", "connect to remote host:port (*rap://, raps://, tcp://, udp://, http://)",
	"=-", "[fd]", "remove all hosts or host 'fd'",
	"==", "[fd]", "open remote session with host 'fd', 'q' to quit",
	"=!=", "", "disable remote cmd mode",
	"!=!", "", "enable remote cmd mode",
	"\nservers:", "", "",
	".:", "9000", "start the tcp server (echo x|nc ::1 9090 or curl ::1:9090/cmd/x)",
	"=:", "port", "start the rap server (o rap://9999)",
	"=g", "[?]", "start the gdbserver",
	"=h", "[?]", "start the http webserver",
	"=H", "[?]", "start the http webserver (and launch the web browser)",
	"\nother:", "", "",
	"=&", ":port", "start rap server in background (same as '&_=h')",
	"=", ":host:port cmd", "run 'cmd' command on remote server",
	"\nexamples:", "", "",
	"=+", "tcp://localhost:9090/", "connect to: rizin -c.:9090 ./bin",
	// "=+", "udp://localhost:9090/", "connect to: rizin -c.:9090 ./bin",
	"=+", "rap://localhost:9090/", "connect to: rizin rap://:9090",
	"=+", "http://localhost:9090/cmd/", "connect to: rizin -c'=h 9090' bin",
	"o ", "rap://:9090/", "start the rap server on tcp port 9090",
	NULL
};

static const char *help_msg_equalh[] = {
	"Usage:", " =[hH] [...]", " # http server",
	"http server:", "", "",
	"=h", " port", "listen for http connections (rizin -qc=H /bin/ls)",
	"=h-", "", "stop background webserver",
	"=h--", "", "stop foreground webserver",
	"=h*", "", "restart current webserver",
	"=h&", " port", "start http server in background",
	"=H", " port", "launch browser and listen for http",
	"=H&", " port", "launch browser and listen for http in background",
	NULL
};

static const char *help_msg_equalg[] = {
	"Usage:", " =[g] [...]", " # gdb server",
	"gdbserver:", "", "",
	"=g", " port file [args]", "listen on 'port' debugging 'file' using gdbserver",
	"=g!", " port file [args]", "same as above, but debug protocol messages (like gdbserver --remote-debug)",
	NULL
};

static int getArg(char ch, int def) {
	switch (ch) {
	case '&':
	case '-':
		return ch;
	}
	return def;
}

RZ_IPI int rz_equal_g_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[0] == '?') {
		rz_core_cmd_help(core, help_msg_equalg);
	} else {
		rz_core_rtr_gdb(core, getArg(input[0], 'g'), input);
	}
	return 0;
}

RZ_IPI int rz_equal_h_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[0] == '?') {
		rz_core_cmd_help(core, help_msg_equalh);
	} else {
		rz_core_rtr_http(core, getArg(input[0], 'h'), 'h', input);
	}
	return 0;
}

RZ_IPI int rz_equal_H_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[0] == '?') {
		rz_core_cmd_help(core, help_msg_equalh);
	} else {
		const char *arg = rz_str_trim_head_ro(input);
		rz_core_rtr_http(core, getArg(input[0], 'H'), 'H', arg);
	}
	return 0;
}

RZ_IPI int rz_cmd_remote(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (*input) {
	case '\0': // "="
		rz_core_rtr_list(core);
		break;
	case 'j': // "=j"
		eprintf("TODO: list connections in json\n");
		break;
	case '!': // "=!"
		if (input[1] == 'q') {
			RZ_FREE(core->cmdremote);
		} else if (input[1] == '=') { // =!=0 or =!= for iosystem
			RZ_FREE(core->cmdremote);
			core->cmdremote = rz_str_trim_dup(input + 2);
		} else {
			char *res = rz_io_system(core->io, input + 1);
			if (res) {
				rz_cons_printf("%s\n", res);
				free(res);
			}
		}
		break;
	case '+': // "=+"
		rz_core_rtr_add(core, input + 1);
		break;
	case '-': // "=-"
		rz_core_rtr_remove(core, input + 1);
		break;
	//case ':': rz_core_rtr_cmds (core, input + 1); break;
	case '<': // "=<"
		rz_core_rtr_pushout(core, input + 1);
		break;
	case '=': // "=="
		rz_core_rtr_session(core, input + 1);
		break;
	case 'g': // "=g"
		rz_equal_g_handler_old(core, input + 1);
		break;
	case 'h': // "=h"
		rz_equal_h_handler_old(core, input + 1);
		break;
	case 'H': // "=H"
		rz_equal_H_handler_old(core, input + 1);
		break;
	case '?': // "=?"
		rz_core_cmd_help(core, help_msg_equal);
		break;
	default:
		rz_core_rtr_cmd(core, input);
		break;
	}
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
	RzCore *core = (RzCore *)data;
	char *res = rz_io_system(core->io, input);
	if (res) {
		rz_cons_printf("%s\n", res);
		free(res);
	}
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
	RZ_FREE(core->cmdremote);
	core->cmdremote = rz_str_trim_dup(argc > 1 ? argv[1] : "0");
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
