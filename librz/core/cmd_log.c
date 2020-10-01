/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <string.h>
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"

// TODO #7967 help refactor: move to another place
static const char *help_msg_L[] = {
	"Usage:", "L[acio]", "[-name][ file]",
	"L",  "", "show this help",
	"L", " blah."R_LIB_EXT, "load plugin file",
	"L-", "duk", "unload core plugin by name",
	"Ll", "", "list lang plugins (same as #!)",
	"LL", "", "lock screen",
	"La", "", "list asm/anal plugins (aL, e asm.arch=" "??" ")",
	"Lc", "", "list core plugins",
	"Ld", "", "list debug plugins (same as dL)",
	"LD", "", "list supported decompilers (e cmd.pdc=?)",
	"Lm", "", "list fs plugins (same as mL)",
	"Lh", "", "list hash plugins (same as ph)",
	"Li", "", "list bin plugins (same as iL)",
	"Lo", "", "list io plugins (same as oL)",
	NULL
};

static const char *help_msg_T[] = {
	"Usage:", "T", "[-][ num|msg]",
	"T", "", "list all Text log messages",
	"T", " message", "add new log message",
	"T", " 123", "list log from 123",
	"T", " 10 3", "list 3 log messages starting from 10",
	"T*", "", "list in radare commands",
	"T-", "", "delete all logs",
	"T-", " 123", "delete logs before 123",
	"Tl", "", "get last log message id",
	"Tj", "", "list in json format",
	"Tm", " [idx]", "display log messages without index",
	"Ts", "", "list files in current directory (see pwd, cd)",
	"TT", "", "enter into the text log chat console",
	"T=", "[.]", "Pull logs from remote r2 instance specified by http.sync",
	"T=&", "", "Start background thread syncing with the remote server",
	NULL
};

// TODO #7967 help refactor: move L to another place
static void cmd_log_init(RzCore *core, RzCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, L);
	DEFINE_CMD_DESCRIPTOR (core, T);
}

static void screenlock(RzCore *core) {
	//  char *pass = rz_cons_input ("Enter new password: ");
	char *pass = rz_cons_password (Color_INVERT "Enter new password:"Color_INVERT_RESET);
	if (!pass || !*pass) {
		return;
	}
	char *again = rz_cons_password (Color_INVERT "Type it again:"Color_INVERT_RESET);
	if (!again || !*again) {
		free (pass);
		return;
	}
	if (strcmp (pass, again)) {
		eprintf ("Password mismatch!\n");
		free (pass);
		free (again);
		return;
	}
	bool running = true;
	rz_cons_clear_buffer ();
	ut64 begin = rz_time_now ();
	ut64 last = UT64_MAX;
	ut64 tries = 0;
	do {
		rz_cons_clear00 ();
		rz_cons_printf ("Retries: %d\n", tries);
		rz_cons_printf ("Locked ts: %s\n", rz_time_to_string (begin));
		if (last != UT64_MAX) {
			rz_cons_printf ("Last try: %s\n", rz_time_to_string (last));
		}
		rz_cons_newline ();
		rz_cons_flush ();
		char *msg = rz_cons_password ("rizin password: ");
		if (msg && !strcmp (msg, pass)) {
			running = false;
		} else {
			eprintf ("\nInvalid password.\n");
			last = rz_time_now ();
			tries++;
		}
		free (msg);
		int n = rz_num_rand (10) + 1;
		rz_sys_usleep (n * 100000);
	} while (running);
	rz_cons_set_cup (true);
	free (pass);
	eprintf ("Unlocked!\n");
}

static int textlog_chat(RzCore *core) {
	char prompt[64];
	char buf[1024];
	int lastmsg = 0;
	const char *me = rz_config_get (core->config, "cfg.user");
	char msg[2048];

	eprintf ("Type '/help' for commands:\n");
	snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
	rz_line_set_prompt (prompt);
	for (;;) {
		rz_core_log_list (core, lastmsg, 0, 0);
		lastmsg = core->log->last;
		if (rz_cons_fgets (buf, sizeof (buf), 0, NULL) < 0) {
			return 1;
		}
		if (!*buf) {
			continue;
		}
		if (!strcmp (buf, "/help")) {
			eprintf ("/quit           quit the chat (same as ^D)\n");
			eprintf ("/name <nick>    set cfg.user name\n");
			eprintf ("/log            show full log\n");
			eprintf ("/clear          clear text log messages\n");
		} else if (!strncmp (buf, "/name ", 6)) {
			snprintf (msg, sizeof (msg) - 1, "* '%s' is now known as '%s'", me, buf + 6);
			rz_core_log_add (core, msg);
			rz_config_set (core->config, "cfg.user", buf + 6);
			me = rz_config_get (core->config, "cfg.user");
			snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
			rz_line_set_prompt (prompt);
			return 0;
		} else if (!strcmp (buf, "/log")) {
			rz_core_log_list (core, 0, 0, 0);
			return 0;
		} else if (!strcmp (buf, "/clear")) {
			// rz_core_log_del (core, 0);
			rz_core_cmd0 (core, "T-");
			return 0;
		} else if (!strcmp (buf, "/quit")) {
			return 0;
		} else if (*buf == '/') {
			eprintf ("Unknown command: %s\n", buf);
		} else {
			snprintf (msg, sizeof (msg), "[%s] %s", me, buf);
			rz_core_log_add (core, msg);
		}
	}
	return 1;
}

static int getIndexFromLogString(const char *s) {
	int len = strlen (s);
	const char *m = s + len;
	int nlctr = 2;
	const char *nl = NULL;
	while (m > s) {
		if (*m == '\n') {
			nl = m;
			if (--nlctr < 1) {
				return atoi (m + 1);
			}
		}
		m--;
	}
		return atoi (nl?nl + 1: s);
	return -1;
}

static char *expr2cmd (RzCoreLog *log, const char *line) {
	if (!line || !*line) {
		return NULL;
	}
	line++;
	if (!strncmp (line, "add-comment", 11)) {
		line += 11;
		if (*line == ' ') {
			char *sp = strchr (line + 1, ' ');
			if (sp) {
				char *msg = sp + 1;
				ut64 addr = rz_num_get (NULL, line);
				return rz_str_newf ("CCu base64:%s @ 0x%"PFMT64x"\n", msg, addr);
			}
		}
		eprintf ("add-comment parsing error\n");
	}
	if (!strncmp (line, "del-comment", 11)) {
		if (line[11] == ' ') {
			return rz_str_newf ("CC-%s\n", line + 12);
		}
		eprintf ("add-comment parsing error\n");
	}
	return NULL;
}

static int log_callback_rz (RzCore *core, int count, const char *line) {
	if (*line == ':') {
		char *cmd = expr2cmd (core->log, line);
		if (cmd) {
			rz_cons_printf ("%s\n", cmd);
			rz_core_cmd (core, cmd, 0);
			free (cmd);
		}
	}
	return 0;
}

static int log_callback_all (RzCore *log, int count, const char *line) {
	rz_cons_printf ("%d %s\n", count, line);
	return 0;
}

static int cmd_log(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	const char *arg, *input2;
	int n, n2;

	if (!input) {
		return 1;
	}

	input2 = (input && *input)? input + 1: "";
	arg = strchr (input2, ' ');
	n = atoi (input2);
	n2 = arg? atoi (arg + 1): 0;

	switch (*input) {
	case 'e': // "Te" shell: less
		{
			char *p = strchr (input, ' ');
			if (p) {
				char *b = rz_file_slurp (p + 1, NULL);
				if (b) {
					rz_cons_less_str (b, NULL);
					free (b);
				} else {
					eprintf ("File not found\n");
				}
			} else {
				eprintf ("Usage: less [filename]\n");
			}
		}
		break;
	case 'l': // "Tl"
		rz_cons_printf ("%d\n", core->log->last - 1);
		break;
	case '-': //  "T-"
		rz_core_log_del (core, n);
		break;
	case '?': // "T?"
		rz_core_cmd_help (core, help_msg_T);
		break;
	case 'T': // "TT" Ts ? as ms?
		if (rz_cons_is_interactive ()) {
			textlog_chat (core);
		} else {
			eprintf ("Only available when the screen is interactive\n");
		}
		break;
	case '=': // "T="
		if (input[1] == '&') { //  "T=&"
			if (input[2] == '&') { // "T=&&"
				rz_cons_break_push (NULL, NULL);
				while (!rz_cons_is_breaked ()) {
					rz_core_cmd0 (core, "T=");
					void *bed = rz_cons_sleep_begin();
					rz_sys_sleep (1);
					rz_cons_sleep_end (bed);
				}
				rz_cons_break_pop ();
			} else {
				// TODO: Sucks that we can't enqueue functions, only commands
				eprintf ("Background thread syncing with http.sync started.\n");
				RzCoreTask *task = rz_core_task_new (core, true, "T=&&", NULL, core);
				rz_core_task_enqueue (&core->tasks, task);
			}
		} else {
			if (atoi (input + 1) > 0 || (input[1] == '0')) {
				core->sync_index = 0;
			} else {
				RzCoreLogCallback log_callback = (input[1] == '*')
					? log_callback_all: log_callback_rz;
				char *res = rz_core_log_get (core, core->sync_index);
				if (res) {
					int idx = getIndexFromLogString (res);
					if (idx != -1) {
						core->sync_index = idx + 1;
					}
					rz_core_log_run (core, res, log_callback);
					free (res);
				} else {
					rz_cons_printf ("Please check e http.sync\n");
				}
			}
		}
		break;
	case ' ': // "T "
		if (n > 0 || *input == '0') {
			rz_core_log_list (core, n, n2, *input);
		} else {
			rz_core_log_add (core, input + 1);
		}
		break;
	case 'm': // "Tm"
		if (n > 0) {
			rz_core_log_list (core, n, 1, 't');
		} else {
			rz_core_log_list (core, n, 0, 't');
		}
		break;
	case 'j': // "Tj"
	case '*':
	case '\0':
		rz_core_log_list (core, n, n2, *input);
		break;
	}
	return 0;
}

static int cmd_plugins(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	switch (input[0]) {
	case 0:
		rz_core_cmd_help (core, help_msg_L);
		// return rz_core_cmd0 (core, "Lc");
		break;
	case '-':
		rz_lib_close (core->lib, rz_str_trim_head_ro (input + 1));
		break;
	case ' ':
		rz_lib_open (core->lib, rz_str_trim_head_ro (input + 1));
		break;
	case '?':
		rz_core_cmd_help (core, help_msg_L);
		break;
	case 'm': // "Lm"
		rz_core_cmdf (core, "mL%s", input + 1);
		break;
	case 'd': // "Ld"
		rz_core_cmdf (core, "dL%s", input + 1);
		break;
	case 'h': // "Lh"
		rz_core_cmd0 (core, "ph"); // rz_hash -L is more verbose
		break;
	case 'a': // "La"
		rz_core_cmd0 (core, "e asm.arch=??");
		break;
	case 'D': // "LD"
		if (input[1] == ' ') {
			rz_core_cmdf (core, "e cmd.pdc=%s", rz_str_trim_head_ro (input + 2));
		} else {
			rz_core_cmd0 (core, "e cmd.pdc=?");
		}
		break;
	case 'l': // "Ll"
		rz_core_cmd0 (core, "#!");
		break;
	case 'L': // "LL"
		screenlock (core);
		break;
	case 'o': // "Lo"
	case 'i': // "Li"
		rz_core_cmdf (core, "%cL", input[0]);
		break;
	case 'c': { // "Lc"
		RzListIter *iter;
		RzCorePlugin *cp;
		switch (input[1]) {
		case 'j': {
			rz_cons_printf ("[");
			bool is_first_element = true;
			rz_list_foreach (core->rcmd->plist, iter, cp) {
				rz_cons_printf ("%s{\"Name\":\"%s\",\"Description\":\"%s\"}",
					is_first_element? "" : ",", cp->name, cp->desc);
				is_first_element = false;
			}
			rz_cons_printf ("]\n");
			break;
			}
		case 0:
			rz_lib_list (core->lib);
			rz_list_foreach (core->rcmd->plist, iter, cp) {
				rz_cons_printf ("%s: %s\n", cp->name, cp->desc);
			}
			break;
		default:
			eprintf ("oops\n");
			break;
		}
		}
		break;
	}
	return 0;
}
