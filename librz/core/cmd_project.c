/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "rz_config.h"
#include "rz_core.h"
#include "rz_util.h"

static const char *help_msg_P[] = {
	"Usage:", "P[?osi] [file]", "Project management",
	"P", "", "list all projects",
	"Pc", " [file]", "show project script to console",
	"Pd", " [file]", "delete project",
	"Pi", " [file]", "show project information",
	"Pn", "[j]", "show project notes (Pnj for json)",
	"Pn", " [base64]", "set notes text",
	"Pn", " -", "edit notes with cfg.editor",
	"Po", " [file]", "open project",
	"Ps", " [file]", "save project",
	"PS", " [file]", "save script file",
	"P-", " [file]", "delete project (alias for Pd)",
	"NOTE:", "", "See 'e??prj.'",
	"NOTE:", "", "project are stored in " R_JOIN_2_PATHS ("~", R2_HOME_PROJECTS),
	NULL
};

static const char *help_msg_Pn[] = {
	"Usage:", "Pn[j-?] [...]", "Project Notes",
	"Pn", "", "show project notes",
	"Pn", " -", "edit notes with cfg.editor",
	"Pn-", "", "delete notes",
	"Pn-", "str", "delete lines matching /str/ in notes",
	"Pn+", "str", "append one line to the notes",
	"Pnj", "", "show notes in base64",
	"Pnj", " [base64]", "set notes in base64",
	"Pnx", "", "run project note commands",
	NULL
};

static void cmd_project_init(RzCore *core, RzCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, P);
	DEFINE_CMD_DESCRIPTOR (core, Pn);
}

static int cmd_project(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	const char *file, *arg;
	const char *fileproject = rz_config_get (core->config, "prj.name");
	char *str = NULL;

	if (!input) {
		return false;
	}
	str = strdup (fileproject);
	arg = strchr (input, ' ');
	if (arg) {
		arg++;
	} else {
		if (*input) {
			arg = input + 1;
			if (*arg == '&') {
				arg++;
			}
		}
	}
	file = arg;
	switch (input[0]) {
	case 'c':
		if (input[1] == ' ') {
			rz_core_project_cat (core, input + 2);
		} else {
			eprintf ("Usage: Pc [prjname]\n");
		}
		break;
	case 'o':
		//	if (rz_file_is_regular (file))
		if (input[1] == '&') {
			rz_core_cmdf (core, "& Po %s", file);
		} else if (input[1]) {
			rz_core_project_open (core, file, false);
		} else {
			if (file && *file) {
				rz_cons_println (file);
			}
		}
		break;
	case 'd':
	case '-':
		rz_core_project_delete (core, file);
		break;
	case 's':
		if (!file || !file[0]) { /* if no argument specified use current project */
			file = str;
		}
		if (rz_core_project_save (core, file)) {
			rz_cons_println (file);
		}
		break;
	case 'S':
		if (input[1] == ' ') {
			rz_core_project_save_script (core, input + 2, R_CORE_PRJ_ALL);
		} else {
			eprintf ("Usage: PS [file]\n");
		}
		break;
	case 'n': // "Pn"
		if (input[1] == '?') {
			rz_core_cmd_help (core, help_msg_Pn);
		} else if (!fileproject || !*fileproject) {
			eprintf ("No project\n");
		} else {
			switch (input[1]) {
			case '-': // "Pn-"
				/* remove lines containing specific words */
			{
				FILE *fd = rz_sandbox_fopen (str, "w");
				if (!fd) {
					eprintf ("Cannot open %s\n", str);
				} else {
					char *str = rz_core_project_notes_file (core, fileproject);
					char *data = rz_file_slurp (str, NULL);
					int del = 0;
					if (data) {
						char *ptr, *nl;
						for (ptr = data; ptr; ptr = nl) {
							nl = strchr (ptr, '\n');
							if (nl) {
								*nl++ = 0;
								if (strstr (ptr, input + 2)) {
									del++;
								} else {
									fprintf (fd, "%s\n", ptr);
								}
							}
						}
						free (data);
					}
					if (del > 0) {
						eprintf ("Deleted %d lines\n", del);
					}
					free (str);
					fclose (fd);
				}
			}
			break;
			case ' ': // "Pn "
				if (input[2] == '-') {
					char *str = rz_core_project_notes_file (core, fileproject);
					// edit with cfg.editor
					const char *editor = rz_config_get (core->config, "cfg.editor");
					if (str && *str && editor && *editor) {
						rz_sys_cmdf ("%s %s", editor, str);
					} else {
						eprintf ("No cfg.editor configured\n");
					}
					free (str);
				} else {
					// char *str = rz_core_project_notes_file (core, fileproject);
					// append line to project notes
					char *str = rz_core_project_notes_file (core, fileproject);
					char *data = rz_file_slurp (str, NULL);
					FILE *fd = rz_sandbox_fopen (str, "a");
					if (fd) {
						fprintf (fd, "%s\n", input + 2);
						fclose (fd);
					}
					free (str);
					free (data);
				}
				break;
			case '+': // "Pn+"
				{
					char *str = rz_core_project_notes_file (core, fileproject);
					char *data = rz_file_slurp (str, NULL);
					data = rz_str_append (data, input + 2);
					data = rz_str_append (data, "\n");
					rz_file_dump (str, (const ut8*)data, strlen (data), false);
					free (data);
					free (str);
				}
				break;
			case 'j': // "Pnj"
				if (!input[2]) {
					size_t len = 0;
					/* get base64 string */
					char *str = rz_core_project_notes_file (core, fileproject);
					if (str) {
						char *data = rz_file_slurp (str, &len);
						char *res = rz_base64_encode_dyn (data, (int)len);
						if (res) {
							rz_cons_println (res);
							free (res);
						}
						free (data);
						free (str);
					}
				} else if (input[2] == ' ') {
					/* set base64 string */
					ut8 *data = rz_base64_decode_dyn (input + 3, -1);
					if (data) {
						char *str = rz_core_project_notes_file (core, fileproject);
						if (str) {
							rz_file_dump (str, data, strlen ((const char *) data), 0);
							free (str);
						}
						free (data);
					}
				} else {
					eprintf ("Usage: `Pnj` or `Pnj ...`\n");
				}
				break;
			case 'x': // "Pnx"
				rz_core_project_execute_cmds (core, fileproject);
				break;
			case 0: // "Pn"
			{
				char *str = rz_core_project_notes_file (core, fileproject);
				char *data = rz_file_slurp (str, NULL);
				if (data) {
					rz_cons_println (data);
					free (data);
				}
				free (str);
			}
			break;
			}
		}
		break;
	case 'i':
		if (file && *file) {
			char *prjName = rz_core_project_info (core, file);
			rz_cons_println (prjName);
			free (prjName);
		}
		break;
	case 0:
	case 'j':
		rz_core_project_list (core, input[0]);
		break;
	default:
		rz_core_cmd_help (core, help_msg_P);
		break;
	}
	free (str);
	return true;
}
