/* rizin - LGPL - Copyright 2009-2020 - pancake */

#include <stddef.h>
#include <stdbool.h>
#include "rz_core.h"

static const char *help_msg_e[] = {
	"Usage:", "e [var[=value]]", "Evaluable vars",
	"e","?asm.bytes", "show description",
	"e", "??", "list config vars with description",
	"e", " a", "get value of var 'a'",
	"e", " a=b", "set var 'a' the 'b' value",
	"e var=?", "", "print all valid values of var",
	"e var=??", "", "print all valid values of var with description",
	"e.", "a=b", "same as 'e a=b' but without using a space",
	"e,", "k=v,k=v,k=v", "comma separated k[=v]",
	"e-", "", "reset config vars",
	"e*", "", "dump config vars in r commands",
	"e!", "a", "invert the boolean value of 'a' var",
	"ec", " [k] [color]", "set color for given key (prompt, offset, ...)",
	"ee", "var", "open editor to change the value of var",
	"ed", "", "open editor to change the ~/.rizinrc",
	"ej", "", "list config vars in JSON",
	"env", " [k[=v]]", "get/set environment variable",
	"er", " [key]", "set config key as readonly. no way back",
	"es", " [space]", "list all eval spaces [or keys]",
	"et", " [key]", "show type of given config variable",
	"ev", " [key]", "list config vars in verbose format",
	"evj", " [key]", "list config vars in verbose format in JSON",
	NULL
};

static const char *help_msg_ec[] = {
	"Usage ec[s?] [key][[=| ]fg] [bg]", "", "",
	"ec", " [key]", "list all/key color keys",
	"ec*", "", "same as above, but using r2 commands",
	"ecd", "", "set default palette",
	"ecr", "", "set random palette (see also scr.randpal)",
	"ecs", "", "show a colorful palette",
	"ecj", "", "show palette in JSON",
	"ecc", " [prefix]", "show palette in CSS",
	"eco", " [theme]", "load theme if provided (list available themes if not)",
	"ecp", "", "load previous color theme",
	"ecn", "", "load next color theme",
	"ecH", " [?]", "highlight word or instruction",
	"ec", " prompt red", "change color of prompt",
	"ec", " prompt red blue", "change color and background of prompt",
	"Vars:", "", "",
	"colors:", "", "rgb:000, red, green, blue, #ff0000, ...",
	"e scr.color", "=0", "use more colors (0: no color 1: ansi 16, 2: 256, 3: 16M)",
	"$DATADIR/rizin/cons", "", RZ_JOIN_2_PATHS ("~", RZ_HOME_THEMES) " ./",
	NULL
};

static const char *help_msg_eco[] = {
	"Usage: eco[jc] [theme]", "", "load theme (cf. Path and dir.prefix)",
	"eco", "", "list available themes",
	"eco.", "", "display current theme name",
	"ecoo", "", "reload current theme",
	"ecoq", "", "list available themes without showing the current one",
	"ecoj", "", "list available themes in JSON",
	"Path:", "", "",
	"$DATADIR/rizin/cons", "", RZ_JOIN_2_PATHS ("~", RZ_HOME_THEMES) " ./",
	NULL
};

static char *curtheme = "default";
static bool getNext = false;

static RzCmdStatus env_handler(RzCore *core, int argc, const char **argv) {
	char *p, **e;
	switch (argc) {
	case 1:
		e = rz_sys_get_environ ();
		while (!RZ_STR_ISEMPTY (e)) {
			rz_cons_println (*e);
			e++;
		}
		return RZ_CMD_STATUS_OK;
	case 2:
		p = rz_sys_getenv (argv[1]);
		if (!p) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_println (p);
		free (p);
		return RZ_CMD_STATUS_OK;
	case 3:
		rz_sys_setenv (argv[1], argv[2]);
		return RZ_CMD_STATUS_OK;
	default:
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
}

static void cmd_eval_init(RzCore *core, RzCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, e);
	DEFINE_CMD_DESCRIPTOR (core, ec);

	DEFINE_CMD_ARGV_DESC (core, env, parent);
}

static bool load_theme(RzCore *core, const char *path) {
	if (!rz_file_exists (path)) {
		return false;
	}
	core->cmdfilter = "ec ";
	bool res = rz_core_cmd_file (core, path);
	if (res) {
		rz_cons_pal_update_event ();
	}
	core->cmdfilter = NULL;
	return res;
}

static bool nextpal_item(RzCore *core, int mode, const char *file, int ctr) {
	const char *fn = rz_str_lchr (file, '/');
	if (!fn) fn = file;
	switch (mode) {
	case 'j': // json
		rz_cons_printf ("%s\"%s\"", ctr?",":"", fn);
		break;
	case 'l': // list
		rz_cons_println (fn);
		break;
	case 'p': // previous
		// TODO: move logic here
		break;
	case 'n': // next
		if (getNext) {
			curtheme = rz_str_dup (curtheme, fn);
			getNext = false;
			return false;
		} else if (curtheme) {
			if (!strcmp (curtheme, fn)) {
				getNext = true;
			}
		} else {
			curtheme = rz_str_dup (curtheme, fn);
			return false;
		}
		break;
	}
	return true;
}

static bool cmd_load_theme(RzCore *core, const char *_arg) {
	bool failed = false;
	char *path;
	if (!_arg || !*_arg) {
		return false;
	}
	if (!rz_str_cmp (_arg, "default", strlen (_arg))) {
		curtheme = strdup (_arg);
		rz_cons_pal_init (core->cons->context);
		return true;
	}
	char *arg = strdup (_arg);

	char *tmp = rz_str_newf (RZ_JOIN_2_PATHS (RZ_HOME_THEMES, "%s"), arg);
	char *home = tmp ? rz_str_home (tmp) : NULL;
	free (tmp);

	tmp = rz_str_newf (RZ_JOIN_2_PATHS (RZ_THEMES, "%s"), arg);
	path = tmp ? rz_str_rz_prefix (tmp) : NULL;
	free (tmp);

	if (!load_theme (core, home)) {
		if (load_theme (core, path)) {
			curtheme = rz_str_dup (curtheme, arg);
		} else {
			if (load_theme (core, arg)) {
				curtheme = rz_str_dup (curtheme, arg);
			} else {
				char *absfile = rz_file_abspath (arg);
				eprintf ("eco: cannot open colorscheme profile (%s)\n", absfile);
				free (absfile);
				failed = true;
			}
		}
	}
	free (home);
	free (path);
	free (arg);
	return !failed;
}

static void list_themes_in_path(RzList *list, const char *path) {
	RzListIter *iter;
	const char *fn;
	RzList *files = rz_sys_dir (path);
	rz_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			rz_list_append (list, strdup (fn));
		}
	}
	rz_list_free (files);
}

RZ_API char *rz_core_get_theme (void) {
	return curtheme;
}

RZ_API RzList *rz_core_list_themes(RzCore *core) {
	RzList *list = rz_list_newf (free);
	getNext = false;
	char *tmp = strdup ("default");
	rz_list_append (list, tmp);
	char *path = rz_str_home (RZ_HOME_THEMES RZ_SYS_DIR);
	if (path) {
		list_themes_in_path (list, path);
		RZ_FREE (path);
	}

	path = rz_str_rz_prefix (RZ_THEMES RZ_SYS_DIR);
	if (path) {
		list_themes_in_path (list, path);
		RZ_FREE (path);
	}

	return list;
}

static void nextpal(RzCore *core, int mode) {
// TODO: use rz_core_list_themes() here instead of rewalking all the time
	RzList *files = NULL;
	RzListIter *iter;
	const char *fn;
	char *path = NULL;
	int ctr = 0;
	char *home = rz_str_home (RZ_HOME_THEMES RZ_SYS_DIR);

	getNext = false;
	if (mode == 'j') {
		rz_cons_printf ("[");
	}
	if (home) {
		files = rz_sys_dir (home);
		rz_list_foreach (files, iter, fn) {
			if (*fn && *fn != '.') {
				if (mode == 'p') {
					const char *nfn = iter->n? iter->n->data: NULL;
					if (!curtheme) {
						free (home);
						rz_list_free (files);
						return;
					}
					eprintf ("%s %s %s\n", nfn, curtheme, fn);
					if (nfn && !strcmp (nfn, curtheme)) {
						rz_list_free (files);
						files = NULL;
						free (curtheme);
						curtheme = strdup (fn);
						RZ_FREE (home);
						goto done;
					}
				} else {
					if (!nextpal_item (core, mode, fn, ctr++)) {
						rz_list_free (files);
						files = NULL;
						RZ_FREE (home);
						goto done;
					}
				}
			}
		}
		rz_list_free (files);
		RZ_FREE (home);
	}

	path = rz_str_rz_prefix (RZ_THEMES RZ_SYS_DIR);
	if (path) {
		files = rz_sys_dir (path);
		rz_list_foreach (files, iter, fn) {
			if (*fn && *fn != '.') {
				if (mode == 'p') {
					const char *nfn = iter->n? iter->n->data: NULL;
					if (!curtheme) {
						free (home);
						rz_list_free (files);
						return;
					}
					eprintf ("%s %s %s\n", nfn, curtheme, fn);
					if (nfn && !strcmp (nfn, curtheme)) {
						free (curtheme);
						curtheme = strdup (fn);
						goto done;
					}
				} else {
					if (!nextpal_item (core, mode, fn, ctr++)) {
						goto done;
					}
				}
			}
		}
	}

done:
	free (path);
	if (getNext) {
		RZ_FREE (curtheme);
		nextpal (core, mode);
		return;
	}
	if (mode == 'l' && !curtheme && !rz_list_empty (files)) {
		//nextpal (core, mode);
	} else if (mode == 'n' || mode == 'p') {
		if (curtheme) {
			rz_core_cmdf (core, "eco %s", curtheme);
		}
	}
	rz_list_free (files);
	files = NULL;
	if (mode == 'j') {
		rz_cons_printf ("]\n");
	}
}

RZ_API void rz_core_echo(RzCore *core, const char *input) {
	if (!strncmp (input, "64 ", 3)) {
		char *buf = strdup (input);
		rz_base64_decode ((ut8*)buf, input + 3, -1);
		if (*buf) {
			rz_cons_echo (buf);
		}
		free (buf);
	} else {
		char *p = strchr (input, ' ');
		if (p) {
			rz_cons_strcat (p + 1);
			rz_cons_newline ();
		}
	}
}

static int cmd_eval(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case '\0': // "e"
		rz_config_list (core->config, NULL, 0);
		break;
	case '?': // "e?"
	default:
		switch (input[1]) {
		case '\0': rz_core_cmd_help (core, help_msg_e); break;
		case '?': rz_config_list (core->config, input + 2, 2); break;
		default: rz_config_list (core->config, input + 1, 2); break;
		}
		break;
	case 't': // "et"
		if (input[1] == 'a') {
			rz_cons_printf ("%s\n", (rz_num_rand (10) % 2)? "wen": "son");
		} else if (input[1]==' ' && input[2]) {
			RzConfigNode *node = rz_config_node_get (core->config, input+2);
			if (node) {
				const char *type = rz_config_node_type (node);
				if (type && *type) {
					rz_cons_println (type);
				}
			}
		} else {
			eprintf ("Usage: et [varname]  ; show type of eval var\n");
		}
		break;
	case 'n': // "en"
		if (!strchr (input, '=')) {
			char *var, *p;
			var = strchr (input, ' ');
			if (var) while (*var==' ') var++;
			p = rz_sys_getenv (var);
			if (p) {
				rz_cons_println (p);
				free (p);
			} else {
				char **e = rz_sys_get_environ ();
				while (e && *e) {
					rz_cons_println (*e);
					e++;
				}
			}
		} else if (strlen (input)>3) {
			char *v, *k = strdup (input+3);
			if (!k) break;
			v = strchr (k, '=');
			if (v) {
				*v++ = 0;
				rz_str_trim (k);
				rz_str_trim (v);
				rz_sys_setenv (k, v);
			}
			free (k);
		}
		return true;
	case 'x': // exit
		// XXX we need headers for the cmd_xxx files.
		return cmd_quit (data, "");
	case 'j': // json
		rz_config_list (core->config, NULL, 'j');
		break;
	case 'v': // verbose
		rz_config_list (core->config, input + 1, 'v');
		break;
	case 'q': // quiet list of eval keys
		rz_config_list (core->config, NULL, 'q');
		break;
	case 'c': // "ec"
		switch (input[1]) {
		case 'd': // "ecd"
			rz_cons_pal_init (core->cons->context);
			break;
		case '?':
			rz_core_cmd_help (core, help_msg_ec);
			break;
		case 'o': // "eco"
			if (input[2] == 'j') {
				nextpal (core, 'j');
			} else if (input[2] == ' ') {
				cmd_load_theme (core, input + 3);
			} else if (input[2] == 'o') {
				cmd_load_theme (core, rz_core_get_theme ());
			} else if (input[2] == 'c' || input[2] == '.') {
				rz_cons_printf ("%s\n", rz_core_get_theme ());
			} else if (input[2] == '?') {
				rz_core_cmd_help (core, help_msg_eco);
			} else if (input[2] == 'q') {
				RzList *themes_list = rz_core_list_themes (core);
				RzListIter *th_iter;
				const char *th;
				rz_list_foreach (themes_list, th_iter, th) {
					rz_cons_printf ("%s\n", th);
				}
			} else {
				RzList *themes_list = rz_core_list_themes (core);
				RzListIter *th_iter;
				const char *th;
				rz_list_foreach (themes_list, th_iter, th) {
					if (curtheme && !strcmp (curtheme, th)) {
						rz_cons_printf ("> %s\n", th);
					} else {
						rz_cons_printf ("  %s\n", th);
					}
				}
			}
			break;
		case 's': rz_cons_pal_show (); break; // "ecs"
		case '*': rz_cons_pal_list (1, NULL); break; // "ec*"
		case 'h': // echo
			if (input[2] == 'o') {
				rz_core_echo (core, input + 3);
			} else {
				rz_cons_pal_list ('h', NULL);
			}
			break;
		case 'j': // "ecj"
			rz_cons_pal_list ('j', NULL);
			break;
		case 'c': // "ecc"
			rz_cons_pal_list ('c', input + 2);
			break;
		case '\0': // "ec"
			rz_cons_pal_list (0, NULL);
			break;
		case 'r': // "ecr"
			rz_cons_pal_random ();
			break;
		case 'n': // "ecn"
			nextpal (core, 'n');
			break;
		case 'p': // "ecp"
			nextpal (core, 'p');
			break;
		case 'H': { // "ecH"
			char *color_code = NULL;
			char *word = NULL;
			int argc = 0;
			int delta = (input[2])? 3: 2;
			char** argv = rz_str_argv (rz_str_trim_head_ro (input + delta), &argc);
			switch (input[2]) {
			case '?': {
				const char *helpmsg[] = {
					"Usage ecH[iw-?]","","",
					"ecHi","[color]","highlight current instruction with 'color' background",
					"ecHw","[word] [color]","highlight 'word ' in current instruction with 'color' background",
					"ecH","","list all the highlight rules",
					"ecH.","","show highlight rule in current offset",
					"ecH-","*","remove all the highlight hints",
					"ecH-","","remove all highlights on current instruction",
					NULL
				};
				rz_core_cmd_help (core, helpmsg);
				}
				rz_str_argv_free (argv);
				return false;
			case '-': // ecH-
				if (input[3] == '*') {
					rz_meta_del (core->anal, RZ_META_TYPE_HIGHLIGHT, 0, UT64_MAX);
				} else {
					rz_meta_del (core->anal, RZ_META_TYPE_HIGHLIGHT, core->offset, 1);
					// rz_meta_set_string (core->anal, RZ_META_TYPE_HIGHLIGHT, core->offset, "");
				}
				rz_str_argv_free (argv);
				return false;
			case '.':
				rz_meta_print_list_in_function (core->anal, RZ_META_TYPE_HIGHLIGHT, 0, core->offset);
				rz_str_argv_free (argv);
				return false;
			case '\0':
				rz_meta_print_list_all (core->anal, RZ_META_TYPE_HIGHLIGHT, 0);
				rz_str_argv_free (argv);
				return false;
			case 'j':
				rz_meta_print_list_all (core->anal, RZ_META_TYPE_HIGHLIGHT, 'j');
				rz_str_argv_free (argv);
				return false;
			case '*':
				rz_meta_print_list_all (core->anal, RZ_META_TYPE_HIGHLIGHT, '*');
				rz_str_argv_free (argv);
				return false;
			case ' ':
			case 'i': // "ecHi"
				if (argc) {
					char *dup = rz_str_newf ("bgonly %s", argv[0]);
					color_code = rz_cons_pal_parse (dup, NULL);
					RZ_FREE (dup);
					if (!color_code) {
						eprintf ("Unknown color %s\n", argv[0]);
						rz_str_argv_free (argv);
						return true;
					}
				}
				break;
			case 'w': // "ecHw"
				if (!argc) {
					eprintf ("Usage: ecHw word [color]\n");
					rz_str_argv_free (argv);
					return true;
				}
				word = strdup (argv[0]);
				if (argc > 1) {
					char *dup = rz_str_newf ("bgonly %s", argv[1]);
					color_code = rz_cons_pal_parse (dup, NULL);
					RZ_FREE (dup);
					if (!color_code) {
						eprintf ("Unknown color %s\n", argv[1]);
						rz_str_argv_free (argv);
						free (word);
						return true;
					}
				}
				break;
			default:
				eprintf ("See ecH?\n");
				rz_str_argv_free (argv);
				return true;
			}
			rz_meta_set_string (core->anal, RZ_META_TYPE_HIGHLIGHT, core->offset, "");
			const char *str = rz_meta_get_string (core->anal, RZ_META_TYPE_HIGHLIGHT, core->offset);
			char *dup = rz_str_newf ("%s \"%s%s\"", str?str:"", word?word:"", color_code?color_code:rz_cons_singleton ()->context->pal.wordhl);
			rz_meta_set_string (core->anal, RZ_META_TYPE_HIGHLIGHT, core->offset, dup);
			rz_str_argv_free (argv);
			RZ_FREE (word);
			RZ_FREE (dup);
			break;
			  }
		default: {
				 char *p = strdup (input + 2);
				 char *q = strchr (p, '=');
				 if (!q) {
					 q = strchr (p, ' ');
				 }
				 if (q) {
					 // Set color
					 *q++ = 0;
					 if (rz_cons_pal_set (p, q)) {
						 rz_cons_pal_update_event ();
					 }
				 } else {
					 char color[32];
					 RColor rcolor = rz_cons_pal_get (p);
					 rz_cons_rgb_str (color, sizeof (color), &rcolor);
					 eprintf ("(%s)(%sCOLOR"Color_RESET")\n", p, color);
				 }
				 free (p);
			 }
		}
		break;
	case 'd': // "ed"
		if (input[1] == '?') {
			eprintf ("Usage: ed[-][?] - edit ~/.rizinrc with cfg.editor\n");
			eprintf ("NOTE: ~ is HOME and this can be changed with %%HOME=/tmp\n");
			eprintf ("  ed    : ${cfg.editor} ~/.rizinrc\n");
			eprintf ("  ed-   : rm ~/.rizinrc\n");
		} else if (input[1] == '-') {
			char *file = rz_str_home (".rizinrc");
			rz_cons_printf ("rm %s\n", file);
			// rz_file_rm (file);
			free (file);
		} else {
			char *file = rz_str_home (".rizinrc");
			if (rz_cons_is_interactive ()) {
				rz_file_touch (file);
				char * res = rz_cons_editor (file, NULL);
				if (res) {
					if (rz_cons_yesno ('y', "Reload? (Y/n)")) {
						rz_core_run_script (core, file);
					}
				}
			} else {
				rz_core_run_script (core, file);
			}
			free (file);
		}
		break;
	case 'e': // "ee"
		if (input[1] == ' ') {
			char *p;
			const char *input2 = strchr (input + 2, ' ');
			input2 = (input2) ? input2 + 1 : input + 2;
			const char *val = rz_config_get (core->config, input2);
			p = rz_core_editor (core, NULL, val);
			if (p) {
				rz_str_replace_char (p, '\n', ';');
				rz_config_set (core->config, input2, p);
			}
		} else {
			eprintf ("Usage: ee varname # use $EDITOR to edit this config value\n");
		}
		break;
	case '!': // "e!"
		input = rz_str_trim_head_ro (input + 1);
		if (!rz_config_toggle (core->config, input)) {
			eprintf ("rz_config: '%s' is not a boolean variable.\n", input);
		}
		break;
	case 's': // "es"
		rz_config_list (core->config, (input[1])? input + 1: NULL, 's');
		break;
	case '-': // "e-"
		rz_core_config_init (core);
		//eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*': // "e*"
		rz_config_list (core->config, NULL, 1);
		break;
	case 'r': // "er"
		if (input[1]) {
			const char *key = input + ((input[1] == ' ')? 2: 1);
			if (!rz_config_readonly (core->config, key)) {
				eprintf ("cannot find key '%s'\n", key);
			}
		} else {
			eprintf ("Usage: er [key]  # make an eval key PERMANENTLY read only\n");
		}
		break;
	case ',': // "e."
		rz_config_eval (core->config, input + 1, true);
		break;
	case '.': // "e "
	case ' ': // "e "
		if (rz_str_endswith (input, ".")) {
			rz_config_list (core->config, input + 1, 0);
		} else {
			// XXX we cant do "e cmd.gprompt=dr=", because the '=' is a token, and quotes dont affect him
			rz_config_eval (core->config, input + 1, false);
		}
		break;
	}
	return 0;
}
