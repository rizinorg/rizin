// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

static bool rtr_visual(RzCore *core, TextLog T, const char *cmd) {
	bool autorefresh = false;
	if (cmd) {
		rz_cons_break_push(NULL, NULL);
		for (;;) {
			char *ret;
			rz_cons_clear00();
			ret = rtrcmd(T, cmd);
			rz_cons_println(ret);
			free(ret);
			rz_cons_flush();
			if (rz_cons_is_breaked()) {
				break;
			}
			rz_sys_sleep(1);
		}
		rz_cons_break_pop();
	} else {
		const char *cmds[] = { "px", "pd", "pxa", "dr", "sr SP;pxa", NULL };
		int cmdidx = 0;
		char *ret, ch;
		free(rtrcmd(T, "e scr.color=true"));
		free(rtrcmd(T, "e scr.html=false"));
		for (;;) {
			rz_cons_clear00();
			ret = rtrcmd(T, cmds[cmdidx]);
			if (ret) {
				rz_cons_println(ret);
				free(ret);
			}
			rz_cons_flush();
			if (autorefresh) {
				rz_cons_printf("(auto-refresh)\n");
				rz_cons_flush();
				rz_cons_break_push(NULL, NULL);
				rz_sys_sleep(1);
				if (rz_cons_is_breaked()) {
					autorefresh = false;
					ch = rz_cons_readchar();
				} else {
					rz_cons_break_pop();
					continue;
				}
				rz_cons_break_pop();
			} else {
				ch = rz_cons_readchar();
			}
#if 0
TODO:
 i   insert hex/string/asm
 0-9 follow jumps
#endif
			switch (ch) {
			case '?':
				rz_cons_clear00();
				rz_cons_printf("Remote Visual keys:\n"
					       " hjkl : move\n"
					       " HJKL : move faster\n"
					       " +-*/ : change block size\n"
					       " pP   : rotate print modes\n"
					       " T    : enter TextLog chat console\n"
					       " @    : enter auto-refresh mode\n"
					       " i    : insert hexpair\n"
					       " q    : quit this mode and go back to the shell\n"
					       " sS   : step / step over\n"
					       " .    : seek entry or pc\n");
				rz_cons_flush();
				rz_cons_any_key(NULL);
				break;
			case 'i': {
#if __UNIX__
#define COLORFLAGS (core->print->flags & RZ_PRINT_FLAGS_COLOR)
#else
#define COLORFLAGS 0
#endif
				char buf[1024];
				if (COLORFLAGS) {
					rz_line_set_prompt(Color_RESET ":> ");
				} else {
					rz_line_set_prompt(":> ");
				}
				showcursor(core, true);
				rz_cons_fgets(buf + 3, sizeof(buf) - 3, 0, NULL);
				memcpy(buf, "wx ", 3);
				if (buf[3]) {
					char *res = rtrcmd(T, buf);
					if (res) {
						rz_cons_println(res);
						free(res);
					}
					rz_cons_flush();
				}
			} break;
			case 's':
				free(rtrcmd(T, "ds;.dr*"));
				break;
			case 'S':
				free(rtrcmd(T, "dso;.dr*"));
				break;
			case '.':
				free(rtrcmd(T, "s entry0;dr?rip;?? sr PC"));
				break;
			case ':': {
				int ret;
				eprintf("Press <enter> to return to Visual mode.\n");
				do {
					char buf[1024];
#if __UNIX__
					rz_line_set_prompt(Color_RESET ":> ");
#else
					rz_line_set_prompt(":> ");
#endif
					showcursor(core, true);
					rz_cons_fgets(buf, sizeof(buf), 0, NULL);
					if (*buf) {
						rz_line_hist_add(buf);
						char *res = rtrcmd(T, buf);
						if (res) {
							rz_cons_println(res);
							free(res);
						}
						rz_cons_flush();
						ret = true;
					} else {
						ret = false;
						//rz_cons_any_key ();
						rz_cons_clear00();
						showcursor(core, false);
					}
				} while (ret);
			} break;
			case '@': autorefresh = true; break;
			case 'j':
				if (cmdidx == 1) {
					free(rtrcmd(T, "so"));
					break;
				} else {
					free(rtrcmd(T, "sd +16"));
					break;
				}
				break;
			case 'k': free(rtrcmd(T, "sd -16")); break;
			case 'h': free(rtrcmd(T, "sd -1")); break;
			case 'l': free(rtrcmd(T, "sd +1")); break;
			case 'J':
				if (cmdidx == 1) {
					free(rtrcmd(T, "4so"));
				} else {
					free(rtrcmd(T, "sd +32"));
				}
				break;
			case 'K': free(rtrcmd(T, "sd -32")); break;
			case 'H': free(rtrcmd(T, "sd -2")); break;
			case 'L': free(rtrcmd(T, "sd +2")); break;
			case '+': free(rtrcmd(T, "b+1")); break;
			case '*': free(rtrcmd(T, "b+16")); break;
			case '-': free(rtrcmd(T, "b-1")); break;
			case '/': free(rtrcmd(T, "b-16")); break;
			case 'p':
				cmdidx++;
				if (!cmds[cmdidx]) {
					cmdidx = 0;
				}
				break;
			case 'P':
				cmdidx--;
				if (cmdidx < 0) {
					cmdidx = 2;
				}
				break;
			case 'q': return false;
			}
		}
	}
	return true;
}

// XXX: this needs to be moved to use the standard shell like in !=! and support visual+panels
static void __rtr_shell(RzCore *core, int nth) {
	char *proto = "http";
	char *host = "";
	char *port = "";
	char *file = "";
	char prompt[64], prompt2[64], *str, *ptr;
	int len;
	const char *res;
	RzSocket *s = NULL;

	TextLog T = { host, port, file };
	snprintf(prompt, sizeof(prompt), "[%s://%s:%s/%s]> ",
		proto, host, port, file);
	snprintf(prompt2, sizeof(prompt2), "[%s:%s]$ ", host, port);
	for (;;) {
		rz_line_set_prompt(prompt);
		res = rz_line_readline();
		if (!res || !*res) {
			break;
		}
		if (*res == 'q') {
			break;
		}
		if (!strcmp(res, "!sh")) {
			for (;;) {
				rz_line_set_prompt(prompt2);
				res = rz_line_readline();
				if (!res || !*res || !strcmp(res, "exit")) {
					break;
				}
				ptr = rz_str_uri_encode(res);
				char *uri = rz_str_newf("http://%s:%s/%s!%s", host, port, file, res);
				str = rz_socket_http_get(uri, NULL, &len);
				if (str) {
					str[len] = 0;
					res = strstr(str, "\n\n");
					if (res) {
						res = strstr(res + 1, "\n\n");
					}
					res = res ? res + 2 : str;
					const char *tail = (res[strlen(res) - 1] == '\n') ? "" : "\n";
					printf("%s%s", res, tail);
					rz_line_hist_add(str);
					free(str);
				}
				free(ptr);
				free(uri);
			}
		} else if (res[0] == 'v' || res[0] == 'V') {
			if (res[1] == ' ') {
				rtr_visual(core, T, res + 1);
			} else {
				rtr_visual(core, T, NULL);
			}
		} else {
			char *cmdline = rz_str_newf("%d %s", nth, res);
			rz_core_rtr_cmd(core, cmdline);
			rz_cons_flush();
			rz_line_hist_add(res);
		}
	}
	rz_socket_free(s);
}
