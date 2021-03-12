// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_regex.h>
#include <rz_util.h>
#include "pager_private.h"

RZ_API int rz_cons_more_str(const char *str, const char *exitkeys) {
	static bool inHelp = false;
	static const char *rz_cons_more_help =
		" space    - page up\n"
		" j        - line down\n"
		" /        - search in buffer\n"
		" _        - enter the hud mode\n"
		" n        - next search result\n"
		" q        - quit\n"
		" ?        - show this help\n"
		"\n";
	int lines_count = 0;
	RzRegex *rx = NULL;
	int w, h, ch, to, ui = 1, from = 0, i;
	const char *sreg;
	RzList **mla;

	if (!str || !*str) {
		return 0;
	}
	// rcons kills str after flushing the buffer, so we must keep a copy
	char *ostr = strdup(str);
	if (!ostr) {
		return 0;
	}
	char *p = strdup(str);
	if (!p) {
		free(ostr);
		return 0;
	}
	int *lines = pager_splitlines(p, &lines_count);
	if (lines_count < 1) {
		mla = NULL;
	} else {
		mla = calloc(lines_count, sizeof(RzList *));
		if (!mla) {
			free(p);
			free(ostr);
			free(lines);
			return 0;
		}
	}
	for (i = 0; i < lines_count; i++) {
		mla[i] = rz_list_new();
	}
	rz_cons_set_raw(true);
	rz_cons_show_cursor(false);
	rz_cons_reset();
	h = 0;
	while (ui) {
		w = rz_cons_get_size(&h);
		to = RZ_MIN(lines_count, from + h);
		if (from + 3 > lines_count) {
			from = lines_count - 3;
		}
		if (from < 0) {
			from = 0;
		}
		pager_printpage(p, lines, mla, from, to, w);
		ch = rz_cons_readchar();
		if (exitkeys && strchr(exitkeys, ch)) {
			for (i = 0; i < lines_count; i++) {
				rz_list_free(mla[i]);
			}
			free(p);
			free(mla);
			free(ostr);
			free(lines);
			return ch;
		}
		ch = rz_cons_arrow_to_hjkl(ch);
		switch (ch) {
		case '_':
			rz_cons_hud_string(ostr);
			break;
		case '?':
			if (!inHelp) {
				inHelp = true;
				rz_cons_more_str(rz_cons_more_help, NULL);
				inHelp = false;
			}
			break;
		case ' ': from += h; break;
		case -1: // EOF
		case '\x03': // ^C
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j': from++; break;
		case 'J': from += h; break;
		case '/': /* search */
			rz_cons_reset_colors();
			rz_line_set_prompt("/");
			sreg = rz_line_readline();
			from = RZ_MIN(lines_count - 1, from);
			/* repeat last search if empty string is provided */
			if (sreg[0]) { /* prepare for a new search */
				if (rx) {
					rz_regex_free(rx);
				}
				rx = rz_regex_new(sreg, "");
			} else { /* we got an empty string */
				from = pager_next_match(from, mla, lines_count);
				break;
			}
			if (!rx) {
				break;
			}
			/* find all occurrences */
			if (pager_all_matches(p, rx, mla, lines, lines_count)) {
				from = pager_next_match(from, mla, lines_count);
			}
			break;
		case 'n': /* next match */
			/* search already performed */
			if (rx) {
				from = pager_next_match(from, mla, lines_count);
			}
			break;
		}
	}
	for (i = 0; i < lines_count; i++) {
		rz_list_free(mla[i]);
	}
	free(mla);
	rz_regex_free(rx);
	free(lines);
	free(p);
	rz_cons_reset_colors();
	rz_cons_set_raw(false);
	rz_cons_show_cursor(true);
	free(ostr);
	return 0;
}

RZ_API void rz_cons_more(void) {
	(void)rz_cons_more_str(rz_cons_singleton()->context->buffer, NULL);
}
