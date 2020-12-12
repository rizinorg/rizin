// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <ctype.h>

#define I(x) rz_cons_singleton ()->x

// Display the content of a file in the hud
RZ_API char *rz_cons_hud_file(const char *f) {
	char *s = rz_file_slurp (f, NULL);
	if (s) {
		char *ret = rz_cons_hud_string (s);
		free (s);
		return ret;
	}
	return NULL;
}

// Display a buffer in the hud (splitting it line-by-line and ignoring
// the lines starting with # )
RZ_API char *rz_cons_hud_string(const char *s) {
	if (!rz_cons_is_interactive ()) {
		eprintf ("Hud mode requires scr.interactive=true.\n");
		return NULL;
	}
	char *os, *track, *ret, *o = strdup (s);
	if (!o) {
		return NULL;
	}
	rz_str_replace_ch (o, '\r', 0, true);
	rz_str_replace_ch (o, '\t', 0, true);
	RzList *fl = rz_list_new ();
	int i;
	if (!fl) {
		free (o);
		return NULL;
	}
	fl->free = free;
	for (os = o, i = 0; o[i]; i++) {
		if (o[i] == '\n') {
			o[i] = 0;
			if (*os && *os != '#') {
				track = strdup (os);
				if (!rz_list_append (fl, track)) {
					free (track);
					break;
				}
			}
			os = o + i + 1;
		}
	}
	ret = rz_cons_hud (fl, NULL);
	free (o);
	rz_list_free (fl);
	return ret;
}

/* Match a filter on a line. A filter can contain multiple words
   separated by spaces, which are all matched *in any order* over the target
   entry. If all words are present, the function returns true.
   The mask is a character buffer which is filled by 'x' to mark those characters
   that match the filter */
static bool __matchString(char *entry, char *filter, char *mask, const int mask_size) {
	char *p, *current_token = filter;
	const char *filter_end = filter + strlen (filter);
	char *ansi_filtered = strdup (entry);
	int *cps;
	rz_str_ansi_filter (ansi_filtered, NULL, &cps, -1);
	entry = ansi_filtered;
	// first we separate the filter in words (include the terminator char
	// to avoid special handling of the last token)
	for (p = filter; p <= filter_end; p++) {
		if (*p == ' ' || *p == '\0') {
			const char *next_match, *entry_ptr = entry;
			char old_char = *p;
			int token_len;

			// Ignoring consecutive spaces
			if (p == current_token) {
				current_token++;
				continue;
			}
			*p = 0;
			token_len = strlen (current_token);
			// look for all matches of the current_token in this entry
			while ((next_match = rz_str_casestr (entry_ptr, current_token))) {
				int real_pos, filtered_pos = next_match - entry;
				int end_pos = cps[filtered_pos + token_len];
				for (real_pos = cps[filtered_pos];
					real_pos < end_pos && real_pos < mask_size;
					real_pos = cps[++filtered_pos]) {
					mask[real_pos] = 'x';
				}
				entry_ptr += token_len;
			}
			*p = old_char;
			if (entry_ptr == entry) {
				// the word is not present in the target
				free (cps);
				free (ansi_filtered);
				return false;
			}
			current_token = p + 1;
		}
	}
	free (cps);
	free (ansi_filtered);
	return true;
}


static RzList *hud_filter(RzList *list, char *user_input, int top_entry_n, int *current_entry_n, char **selected_entry) {
	RzListIter *iter;
	char *current_entry;
	char mask[HUD_BUF_SIZE];
	char *p, *x;
	int j, rows;
	(void) rz_cons_get_size (&rows);
	int counter = 0;
	bool first_line = true;
	RzList *res = rz_list_newf (free);
	rz_list_foreach (list, iter, current_entry) {
		memset (mask, 0, HUD_BUF_SIZE);
		if (*user_input && !__matchString (current_entry, user_input, mask, HUD_BUF_SIZE)) {
			continue;
		}
		if (++counter == rows + top_entry_n) {
			break;
		}
		// if the user scrolled down the list, do not print the first entries
		if (!top_entry_n || *current_entry_n >= top_entry_n) {
			// remove everything after a tab (in ??, it contains the commands)
			x = strchr (current_entry, '\t');
			if (x) {
				*x = 0;
			}
			p = strdup (current_entry);
			// if the filter is empty, print the entry and move on
			if (!user_input[0]) {
				rz_list_append (res, rz_str_newf (" %c %s", first_line? '-': ' ', p));
			} else {
				// otherwise we need to emphasize the matching part
				if (I (context->color_mode)) {
					int last_color_change = 0;
					int last_mask = 0;
					char *str = rz_str_newf (" %c ", first_line? '-': ' ');
					// Instead of printing one char at the time
					// (which would be slow), we group substrings of the same color
					for (j = 0; p[j] && j < HUD_BUF_SIZE; j++) {
						if (mask[j] != last_mask) {
							char tmp = p[j];
							p[j] = 0;
							if (mask[j]) {
								str = rz_str_appendf (str, Color_RESET "%s", p + last_color_change);
							} else {
								str = rz_str_appendf (str, Color_GREEN "%s", p + last_color_change);
							}
							p[j] = tmp;
							last_color_change = j;
							last_mask = mask[j];
						}
					}
					if (last_mask) {
						str = rz_str_appendf (str, Color_GREEN "%s"Color_RESET, p + last_color_change);
					} else {
						str = rz_str_appendf (str, Color_RESET "%s", p + last_color_change);
					}
					rz_list_append (res, str);
				} else {
					// Otherwise we print the matching characters uppercase
					for (j = 0; p[j]; j++) {
						if (mask[j]) {
							p[j] = toupper ((unsigned char) p[j]);
						}
					}
					rz_list_append (res, rz_str_newf (" %c %s", first_line? '-': ' ', p));
				}
			}
			// Clean up and restore the tab character (if any)
			free (p);
			if (x) {
				*x = '\t';
			}
			if (first_line) {
				*selected_entry = current_entry;
			}
			first_line = false;
		}
		(*current_entry_n)++;

	}
	return res;
}

static void mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	rz_list_free (kv->value);
}

// Display a list of entries in the hud, filtered and emphasized based on the user input.

#define HUD_CACHE 0
RZ_API char *rz_cons_hud(RzList *list, const char *prompt) {
	char user_input[HUD_BUF_SIZE + 1];
	char *selected_entry = NULL;
	RzListIter *iter;

	HtPP *ht = ht_pp_new (NULL, (HtPPKvFreeFunc)mht_free_kv, (HtPPCalcSizeV)strlen);
	RzLineHud *hud = (RzLineHud*) RZ_NEW (RzLineHud);
	hud->activate = 0;
	hud->vi = 0;
	I(line)->echo = false;
	I(line)->hud = hud;
	user_input [0] = 0;
	user_input[HUD_BUF_SIZE] = 0;
	hud->top_entry_n = 0;
	rz_cons_show_cursor (false);
	rz_cons_enable_mouse (false);
	rz_cons_clear ();

	// Repeat until the user exits the hud
	for (;;) {
		rz_cons_gotoxy (0, 0);
		hud->current_entry_n = 0;

		if (hud->top_entry_n < 0) {
			hud->top_entry_n = 0;
		}
		selected_entry = NULL;
		if (prompt && *prompt) {
			rz_cons_printf (">> %s\n", prompt);
		}
		rz_cons_printf ("%d> %s|\n", hud->top_entry_n, user_input);
		char *row;
		RzList *filtered_list = NULL;

		bool found = false;
		filtered_list = ht_pp_find (ht, user_input, &found);
		if (!found) {
			filtered_list = hud_filter (list, user_input,
				hud->top_entry_n, &(hud->current_entry_n), &selected_entry);
#if HUD_CACHE
			ht_pp_insert (ht, user_input, filtered_list);
#endif
		}
		rz_list_foreach (filtered_list, iter, row) {
			rz_cons_printf ("%s\n", row);
		}
		if (!filtered_list->length) {				// hack to remove garbage value when list is empty
			printf ("%s", RZ_CONS_CLEAR_LINE);
		}
#if !HUD_CACHE
		rz_list_free (filtered_list);
#endif
		rz_cons_visual_flush ();
		(void) rz_line_readline ();
		strncpy (user_input, I(line)->buffer.data, HUD_BUF_SIZE); 				// to search

		if (!hud->activate) {
			hud->top_entry_n = 0;
			if (hud->current_entry_n >= 1 ) {
				if (selected_entry) {
					RZ_FREE (I(line)->hud);
					I(line)->echo = true;
					rz_cons_enable_mouse (false);
					rz_cons_show_cursor (true);
					rz_cons_set_raw (false);
					return strdup (selected_entry);
				}
			} else {
				goto _beach;
			}
		}
	}
_beach:
	RZ_FREE (I(line)->hud);
	I(line)->echo = true;
	rz_cons_show_cursor (true);
	rz_cons_enable_mouse (false);
	rz_cons_set_raw (false);
	ht_pp_free (ht);
	return NULL;
}

// Display the list of files in a directory
RZ_API char *rz_cons_hud_path(const char *path, int dir) {
	char *tmp, *ret = NULL;
	RzList *files;
	if (path) {
		path = rz_str_trim_head_ro (path);
		tmp = strdup (*path? path: "./");
	} else {
		tmp = strdup ("./");
	}
	files = rz_sys_dir (tmp);
	if (files) {
		ret = rz_cons_hud (files, tmp);
		if (ret) {
			tmp = rz_str_append (tmp, "/");
			tmp = rz_str_append (tmp, ret);
			free (ret);
			ret = rz_file_abspath (tmp);
			free (tmp);
			tmp = ret;
			if (rz_file_is_directory (tmp)) {
				ret = rz_cons_hud_path (tmp, dir);
				free (tmp);
				tmp = ret;
			}
		}
		rz_list_free (files);
	} else {
		eprintf ("No files found\n");
	}
	if (!ret) {
		free (tmp);
		return NULL;
	}
	return tmp;
}

RZ_API char *rz_cons_message(const char *msg) {
	int len = strlen (msg);
	int rows, cols = rz_cons_get_size (&rows);
	rz_cons_clear ();
	rz_cons_gotoxy ((cols - len) / 2, rows / 2);
	rz_cons_println (msg);
	rz_cons_flush ();
	rz_cons_gotoxy (0, rows - 2);
	rz_cons_any_key (NULL);
	return NULL;
}
