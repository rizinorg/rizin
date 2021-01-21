// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>

static bool gethtmlrgb(const char *str, char *buf) {
	ut8 r = 0, g = 0, b = 0;
	if (rz_cons_rgb_parse(str, &r, &g, &b, 0)) {
		sprintf(buf, "#%02x%02x%02x", r, g, b);
		return true;
	}
	buf[0] = '\0';
	return false;
}

static const char *gethtmlcolor(const char ptrch) {
	switch (ptrch) {
	case '0': return "#000"; // BLACK
	case '1': return "#f00"; // RED
	case '2': return "#0f0"; // GREEN
	case '3': return "#ff0"; // YELLOW
	case '4': return "#00f"; // BLUE
	case '5': return "#f0f"; // MAGENTA
	case '6': return "#aaf"; // TURQOISE
	case '7': return "#fff"; // WHITE
	case '8': return "#777"; // GREY
	case '9': break; // default
	}
	return "";
}

// TODO: move into rz_util/str
RZ_API char *rz_cons_html_filter(const char *ptr, int *newlen) {
	const char *str = ptr;
	int esc = 0;
	int len = 0;
	bool inv = false;
	char text_color[16] = { 0 };
	char background_color[16] = { 0 };
	bool has_set = false;
	bool need_to_set = false;
	bool need_to_clear = false;
	bool first_style;
	int tmp;
	if (!ptr) {
		return NULL;
	}
	RzStrBuf *res = rz_strbuf_new("");
	if (!res) {
		return NULL;
	}
	for (; ptr[0]; ptr = ptr + 1) {
		if (esc == 0 && ptr[0] != 0x1b && need_to_set) {
			if (has_set) {
				rz_strbuf_append(res, "</font>");
				has_set = false;
			}
			if (!need_to_clear) {
				first_style = true;
				rz_strbuf_append(res, "<font");
				if (text_color[0]) {
					rz_strbuf_appendf(res, " color='%s'", text_color);
				}
				if (background_color[0]) {
					rz_strbuf_append(res, first_style ? " style='" : ";");
					rz_strbuf_appendf(res, "background-color:%s", background_color);
					first_style = false;
				}
				if (inv) {
					rz_strbuf_append(res, first_style ? " style='" : ";");
					rz_strbuf_append(res, "text-decoration:underline overline");
					first_style = false;
				}
				rz_strbuf_append(res, first_style ? ">" : "'>");
				has_set = true;
			}
			need_to_clear = false;
			need_to_set = false;
		}
		if (ptr[0] == '\n') {
			tmp = (int)(size_t)(ptr - str);
			rz_strbuf_append_n(res, str, tmp);
			if (!ptr[1]) {
				// write new line if it's the end of the output
				rz_strbuf_append(res, "\n");
			} else {
				rz_strbuf_append(res, "<br />");
			}
			str = ptr + 1;
			continue;
		} else if (ptr[0] == '<') {
			tmp = (int)(size_t)(ptr - str);
			rz_strbuf_append_n(res, str, tmp);
			rz_strbuf_append(res, "&lt;");
			str = ptr + 1;
			continue;
		} else if (ptr[0] == '>') {
			tmp = (int)(size_t)(ptr - str);
			rz_strbuf_append_n(res, str, tmp);
			rz_strbuf_append(res, "&gt;");
			str = ptr + 1;
			continue;
		} else if (ptr[0] == ' ') {
			tmp = (int)(size_t)(ptr - str);
			rz_strbuf_append_n(res, str, tmp);
			rz_strbuf_append(res, "&nbsp;");
			str = ptr + 1;
			continue;
		}
		if (ptr[0] == 0x1b) {
			esc = 1;
			tmp = (int)(size_t)(ptr - str);
			rz_strbuf_append_n(res, str, tmp);
			str = ptr + 1;
			continue;
		}
		if (esc == 1) {
			// \x1b[2J
			if (ptr[0] != '[') {
				eprintf("Oops invalid escape char\n");
				esc = 0;
				str = ptr + 1;
				continue;
			}
			esc = 2;
			continue;
		} else if (esc == 2) {
			// TODO: use dword comparison here
			if (ptr[0] == '0' && ptr[1] == 'J') { // RZ_CONS_CLEAR_FROM_CURSOR_TO_END
				ptr += 2;
				esc = 0;
				str = ptr;
			} else if (!memcmp(ptr, "2K", 2)) {
				ptr += 2;
				esc = 0;
				str = ptr;
				continue;
			} else if (ptr[0] == '2' && ptr[1] == 'J') {
				rz_strbuf_append(res, "<hr />");
				ptr++;
				esc = 0;
				str = ptr;
				continue;
			} else if (!strncmp(ptr, "48;5;", 5) || !strncmp(ptr, "48;2;", 5)) {
				char *end = strchr(ptr, 'm');
				gethtmlrgb(ptr, background_color);
				need_to_set = true;
				ptr = end;
				str = ptr + 1;
				esc = 0;
			} else if (!strncmp(ptr, "38;5;", 5) || !strncmp(ptr, "38;2;", 5)) {
				char *end = strchr(ptr, 'm');
				gethtmlrgb(ptr, text_color);
				need_to_set = true;
				ptr = end;
				str = ptr + 1;
				esc = 0;
			} else if (ptr[0] == '0' && ptr[1] == ';' && ptr[2] == '0') {
				rz_cons_gotoxy(0, 0);
				ptr += 4;
				esc = 0;
				str = ptr;
				continue;
			} else if (ptr[0] == '0' && ptr[1] == 'm') {
				str = (++ptr) + 1;
				esc = 0;
				inv = false;
				text_color[0] = '\0';
				background_color[0] = '\0';
				need_to_set = need_to_clear = true;
				continue;
				// reset color
			} else if (!strncmp(ptr, "27m", 3)) {
				inv = false;
				need_to_set = true;
				ptr = ptr + 2;
				str = ptr + 1;
				esc = 0;
				continue;
				// reset invert color
			} else if (ptr[0] == '7' && ptr[1] == 'm') {
				str = (++ptr) + 1;
				inv = true;
				need_to_set = true;
				esc = 0;
				continue;
				// invert color
			} else if (ptr[0] == '3' && ptr[2] == 'm') {
				const char *htmlColor = gethtmlcolor(ptr[1]);
				if (htmlColor) {
					rz_str_ncpy(text_color, htmlColor, sizeof(text_color));
				}
				need_to_set = true;
				ptr = ptr + 2;
				str = ptr + 1;
				esc = 0;
				continue;
			} else if (ptr[0] == '4' && ptr[2] == 'm') {
				const char *htmlColor = gethtmlcolor(ptr[1]);
				if (htmlColor) {
					rz_str_ncpy(background_color, htmlColor, sizeof(background_color));
				}
				need_to_set = true;
				ptr = ptr + 2;
				str = ptr + 1;
				esc = 0;
				continue;
			}
		}
		len++;
	}
	rz_strbuf_append_n(res, str, ptr - str);
	if (has_set) {
		rz_strbuf_append(res, "</font>");
	}
	if (newlen) {
		*newlen = res->len;
	}
	return rz_strbuf_drain(res);
}
