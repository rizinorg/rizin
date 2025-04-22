// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "i/private.h"

static bool false_positive(const char *str) {
	int up = 0;
	int lo = 0;
	int ot = 0;
	int ln = 0;
	int nm = 0;
	for (int i = 0; str[i]; i++) {
		if (IS_DIGIT(str[i])) {
			nm++;
		} else if (str[i] >= 'a' && str[i] <= 'z') {
			lo++;
		} else if (str[i] >= 'A' && str[i] <= 'Z') {
			up++;
		} else {
			ot++;
		}
		if (str[i] == '\\') {
			ot++;
		}
		ln++;
	}
	if (ln > 2 && str[0] != '_') {
		if (ln < 10) {
			return true;
		}
		if (ot >= (nm + up + lo)) {
			return true;
		}
		if (lo < 3) {
			return true;
		}
	}
	return false;
}

RZ_API bool rz_bin_strpurge(RzBin *bin, const char *str, ut64 refaddr) {
	bool purge = false;
	if (bin->strpurge) {
		char *addrs = rz_str_dup(bin->strpurge);
		if (addrs) {
			int splits = rz_str_split(addrs, ',');
			int i;
			char *ptr;
			char *range_sep;
			ut64 addr, from, to;
			for (i = 0, ptr = addrs; i < splits; i++, ptr += strlen(ptr) + 1) {
				if (!strcmp(ptr, "true") && false_positive(str)) {
					purge = true;
					continue;
				}
				bool bang = false;
				if (*ptr == '!') {
					bang = true;
					ptr++;
				}
				if (!strcmp(ptr, "all")) {
					purge = !bang;
					continue;
				}
				range_sep = strchr(ptr, '-');
				if (range_sep) {
					*range_sep = 0;
					from = rz_num_get(NULL, ptr);
					ptr = range_sep + 1;
					to = rz_num_get(NULL, ptr);
					if (refaddr >= from && refaddr <= to) {
						purge = !bang;
						continue;
					}
				}
				addr = rz_num_get(NULL, ptr);
				if (addr != 0 || *ptr == '0') {
					if (refaddr == addr) {
						purge = !bang;
						continue;
					}
				}
			}
			free(addrs);
		}
	}
	return purge;
}

static int get_char_ratio(char ch, const char *str) {
	int i;
	int ch_count = 0;
	for (i = 0; str[i]; i++) {
		if (str[i] == ch) {
			ch_count++;
		}
	}
	return i ? ch_count * 100 / i : 0;
}

static bool bin_strfilter(RzBin *bin, const char *str) {
	int i;
	bool got_uppercase, in_esc_seq;
	switch (bin->strfilter) {
	case 'U': // only uppercase strings
		got_uppercase = false;
		in_esc_seq = false;
		for (i = 0; str[i]; i++) {
			signed char ch = str[i];
			if (ch == ' ' ||
				(in_esc_seq && (ch == 't' || ch == 'n' || ch == 'r'))) {
				goto loop_end;
			}
			if (ch < 0 || IS_LOWER(ch)) {
				return false;
			}
			if (IS_UPPER(ch)) {
				got_uppercase = true;
			}
		loop_end:
			in_esc_seq = in_esc_seq ? false : ch == '\\';
		}
		if (get_char_ratio(str[0], str) >= 60) {
			return false;
		}
		if (str[0] && get_char_ratio(str[1], str) >= 60) {
			return false;
		}
		if (!got_uppercase) {
			return false;
		}
		break;
	case 'a': // only alphanumeric - plain ascii
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (ch < 1 || !IS_PRINTABLE(ch)) {
				return false;
			}
		}
		break;
	case 'e': // emails
		if (str && *str) {
			if (!strchr(str + 1, '@')) {
				return false;
			}
			if (!strchr(str + 1, '.')) {
				return false;
			}
		} else {
			return false;
		}
		break;
	case 'f': // format-string
		if (str && *str) {
			if (!strchr(str + 1, '%')) {
				return false;
			}
		} else {
			return false;
		}
		break;
	case 'u': // URLs
		if (!strstr(str, "://")) {
			return false;
		}
		break;
	case 'i': // IPV4
	{
		int segment = 0;
		int segmentsum = 0;
		bool prevd = false;
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (IS_DIGIT(ch)) {
				segmentsum = segmentsum * 10 + (ch - '0');
				if (segment == 3) {
					return true;
				}
				prevd = true;
			} else if (ch == '.') {
				if (prevd == true && segmentsum < 256) {
					segment++;
					segmentsum = 0;
				} else {
					segmentsum = 0;
					segment = 0;
				}
				prevd = false;
			} else {
				segmentsum = 0;
				prevd = false;
				segment = 0;
			}
		}
		return false;
	}
	case 'p': // path
		if (str[0] != '/') {
			return false;
		}
		break;
	case '8': // utf8
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (ch < 0) {
				return true;
			}
		}
		return false;
	}
	return true;
}

/**
 * Filter the given string, respecting bin->strpurge, bin->strfilter
 */
RZ_API bool rz_bin_string_filter(RzBin *bin, const char *str, ut64 addr) {
	if (rz_bin_strpurge(bin, str, addr) || !bin_strfilter(bin, str)) {
		return false;
	}
	return true;
}
