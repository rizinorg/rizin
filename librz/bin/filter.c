// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "i/private.h"

static char *__hashify(char *s, ut64 vaddr) {
	rz_return_val_if_fail(s, NULL);

	char *os = s;
	while (*s) {
		if (!IS_PRINTABLE(*s)) {
			if (vaddr && vaddr != UT64_MAX) {
				char *ret = rz_str_newf("_%" PFMT64d, vaddr);
				if (ret) {
					free(os);
				}
				return ret;
			}
			ut32 hash = sdb_hash(s);
			char *ret = rz_str_newf("%x", hash);
			if (ret) {
				free(os);
			}
			return ret;
		}
		s++;
	}
	return os;
}

// - name should be allocated on the heap
RZ_API char *rz_bin_filter_name(RzBinFile *bf, Sdb *db, ut64 vaddr, char *name) {
	rz_return_val_if_fail(db && name, NULL);

	char *resname = name;
	const char *uname = sdb_fmt("%" PFMT64x ".%s", vaddr, resname);
	ut32 vhash = sdb_hash(uname); // vaddr hash - unique
	ut32 hash = sdb_hash(resname); // name hash - if dupped and not in unique hash must insert
	int count = sdb_num_inc(db, sdb_fmt("%x", hash), 1, 0);

	if (sdb_exists(db, sdb_fmt("%x", vhash))) {
		// TODO: symbol is dupped, so symbol can be removed!
		return resname;
	}
	sdb_num_set(db, sdb_fmt("%x", vhash), 1, 0);
	if (vaddr) {
		char *p = __hashify(resname, vaddr);
		if (p) {
			resname = p;
		}
	}
	if (count > 1) {
		char *p = rz_str_appendf(resname, "_%d", count - 1);
		if (p) {
			resname = p;
		}

		// two symbols at different addresses and same name
		//	eprintf ("Symbol '%s' dupped!\n", sym->name);
	}
	return resname;
}

RZ_API void rz_bin_filter_sym(RzBinFile *bf, HtPP *ht, ut64 vaddr, RzBinSymbol *sym) {
	rz_return_if_fail(ht && sym && sym->name);
	const char *name = sym->name;
	// if (!strncmp (sym->name, "imp.", 4)) {
	// demangle symbol name depending on the language specs if any
	if (bf && bf->o && bf->o->lang) {
		const char *lang = rz_bin_lang_tostring(bf->o->lang);
		char *dn = rz_bin_demangle(bf, lang, sym->name, sym->vaddr, false);
		if (dn && *dn) {
			sym->dname = dn;
			// XXX this is wrong but is required for this test to pass
			// pmb:new pancake$ bin/rz_test.js db/formats/mangling/swift
			sym->name = dn;
			// extract class information from demangled symbol name
			char *p = strchr(dn, '.');
			if (p) {
				if (IS_UPPER(*dn)) {
					sym->classname = strdup(dn);
					sym->classname[p - dn] = 0;
				} else if (IS_UPPER(p[1])) {
					sym->classname = strdup(p + 1);
					p = strchr(sym->classname, '.');
					if (p) {
						*p = 0;
					}
				}
			}
		}
	}

	const char *uname = sdb_fmt("%" PFMT64x ".%c.%s", vaddr, sym->is_imported ? 'i' : 's', name);
	bool res = ht_pp_insert(ht, uname, sym);
	if (!res) {
		return;
	}
	sym->dup_count = 0;

	const char *oname = sdb_fmt("o.0.%c.%s", sym->is_imported ? 'i' : 's', name);
	RzBinSymbol *prev_sym = ht_pp_find(ht, oname, NULL);
	if (!prev_sym) {
		if (!ht_pp_insert(ht, oname, sym)) {
			RZ_LOG_WARN("Failed to insert dup_count in ht");
			return;
		}
	} else {
		sym->dup_count = prev_sym->dup_count + 1;
		ht_pp_update(ht, oname, sym);
	}
}

RZ_API void rz_bin_filter_symbols(RzBinFile *bf, RzList *list) {
	HtPP *ht = ht_pp_new0();
	if (!ht) {
		return;
	}

	RzListIter *iter;
	RzBinSymbol *sym;
	rz_list_foreach (list, iter, sym) {
		if (sym && sym->name && *sym->name) {
			rz_bin_filter_sym(bf, ht, sym->vaddr, sym);
		}
	}
	ht_pp_free(ht);
}

RZ_API void rz_bin_filter_sections(RzBinFile *bf, RzList *list) {
	RzBinSection *sec;
	Sdb *db = sdb_new0();
	RzListIter *iter;
	rz_list_foreach (list, iter, sec) {
		char *p = rz_bin_filter_name(bf, db, sec->vaddr, sec->name);
		if (p) {
			sec->name = p;
		}
	}
	sdb_free(db);
}

static bool false_positive(const char *str) {
	int i;
	ut8 bo[0x100];
	int up = 0;
	int lo = 0;
	int ot = 0;
	int di = 0;
	int ln = 0;
	int sp = 0;
	int nm = 0;
	for (i = 0; i < 0x100; i++) {
		bo[i] = 0;
	}
	for (i = 0; str[i]; i++) {
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
		if (str[i] == ' ') {
			sp++;
		}
		bo[(ut8)str[i]] = 1;
		ln++;
	}
	for (i = 0; i < 0x100; i++) {
		if (bo[i]) {
			di++;
		}
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
		char *addrs = strdup(bin->strpurge);
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
			char ch = str[i];
			if (ch == ' ' ||
				(in_esc_seq && (ch == 't' || ch == 'n' || ch == 'r'))) {
				goto loop_end;
			}
			if (ch < 0 || !IS_PRINTABLE(ch) || IS_LOWER(ch)) {
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
	case 'i': //IPV4
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
 * Filter the given string, respecting bin->strpurge, bin->strfilter,
 * and if len >= 0, also bin->minstrlen and bin->maxstrlen.
 */
RZ_API bool rz_bin_string_filter(RzBin *bin, const char *str, int len, ut64 addr) {
	if (len >= 0 && (len < bin->minstrlen || (bin->maxstrlen > 0 && len > bin->maxstrlen))) {
		return false;
	}
	if (rz_bin_strpurge(bin, str, addr) || !bin_strfilter(bin, str)) {
		return false;
	}
	return true;
}
