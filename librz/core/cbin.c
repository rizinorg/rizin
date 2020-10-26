// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_config.h>
#include "rz_util.h"
#include "rz_util/rz_time.h"

#define is_in_range(at, from, sz) ((at) >= (from) && (at) < ((from) + (sz)))

#define VA_FALSE    0
#define VA_TRUE     1
#define VA_NOREBASE 2

#define LOAD_BSS_MALLOC 0

#define IS_MODE_SET(mode) ((mode) & RZ_MODE_SET)
#define IS_MODE_SIMPLE(mode) ((mode) & RZ_MODE_SIMPLE)
#define IS_MODE_SIMPLEST(mode) ((mode) & RZ_MODE_SIMPLEST)
#define IS_MODE_JSON(mode) ((mode) & RZ_MODE_JSON)
#define IS_MODE_RAD(mode) ((mode) & RZ_MODE_RADARE)
#define IS_MODE_EQUAL(mode) ((mode) & RZ_MODE_EQUAL)
#define IS_MODE_NORMAL(mode) (!(mode))
#define IS_MODE_CLASSDUMP(mode) ((mode) & RZ_MODE_CLASSDUMP)

// dup from cmd_info
#define PAIR_WIDTH 9

#define bprintf if (binfile && binfile->rbin && binfile->rbin->verbose) eprintf

static void pair(const char *key, const char *val, int mode, bool last) {
	if (!val || !*val) {
		return;
	}
	if (IS_MODE_JSON (mode)) {
		const char *lst = last ? "" : ",";
		rz_cons_printf ("\"%s\":%s%s", key, val, lst);
	} else {
		char ws[16];
		const int keyl = strlen (key);
		const int wl = (keyl > PAIR_WIDTH) ? 0 : PAIR_WIDTH - keyl;
		memset (ws, ' ', wl);
		ws[wl] = 0;
		rz_cons_printf ("%s%s%s\n", key, ws, val);
	}
}

static void pair_bool(const char *key, bool val, int mode, bool last) {
	pair (key, rz_str_bool (val), mode, last);
}

static void pair_int(const char *key, int val, int mode, bool last) {
	pair (key, sdb_fmt ("%d", val), mode, last);
}

static void pair_ut64(const char *key, ut64 val, int mode, bool last) {
	pair (key, sdb_fmt ("%"PFMT64d, val), mode, last);
}

static char *__filterQuotedShell(const char *arg) {
	rz_return_val_if_fail (arg, NULL);
	char *a = malloc (strlen (arg) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*arg) {
		switch (*arg) {
		case ' ':
		case '=':
		case '"':
		case '\\':
		case '\r':
		case '\n':
			break;
		default:
			*b++ = *arg;
			break;
		}
		arg++;
	}
	*b = 0;
	return a;
}
// TODO: move into librz/util/name.c
static char *__filterShell(const char *arg) {
	rz_return_val_if_fail (arg, NULL);
	char *a = malloc (strlen (arg) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*arg) {
		char ch = *arg;
		switch (ch) {
		case '@':
		case '`':
		case '|':
		case ';':
		case '=':
		case '\n':
			break;
		default:
			*b++ = ch;
			break;
		}
		arg++;
	}
	*b = 0;
	return a;
}

static void pair_ut64x(const char *key, ut64 val, int mode, bool last) {
	const char *str_val = IS_MODE_JSON (mode) ? sdb_fmt ("%"PFMT64d, val) : sdb_fmt ("0x%"PFMT64x, val);
	pair (key, str_val, mode, last);
}

static void pair_str(const char *key, const char *val, int mode, int last) {
	if (IS_MODE_JSON (mode)) {
		if (!val) {
			val = "";
		}
		char *encval = rz_str_escape_utf8_for_json (val, -1);
		if (encval) {
			char *qs = rz_str_newf ("\"%s\"", encval);
			pair (key, qs, mode, last);
			free (encval);
			free (qs);
		}
	} else {
		pair (key, val, mode, last);
	}
}

#define STR(x) (x)? (x): ""
RZ_API int rz_core_bin_set_cur(RzCore *core, RzBinFile *binfile);

static ut64 rva(RzBin *bin, ut64 paddr, ut64 vaddr, int va) {
	if (va == VA_TRUE) {
		if (paddr != UT64_MAX) {
			return rz_bin_get_vaddr (bin, paddr, vaddr);
		}
	}
	if (va == VA_NOREBASE) {
		return vaddr;
	}
	return paddr;
}

RZ_API int rz_core_bin_set_by_fd(RzCore *core, ut64 bin_fd) {
	if (rz_bin_file_set_cur_by_fd (core->bin, bin_fd)) {
		rz_core_bin_set_cur (core, rz_bin_cur (core->bin));
		return true;
	}
	return false;
}

RZ_API void rz_core_bin_export_info(RzCore *core, int mode) {
	char *flagname = NULL, *offset = NULL;
	RzBinFile *bf = rz_bin_cur (core->bin);
	if (!bf) {
		return;
	}
	Sdb *db = sdb_ns (bf->sdb, "info", 0);;
	if (!db) {
		return;
	}
	SdbListIter *iter;
	SdbKv *kv;
	if (IS_MODE_RAD (mode)) {
		rz_cons_printf ("fs format\n");
	} else if (IS_MODE_SET (mode)) {
		rz_flag_space_push (core->flags, "format");
	}
	// iterate over all keys
	SdbList *ls = sdb_foreach_list (db, false);
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key (kv);
		char *v = sdbkv_value (kv);
		char *dup = strdup (k);
		//printf ("?e (%s) (%s)\n", k, v);
		if ((flagname = strstr (dup, ".offset"))) {
			*flagname = 0;
			flagname = dup;
			if (IS_MODE_RAD (mode)) {
				rz_cons_printf ("f %s @ %s\n", flagname, v);
			} else if (IS_MODE_SET (mode)) {
				ut64 nv = rz_num_math (core->num, v);
				rz_flag_set (core->flags, flagname, nv, 0);
			}
			free (offset);
			offset = strdup (v);
		}
		if ((flagname = strstr (dup, ".cparse"))) {
			if (IS_MODE_RAD (mode)) {
				rz_cons_printf ("\"td %s\"\n", v);
			} else if (IS_MODE_SET (mode)) {
				char *code = rz_str_newf ("%s;", v);
				char *error_msg = NULL;
				char *out = rz_parse_c_string (core->anal, code, &error_msg);
				free (code);
				if (error_msg) {
					eprintf ("%s", error_msg);
					free (error_msg);
				}
				if (out) {
					rz_anal_save_parsed_type (core->anal, out);
					free (out);
				}
			}
		}
		free (dup);
	}
	RZ_FREE (offset);
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key (kv);
		char *v = sdbkv_value (kv);
		char *dup = strdup (k);
		if ((flagname = strstr (dup, ".format"))) {
			*flagname = 0;
			if (!offset) {
				offset = strdup ("0");
			}
			flagname = dup;
			if (IS_MODE_RAD (mode)) {
				rz_cons_printf ("pf.%s %s\n", flagname, v);
			} else if (IS_MODE_SET (mode)) {
				sdb_set (core->print->formats, flagname, v, 0);
			}
		}
		free (dup);
	}
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key (kv);
		char *v = sdbkv_value (kv);
		char *dup = strdup (k);
		if ((flagname = strstr (dup, ".format"))) {
			*flagname = 0;
			if (!offset) {
				offset = strdup ("0");
			}
			flagname = dup;
			int fmtsize = rz_print_format_struct_size (core->print, v, 0, 0);
			char *offset_key = rz_str_newf ("%s.offset", flagname);
			const char *off = sdb_const_get (db, offset_key, 0);
			free (offset_key);
			if (off) {
				if (IS_MODE_RAD (mode)) {
					rz_cons_printf ("Cf %d %s @ %s\n", fmtsize, v, off);
				} else if (IS_MODE_SET (mode)) {
					ut64 addr = rz_num_get (NULL, off);
					ut8 *buf = malloc (fmtsize);
					if (buf) {
						rz_io_read_at (core->io, addr, buf, fmtsize);
						int res = rz_print_format (core->print, addr, buf,
								fmtsize, v, 0, NULL, NULL);
						free (buf);
						if (res < 0) {
							eprintf ("Warning: Cannot register invalid format (%s)\n", v);
						}
					}
				}
			}
		}
		if ((flagname = strstr (dup, ".size"))) {
			*flagname = 0;
			flagname = dup;
			if (IS_MODE_RAD (mode)) {
				rz_cons_printf ("fl %s %s\n", flagname, v);
			} else if (IS_MODE_SET (mode)) {
				RzFlagItem *fi = rz_flag_get (core->flags, flagname);
				if (fi) {
					fi->size = rz_num_math (core->num, v);
				} else {
					eprintf ("Cannot find flag named '%s'\n", flagname);
				}
			}
		}
		free (dup);
	}
	free (offset);
	if (IS_MODE_SET (mode)) {
		rz_flag_space_pop (core->flags);
	}
}


RZ_API bool rz_core_bin_load_structs(RzCore *core, const char *file) {
	rz_return_val_if_fail (core && file && core->io, false);
	if (!file) {
		int fd = rz_io_fd_get_current (core->io);
		RzIODesc *desc = rz_io_desc_get (core->io, fd);
		if (desc) {
			file = desc->name;
		}
		if (!file) {
			return false;
		}
	}
	if (strchr (file, '\"')) {  // TODO: escape "?
		eprintf ("Invalid char found in filename\n");
		return false;
	}
	RzBinOptions opt = { 0 };
	rz_bin_open (core->bin, file, &opt);
	RzBinFile *bf = rz_bin_cur (core->bin);
	if (bf) {
		rz_core_bin_export_info (core, RZ_MODE_SET);
		rz_bin_file_delete (core->bin, bf->id);
		return true;
	}
	eprintf ("Cannot open bin '%s'\n", file);
	return false;
}

RZ_API int rz_core_bin_set_by_name(RzCore *core, const char * name) {
	if (rz_bin_file_set_cur_by_name (core->bin, name)) {
		rz_core_bin_set_cur (core, rz_bin_cur (core->bin));
		return true;
	}
	return false;
}

RZ_API int rz_core_bin_set_env(RzCore *r, RzBinFile *binfile) {
	rz_return_val_if_fail (r, false);

	RzBinObject *binobj = binfile? binfile->o: NULL;
	RzBinInfo *info = binobj? binobj->info: NULL;
	if (info) {
		int va = info->has_va;
		const char *arch = info->arch;
		ut16 bits = info->bits;
		ut64 baseaddr = rz_bin_get_baddr (r->bin);
		rz_config_set_i (r->config, "bin.baddr", baseaddr);
		sdb_num_add (r->sdb, "orig_baddr", baseaddr, 0);
		r->dbg->bp->baddr = baseaddr;
		rz_config_set (r->config, "asm.arch", arch);
		rz_config_set_i (r->config, "asm.bits", bits);
		rz_config_set (r->config, "anal.arch", arch);
		if (info->cpu && *info->cpu) {
			rz_config_set (r->config, "anal.cpu", info->cpu);
		} else {
			rz_config_set (r->config, "anal.cpu", arch);
		}
		rz_asm_use (r->rasm, arch);
		rz_core_bin_info (r, RZ_CORE_BIN_ACC_ALL, RZ_MODE_SET, va, NULL, NULL);
		rz_core_bin_set_cur (r, binfile);
		return true;
	}
	return false;
}

RZ_API int rz_core_bin_set_cur(RzCore *core, RzBinFile *binfile) {
	if (!core->bin) {
		return false;
	}
	if (!binfile) {
		// Find first available binfile
		ut32 fd = rz_core_file_cur_fd (core);
		binfile = fd != (ut32)-1
				  ? rz_bin_file_find_by_fd (core->bin, fd)
				  : NULL;
		if (!binfile) {
			return false;
		}
	}
	rz_bin_file_set_cur_binfile (core->bin, binfile);
	return true;
}

static void _print_strings(RzCore *r, RzList *list, int mode, int va) {
	bool b64str = rz_config_get_i (r->config, "bin.b64str");
	int minstr = rz_config_get_i (r->config, "bin.minstr");
	int maxstr = rz_config_get_i (r->config, "bin.maxstr");
	RTable *table = rz_core_table (r);
	rz_return_if_fail (table);
	RzBin *bin = r->bin;
	RzBinObject *obj = rz_bin_cur_object (bin);
	RzListIter *iter;
	RzBinString *string;
	RzBinSection *section;
	PJ *pj = NULL;

	bin->minstrlen = minstr;
	bin->maxstrlen = maxstr;
	if (IS_MODE_JSON (mode)) {
		pj = pj_new ();
		pj_a (pj);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_println ("fs strings");
	} else if (IS_MODE_SET (mode) && rz_config_get_i (r->config, "bin.strings")) {
		rz_flag_space_set (r->flags, RZ_FLAGS_FS_STRINGS);
		rz_cons_break_push (NULL, NULL);
	} else if (IS_MODE_NORMAL (mode)) {
		rz_cons_printf ("[Strings]\n");
		rz_table_set_columnsf (table, "nXXnnsss", "nth", "paddr", "vaddr", "len", "size", "section", "type", "string");
	}
	RzBinString b64 = { 0 };
	rz_list_foreach (list, iter, string) {
		const char *section_name, *type_string;
		ut64 paddr, vaddr;
		paddr = string->paddr;
		vaddr = rva (r->bin, paddr, string->vaddr, va);
		if (!rz_bin_string_filter (bin, string->string, vaddr)) {
			continue;
		}
		if (string->length < minstr) {
			continue;
		}
		if (maxstr && string->length > maxstr) {
			continue;
		}

		section = obj? rz_bin_get_section_at (obj, paddr, 0): NULL;
		section_name = section ? section->name : "";
		type_string = rz_bin_string_type (string->type);
		if (b64str) {
			ut8 *s = rz_base64_decode_dyn (string->string, -1);
			if (s && *s && IS_PRINTABLE (*s)) {
				// TODO: add more checks
				free (b64.string);
				memcpy (&b64, string, sizeof (b64));
				b64.string = (char *)s;
				b64.size = strlen (b64.string);
				string = &b64;
			}
		}
		if (IS_MODE_SET (mode)) {
			char *f_name, *str;
			if (rz_cons_is_breaked ()) {
				break;
			}
			rz_meta_set (r->anal, RZ_META_TYPE_STRING, vaddr, string->size, string->string);
			f_name = strdup (string->string);
			rz_name_filter (f_name, -1);
			if (r->bin->prefix) {
				str = rz_str_newf ("%s.str.%s", r->bin->prefix, f_name);
			} else {
				str = rz_str_newf ("str.%s", f_name);
			}
			(void)rz_flag_set (r->flags, str, vaddr, string->size);
			free (str);
			free (f_name);
		} else if (IS_MODE_SIMPLE (mode)) {
			rz_cons_printf ("0x%"PFMT64x" %d %d %s\n", vaddr,
				string->size, string->length, string->string);
		} else if (IS_MODE_SIMPLEST (mode)) {
			rz_cons_println (string->string);
		} else if (IS_MODE_JSON (mode)) {
			int *block_list;
			pj_o (pj);
			pj_kn (pj, "vaddr", vaddr);
			pj_kn (pj, "paddr", paddr);
			pj_kn (pj, "ordinal", string->ordinal);
			pj_kn (pj, "size", string->size);
			pj_kn (pj, "length", string->length);
			pj_ks (pj, "section", section_name);
			pj_ks (pj, "type", type_string);
			pj_ks (pj, "string", string->string);
			switch (string->type) {
			case RZ_STRING_TYPE_UTF8:
			case RZ_STRING_TYPE_WIDE:
			case RZ_STRING_TYPE_WIDE32:
				block_list = rz_utf_block_list ((const ut8*)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't include block list if
						   just Basic Latin (0x00 - 0x7F) */
						RZ_FREE (block_list);
						break;
					}
					int *block_ptr = block_list;
					pj_k (pj, "blocks");
					pj_a (pj);
					for (; *block_ptr != -1; block_ptr++) {
						const char *utfName = rz_utf_block_name (*block_ptr);
						pj_s (pj, utfName? utfName: "");
					}
					pj_end (pj);
					RZ_FREE (block_list);
				}
			}
			pj_end (pj);
		} else if (IS_MODE_RAD (mode)) {
			char *f_name = strdup (string->string);
			rz_name_filter (f_name, RZ_FLAG_NAME_SIZE);
			char *str = (r->bin->prefix)
				? rz_str_newf ("%s.str.%s", r->bin->prefix, f_name)
				: rz_str_newf ("str.%s", f_name);
			rz_cons_printf ("f %s %u 0x%08"PFMT64x"\n"
				"Cs %u @ 0x%08"PFMT64x"\n",
				str, string->size, vaddr,
				string->size, vaddr);
			free (str);
			free (f_name);
		} else {
			int *block_list;
			char *str = string->string;
			char *no_dbl_bslash_str = NULL;
			if (!r->print->esc_bslash) {
				char *ptr;
				for (ptr = str; *ptr; ptr++) {
					if (*ptr != '\\') {
						continue;
					}
					if (*(ptr + 1) == '\\') {
						if (!no_dbl_bslash_str) {
							no_dbl_bslash_str = strdup (str);
							if (!no_dbl_bslash_str) {
								break;
							}
							ptr = no_dbl_bslash_str + (ptr - str);
						}
						memmove (ptr + 1, ptr + 2, strlen (ptr + 2) + 1);
					}
				}
				if (no_dbl_bslash_str) {
					str = no_dbl_bslash_str;
				}
			}

			RzStrBuf *buf = rz_strbuf_new (str);
			switch (string->type) {
			case RZ_STRING_TYPE_UTF8:
			case RZ_STRING_TYPE_WIDE:
			case RZ_STRING_TYPE_WIDE32:
				block_list = rz_utf_block_list ((const ut8*)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't show block list if
						   just Basic Latin (0x00 - 0x7F) */
						break;
					}
					int *block_ptr = block_list;
					rz_strbuf_append (buf, " blocks=");
					for (; *block_ptr != -1; block_ptr++) {
						if (block_ptr != block_list) {
							rz_strbuf_append (buf, ",");
						}
						const char *name = rz_utf_block_name (*block_ptr);
						rz_strbuf_appendf (buf,"%s", name? name: "");
					}
					free (block_list);
				}
				break;
			}
			char *bufstr = rz_strbuf_drain (buf);
			rz_table_add_rowf (table, "nXXddsss", (ut64)string->ordinal, paddr, vaddr,
				(int)string->length, (int)string->size, section_name,
				type_string, bufstr);
			free (bufstr);
			free (no_dbl_bslash_str);
		}
	}
	RZ_FREE (b64.string);
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		rz_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		pj = NULL;
	} else if (IS_MODE_SET (mode)) {
		rz_cons_break_pop ();
	} else if (IS_MODE_NORMAL (mode)) {
		if (r->table_query) {
			rz_table_query (table, r->table_query);
		}
		char *s = rz_table_tostring (table);
		if (s) {
			rz_cons_printf ("%s", s);
			free (s);
		}

	}
	rz_table_free (table);
}

static bool bin_raw_strings(RzCore *r, int mode, int va) {
	RzBinFile *bf = rz_bin_cur (r->bin);
	bool new_bf = false;
	if (bf && strstr (bf->file, "malloc://")) {
		//sync bf->buf to search string on it
		ut8 *tmp = RZ_NEWS (ut8, bf->size);
		if (!tmp) {
			return false;
		}
		rz_io_read_at (r->io, 0, tmp, bf->size);
		rz_buf_write_at (bf->buf, 0, tmp, bf->size);
	}
	if (!r->file) {
		eprintf ("Core file not open\n");
		if (IS_MODE_JSON (mode)) {
			rz_cons_print ("[]");
			return true;
		}
		return false;
	}
	if (!bf) {
		bf = RZ_NEW0 (RzBinFile);
		if (!bf) {
			return false;
		}
		RzIODesc *desc = rz_io_desc_get (r->io, r->file->fd);
		if (!desc) {
			free (bf);
			return false;
		}
		bf->file = strdup (desc->name);
		bf->size = rz_io_desc_size (desc);
		if (bf->size == UT64_MAX) {
			free (bf);
			return false;
		}
		bf->buf = rz_buf_new_with_io (&r->bin->iob, r->file->fd);
		bf->o = NULL;
		bf->rbin = r->bin;
		new_bf = true;
		va = false;
	}
	RzList *l = rz_bin_raw_strings (bf, 0);
	_print_strings (r, l, mode, va);
	rz_list_free (l);
	if (new_bf) {
		rz_buf_free (bf->buf);
		bf->buf = NULL;
		bf->id = -1;
		rz_bin_file_free (bf);
	}
	return true;
}

static bool bin_strings(RzCore *r, int mode, int va) {
	RzList *list;
	RzBinFile *binfile = rz_bin_cur (r->bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin (binfile);
	int rawstr = rz_config_get_i (r->config, "bin.rawstr");
	if (!binfile || !plugin) {
		return false;
	}
	if (!rz_config_get_i (r->config, "bin.strings")) {
		return false;
	}
	if (plugin->info && plugin->name) {
		if (strcmp (plugin->name, "any") == 0 && !rawstr) {
			if (IS_MODE_JSON (mode)) {
				rz_cons_print ("[]\n");
				return true;
			}
			return false;
		}
	}
	if (!(list = rz_bin_get_strings (r->bin))) {
		return false;
	}
	_print_strings (r, list, mode, va);
	return true;
}

static const char* get_compile_time(Sdb *binFileSdb) {
	Sdb *info_ns = sdb_ns (binFileSdb, "info", false);
	const char *timeDateStamp_string = sdb_const_get (info_ns,
		"image_file_header.TimeDateStamp_string", 0);
	return timeDateStamp_string;
}

static bool is_executable(RzBinObject *obj) {
	RzListIter *it;
	RzBinSection* sec;
	rz_return_val_if_fail (obj, false);
	if (obj->info && obj->info->arch) {
		return true;
	}
	rz_list_foreach (obj->sections, it, sec) {
		if (sec->perm & RZ_PERM_X) {
			return true;
		}
	}
	return false;
}

static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new (0, path, 0);
	sdb_merge (s, db);
	sdb_close (db);
	sdb_free (db);
}

RZ_API void rz_core_anal_type_init(RzCore *core) {
	rz_return_if_fail (core && core->anal);
	const char *dir_prefix = rz_config_get (core->config, "dir.prefix");
	int bits = core->rasm->bits;
	Sdb *types = core->anal->sdb_types;
	// make sure they are empty this is initializing
	sdb_reset (types);
	const char *anal_arch = rz_config_get (core->config, "anal.arch");
	const char *os = rz_config_get (core->config, "asm.os");
	// spaguetti ahead

	const char *dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types.sdb"), dir_prefix);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, anal_arch);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, os);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%d.sdb"),
		dir_prefix, bits);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s-%d.sdb"),
		dir_prefix, os, bits);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s-%d.sdb"),
		dir_prefix, anal_arch, bits);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s-%s.sdb"),
		dir_prefix, anal_arch, os);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s-%s-%d.sdb"),
		dir_prefix, anal_arch, os, bits);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
}

RZ_API void rz_core_anal_cc_init(RzCore *core) {
	const char *dir_prefix = rz_config_get (core->config, "dir.prefix");
	const char *anal_arch = rz_config_get (core->config, "anal.arch");
	int bits = core->anal->bits;
	Sdb *cc = core->anal->sdb_cc;

	char *dbpath = rz_str_newf (RZ_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "cc-%s-%d.sdb"),
		dir_prefix, anal_arch, bits);
	char *dbhomepath = rz_str_newf (RZ_JOIN_3_PATHS ("~", RZ_HOME_SDB_FCNSIGN, "cc-%s-%d.sdb"),
		anal_arch, bits);
	// Avoid sdb reloading
	if (cc->path && !strcmp (cc->path, dbpath) && !strcmp (cc->path, dbhomepath)) {
		return;
	}
	sdb_reset (cc);
	RZ_FREE (cc->path);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (cc, dbpath);
		cc->path = strdup (dbpath);
	}
	if (rz_file_exists (dbhomepath)) {
		sdb_concat_by_path (cc, dbhomepath);
		cc->path = strdup (dbhomepath);
	}
	// same as "tcc `arcc`"
	char *s = rz_reg_profile_to_cc (core->anal->reg);
	if (s) {
		if (!rz_anal_cc_set (core->anal, s)) {
			eprintf ("Warning: Invalid CC from reg profile.\n");
		}
		free (s);
	} else {
		eprintf ("Warning: Cannot derive CC from reg profile.\n");
	}
	if (sdb_isempty (core->anal->sdb_cc)) {
		eprintf ("Warning: Missing calling conventions for '%s'. Deriving it from the regprofile.\n", anal_arch);
	}
}

static int bin_info(RzCore *r, int mode, ut64 laddr) {
	int i, j, v;
	char str[RZ_FLAG_NAME_SIZE];
	RzBinInfo *info = rz_bin_get_info (r->bin);
	RzBinFile *bf = rz_bin_cur (r->bin);
	if (!bf) {
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("{}\n");
		}
		return false;
	}
	RzBinObject *obj = bf->o;
	const char *compiled = NULL;
	bool havecode;

	if (!bf || !info || !obj) {
		if (mode & RZ_MODE_JSON) {
			rz_cons_printf ("{}\n");
			return true;
		}
		return false;
	}
	havecode = is_executable (obj) | (obj->entries != NULL);
	compiled = get_compile_time (bf->sdb);

	if (IS_MODE_SET (mode)) {
		rz_config_set (r->config, "file.type", info->rclass);
		rz_config_set (r->config, "cfg.bigendian",
			      info->big_endian ? "true" : "false");
		if (!info->rclass || strcmp (info->rclass, "fs")) {
			if (info->lang) {
				rz_config_set (r->config, "bin.lang", info->lang);
			}
			rz_config_set (r->config, "asm.os", info->os);
			if (info->rclass && !strcmp (info->rclass, "pe")) {
				rz_config_set (r->config, "anal.cpp.abi", "msvc");
			} else {
				rz_config_set (r->config, "anal.cpp.abi", "itanium");
			}
			rz_config_set (r->config, "asm.arch", info->arch);
			if (info->cpu && *info->cpu) {
				rz_config_set (r->config, "asm.cpu", info->cpu);
			}
			if (info->features && *info->features) {
				rz_config_set (r->config, "asm.features", info->features);
			}
			rz_config_set (r->config, "anal.arch", info->arch);
			snprintf (str, RZ_FLAG_NAME_SIZE, "%i", info->bits);
			rz_config_set (r->config, "asm.bits", str);
			rz_config_set (r->config, "asm.dwarf",
				(RZ_BIN_DBG_STRIPPED & info->dbg_info) ? "false" : "true");
			v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_ALIGN);
			if (v != -1) {
				rz_config_set_i (r->config, "asm.pcalign", v);
			}
		}
		rz_core_anal_type_init (r);
		rz_core_anal_cc_init (r);
		if (info->default_cc && rz_anal_cc_exist (r->anal, info->default_cc)) {
			rz_core_cmdf (r, "k anal/cc/default.cc=%s", info->default_cc);
		}
	} else if (IS_MODE_SIMPLE (mode)) {
		rz_cons_printf ("arch %s\n", info->arch);
		if (info->cpu && *info->cpu) {
			rz_cons_printf ("cpu %s\n", info->cpu);
		}
		rz_cons_printf ("bits %d\n", info->bits);
		rz_cons_printf ("os %s\n", info->os);
		rz_cons_printf ("endian %s\n", info->big_endian? "big": "little");
		v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			rz_cons_printf ("minopsz %d\n", v);
		}
		v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_MAX_OP_SIZE);
		if (v != -1) {
			rz_cons_printf ("maxopsz %d\n", v);
		}
		v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_ALIGN);
		if (v != -1) {
			rz_cons_printf ("pcalign %d\n", v);
		}
	} else if (IS_MODE_RAD (mode)) {
		if (info->type && !strcmp (info->type, "fs")) {
			rz_cons_printf ("e file.type=fs\n");
			rz_cons_printf ("m /root %s 0\n", info->arch);
		} else {
			rz_cons_printf ("e cfg.bigendian=%s\n"
				"e asm.bits=%i\n"
				"e asm.dwarf=%s\n",
				rz_str_bool (info->big_endian),
				info->bits,
				rz_str_bool (RZ_BIN_DBG_STRIPPED &info->dbg_info));
			if (info->lang && *info->lang) {
				rz_cons_printf ("e bin.lang=%s\n", info->lang);
			}
			if (info->rclass && *info->rclass) {
				rz_cons_printf ("e file.type=%s\n",
					info->rclass);
			}
			if (info->os) {
				rz_cons_printf ("e asm.os=%s\n", info->os);
			}
			if (info->arch) {
				rz_cons_printf ("e asm.arch=%s\n", info->arch);
			}
			if (info->cpu && *info->cpu) {
				rz_cons_printf ("e asm.cpu=%s\n", info->cpu);
			}
			if (info->default_cc) {
				rz_cons_printf ("k anal/cc/default.cc=%s", info->default_cc);
			}
			v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_ALIGN);
			if (v != -1) {
				rz_cons_printf ("e asm.pcalign=%d\n", v);
			}
		}
	} else {
		// XXX: if type is 'fs' show something different?
		char *tmp_buf;
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("{");
		}
		pair_str ("arch", info->arch, mode, false);
		if (info->cpu && *info->cpu) {
			pair_str ("cpu", info->cpu, mode, false);
		}
		pair_ut64x ("baddr", rz_bin_get_baddr (r->bin), mode, false);
		pair_ut64 ("binsz", rz_bin_get_size (r->bin), mode, false);
		pair_str ("bintype", info->rclass, mode, false);
		pair_int ("bits", info->bits, mode, false);
		pair_bool ("canary", info->has_canary, mode, false);
		if (info->has_retguard != -1) {
			pair_bool ("retguard", info->has_retguard, mode, false);
		}
		pair_str ("class", info->bclass, mode, false);
		if (info->actual_checksum) {
			/* computed checksum */
			pair_str ("cmp.csum", info->actual_checksum, mode, false);
		}
		pair_str ("compiled", compiled, mode, false);
		pair_str ("compiler", info->compiler, mode, false);
		pair_bool ("crypto", info->has_crypto, mode, false);
		pair_str ("dbg_file", info->debug_file_name, mode, false);
		pair_str ("endian", info->big_endian ? "big" : "little", mode, false);
		if (info->rclass && !strcmp (info->rclass, "mdmp")) {
			tmp_buf = sdb_get (bf->sdb, "mdmp.flags", 0);
			if (tmp_buf) {
				pair_str ("flags", tmp_buf, mode, false);
				free (tmp_buf);
			}
		}
		pair_bool ("havecode", havecode, mode, false);
		if (info->claimed_checksum) {
			/* checksum specified in header */
			pair_str ("hdr.csum", info->claimed_checksum, mode, false);
		}
		pair_str ("guid", info->guid, mode, false);
		pair_str ("intrp", info->intrp, mode, false);
		pair_ut64x ("laddr", laddr, mode, false);
		pair_str ("lang", info->lang, mode, false);
		pair_bool ("linenum", RZ_BIN_DBG_LINENUMS & info->dbg_info, mode, false);
		pair_bool ("lsyms", RZ_BIN_DBG_SYMS & info->dbg_info, mode, false);
		pair_str ("machine", info->machine, mode, false);
		v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_MAX_OP_SIZE);
		if (v != -1) {
			pair_int ("maxopsz", v, mode, false);
		}
		v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			pair_int ("minopsz", v, mode, false);
		}
		pair_bool ("nx", info->has_nx, mode, false);
		pair_str ("os", info->os, mode, false);
		if (info->rclass && !strcmp (info->rclass, "pe")) {
			pair_bool ("overlay", info->pe_overlay, mode, false);
		}
		pair_str ("cc", info->default_cc, mode, false);
		v = rz_anal_archinfo (r->anal, RZ_ANAL_ARCHINFO_ALIGN);
		if (v != -1) {
			pair_int ("pcalign", v, mode, false);
		}
		pair_bool ("pic", info->has_pi, mode, false);
		pair_bool ("relocs", RZ_BIN_DBG_RELOCS & info->dbg_info, mode, false);
		Sdb *sdb_info = sdb_ns (obj->kv, "info", false);
		tmp_buf = sdb_get (sdb_info, "elf.relro", 0);
		if (tmp_buf) {
			pair_str ("relro", tmp_buf, mode, false);
			free (tmp_buf);
		}
		pair_str ("rpath", info->rpath, mode, false);
		if (info->rclass && !strcmp (info->rclass, "pe")) {
			//this should be moved if added to mach0 (or others)
			pair_bool ("signed", info->signature, mode, false);
		}
		pair_bool ("sanitiz", info->has_sanitizers, mode, false);
		pair_bool ("static", rz_bin_is_static (r->bin), mode, false);
		if (info->rclass && !strcmp (info->rclass, "mdmp")) {
			v = sdb_num_get (bf->sdb, "mdmp.streams", 0);
			if (v != -1) {
				pair_int ("streams", v, mode, false);
			}
		}
		pair_bool ("stripped", RZ_BIN_DBG_STRIPPED & info->dbg_info, mode, false);
		pair_str ("subsys", info->subsystem, mode, false);
		pair_bool ("va", info->has_va, mode, true);
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf (",\"checksums\":{");
			for (i = 0; info->sum[i].type; i++) {
				RzBinHash *h = &info->sum[i];
				ut64 hash = rz_hash_name_to_bits (h->type);
				RzHash *rh = rz_hash_new (true, hash);
				ut8 *tmp = RZ_NEWS (ut8, h->to);
				if (!tmp) {
					return false;
				}
				rz_buf_read_at (bf->buf, h->from, tmp, h->to);
				int len = rz_hash_calculate (rh, hash, tmp, h->to);
				free (tmp);
				if (len < 1) {
					eprintf ("Invalid checksum length\n");
				}
				rz_hash_free (rh);
				rz_cons_printf ("%s\"%s\":{\"hex\":\"", i?",": "", h->type);
				// rz_cons_printf ("%s\t%d-%dc\t", h->type, h->from, h->to+h->from);
				for (j = 0; j < h->len; j++) {
					rz_cons_printf ("%02x", h->buf[j]);
				}
				rz_cons_printf ("\"}");
			}
			rz_cons_printf ("}");
		} else {
			for (i = 0; info->sum[i].type; i++) {
				RzBinHash *h = &info->sum[i];
				ut64 hash = rz_hash_name_to_bits (h->type);
				RzHash *rh = rz_hash_new (true, hash);
				ut8 *tmp = RZ_NEWS (ut8, h->to);
				if (!tmp) {
					return false;
				}
				rz_buf_read_at (bf->buf, h->from, tmp, h->to);
				int len = rz_hash_calculate (rh, hash, tmp, h->to);
				free (tmp);
				if (len < 1) {
					eprintf ("Invalid wtf\n");
				}
				rz_hash_free (rh);
				rz_cons_printf ("%s  %" PFMT64u "-%" PFMT64u "c  ", h->type, h->from, h->to+h->from);
				for (j = 0; j < h->len; j++) {
					rz_cons_printf ("%02x", h->buf[j]);
				}
				rz_cons_newline ();
			}
		}
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("}\n");
		}
	}
	const char *dir_prefix = rz_config_get (r->config, "dir.prefix");
	char *spath = sdb_fmt ("%s/"RZ_SDB_FCNSIGN"/spec.sdb", dir_prefix);
	if (rz_file_exists (spath)) {
		sdb_concat_by_path (r->anal->sdb_fmts, spath);
	}
	return true;
}

typedef struct {
	size_t *line_starts;
	char *content;
	size_t line_count;
} FileLines;

static void file_lines_free(FileLines *file) {
	if (!file) {
		return;
	}
	free (file->line_starts);
	free (file->content);
	free (file);
}

FileLines *read_file_lines(const char *path) {
	FileLines *result = RZ_NEW0 (FileLines);
	if (!result) {
		return result;
	}
	result->content = rz_file_slurp (path, NULL);
	if (result->content) {
		result->line_starts = rz_str_split_lines (result->content, &result->line_count);
	}
	if (!result->content || !result->line_starts) {
		RZ_FREE (result);
	}
	return result;
}

static void file_lines_free_kv(HtPPKv *kv) {
	free (kv->key);
	file_lines_free (kv->value);
}

static int bin_dwarf(RzCore *core, int mode) {
	RzBinDwarfRow *row;
	RzListIter *iter;
	if (!rz_config_get_i (core->config, "bin.dbginfo")) {
		return false;
	}
	RzBinFile *binfile = rz_bin_cur (core->bin);
	RzBinPlugin * plugin = rz_bin_file_cur_plugin (binfile);
	if (!binfile) {
		return false;
	}
	RzList *list = NULL;
	RzList *ownlist = NULL;
	if (plugin && plugin->lines) {
		// list is not cloned to improve speed. avoid use after free
		list = plugin->lines (binfile);
	} else if (core->bin) {
		// TODO: complete and speed-up support for dwarf
		RzBinDwarfDebugAbbrev *da = NULL;
		da = rz_bin_dwarf_parse_abbrev (core->bin, mode);
		RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info (da, core->bin, mode);
		HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc (core->bin, core->anal->bits / 8);
		// I suppose there is no reason the parse it for a printing purposes
		if (info && mode != RZ_MODE_PRINT) {
			/* Should we do this by default? */
			RzAnalDwarfContext ctx = {
				.info = info,
				.loc = loc_table
			};
			rz_anal_dwarf_process_info (core->anal, &ctx);
		}
		if (loc_table) {
			if (mode == RZ_MODE_PRINT) {
				rz_bin_dwarf_print_loc (loc_table, core->anal->bits / 8, rz_cons_printf);
			}
			rz_bin_dwarf_free_loc (loc_table);
		}
		rz_bin_dwarf_free_debug_info (info);
		rz_bin_dwarf_parse_aranges (core->bin, mode);
		list = ownlist = rz_bin_dwarf_parse_line (core->bin, mode);
		rz_bin_dwarf_free_debug_abbrev (da);
	}
	if (!list) {
		return false;
	}

	rz_cons_break_push (NULL, NULL);
	/* cache file:line contents */
	HtPP* file_lines = ht_pp_new (NULL, file_lines_free_kv, NULL);

	PJ *j = NULL;
	if (IS_MODE_JSON (mode)) {
		j = pj_new ();
		pj_a (j);
	}

	//TODO we should need to store all this in sdb, or do a filecontentscache in librz/util
	//XXX this whole thing has leaks
	rz_list_foreach (list, iter, row) {
		if (rz_cons_is_breaked ()) {
			break;
		}
		if (mode) {
			// TODO: use 'Cl' instead of CC
			const char *path = row->file;
			FileLines *current_lines = ht_pp_find (file_lines, path, NULL);
			if (!current_lines) {
				current_lines = read_file_lines (path);
				if (!ht_pp_insert (file_lines, path, current_lines)) {
					file_lines_free (current_lines);
					current_lines = NULL;
				}
			}
			char *line = NULL;

			if (current_lines) {
				int nl = row->line - 1;
				if (nl >= 0 && nl < current_lines->line_count) {
					line = strdup (current_lines->content + current_lines->line_starts[nl]);
				}
			}
			if (line) {
				rz_str_filter (line, strlen (line));
				line = rz_str_replace (line, "\"", "\\\"", 1);
				line = rz_str_replace (line, "\\\\", "\\", 1);
			}
			bool chopPath = !rz_config_get_i (core->config, "dir.dwarf.abspath");
			char *file = strdup (row->file);
			if (chopPath) {
				const char *slash = rz_str_lchr (file, '/');
				if (slash) {
					memmove (file, slash + 1, strlen (slash));
				}
			}
			// TODO: implement internal : if ((mode & RZ_MODE_SET))
			if ((mode & RZ_MODE_SET)) {
				// TODO: use CL here.. but its not necessary.. so better not do anything imho
				// rz_core_cmdf (core, "CL %s:%d 0x%08"PFMT64x, file, (int)row->line, row->address);
#if 0
				char *cmt = rz_str_newf ("%s:%d %s", file, (int)row->line, line? line: "");
				rz_meta_set_string (core->anal, RZ_META_TYPE_COMMENT, row->address, cmt);
				free (cmt);
#endif
			} else if(IS_MODE_JSON(mode)) {
				pj_a (j);

				pj_o (j);
				pj_ks (j, "name", "CC");
				pj_ks (j, "file", file);
				pj_ki (j, "line_num", (int) row->line);
				pj_kn (j, "addr", row->address);
				pj_end (j);

				pj_o (j);
				pj_ks (j, "name", "CL");
				pj_ks (j, "file", file);
				pj_ki (j, "line_num", (int) row->line);
				pj_ks (j, "line", line ? line : "");
				pj_kn (j, "addr", row->address);
				pj_end (j);

				pj_end (j);
			} else {
				rz_cons_printf ("CL %s:%d 0x%08" PFMT64x "\n",
					       file, (int)row->line,
					       row->address);
				rz_cons_printf ("\"CC %s:%d %s\"@0x%" PFMT64x
					       "\n",
					       file, row->line,
					       line ? line : "", row->address);
			}
			free (file);
			free (line);
		} else {
			rz_cons_printf ("0x%08" PFMT64x "\t%s\t%d\n",
				       row->address, row->file, row->line);
		}
	}
	if (IS_MODE_JSON(mode)) {
		pj_end (j);
		rz_cons_printf ("%s", pj_string (j));
		pj_free (j);
		j = NULL;
	}
	rz_cons_break_pop ();
	ht_pp_free (file_lines);
	rz_list_free (ownlist);
	return true;
}

RZ_API bool rz_core_pdb_info(RzCore *core, const char *file, int mode) {
	rz_return_val_if_fail (core && file, false);

	ut64 baddr = rz_config_get_i (core->config, "bin.baddr");
	if (core->bin->cur && core->bin->cur->o && core->bin->cur->o->baddr) {
		baddr = core->bin->cur->o->baddr;
	} else {
		eprintf ("Warning: Cannot find base address, flags will probably be misplaced\n");
	}

	RPdb pdb = RZ_EMPTY;

	pdb.cb_printf = rz_cons_printf;
	if (!init_pdb_parser (&pdb, file)) {
		return false;
	}
	if (!pdb.pdb_parse (&pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb.finish_pdb_parse (&pdb);
		return false;
	}

	switch (mode) {
	case RZ_MODE_SET:
		mode = 's';
		rz_core_cmd0 (core, ".iP*");
		return true;
	case RZ_MODE_JSON:
		mode = 'j';
		break;
	case '*':
	case 1:
		mode = 'r';
		break;
	default:
		mode = 'd'; // default
		break;
	}
	PJ *pj = pj_new ();

	pdb.print_types (&pdb, pj, mode);
	pdb.print_gvars (&pdb, baddr, pj, mode);
	// Save compound types into SDB
	rz_parse_pdb_types (core->anal, &pdb);
	pdb.finish_pdb_parse (&pdb);

	if (mode == 'j') {
		rz_cons_printf ("%s\n", pj_string (pj));
	}
	pj_free (pj);
	return true;
}

static int srclineCmp(const void *a, const void *b) {
	return rz_str_cmp (a, b, -1);
}

static int bin_source(RzCore *r, int mode) {
	RzList *final_list = rz_list_new ();
	RzBinFile * binfile = r->bin->cur;

	if (!binfile) {
		bprintf ("[Error bin file]\n");
		rz_list_free (final_list);
		return false;
	}

	SdbListIter *iter;
	RzListIter *iter2;
	char* srcline;
	SdbKv *kv;
	SdbList *ls = sdb_foreach_list (binfile->sdb_addrinfo, false);
	ls_foreach (ls, iter, kv) {
		char *v = sdbkv_value (kv);
		RzList *list = rz_str_split_list (v, "|", 0);
		srcline = rz_list_get_bottom (list);
		if (srcline) {
			if (!strstr (srcline, "0x")){
				rz_list_append (final_list, srcline);
			}
		}
		rz_list_free (list);
	}
	rz_cons_printf ("[Source file]\n");
	RzList *uniqlist = rz_list_uniq (final_list, srclineCmp);
	rz_list_foreach (uniqlist, iter2, srcline) {
		rz_cons_printf ("%s\n", srcline);
	}
	rz_list_free (uniqlist);
	rz_list_free (final_list);
	return true;
}

static int bin_main(RzCore *r, int mode, int va) {
	RzBinAddr *binmain = rz_bin_get_sym (r->bin, RZ_BIN_SYM_MAIN);
	ut64 addr;
	if (!binmain) {
		return false;
	}
	addr = va ? rz_bin_a2b (r->bin, binmain->vaddr) : binmain->paddr;

	if (IS_MODE_SET (mode)) {
		rz_flag_space_set (r->flags, RZ_FLAGS_FS_SYMBOLS);
		rz_flag_set (r->flags, "main", addr, r->blocksize);
	} else if (IS_MODE_SIMPLE (mode)) {
		rz_cons_printf ("%"PFMT64d, addr);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_printf ("fs symbols\n");
		rz_cons_printf ("f main @ 0x%08"PFMT64x"\n", addr);
	} else if (IS_MODE_JSON (mode)) {
		rz_cons_printf ("{\"vaddr\":%" PFMT64d
			",\"paddr\":%" PFMT64d "}", addr, binmain->paddr);
	} else {
		rz_cons_printf ("[Main]\n");
		rz_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x"\n",
			addr, binmain->paddr);
	}
	return true;
}

static inline bool is_initfini(RzBinAddr *entry) {
	switch (entry->type) {
	case RZ_BIN_ENTRY_TYPE_INIT:
	case RZ_BIN_ENTRY_TYPE_FINI:
	case RZ_BIN_ENTRY_TYPE_PREINIT:
		return true;
	default:
		return false;
	}
}

static int bin_entry(RzCore *r, int mode, ut64 laddr, int va, bool inifin) {
	char str[RZ_FLAG_NAME_SIZE];
	RzList *entries = rz_bin_get_entries (r->bin);
	RzListIter *iter;
	RzListIter *last_processed = NULL;
	RzBinAddr *entry = NULL;
	int i = 0, init_i = 0, fini_i = 0, preinit_i = 0;
	ut64 baddr = rz_bin_get_baddr (r->bin);

	if (IS_MODE_RAD (mode)) {
		rz_cons_printf ("fs symbols\n");
	} else if (IS_MODE_JSON (mode)) {
		rz_cons_printf ("[");
	} else if (IS_MODE_NORMAL (mode)) {
		if (inifin) {
			rz_cons_printf ("[Constructors]\n");
		} else {
			rz_cons_printf ("[Entrypoints]\n");
		}
	}

	rz_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 hpaddr = UT64_MAX;
		ut64 hvaddr = UT64_MAX;
		if (mode != RZ_MODE_SET) {
			if (inifin) {
				if (entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM) {
					continue;
				}
			} else {
				if (entry->type != RZ_BIN_ENTRY_TYPE_PROGRAM) {
					continue;
				}
			}
		}
		if (entry->hpaddr) {
			hpaddr = entry->hpaddr;
			if (entry->hvaddr) {
				hvaddr = rva (r->bin, hpaddr, entry->hvaddr, va);
			}
		}
		ut64 at = rva (r->bin, paddr, entry->vaddr, va);
		const char *type = rz_bin_entry_type_string (entry->type);
		if (!type) {
			type = "unknown";
		}
		const char *hpaddr_key = (entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM)
		                ? "haddr" : "hpaddr";
		if (IS_MODE_SET (mode)) {
			rz_flag_space_set (r->flags, RZ_FLAGS_FS_SYMBOLS);
			if (entry->type == RZ_BIN_ENTRY_TYPE_INIT) {
				snprintf (str, RZ_FLAG_NAME_SIZE, "entry.init%i", init_i);
			} else if (entry->type == RZ_BIN_ENTRY_TYPE_FINI) {
				snprintf (str, RZ_FLAG_NAME_SIZE, "entry.fini%i", fini_i);
			} else if (entry->type == RZ_BIN_ENTRY_TYPE_PREINIT) {
				snprintf (str, RZ_FLAG_NAME_SIZE, "entry.preinit%i", preinit_i);
			} else {
				snprintf (str, RZ_FLAG_NAME_SIZE, "entry%i", i);
			}
			rz_flag_set (r->flags, str, at, 1);
			if (is_initfini (entry) && hvaddr != UT64_MAX) {
				rz_meta_set (r->anal, RZ_META_TYPE_DATA, hvaddr, entry->bits / 8, NULL);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			rz_cons_printf ("0x%08"PFMT64x"\n", at);
		} else if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("%s{\"vaddr\":%" PFMT64u ","
				"\"paddr\":%" PFMT64u ","
				"\"baddr\":%" PFMT64u ","
				"\"laddr\":%" PFMT64u ",",
				last_processed ? "," : "", at, paddr, baddr, laddr);
			if (hvaddr != UT64_MAX) {
				rz_cons_printf ("\"hvaddr\":%" PFMT64u ",", hvaddr);
			}
			rz_cons_printf ("\"%s\":%" PFMT64u ","
				"\"type\":\"%s\"}",
				hpaddr_key, hpaddr, type);
		} else if (IS_MODE_RAD (mode)) {
			char *name = NULL;
			if (entry->type == RZ_BIN_ENTRY_TYPE_INIT) {
				name = rz_str_newf ("entry.init%i", init_i);
			} else if (entry->type == RZ_BIN_ENTRY_TYPE_FINI) {
				name = rz_str_newf ("entry.fini%i", fini_i);
			} else if (entry->type == RZ_BIN_ENTRY_TYPE_PREINIT) {
				name = rz_str_newf ("entry.preinit%i", preinit_i);
			} else {
				name = rz_str_newf ("entry%i", i);
			}
			char *n = __filterQuotedShell (name);
			rz_cons_printf ("\"f %s 1 0x%08"PFMT64x"\"\n", n, at);
			rz_cons_printf ("\"f %s_%s 1 0x%08"PFMT64x"\"\n", n, hpaddr_key, hpaddr);
			rz_cons_printf ("\"s %s\"\n", n);
			free (n);
			free (name);
		} else {
			rz_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x, at, paddr);
			if (is_initfini (entry) && hvaddr != UT64_MAX) {
				rz_cons_printf (" hvaddr=0x%08"PFMT64x, hvaddr);
			}
			rz_cons_printf (" %s=", hpaddr_key);
			if (hpaddr == UT64_MAX) {
				rz_cons_printf ("%"PFMT64d, hpaddr);
			} else {
				rz_cons_printf ("0x%08"PFMT64x, hpaddr);
			}
			if (entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM && hvaddr != UT64_MAX) {
				rz_cons_printf (" hvaddr=0x%08"PFMT64x, hvaddr);
			}
			rz_cons_printf (" type=%s\n", type);
		}
		if (entry->type == RZ_BIN_ENTRY_TYPE_INIT) {
			init_i++;
		} else if (entry->type == RZ_BIN_ENTRY_TYPE_FINI) {
			fini_i++;
		} else if (entry->type == RZ_BIN_ENTRY_TYPE_PREINIT) {
			preinit_i++;
		} else {
			i++;
		}
		last_processed = iter;
	}
	if (IS_MODE_SET (mode)) {
		if (entry) {
			ut64 at = rva (r->bin, entry->paddr, entry->vaddr, va);
			rz_core_seek (r, at, false);
		}
	} else if (IS_MODE_JSON (mode)) {
		rz_cons_printf ("]");
		rz_cons_newline ();
	} else if (IS_MODE_NORMAL (mode)) {
		rz_cons_printf ("\n%i entrypoints\n", init_i + fini_i + preinit_i + i);
	}
	return true;
}

static const char *bin_reloc_type_name(RzBinReloc *reloc) {
#define CASE(T) case RZ_BIN_RELOC_ ## T: return reloc->additive ? "ADD_" #T : "SET_" #T
	switch (reloc->type) {
	CASE(8);
	CASE(16);
	CASE(32);
	CASE(64);
	}
	return "UNKNOWN";
#undef CASE
}

static ut8 bin_reloc_size(RzBinReloc *reloc) {
#define CASE(T) case RZ_BIN_RELOC_ ## T: return (T) / 8
	switch (reloc->type) {
	CASE(8);
	CASE(16);
	CASE(32);
	CASE(64);
	}
	return 0;
#undef CASE
}

static char *resolveModuleOrdinal(Sdb *sdb, const char *module, int ordinal) {
	Sdb *db = sdb;
	char *foo = sdb_get (db, sdb_fmt ("%d", ordinal), 0);
	return (foo && *foo) ? foo : NULL;
}

// name can be optionally used to explicitly set the used base name (for example for demangling), otherwise the import name will be used.
static char *construct_reloc_name(RZ_NONNULL RzBinReloc *reloc, RZ_NULLABLE const char *name) {
	RzStrBuf *buf = rz_strbuf_new ("");

	// (optional) libname_
	if (reloc->import && reloc->import->libname) {
		rz_strbuf_appendf (buf, "%s_", reloc->import->libname);
	} else if (reloc->symbol && reloc->symbol->libname) {
		rz_strbuf_appendf (buf, "%s_", reloc->symbol->libname);
	}

	// actual name
	if (name) {
		rz_strbuf_append (buf, name);
	} else if (reloc->import && reloc->import->name && *reloc->import->name) {
		rz_strbuf_append (buf, reloc->import->name);
	} else if (reloc->symbol && reloc->symbol->name && *reloc->symbol->name) {
		rz_strbuf_appendf (buf, "%s", reloc->symbol->name);
	} else if (reloc->is_ifunc) {
		// addend is the function pointer for the resolving ifunc
		rz_strbuf_appendf (buf, "ifunc_%"PFMT64x, reloc->addend);
	} else {
		// TODO(eddyb) implement constant relocs.
		rz_strbuf_set (buf, "");
	}

	return rz_strbuf_drain (buf);
}

static void set_bin_relocs(RzCore *r, RzBinReloc *reloc, ut64 addr, Sdb **db, char **sdb_module) {
	int bin_demangle = rz_config_get_i (r->config, "bin.demangle");
	bool keep_lib = rz_config_get_i (r->config, "bin.demangle.libs");
	const char *lang = rz_config_get (r->config, "bin.lang");
	bool is_pe = true;
	int is_sandbox = rz_sandbox_enable (0);

	if (is_pe && !is_sandbox && reloc->import
			&& reloc->import->name && reloc->import->libname
			&& rz_str_startswith (reloc->import->name, "Ordinal_")) {
		char *module = reloc->import->libname;
		rz_str_case (module, false);

		// strip trailing ".dll"
		size_t module_len = strlen (module);
		if (module_len > 4 && !strcmp (module + module_len - 4, ".dll")) {
			module[module_len - 4] = '\0';
		}

		const char *import = reloc->import->name + strlen ("Ordinal_");
		if (import) {
			char *filename = NULL;
			int ordinal = atoi (import);
			if (!*sdb_module || strcmp (module, *sdb_module)) {
				sdb_free (*db);
				*db = NULL;
				free (*sdb_module);
				*sdb_module = strdup (module);
				/* always lowercase */
				filename = sdb_fmt ("%s.sdb", module);
				rz_str_case (filename, false);
				if (rz_file_exists (filename)) {
					*db = sdb_new (NULL, filename, 0);
				} else {
					const char *dirPrefix = rz_sys_prefix (NULL);
					filename = sdb_fmt (RZ_JOIN_4_PATHS ("%s", RZ_SDB_FORMAT, "dll", "%s.sdb"),
						dirPrefix, module);
					if (rz_file_exists (filename)) {
						*db = sdb_new (NULL, filename, 0);
					}
				}
			}
			if (*db) {
				// ordinal-1 because we enumerate starting at 0
				char *symname = resolveModuleOrdinal (*db, module, ordinal - 1);  // uses sdb_get
				if (symname) {
					if (r->bin->prefix) {
						reloc->import->name = rz_str_newf
							("%s.%s", r->bin->prefix, symname);
						RZ_FREE (symname);
					} else {
						reloc->import->name = symname;
					}
				}
			}
		}
		rz_anal_hint_set_size (r->anal, reloc->vaddr, 4);
		rz_meta_set (r->anal, RZ_META_TYPE_DATA, reloc->vaddr, 4, NULL);
	}

	char flagname[RZ_FLAG_NAME_SIZE];
	char *reloc_name = construct_reloc_name (reloc, NULL);
	if (!reloc_name || !*reloc_name) {
		free (reloc_name);
		return;
	}
	if (r->bin->prefix) {
		snprintf (flagname, RZ_FLAG_NAME_SIZE, "%s.reloc.%s", r->bin->prefix, reloc_name);
	} else {
		snprintf (flagname, RZ_FLAG_NAME_SIZE, "reloc.%s", reloc_name);
	}
	free (reloc_name);
	char *demname = NULL;
	if (bin_demangle) {
		demname = rz_bin_demangle (r->bin->cur, lang, flagname, addr, keep_lib);
		if (demname) {
			snprintf (flagname, RZ_FLAG_NAME_SIZE, "reloc.%s", demname);
		}
	}
	rz_name_filter (flagname, 0);
	RzFlagItem *fi = rz_flag_set (r->flags, flagname, addr, bin_reloc_size (reloc));
	if (demname) {
		char *realname;
		if (r->bin->prefix) {
			realname = sdb_fmt ("%s.reloc.%s", r->bin->prefix, demname);
		} else {
			realname = sdb_fmt ("reloc.%s", demname);
		}
		rz_flag_item_set_realname (fi, realname);
	}
	free (demname);
}

/* Define new data at relocation address if it's not in an executable section */
static void add_metadata(RzCore *r, RzBinReloc *reloc, ut64 addr, int mode) {
	RzBinFile * binfile = r->bin->cur;
	RzBinObject *binobj = binfile ? binfile->o: NULL;
	RzBinInfo *info = binobj ? binobj->info: NULL;

	int cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;
	if (cdsz == 0) {
		return;
	}

	RzIOMap *map = rz_io_map_get (r->io, addr);
	if (!map || map ->perm & RZ_PERM_X) {
		return;
	}
	if (IS_MODE_SET (mode)) {
		rz_meta_set (r->anal, RZ_META_TYPE_DATA, reloc->vaddr, cdsz, NULL);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_printf ("Cd %d @ 0x%08" PFMT64x "\n", cdsz, addr);
	}
}

static bool is_section_symbol(RzBinSymbol *s) {
	/* workaround for some bin plugs (e.g. ELF) */
	if (!s || *s->name) {
		return false;
	}
	return (s->type && !strcmp (s->type, RZ_BIN_TYPE_SECTION_STR));
}

static bool is_special_symbol(RzBinSymbol *s) {
	return s->type && !strcmp (s->type, RZ_BIN_TYPE_SPECIAL_SYM_STR);
}

static bool is_section_reloc(RzBinReloc *r) {
	return is_section_symbol (r->symbol);
}

static bool is_file_symbol(RzBinSymbol *s) {
	/* workaround for some bin plugs (e.g. ELF) */
	return (s && s->type && !strcmp (s->type, RZ_BIN_TYPE_FILE_STR));
}

static bool is_file_reloc(RzBinReloc *r) {
	return is_file_symbol (r->symbol);
}

static int bin_relocs(RzCore *r, int mode, int va) {
	bool bin_demangle = rz_config_get_i (r->config, "bin.demangle");
	bool keep_lib = rz_config_get_i (r->config, "bin.demangle.libs");
	const char *lang = rz_config_get (r->config, "bin.lang");
	RTable *table = rz_core_table (r);
	rz_return_val_if_fail (table, false);
	RBIter iter;
	RzBinReloc *reloc = NULL;
	Sdb *db = NULL;
	PJ *pj = NULL;
	char *sdb_module = NULL;
	int i = 0;

	RZ_TIME_PROFILE_BEGIN;

	va = VA_TRUE; // XXX relocs always vaddr?
	//this has been created for reloc object files
	RBNode *relocs = rz_bin_patch_relocs (r->bin);
	if (!relocs) {
		relocs = rz_bin_get_relocs (r->bin);
	}

	if (IS_MODE_RAD (mode)) {
		rz_cons_println ("fs relocs");
	} else if (IS_MODE_NORMAL (mode)) {
		rz_cons_println ("[Relocations]");
		rz_table_set_columnsf (table, "XXss", "vaddr", "paddr", "type", "name");
	} else if (IS_MODE_JSON (mode)) {
		// start a new JSON object
		pj = pj_new ();
		if (pj) {
			pj_a (pj);
		}
	} else if (IS_MODE_SET (mode)) {
		rz_flag_space_set (r->flags, RZ_FLAGS_FS_RELOCS);
	}

	rz_rbtree_foreach (relocs, iter, reloc, RzBinReloc, vrb) {
		ut64 addr = rva (r->bin, reloc->paddr, reloc->vaddr, va);
		if (IS_MODE_SET (mode) && (is_section_reloc (reloc) || is_file_reloc (reloc))) {
			/*
			 * Skip section reloc because they will have their own flag.
			 * Skip also file reloc because not useful for now.
			 */
		} else if (IS_MODE_SET (mode)) {
			set_bin_relocs (r, reloc, addr, &db, &sdb_module);
			add_metadata (r, reloc, addr, mode);
		} else if (IS_MODE_SIMPLE (mode)) {
			rz_cons_printf ("0x%08"PFMT64x"  %s\n", addr, reloc->import ? reloc->import->name : "");
		} else if (IS_MODE_RAD (mode)) {
			char *name = reloc->import
				? strdup (reloc->import->name)
				: (reloc->symbol ? strdup (reloc->symbol->name) : NULL);
			if (name && bin_demangle) {
				char *mn = rz_bin_demangle (r->bin->cur, NULL, name, addr, keep_lib);
				if (mn) {
					free (name);
					name = mn;
				}
			}
			if (name) {
				int reloc_size = 4;
				char *n = __filterQuotedShell (name);
				rz_cons_printf ("\"f %s%s%s %d 0x%08"PFMT64x"\"\n",
					r->bin->prefix ? r->bin->prefix : "reloc.",
					r->bin->prefix ? "." : "", n, reloc_size, addr);
				add_metadata (r, reloc, addr, mode);
				free (n);
				free (name);
			}
		} else if (IS_MODE_JSON (mode)) {
			if (pj) {
				pj_o (pj);
				char *mn = NULL;
				char *relname = NULL;

				// take care with very long symbol names! do not use sdb_fmt or similar
				if (reloc->import) {
					mn = rz_bin_demangle (r->bin->cur, lang, reloc->import->name, addr, keep_lib);
					relname = strdup (reloc->import->name);
				} else if (reloc->symbol) {
					mn = rz_bin_demangle (r->bin->cur, lang, reloc->symbol->name, addr, keep_lib);
					relname = strdup (reloc->symbol->name);
				}

				// check if name is available
				if (relname && *relname) {
					pj_ks (pj, "name", relname);
				}
				pj_ks (pj, "demname", mn ? mn : "");
				pj_ks (pj, "type", bin_reloc_type_name (reloc));
				pj_kn (pj, "vaddr", reloc->vaddr);
				pj_kn (pj, "paddr", reloc->paddr);
				if (reloc->symbol) {
					pj_kn (pj, "sym_va", reloc->symbol->vaddr);
				}
				pj_kb (pj, "is_ifunc", reloc->is_ifunc);
				// end reloc item
				pj_end (pj);

				free (mn);
				if (relname) {
					free (relname);
				}
			}
		} else if (IS_MODE_NORMAL (mode)) {
			char *name = reloc->import
				? strdup (reloc->import->name)
				: reloc->symbol
				? strdup (reloc->symbol->name)
				: NULL;
			if (bin_demangle) {
				char *mn = rz_bin_demangle (r->bin->cur, NULL, name, addr, keep_lib);
				if (mn && *mn) {
					free (name);
					name = mn;
				}
			}
			char *reloc_name = construct_reloc_name (reloc, name);
			RzStrBuf *buf = rz_strbuf_new (reloc_name ? reloc_name : "");
			free (reloc_name);
			RZ_FREE (name);
			if (reloc->addend) {
				if ((reloc->import || reloc->symbol) && !rz_strbuf_is_empty (buf) && reloc->addend > 0) {
					rz_strbuf_append (buf," +");
				}
				if (reloc->addend < 0) {
					rz_strbuf_appendf (buf," - 0x%08"PFMT64x, -reloc->addend);
				} else {
					rz_strbuf_appendf (buf," 0x%08"PFMT64x, reloc->addend);
				}
			}
			if (reloc->is_ifunc) {
				rz_strbuf_append (buf, " (ifunc)");
			}
			char *res = rz_strbuf_drain (buf);
			rz_table_add_rowf (table, "XXss", addr, reloc->paddr,
				bin_reloc_type_name (reloc), res);
			free (res);
		}
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		// close Json output
		pj_end (pj);
		rz_cons_println (pj_string (pj));
	}
	if (IS_MODE_NORMAL (mode)) {
		if (r->table_query) {
			rz_table_query (table, r->table_query);
		}
		char *s = rz_table_tostring (table);
		rz_cons_printf ("\n%s\n", s);
		free (s);
		rz_cons_printf ("\n%i relocations\n", i);

	}

	// free PJ object if used
	if (pj) {
		pj_free (pj);
	}
	rz_table_free (table);
	RZ_FREE (sdb_module);
	sdb_free (db);
	db = NULL;

	RZ_TIME_PROFILE_END;
	if (IS_MODE_JSON (mode) && relocs == NULL) {
		return true;
	}
	return relocs != NULL;
}

#define MYDB 1
/* this is a VERY VERY VERY hacky and bad workaround that needs proper refactoring in Rbin to use Sdb */
#if MYDB
RZ_DEPRECATE static Sdb *mydb = NULL;
RZ_DEPRECATE static RzList *osymbols = NULL;

RZ_DEPRECATE static RzBinSymbol *get_import(RzBin *bin, RzList *symbols, const char *name, ut64 addr) {
	RzBinSymbol *symbol, *res = NULL;
	RzListIter *iter;
	if (mydb && symbols && symbols != osymbols) {
		sdb_free (mydb);
		mydb = NULL;
		osymbols = symbols;
	}
	if (mydb) {
		if (name) {
			res = (RzBinSymbol*)(void*)(size_t)
				sdb_num_get (mydb, sdb_fmt ("%x", sdb_hash (name)), NULL);
		} else {
			res = (RzBinSymbol*)(void*)(size_t)
				sdb_num_get (mydb, sdb_fmt ("0x%08"PFMT64x, addr), NULL);
		}
	} else {
		mydb = sdb_new0 ();
		rz_list_foreach (symbols, iter, symbol) {
			if (!symbol->name || !symbol->is_imported) {
				continue;
			}
			/* ${name}=${ptrToSymbol} */
			if (!sdb_num_add (mydb, sdb_fmt ("%x", sdb_hash (symbol->name)), (ut64)(size_t)symbol, 0)) {
			//	eprintf ("DUP (%s)\n", symbol->name);
			}
			/* 0x${vaddr}=${ptrToSymbol} */
			if (!sdb_num_add (mydb, sdb_fmt ("0x%08"PFMT64x, symbol->vaddr), (ut64)(size_t)symbol, 0)) {
			//	eprintf ("DUP (%s)\n", symbol->name);
			}
			if (name) {
				if (!res && !strcmp (symbol->name, name)) {
					res = symbol;
				}
			} else {
				if (symbol->vaddr == addr) {
					res = symbol;
				}
			}
		}
		osymbols = symbols;
	}
	return res;
}
#else
static RzList *osymbols = NULL;
static RzBinSymbol *get_symbol(RzBin *bin, RzList *symbols, const char *name, ut64 addr) {
	RzBinSymbol *symbol;
	RzListIter *iter;
	// XXX this is slow, we should use a hashtable here
	rz_list_foreach (symbols, iter, symbol) {
		if (name) {
			if (!strcmp (symbol->name, name))
				return symbol;
		} else {
			if (symbol->vaddr == addr) {
				return symbol;
			}
		}
	}
	return NULL;
}
#endif

/* XXX: This is a hack to get PLT references in rz_bin -i */
RZ_API ut64 rz_core_bin_impaddr(RzBin *bin, int va, const char *name) {
	RzList *symbols;

	if (!name || !*name) {
		return false;
	}
	if (!(symbols = rz_bin_get_symbols (bin))) {
		return false;
	}
	RzBinSymbol *s = get_import (bin, symbols, name, 0LL);
	// maybe ut64_MAX to indicate import not found?
	ut64 addr = 0LL;
	if (s) {
		if (va) {
			if (s->paddr == UT64_MAX) {
				addr = s->vaddr;
			} else {
				addr = rz_bin_get_vaddr (bin, s->paddr, s->vaddr);
			}
		} else {
			addr = s->paddr;
		}
	}
	return addr;
}

static int bin_imports(RzCore *r, int mode, int va, const char *name) {
	RzBinInfo *info = rz_bin_get_info (r->bin);
	int bin_demangle = rz_config_get_i (r->config, "bin.demangle");
	bool keep_lib = rz_config_get_i (r->config, "bin.demangle.libs");
	RTable *table = rz_core_table (r);
	rz_return_val_if_fail (table, false);
	RzBinImport *import;
	RzListIter *iter;
	bool lit = info ? info->has_lit: false;
	char *str;
	int i = 0;
	PJ *pj = NULL; 

	if (!info) {
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("[]");
		}
		return false;
	}

	RzList *imports = rz_bin_get_imports (r->bin);
	int cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;
	if (IS_MODE_JSON (mode)) {
		pj = pj_new ();
		pj_a (pj);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_println ("fs imports");
	} else if (IS_MODE_NORMAL (mode)) {
		rz_cons_println ("[Imports]");
		rz_table_set_columnsf (table, "nXssss", "nth", "vaddr", "bind", "type", "lib", "name");
	}
	rz_list_foreach (imports, iter, import) {
		if (name && strcmp (import->name, name)) {
			continue;
		}
		char *symname = strdup (import->name);
		char *libname = import->libname ? strdup (import->libname) : NULL;
		ut64 addr = lit ? rz_core_bin_impaddr (r->bin, va, symname): 0;
		if (bin_demangle) {
			char *dname = rz_bin_demangle (r->bin->cur, NULL, symname, addr, keep_lib);
			if (dname) {
				free (symname);
				symname = rz_str_newf ("sym.imp.%s", dname);
				free (dname);
			}
		}
		if (r->bin->prefix) {
			char *prname = rz_str_newf ("%s.%s", r->bin->prefix, symname);
			free (symname);
			symname = prname;
		}
		if (IS_MODE_SET (mode)) {
			// TODO(eddyb) symbols that are imports.
			// Add a dword/qword for PE imports
			if (libname && strstr (libname, ".dll") && cdsz) {
				rz_meta_set (r->anal, RZ_META_TYPE_DATA, addr, cdsz, NULL);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			rz_cons_printf ("%s%s%s\n",
					libname ? libname : "", libname ? " " : "", symname);
		} else if (IS_MODE_SIMPLEST (mode)) {
			rz_cons_println (symname);
		} else if (IS_MODE_JSON (mode)) {

			pj_o (pj);

			str = rz_str_escape_utf8_for_json (symname, -1);
			str = rz_str_replace (str, "\"", "\\\"", 1);

			pj_ki (pj, "ordinal", import->ordinal);
			if (import->bind) {
				pj_ks (pj, "bind", import->bind);
			}
			if (import->type) {
				pj_ks (pj, "type", import->type);
			}
			if (import->classname && import->classname[0]) {
				pj_ks (pj, "classname", import->classname);
				pj_ks (pj, "descriptor", import->descriptor);
			}
			pj_ks (pj, "name", str);
			if (libname) {
				pj_ks (pj, "libname", libname);
			}
			pj_kn (pj, "plt", addr);
			pj_end (pj);
			free (str);
		} else if (IS_MODE_RAD (mode)) {
			// TODO(eddyb) symbols that are imports.
		} else {
			const char *bind = import->bind? import->bind: "NONE";
			const char *type = import->type? import->type: "NONE";
			if (import->classname && import->classname[0]) {
				rz_table_add_rowf (table, "nXssss", (ut64)import->ordinal, addr, bind, type, libname ? libname : "", sdb_fmt ("%s.%s", import->classname, symname));
			} else {
				rz_table_add_rowf (table, "nXssss", (ut64)import->ordinal, addr, bind, type, libname ? libname : "", symname);
			}

			if (import->descriptor && import->descriptor[0]) {
				// Uh?
				rz_cons_printf (" descriptor=%s", import->descriptor);
			}
			if (!IS_MODE_NORMAL (mode)) {
				rz_cons_newline ();
			}
		}
		RZ_FREE (symname);
		RZ_FREE (libname);
		i++;
	}

	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	} else if (IS_MODE_NORMAL (mode)) {
		if (r->table_query) {
			rz_table_query (table, r->table_query);
		}
		char *s = rz_table_tostring (table);
		rz_cons_printf ("%s\n", s);
		free (s);
	}

	if (pj) {
		pj_end (pj);
		rz_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}

	rz_table_free (table);
#if MYDB
	// NOTE: if we comment out this, it will leak.. but it will be faster
	// because it will keep the cache across multiple RzBin calls
	osymbols = NULL;
	sdb_free (mydb);
	mydb = NULL;
#endif
	return true;
}

static const char *getPrefixFor(RzBinSymbol *sym) {
	if (sym) {
		// workaround for ELF
		if (sym->type) {
			if (!strcmp (sym->type, RZ_BIN_TYPE_NOTYPE_STR)) {
				return sym->is_imported ? "loc.imp" : "loc";
			}
			if (!strcmp (sym->type, RZ_BIN_TYPE_OBJECT_STR)) {
				return sym->is_imported ? "obj.imp" : "obj";
			}
		}
		return sym->is_imported ? "sym.imp" : "sym";
	}
	return "sym";
}

#define MAXFLAG_LEN_DEFAULT 128

static char *construct_symbol_flagname(const char *pfx, const char *libname, const char *symname, int len) {
	char *r = rz_str_newf ("%s.%s%s%s", pfx, libname ? libname : "", libname ? "_" : "", symname);
	if (r) {
		rz_name_filter (r, len); // maybe unnecessary..
		char *R = __filterQuotedShell (r);
		free (r);
		return R;
	}
	return NULL;
}

typedef struct {
	const char *pfx; // prefix for flags
	char *name;      // raw symbol name
	char *libname;   // name of the lib this symbol is specific to, if any
	char *nameflag;  // flag name for symbol
	char *demname;   // demangled raw symbol name
	char *demflag;   // flag name for demangled symbol
	char *classname; // classname
	char *classflag; // flag for classname
	char *methname;  // methods [class]::[method]
	char *methflag;  // methods flag sym.[class].[method]
} SymName;

static void snInit(RzCore *r, SymName *sn, RzBinSymbol *sym, const char *lang) {
	int bin_demangle = lang != NULL;
	bool keep_lib = rz_config_get_i (r->config, "bin.demangle.libs");
	if (!r || !sym || !sym->name) {
		return;
	}
	sn->name = rz_str_newf ("%s%s", sym->is_imported ? "imp." : "", sym->name);
	sn->libname = sym->libname ? strdup (sym->libname) : NULL;
	const char *pfx = getPrefixFor (sym);
	sn->nameflag = construct_symbol_flagname (pfx, sym->libname, rz_bin_symbol_name (sym), MAXFLAG_LEN_DEFAULT);
	if (sym->classname && sym->classname[0]) {
		sn->classname = strdup (sym->classname);
		sn->classflag = rz_str_newf ("sym.%s.%s", sn->classname, sn->name);
		rz_name_filter (sn->classflag, MAXFLAG_LEN_DEFAULT);
		const char *name = sym->dname? sym->dname: sym->name;
		sn->methname = rz_str_newf ("%s::%s", sn->classname, name);
		sn->methflag = rz_str_newf ("sym.%s.%s", sn->classname, name);
		rz_name_filter (sn->methflag, strlen (sn->methflag));
	} else {
		sn->classname = NULL;
		sn->classflag = NULL;
		sn->methname = NULL;
		sn->methflag = NULL;
	}
	sn->demname = NULL;
	sn->demflag = NULL;
	if (bin_demangle && sym->paddr) {
		sn->demname = rz_bin_demangle (r->bin->cur, lang, sn->name, sym->vaddr, keep_lib);
		if (sn->demname) {
			sn->demflag = construct_symbol_flagname (pfx, sym->libname, sn->demname, -1);
		}
	}
}

static void snFini(SymName *sn) {
	RZ_FREE (sn->name);
	RZ_FREE (sn->libname);
	RZ_FREE (sn->nameflag);
	RZ_FREE (sn->demname);
	RZ_FREE (sn->demflag);
	RZ_FREE (sn->classname);
	RZ_FREE (sn->classflag);
	RZ_FREE (sn->methname);
	RZ_FREE (sn->methflag);
}

static bool isAnExport(RzBinSymbol *s) {
	/* workaround for some bin plugs */
	if (s->is_imported) {
		return false;
	}
	return (s->bind && !strcmp (s->bind, RZ_BIN_BIND_GLOBAL_STR));
}

static ut64 compute_addr(RzBin *bin, ut64 paddr, ut64 vaddr, int va) {
	return paddr == UT64_MAX? vaddr: rva (bin, paddr, vaddr, va);
}

static void handle_arm_special_symbol(RzCore *core, RzBinSymbol *symbol, int va) {
	ut64 addr = compute_addr (core->bin, symbol->paddr, symbol->vaddr, va);
	if (!strcmp (symbol->name, "$a")) {
		rz_anal_hint_set_bits (core->anal, addr, 32);
	} else if (!strcmp (symbol->name, "$x")) {
		rz_anal_hint_set_bits (core->anal, addr, 64);
	} else if (!strcmp (symbol->name, "$t")) {
		rz_anal_hint_set_bits (core->anal, addr, 16);
	} else if (!strcmp (symbol->name, "$d")) {
		// TODO: we could add data meta type at addr, but sometimes $d
		// is in the middle of the code and it would make the code less
		// readable.
	} else {
		if (core->bin->verbose) {
			RZ_LOG_WARN ("Special symbol %s not handled\n", symbol->name);
		}
	}
}

static void handle_arm_hint(RzCore *core, RzBinInfo *info, ut64 paddr, ut64 vaddr, int bits, int va) {
	if (info->bits > 32) { // we look at 16 or 32 bit only
		return;
	}

	int force_bits = 0;
	ut64 addr = compute_addr (core->bin, paddr, vaddr, va);
	if (paddr & 1 || bits == 16) {
		force_bits = 16;
	} else if (info->bits == 16 && bits == 32) {
		force_bits = 32;
	} else if (!(paddr & 1) && bits == 32) {
		force_bits = 32;
	}
	if (force_bits) {
		rz_anal_hint_set_bits (core->anal, addr, force_bits);
	}
}

static void handle_arm_symbol(RzCore *core, RzBinSymbol *symbol, RzBinInfo *info, int va) {
	handle_arm_hint (core, info, symbol->paddr, symbol->vaddr, symbol->bits, va);
}

static void handle_arm_entry(RzCore *core, RzBinAddr *entry, RzBinInfo *info, int va) {
	handle_arm_hint (core, info, entry->paddr, entry->vaddr, entry->bits, va);
}

static void select_flag_space(RzCore *core, RzBinSymbol *symbol) {
	if (symbol->is_imported) {
		rz_flag_space_push (core->flags, RZ_FLAGS_FS_IMPORTS);
	} else if (symbol->type && !strcmp (symbol->type, RZ_BIN_TYPE_SECTION_STR)) {
		rz_flag_space_push (core->flags, RZ_FLAGS_FS_SYMBOLS_SECTIONS);
	} else {
		rz_flag_space_push (core->flags, RZ_FLAGS_FS_SYMBOLS);
	}
}

static int bin_symbols(RzCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, bool exponly, const char *args) {
	RzBinInfo *info = rz_bin_get_info (r->bin);
	RzList *entries = rz_bin_get_entries (r->bin);
	RzBinSymbol *symbol;
	RzBinAddr *entry;
	RzListIter *iter;
	bool firstexp = true;
	bool printHere = (args && *args == '.');

	int i = 0, lastfs = 's';
	RTable *table = rz_core_table (r);
	bool bin_demangle = rz_config_get_i (r->config, "bin.demangle");
	if (!info) {
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf (printHere? "{}": "[]\n");
		}
		rz_table_free (table);
		return 0;
	}

	PJ *pj = pj_new ();
	bool is_arm = info && info->arch && !strncmp (info->arch, "arm", 3);
	const char *lang = bin_demangle ? rz_config_get (r->config, "bin.lang") : NULL;

	RzList *symbols = rz_bin_get_symbols (r->bin);
	rz_spaces_push (&r->anal->meta_spaces, "bin");

	if (IS_MODE_JSON (mode) && !printHere) {
		pj_a (pj);
	} else if (IS_MODE_SET (mode)) {
		rz_flag_space_set (r->flags, RZ_FLAGS_FS_SYMBOLS);
	} else if (at == UT64_MAX && exponly) {
		if (IS_MODE_RAD (mode)) {
			rz_cons_printf ("fs exports\n");
		} else if (IS_MODE_NORMAL (mode)) {
			rz_cons_printf (printHere ? "" : "[Exports]\n");
		}
	} else if (at == UT64_MAX && !exponly) {
		if (IS_MODE_RAD (mode)) {
			rz_cons_printf ("fs symbols\n");
		} else if (IS_MODE_NORMAL (mode)) {
			rz_cons_printf (printHere ? "" : "[Symbols]\n");
		}
	}
	if (IS_MODE_NORMAL (mode)) {
		rz_table_set_columnsf (table, "dssssdss", "nth", "paddr","vaddr","bind", "type", "size", "lib", "name");
	}

	size_t count = 0;
	rz_list_foreach (symbols, iter, symbol) {
		if (!symbol->name) {
			continue;
		}
		if (exponly && !isAnExport (symbol)) {
			continue;
		}
		if (name && strcmp (symbol->name, name)) {
			continue;
		}
		ut64 addr = compute_addr (r->bin, symbol->paddr, symbol->vaddr, va);
		ut32 len = symbol->size ? symbol->size : 32;
		if (at != UT64_MAX && (!symbol->size || !is_in_range (at, addr, symbol->size))) {
			continue;
		}
		if ((printHere && !is_in_range (r->offset, symbol->paddr, len))
			&& (printHere && !is_in_range (r->offset, addr, len))) {
			continue;
		}
		SymName sn = {0};
		count ++;
		snInit (r, &sn, symbol, lang);
		char *rz_symbol_name = rz_str_escape_utf8 (sn.name, false, true);

		if (IS_MODE_SET (mode) && (is_section_symbol (symbol) || is_file_symbol (symbol))) {
			/*
			 * Skip section symbols because they will have their own flag.
			 * Skip also file symbols because not useful for now.
			 */
		} else if (IS_MODE_SET (mode) && is_special_symbol (symbol)) {
			if (is_arm) {
				handle_arm_special_symbol (r, symbol, va);
			}
		} else if (IS_MODE_SET (mode)) {
			// TODO: provide separate API in RzBinPlugin to let plugins handle anal hints/metadata
			if (is_arm) {
				handle_arm_symbol (r, symbol, info, va);
			}
			select_flag_space (r, symbol);
			/* If that's a Classed symbol (method or so) */
			if (sn.classname) {
				RzFlagItem *fi = rz_flag_get (r->flags, sn.methflag);
				if (r->bin->prefix) {
					char *prname = rz_str_newf ("%s.%s", r->bin->prefix, sn.methflag);
					rz_name_filter (sn.methflag, -1);
					free (sn.methflag);
					sn.methflag = prname;
				}
				if (fi) {
					rz_flag_item_set_realname (fi, sn.methname);
					if ((fi->offset - r->flags->base) == addr) {
				//		char *comment = fi->comment ? strdup (fi->comment) : NULL;
						rz_flag_unset (r->flags, fi);
					}
				} else {
					fi = rz_flag_set (r->flags, sn.methflag, addr, symbol->size);
					char *comment = fi->comment ? strdup (fi->comment) : NULL;
					if (comment) {
						rz_flag_item_set_comment (fi, comment);
						RZ_FREE (comment);
					}
				}
			} else {
				const char *n = sn.demname ? sn.demname : symbol->name;
				const char *fn = sn.demflag ? sn.demflag : sn.nameflag;
				char *fnp = (r->bin->prefix) ?
					rz_str_newf ("%s.%s", r->bin->prefix, fn):
					strdup (fn? fn: "");
				RzFlagItem *fi = rz_flag_set (r->flags, fnp, addr, symbol->size);
				if (fi) {
					rz_flag_item_set_realname (fi, n);
					fi->demangled = (bool)(size_t)sn.demname;
				} else {
					if (fn) {
						eprintf ("[Warning] Can't find flag (%s)\n", fn);
					}
				}
				free (fnp);
			}
			if (sn.demname) {
				ut64 size = symbol->size? symbol->size: 1;
				rz_meta_set (r->anal, RZ_META_TYPE_COMMENT,
							addr, size, sn.demname);
			}
			rz_flag_space_pop (r->flags);
		} else if (IS_MODE_JSON (mode)) {
			char *str = rz_str_escape_utf8_for_json (rz_symbol_name, -1);
			pj_o (pj);
			pj_ks (pj, "name", str);
			if (sn.demname) {
				pj_ks (pj, "demname", sn.demname);
			}
			pj_ks (pj, "flagname", sn.nameflag);
			pj_ks (pj, "realname", symbol->name);
			pj_ki (pj, "ordinal", symbol->ordinal);
			pj_ks (pj, "bind", symbol->bind);
			pj_kn (pj, "size", (ut64)symbol->size);
			pj_ks (pj, "type", symbol->type);
			pj_kn (pj, "vaddr", addr);
			pj_kn (pj, "paddr", symbol->paddr);
			pj_kb (pj, "is_imported", symbol->is_imported);
			pj_end (pj);
			free (str);
		} else if (IS_MODE_SIMPLE (mode)) {
			const char *name = sn.demname? sn.demname: rz_symbol_name;
			rz_cons_printf ("0x%08"PFMT64x" %d %s%s%s\n",
				addr, (int)symbol->size,
				sn.libname ? sn.libname : "", sn.libname ? " " : "",
				name);
		} else if (IS_MODE_SIMPLEST (mode)) {
			const char *name = sn.demname? sn.demname: rz_symbol_name;
			rz_cons_printf ("%s\n", name);
		} else if (IS_MODE_RAD (mode)) {
			/* Skip special symbols because we do not flag them and
			 * they shouldn't be printed in the rad format either */
			if (is_special_symbol (symbol)) {
				goto next;
			}
			RzBinFile *binfile;
			RzBinPlugin *plugin;
			const char *name = sn.demname? sn.demname: rz_symbol_name;
			if (!name) {
				goto next;
			}
			if (symbol->is_imported) {
				if (lastfs != 'i') {
					rz_cons_printf ("fs imports\n");
				}
				lastfs = 'i';
			} else {
				if (lastfs != 's') {
					const char *fs = exponly? "exports": "symbols";
					rz_cons_printf ("fs %s\n", fs);
				}
				lastfs = 's';
			}
			if (r->bin->prefix || *name) { // we don't want unnamed symbol flags
				char *flagname = construct_symbol_flagname ("sym", sn.libname, name, MAXFLAG_LEN_DEFAULT);
				if (!flagname) {
					goto next;
				}
				rz_cons_printf ("\"f %s%s%s %u 0x%08" PFMT64x "\"\n",
					r->bin->prefix ? r->bin->prefix : "", r->bin->prefix ? "." : "",
					flagname, symbol->size, addr);
				free (flagname);
			}
			binfile = rz_bin_cur (r->bin);
			plugin = rz_bin_file_cur_plugin (binfile);
			if (plugin && plugin->name) {
				if (rz_str_startswith (plugin->name, "pe")) {
					char *module = strdup (rz_symbol_name);
					char *p = strstr (module, ".dll_");
					if (p && symbol->is_imported) {
						char *symname = __filterShell (p + 5);
						char *m = __filterShell (module);
						*p = 0;
						if (r->bin->prefix) {
							rz_cons_printf ("\"k bin/pe/%s/%d=%s.%s\"\n",
								module, symbol->ordinal, r->bin->prefix, symname);
						} else {
							rz_cons_printf ("\"k bin/pe/%s/%d=%s\"\n",
								module, symbol->ordinal, symname);
						}
						free (symname);
						free (m);
					}
					free (module);
				}
			}
		} else {
			const char *bind = symbol->bind? symbol->bind: "NONE";
			const char *type = symbol->type? symbol->type: "NONE";
			const char *name = rz_str_get (sn.demname? sn.demname: sn.name);
			// const char *fwd = rz_str_get (symbol->forwarder);
			rz_table_add_rowf (table, "dssssdss",
					symbol->ordinal,
					symbol->paddr == UT64_MAX ? " ----------": sdb_fmt (" 0x%08"PFMT64x, symbol->paddr),
					sdb_fmt("0x%08"PFMT64x, addr),
					bind,
					type,
					symbol->size,
					symbol->libname ? symbol->libname : "",
					name);
		}
next:
		snFini (&sn);
		i++;
		free (rz_symbol_name);
		if (exponly && firstexp) {
			firstexp = false;
		}
		if (printHere) {
			break;
		}
	}
	if (IS_MODE_NORMAL (mode)){
		if (r->table_query) {
			rz_table_query (table, r->table_query);
		}
		char *s = rz_table_tostring (table);
		rz_cons_printf ("\n%s", s);
		free (s);
	}

	//handle thumb and arm for entry point since they are not present in symbols
	if (is_arm) {
		rz_list_foreach (entries, iter, entry) {
			if (IS_MODE_SET (mode)) {
				handle_arm_entry (r, entry, info, va);
			}
		}
	}
	if (IS_MODE_JSON (mode)) {
		if (!printHere) {
			pj_end (pj);
		}
		const char *js = pj_string (pj);
		rz_cons_printf ("%s\n", (js && *js)? js: "{}");
	}
	pj_free (pj);

	rz_spaces_pop (&r->anal->meta_spaces);
	rz_table_free (table);
	return true;
}

static char *build_hash_string(int mode, const char *chksum, ut8 *data, ut32 datalen) {
	char *chkstr = NULL, *aux, *ret = NULL;
	RzList *hashlist = rz_str_split_duplist (chksum, ",", true);
	RzListIter *iter;
	char *hashname;
	rz_list_foreach (hashlist, iter, hashname) {
		chkstr = rz_hash_to_string (NULL, hashname, data, datalen);
		if (!chkstr) {
			continue;
		}
		if (IS_MODE_SIMPLE (mode) || IS_MODE_NORMAL (mode)) {
			aux = rz_str_newf (iter->n? "%s " : "%s", chkstr);
		} else if (IS_MODE_JSON (mode)) {
			aux = rz_str_newf ("\"%s\":\"%s\",", hashname, chkstr);
		} else {
			aux = rz_str_newf ("%s=%s ", hashname, chkstr);
		}
		ret = rz_str_append (ret, aux);
		free (chkstr);
		free (aux);
	}
	rz_list_free (hashlist);
	return ret;
}

static char *filter_hash_string(const char *chksum) {
	if (!chksum) {
		return NULL;
	}

	char *aux, *ret = NULL;
	bool isFirst = true;
	RzList *hashlist = rz_str_split_duplist (chksum, ",", true);
	RzListIter *iter;
	char *hashname;
	rz_list_foreach (hashlist, iter, hashname) {
		if (rz_hash_name_to_bits (hashname)) {
			aux = rz_str_newf (isFirst? "%s" : ", %s", hashname);
			ret = rz_str_append (ret, aux);
			free (aux);
			if (isFirst) {
				isFirst = false;
			}
		}
	}
	rz_list_free (hashlist);
	return ret;
}

typedef struct {
	const char *uri;
	int perm;
	RzIODesc *desc;
} FindFile;

static bool findFile(void *user, void *data, ut32 id) {
	FindFile *res = (FindFile*)user;
	RzIODesc *desc = (RzIODesc*)data;
	if (desc->perm && res->perm && !strcmp (desc->uri, res->uri)) {
		res->desc = desc;
		return false;
	}
	return true;
}

static RzIODesc *findReusableFile(RzIO *io, const char *uri, int perm) {
	FindFile arg = {
		.uri = uri,
		.perm = perm,
		.desc = NULL,
	};
	rz_id_storage_foreach (io->files, findFile, &arg);
	return arg.desc;
}

static bool io_create_mem_map(RzIO *io, RzBinSection *sec, ut64 at) {
	rz_return_val_if_fail (io && sec, false);

	bool reused = false;
	ut64 gap = sec->vsize - sec->size;
	char *uri = rz_str_newf ("null://%"PFMT64u, gap);
	RzIODesc *desc = findReusableFile (io, uri, sec->perm);
	if (desc) {
		RzIOMap *map = rz_io_map_get (io, at);
		if (!map) {
			rz_io_map_add_batch (io, desc->fd, desc->perm, 0LL, at, gap);
		}
		reused = true;
	}
	if (!desc) {
		desc = rz_io_open_at (io, uri, sec->perm, 0664, at);
	}
	free (uri);
	if (!desc) {
		return false;
	}
	// this works, because new maps are always born on the top
	RzIOMap *map = rz_io_map_get (io, at);
	// check if the mapping failed
	if (!map) {
		if (!reused) {
			rz_io_desc_close (desc);
		}
		return false;
	}
	// let the section refere to the map as a memory-map
	free (map->name);
	map->name = rz_str_newf ("mmap.%s", sec->name);
	return true;
}

static void add_section(RzCore *core, RzBinSection *sec, ut64 addr, int fd) {
	if (!rz_io_desc_get (core->io, fd) || UT64_ADD_OVFCHK (sec->size, sec->paddr) ||
	    UT64_ADD_OVFCHK (sec->size, addr) || !sec->vsize) {
		return;
	}

	ut64 size = sec->vsize;
	// if there is some part of the section that needs to be zeroed by the loader
	// we add a null map that takes care of it
	if (sec->vsize > sec->size) {
		if (!io_create_mem_map (core->io, sec, addr + sec->size)) {
			return;
		}

		size = sec->size;
	}

	// then we map the part of the section that comes from the physical file
	char *map_name = rz_str_newf ("fmap.%s", sec->name);
	if (!map_name) {
		return;
	}

	int perm = sec->perm;
	// workaround to force exec bit in text section
	if (sec->name &&  strstr (sec->name, "text")) {
		perm |= RZ_PERM_X;
	}

	RzIOMap *map = rz_io_map_add_batch (core->io, fd, perm, sec->paddr, addr, size);
	if (!map) {
		free (map_name);
		return;
	}
	map->name = map_name;
	return;
}

struct io_bin_section_info_t {
	RzBinSection *sec;
	ut64 addr;
	int fd;
};

/* Map Sections to Segments https://github.com/rizinorg/rizin/issues/14647 */
static int bin_map_sections_to_segments (RzBin *bin, int mode) {
	RzListIter *iter, *iter2;
	RzBinSection *section = NULL, *segment = NULL;
	RzList *sections = rz_list_new ();
	RzList *segments = rz_list_new ();
	RzList *tmp = rz_bin_get_sections (bin);
	char *json_output = rz_str_new ("");
	RTable *table = rz_table_new ();
	RTableColumnType *typeString = rz_table_type ("string");

	rz_table_add_column (table, typeString, "Segment", 0);
	rz_table_add_column (table, typeString, "Section", 0);

	rz_list_foreach (tmp, iter, section) {
		RzList *list = section->is_segment? segments: sections;
		rz_list_append (list, section);
	}

	rz_list_foreach (segments, iter, segment) {
		RInterval segment_itv = (RInterval){segment->vaddr, segment->size};
		char *tmp2 = rz_str_new ("");
		rz_list_foreach (sections, iter2, section) {
			RInterval section_itv = (RInterval){section->vaddr, section->size};
			if (rz_itv_begin (section_itv) >= rz_itv_begin (segment_itv) && rz_itv_end (section_itv) <= rz_itv_end (segment_itv) && section->name[0]) {
				tmp2 = rz_str_appendf (tmp2, "%s ", section->name);
			}
		}
		rz_table_add_row (table, segment->name, tmp2, 0);
		/*output to json*/
		json_output = rz_str_appendf (json_output, "\"%s\": \"%s\",", segment->name, tmp2);
		free (tmp2);
	}
	// remove last ,
	json_output [strlen (json_output) - 1] = 0;
	char *jo = rz_str_newf ("[{%s}]", json_output);
	free (json_output);
	json_output = jo;

	if (IS_MODE_JSON (mode)){
		rz_cons_printf ("%s", json_output);
	} else if (IS_MODE_NORMAL (mode)){
		rz_cons_printf ("Section to Segment mapping:\n");
		char *s = rz_table_tostring (table);
		rz_cons_printf ("%s\n", s);
		free (s);
	}
	free (json_output);
	rz_list_free (segments);
	rz_table_free (table);
	return true;
}

static int bin_sections(RzCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, const char *chksum, bool print_segments) {
	char *str = NULL;
	RzBinSection *section;
	RzBinInfo *info = NULL;
	RzList *sections;
	RzListIter *iter;
	RzListIter *last_processed = NULL;
	RTable *table = rz_core_table (r);
	rz_return_val_if_fail (table, false);
	int i = 0;
	int fd = -1;
	bool printHere = false;
	sections = rz_bin_get_sections (r->bin);
#if LOAD_BSS_MALLOC
	bool inDebugger = rz_config_get_i (r->config, "cfg.debug");
#endif
	HtPP *dup_chk_ht = ht_pp_new0 ();
	bool ret = false;
	const char *type = print_segments ? "segment" : "section";
	bool segments_only = true;
	RzList *io_section_info = NULL;

	if (!dup_chk_ht) {
		return false;
	}

	if (chksum && *chksum == '.') {
		printHere = true;
		chksum++;
	}
	char *hashtypes = filter_hash_string (chksum);
	if (IS_MODE_EQUAL (mode)) {
		int cols = rz_cons_get_size (NULL);
		RzList *list = rz_list_newf ((RzListFree) rz_listinfo_free);
		if (!list) {
			free (hashtypes);
			return false;
		}
		RzBinSection *s;
		rz_list_foreach (sections, iter, s) {
			char humansz[8];
			if (print_segments != s->is_segment) {
				continue;
			}
			RInterval pitv = (RInterval){s->paddr, s->size};
			RInterval vitv = (RInterval){s->vaddr, s->vsize};
			rz_num_units (humansz, sizeof (humansz), s->size);
			RzListInfo *info = rz_listinfo_new (s->name, pitv, vitv, s->perm, strdup (humansz));
			rz_list_append (list, info);
		}
		RTable *table = rz_core_table (r);
		rz_table_visual_list (table, list, r->offset, -1, cols, r->io->va);
		if (r->table_query) {
			rz_table_query (table, r->table_query);
		}
		{
			char *s = rz_table_tostring (table);
			rz_cons_printf ("\n%s\n", s);
			free (s);
		}
		rz_table_free (table);
		rz_list_free (list);
		goto out;
	}
	if (IS_MODE_JSON (mode) && !printHere) {
		rz_cons_printf ("[");
	} else if (IS_MODE_RAD (mode) && at == UT64_MAX) {
		rz_cons_printf ("fs %ss\n", type);
	} else if (IS_MODE_NORMAL (mode) && at == UT64_MAX && !printHere) {
		rz_cons_printf ("[%s]\n", print_segments ? "Segments" : "Sections");
	} else if (IS_MODE_NORMAL (mode) && printHere) {
		rz_cons_printf ("Current section\n");
	} else if (IS_MODE_SET (mode)) {
		fd = rz_core_file_cur_fd (r);
		rz_flag_space_set (r->flags, print_segments? RZ_FLAGS_FS_SEGMENTS: RZ_FLAGS_FS_SECTIONS);
	}
	if (IS_MODE_NORMAL (mode)) {
		if (hashtypes) {
			rz_table_set_columnsf (table, "dXxXxsss",
				"nth", "paddr", "size", "vaddr", "vsize", "perm", hashtypes, "name");
		} else {
			rz_table_set_columnsf (table, "dXxXxss",
				"nth", "paddr", "size", "vaddr", "vsize", "perm", "name");
		}
		// rz_table_align (table, 0, RZ_TABLE_ALIGN_CENTER);
		rz_table_align (table, 2, RZ_TABLE_ALIGN_RIGHT);
		rz_table_align (table, 4, RZ_TABLE_ALIGN_RIGHT);
	}
	if (IS_MODE_SET (mode)) {
		rz_list_foreach (sections, iter, section) {
			if (!section->is_segment) {
				segments_only = false;
				break;
			}
		}

		io_section_info = rz_list_newf ((RzListFree)free);
	}
	rz_list_foreach (sections, iter, section) {
		char perms[] = "----";
		int va_sect = va;
		ut64 addr;

		if (va && !(section->perm & RZ_PERM_R)) {
			va_sect = VA_NOREBASE;
		}
		addr = rva (r->bin, section->paddr, section->vaddr, va_sect);

		if (name && strcmp (section->name, name)) {
			continue;
		}

		if ((printHere && !(section->paddr <= r->offset && r->offset < (section->paddr + section->size)))
				&& (printHere && !(addr <= r->offset && r->offset < (addr + section->size)))) {
			continue;
		}

		rz_name_filter (section->name, strlen (section->name) + 1);
		if (at != UT64_MAX && (!section->size || !is_in_range (at, addr, section->size))) {
			continue;
		}

		if (section->is_segment != print_segments) {
			continue;
		}
		// XXX use rz_str_perm instead of doing it here imho
		if (section->perm & RZ_PERM_SHAR) {
			perms[0] = 's';
		}
		if (section->perm & RZ_PERM_R) {
			perms[1] = 'r';
		}
		if (section->perm & RZ_PERM_W) {
			perms[2] = 'w';
		}
		if (section->perm & RZ_PERM_X) {
			perms[3] = 'x';
		}
		const char *arch = NULL;
		int bits = 0;
		if (section->arch || section->bits) {
			arch = section->arch;
			bits = section->bits;
		}
		if (info) {
			if (!arch) {
				arch = info->arch;
			}
			if (!bits) {
				bits = info->bits;
			}
		}
		if (!arch) {
			arch = rz_config_get (r->config, "asm.arch");
		}
		if (!bits) {
			bits = RZ_SYS_BITS;
		}
		if (IS_MODE_RAD (mode)) {
			char *n = __filterQuotedShell (section->name);
			rz_cons_printf ("\"f %s.%s 1 0x%08"PFMT64x"\"\n", type, n, section->vaddr);
			free (n);
		} else if (IS_MODE_SET (mode)) {
#if LOAD_BSS_MALLOC
			if (!strcmp (section->name, ".bss")) {
				// check if there's already a file opened there
				int loaded = 0;
				RzListIter *iter;
				RzIOMap *m;
				rz_list_foreach (r->io->maps, iter, m) {
					if (m->from == addr) {
						loaded = 1;
					}
				}
				if (!loaded && !inDebugger) {
					rz_core_cmdf (r, "on malloc://%d 0x%"PFMT64x" # bss\n",
						section->vsize, addr);
				}
			}
#endif
			if (section->format) {
				// This is damn slow if section vsize is HUGE
				if (section->vsize < 1024 * 1024 * 2) {
					rz_core_cmdf (r, "%s @ 0x%"PFMT64x, section->format, section->vaddr);
				}
			}
			if (r->bin->prefix) {
				str = rz_str_newf ("%s.%s.%s", r->bin->prefix, type, section->name);
			} else {
				str = rz_str_newf ("%s.%s", type, section->name);

			}
			ut64 size = r->io->va? section->vsize: section->size;
			rz_flag_set (r->flags, str, addr, size);
			RZ_FREE (str);

			if (!section->is_segment || segments_only) {
				char *pfx = r->bin->prefix;
				str = rz_str_newf ("[%02d] %s %s size %" PFMT64d" named %s%s%s",
				                  i, perms, type, size,
				                  pfx? pfx: "", pfx? ".": "", section->name);
				rz_meta_set (r->anal, RZ_META_TYPE_COMMENT, addr, 1, str);
				RZ_FREE (str);
			}
			if (section->add) {
				bool found;
				str = rz_str_newf ("%"PFMT64x".%"PFMT64x".%"PFMT64x".%"PFMT64x".%"PFMT32u".%s.%"PFMT32u".%d",
					section->paddr, addr, section->size, section->vsize, section->perm, section->name, r->bin->cur->id, fd);
				ht_pp_find (dup_chk_ht, str, &found);
				if (!found) {
					// can't directly add maps because they
					// need to be reversed, otherwise for
					// the way IO works maps would be shown
					// in reverse order
					struct io_bin_section_info_t *ibs = RZ_NEW (struct io_bin_section_info_t);
					if (!ibs) {
						eprintf ("Could not allocate memory\n");
						goto out;
					}

					ibs->sec = section;
					ibs->addr = addr;
					ibs->fd = fd;
					rz_list_append (io_section_info, ibs);
					ht_pp_insert (dup_chk_ht, str, NULL);
				}
				RZ_FREE (str);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			char *hashstr = NULL;
			if (hashtypes) {
				ut8 *data = malloc (section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				rz_io_pread_at (r->io, section->paddr, data, datalen);
				hashstr = build_hash_string (mode, hashtypes, data, datalen);
				free (data);
			}
			rz_cons_printf ("0x%"PFMT64x" 0x%"PFMT64x" %s %s%s%s\n",
				addr, addr + section->size,
				perms,
				hashstr ? hashstr : "", hashstr ? " " : "",
				section->name
			);
			free (hashstr);
		} else if (IS_MODE_JSON (mode)) {
			char *hashstr = NULL;
			if (hashtypes && section->size > 0) {
				ut8 *data = malloc (section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				rz_io_pread_at (r->io, section->paddr, data, datalen);
				hashstr = build_hash_string (mode, hashtypes,
					data, datalen);
				free (data);
			}
			rz_cons_printf ("%s{\"name\":\"%s\","
				"\"size\":%"PFMT64d","
				"\"vsize\":%"PFMT64d","
				"\"perm\":\"%s\","
				"%s"
				"\"paddr\":%"PFMT64d","
				"\"vaddr\":%"PFMT64d"}",
				(last_processed && !printHere) ? "," : "",
				section->name,
				section->size,
				section->vsize,
				perms,
				hashstr ? hashstr : "",
				section->paddr,
				addr);
			free (hashstr);
		} else {
			char *hashstr = NULL, str[128];
			if (hashtypes) {
				ut8 *data = malloc (section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				// VA READ IS BROKEN?
				if (datalen > 0) {
					rz_io_pread_at (r->io, section->paddr, data, datalen);
				}
				hashstr = build_hash_string (mode, hashtypes, data, datalen);
				free (data);
			}
			if (section->arch || section->bits) {
				snprintf (str, sizeof (str), "arch=%s bits=%d ",
					rz_str_get2 (arch), bits);
			} else {
				str[0] = 0;
			}
			const char *section_name = (r->bin->prefix)
				? sdb_fmt ("%s.%s", r->bin->prefix, section->name)
				: section->name;
			// seems like asm.bits is a bitmask that seems to be always 32,64
			// const char *asmbits = rz_str_sysbits (bits);
			if (hashtypes) {
				rz_table_add_rowf (table, "dXxXxsss", i,
					(ut64)section->paddr, (ut64)section->size,
					(ut64)addr, (ut64)section->vsize,
					perms, hashstr, section_name);
			} else {
				rz_table_add_rowf (table, "dXxXxss", i,
					(ut64)section->paddr, (ut64)section->size,
					(ut64)addr, (ut64)section->vsize,
					perms, section_name);
			}
			free (hashstr);
		}
		i++;
		last_processed = iter;
		if (printHere) {
			if (IS_MODE_JSON (mode)) {
				rz_cons_print ("\n");
			}
			break;
		}
	}
	if (IS_MODE_SET (mode) && !rz_io_desc_is_dbg (r->io->desc)) {
		RzListIter *it;
		struct io_bin_section_info_t *ibs;
		rz_list_foreach_prev (io_section_info, it, ibs) {
			add_section (r, ibs->sec, ibs->addr, ibs->fd);
		}
		rz_io_update (r->io);
		rz_list_free (io_section_info);
		io_section_info = NULL;
	}
	if (IS_MODE_JSON (mode) && !printHere) {
		rz_cons_println ("]");
	} else if (IS_MODE_NORMAL (mode) && at == UT64_MAX && !printHere) {
		// rz_cons_printf ("\n%i sections\n", i);
	}

	ret = true;
out:
	if (IS_MODE_NORMAL (mode)) {
		if (r->table_query) {
			rz_table_query (table, r->table_query);
		}
		char *s = rz_table_tostring (table);
		rz_cons_printf ("\n%s\n", s);
		free (s);
	}
	free (hashtypes);
	rz_table_free (table);
	ht_pp_free (dup_chk_ht);
	return ret;
}

static int bin_fields(RzCore *r, int mode, int va) {
	RzList *fields;
	RzListIter *iter;
	RzBinField *field;
	int i = 0;
	RzBin *bin = r->bin;

	if (!(fields = rz_bin_get_fields (bin))) {
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		rz_cons_print ("[");
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_println ("fs header");
	} else if (IS_MODE_NORMAL (mode)) {
		rz_cons_println ("[Header fields]");
	}
	rz_list_foreach (fields, iter, field) {
		ut64 addr = rva (bin, field->paddr, field->vaddr, va);

		if (IS_MODE_RAD (mode)) {
			char *n = __filterQuotedShell (field->name);
			rz_name_filter (n, -1);
			rz_cons_printf ("\"f header.%s 1 0x%08"PFMT64x"\"\n", n, addr);
			if (field->comment && *field->comment) {
				char *e = sdb_encode ((const ut8*)field->comment, -1);
				rz_cons_printf ("CCu %s @ 0x%"PFMT64x"\n", e, addr);
				free (e);
				char *f = __filterShell (field->format);
				rz_cons_printf ("Cf %d %s @ 0x%"PFMT64x"\n", field->size, f, addr);
				free (f);
			}
			if (field->format && *field->format && !field->format_named) {
				rz_cons_printf ("pf.%s %s\n", n, field->format);
			}
			free (n);
		} else if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("%s{\"name\":\"%s\","
				"\"vaddr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d,
				iter->p? ",": "",
				field->name,
				field->vaddr,
				field->paddr
				);
			if (field->comment && *field->comment) {
				// TODO: filter comment before json
				rz_cons_printf (",\"comment\":\"%s\"", field->comment);
			}
			if (field->format && *field->format) {
				// TODO: filter comment before json
				rz_cons_printf (",\"format\":\"%s\"", field->format);
			}
			char *o = rz_core_cmd_strf (r, "pfj%c%s@0x%"PFMT64x,
				field->format_named ? '.' :  ' ', field->format, field->vaddr);
			if (o && *o) {
				rz_cons_printf (",\"pf\":%s", o);
			}
			free (o);
			rz_cons_printf ("}");
		} else if (IS_MODE_NORMAL (mode)) {
			const bool haveComment = (field->comment && *field->comment);
			rz_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %s%s%s\n",
				field->vaddr, field->paddr, field->name,
				haveComment? "; ": "",
				haveComment? field->comment: "");
		}
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		rz_cons_printf ("]");
	} else if (IS_MODE_NORMAL (mode)) {
		rz_cons_printf ("\n%i fields\n", i);
	}

	return true;
}

static char *get_rp(const char *rtype) {
	char *rp = NULL;
	switch (rtype[0]) {
	case 'v':
		rp = strdup ("void");
		break;
	case 'c':
		rp = strdup ("char");
		break;
	case 'i':
		rp = strdup ("int");
		break;
	case 's':
		rp = strdup ("short");
		break;
	case 'l':
		rp = strdup ("long");
		break;
	case 'q':
		rp = strdup ("long long");
		break;
	case 'C':
		rp = strdup ("unsigned char");
		break;
	case 'I':
		rp = strdup ("unsigned int");
		break;
	case 'S':
		rp = strdup ("unsigned short");
		break;
	case 'L':
		rp = strdup ("unsigned long");
		break;
	case 'Q':
		rp = strdup ("unsigned long long");
		break;
	case 'f':
		rp = strdup ("float");
		break;
	case 'd':
		rp = strdup ("double");
		break;
	case 'D':
		rp = strdup ("long double");
		break;
	case 'B':
		rp = strdup ("bool");
		break;
	case '#':
		rp = strdup ("CLASS");
		break;
	default:
		rp = strdup ("unknown");
		break;
	}
	return rp;
}

static int bin_trycatch(RzCore *core, int mode) {
	RzBinFile *bf = rz_bin_cur (core->bin);
	RzListIter *iter;
	RzBinTrycatch *tc;
	RzList *trycatch = rz_bin_file_get_trycatch (bf);
	int idx = 0;
	rz_list_foreach (trycatch, iter, tc) {
		rz_cons_printf ("f try.%d.%"PFMT64x".from=0x%08"PFMT64x"\n", idx, tc->source, tc->from);
		rz_cons_printf ("f try.%d.%"PFMT64x".to=0x%08"PFMT64x"\n", idx, tc->source, tc->to);
		rz_cons_printf ("f try.%d.%"PFMT64x".catch=0x%08"PFMT64x"\n", idx, tc->source, tc->handler);
		idx++;
	}
	return true;
}

// https://nshipster.com/type-encodings/
static char *objc_type_toc(const char *objc_type) {
	if (!objc_type) {
		return strdup ("void*");
	}
	if (*objc_type == '^' && objc_type[1] == '{') {
		char *a = strdup (objc_type + 2);
		char *b = strchr (a, '>');
		if (b) {
			*b = 0;
		}
		a[strlen (a) - 1] = 0;
		return a;
	}
	if (*objc_type == '<') {
		char *a = strdup (objc_type + 1);
		char *b = strchr (a, '>');
		if (b) {
			*b = 0;
		}
		return a;
	}
	if (!strcmp (objc_type, "f")) { return strdup ("float"); }
	if (!strcmp (objc_type, "d")) { return strdup ("double"); }
	if (!strcmp (objc_type, "i")) { return strdup ("int"); }
	if (!strcmp (objc_type, "s")) { return strdup ("short"); }
	if (!strcmp (objc_type, "l")) { return strdup ("long"); }
	if (!strcmp (objc_type, "L")) { return strdup ("unsigned long"); }
	if (!strcmp (objc_type, "*")) { return strdup ("char*"); }
	if (!strcmp (objc_type, "c")) { return strdup ("bool"); }
	if (!strcmp (objc_type, "v")) { return strdup ("void"); }
	if (!strcmp (objc_type, "#")) { return strdup ("class"); }
	if (!strcmp (objc_type, "B")) { return strdup ("cxxbool"); }
	if (!strcmp (objc_type, "Q")) { return strdup ("uint64_t"); }
	if (!strcmp (objc_type, "q")) { return strdup ("long long"); }
	if (!strcmp (objc_type, "C")) { return strdup ("uint8_t"); }
	if (strlen (objc_type) == 1) {
		eprintf ("Unknown objc type '%s'\n", objc_type);
	}
	if (rz_str_startswith (objc_type, "@\"")) {
		char *s = rz_str_newf ("struct %s", objc_type + 2);
		s[strlen (s) - 1] = '*';
		return s;
	}
	return strdup (objc_type);
}

static char *objc_name_toc(const char *objc_name) {
	const char *n = rz_str_lchr (objc_name, ')');
	char *s = strdup (n? n + 1: objc_name);
	char *p = strchr (s, '(');
	if (p) {
		*p = 0;
	}
	return s;
}

static void classdump_c(RzCore *r, RzBinClass *c) {
	rz_cons_printf ("typedef struct class_%s {\n", c->name);
	RzListIter *iter2;
	RzBinField *f;
	rz_list_foreach (c->fields, iter2, f) {
		if (f->type && f->name) {
			char *n = objc_name_toc (f->name);
			char *t = objc_type_toc (f->type);
			rz_cons_printf ("    %s %s; // %d\n", t, n, f->offset);
			free (t);
			free (n);
		}
	}
	rz_cons_printf ("} %s;\n", c->name);
}

static void classdump_objc(RzCore *r, RzBinClass *c) {
	if (c->super) {
		rz_cons_printf ("@interface %s : %s\n{\n", c->name, c->super);
	} else {
		rz_cons_printf ("@interface %s\n{\n", c->name);
	}
	RzListIter *iter2, *iter3;
	RzBinField *f;
	RzBinSymbol *sym;
	rz_list_foreach (c->fields, iter2, f) {
		if (f->name && rz_regex_match ("ivar","e", f->name)) {
			rz_cons_printf ("  %s %s\n", f->type, f->name);
		}
	}
	rz_cons_printf ("}\n");
	rz_list_foreach (c->methods, iter3, sym) {
		if (sym->rtype && sym->rtype[0] != '@') {
			char *rp = get_rp (sym->rtype);
			rz_cons_printf ("%s (%s) %s\n",
					strncmp (sym->type, RZ_BIN_TYPE_METH_STR, 4)? "+": "-",
					rp, sym->dname? sym->dname: sym->name);
			free (rp);
		} else if (sym->type) {
			rz_cons_printf ("%s (id) %s\n",
					strncmp (sym->type, RZ_BIN_TYPE_METH_STR, 4)? "+": "-",
					sym->dname? sym->dname: sym->name);
		}
	}
	rz_cons_printf ("@end\n");
}

static void classdump_java(RzCore *r, RzBinClass *c) {
	RzBinField *f;
	RzListIter *iter2, *iter3;
	RzBinSymbol *sym;
	char *pn = strdup (c->name);
	char *cn = (char *)rz_str_rchr (pn, NULL, '/');
	if (cn) {
		*cn = 0;
		cn++;
		rz_str_replace_char (pn, '/', '.');
	}
	rz_cons_printf ("package %s;\n\n", pn);
	rz_cons_printf ("public class %s {\n", cn);
	free (pn);
	rz_list_foreach (c->fields, iter2, f) {
		if (f->name && rz_regex_match ("ivar","e", f->name)) {
			rz_cons_printf ("  public %s %s\n", f->type, f->name);
		}
	}
	rz_list_foreach (c->methods, iter3, sym) {
		const char *mn = sym->dname? sym->dname: sym->name;
		const char *ms = strstr (mn, "method.");
		if (ms) {
			mn = ms + strlen ("method.");
		}
		rz_cons_printf ("  public %s ();\n", mn);
	}
	rz_cons_printf ("}\n\n");
}

static int bin_classes(RzCore *r, int mode) {
	RzListIter *iter, *iter2, *iter3;
	RzBinSymbol *sym;
	RzBinClass *c;
	RzBinField *f;
	char *name;
	RzList *cs = rz_bin_get_classes (r->bin);
	if (!cs) {
		if (IS_MODE_JSON (mode)) {
			rz_cons_print ("[]\n");
			return true;
		}
		return false;
	}
	// XXX: support for classes is broken and needs more love
	if (IS_MODE_JSON (mode)) {
		rz_cons_print ("[");
	} else if (IS_MODE_SET (mode)) {
		if (!rz_config_get_i (r->config, "bin.classes")) {
			return false;
		}
		rz_flag_space_set (r->flags, RZ_FLAGS_FS_CLASSES);
	} else if (IS_MODE_RAD (mode) && !IS_MODE_CLASSDUMP (mode)) {
		rz_cons_println ("fs classes");
	}

	rz_list_foreach (cs, iter, c) {
		if (!c || !c->name || !c->name[0]) {
			continue;
		}
		name = strdup (c->name);
		rz_name_filter (name, 0);
		ut64 at_min = UT64_MAX;
		ut64 at_max = 0LL;

		rz_list_foreach (c->methods, iter2, sym) {
			if (sym->vaddr) {
				if (sym->vaddr < at_min) {
					at_min = sym->vaddr;
				}
				if (sym->vaddr + sym->size > at_max) {
					at_max = sym->vaddr + sym->size;
				}
			}
		}
		if (at_min == UT64_MAX) {
			at_min = c->addr;
			at_max = c->addr; // XXX + size?
		}

		if (IS_MODE_SET (mode)) {
			const char *classname = sdb_fmt ("class.%s", name);
			rz_flag_set (r->flags, classname, c->addr, 1);
			rz_list_foreach (c->methods, iter2, sym) {
				char *mflags = rz_core_bin_method_flags_str (sym->method_flags, mode);
				char *method = sdb_fmt ("method%s.%s.%s",
					mflags, c->name, sym->name);
				RZ_FREE (mflags);
				rz_name_filter (method, -1);
				rz_flag_set (r->flags, method, sym->vaddr, 1);
			}
#if 0
			rz_list_foreach (c->fields, iter2, f) {
				char *fn = rz_str_newf ("field.%s.%s", classname, f->name);
				ut64 at = f->vaddr; //  sym->vaddr + (f->vaddr &  0xffff);
				rz_flag_set (r->flags, fn, at, 1);
				free (fn);
			}
#endif
		} else if (IS_MODE_SIMPLEST (mode)) {
			rz_cons_printf ("%s\n", c->name);
		} else if (IS_MODE_SIMPLE (mode)) {
			rz_cons_printf ("0x%08"PFMT64x" [0x%08"PFMT64x" - 0x%08"PFMT64x"] %s%s%s\n",
				c->addr, at_min, at_max, c->name, c->super ? " " : "",
				c->super ? c->super : "");
		} else if (IS_MODE_CLASSDUMP (mode)) {
			if (c) {
				RzBinFile *bf = rz_bin_cur (r->bin);
				if (bf && bf->o) {
					if (IS_MODE_RAD (mode)) {
						classdump_c (r, c);
					} else if (bf->o->lang == RZ_BIN_NM_JAVA || (bf->o->info && bf->o->info->lang && strstr (bf->o->info->lang, "dalvik"))) {
						classdump_java (r, c);
					} else {
						classdump_objc (r, c);
					}
				} else {
					classdump_objc (r, c);
				}
			}
		} else if (IS_MODE_RAD (mode)) {
			char *n = __filterShell (name);
			rz_cons_printf ("\"f class.%s = 0x%"PFMT64x"\"\n", n, at_min);
			free (n);
			if (c->super) {
				char *cn = c->name; // __filterShell (c->name);
				char *su = c->super; // __filterShell (c->super);
				rz_cons_printf ("\"f super.%s.%s = %d\"\n",
						cn, su, c->index);
				// free (cn);
				// free (su);
			}
			rz_list_foreach (c->methods, iter2, sym) {
				char *mflags = rz_core_bin_method_flags_str (sym->method_flags, mode);
				char *n = c->name; //  __filterShell (c->name);
				char *sn = sym->name; //__filterShell (sym->name);
				char *cmd = rz_str_newf ("\"f method%s.%s.%s = 0x%"PFMT64x"\"\n", mflags, n, sn, sym->vaddr);
				// free (n);
				// free (sn);
				if (cmd) {
					rz_str_replace_char (cmd, ' ', '_');
					if (strlen (cmd) > 2) {
						cmd[2] = ' ';
					}
					char *eq = (char *)rz_str_rchr (cmd, NULL, '=');
					if (eq && eq != cmd) {
						eq[-1] = eq[1] = ' ';
					}
					rz_str_replace_char (cmd, '\n', 0);
					rz_cons_printf ("%s\n", cmd);
					free (cmd);
				}
				RZ_FREE (mflags);
			}
			rz_list_foreach (c->fields, iter2, f) {
				char *fn = rz_str_newf ("field.%s.%s", c->name, f->name);
				ut64 at = f->vaddr; //  sym->vaddr + (f->vaddr &  0xffff);
				rz_cons_printf ("\"f %s = 0x%08"PFMT64x"\"\n", fn, at);
				free (fn);
			}

			// C struct
			rz_cons_printf ("\"td struct %s {", c->name);
			if (rz_list_empty (c->fields)) {
				// XXX workaround because we cant register empty structs yet
				// XXX https://github.com/rizinorg/rizin/issues/16342
				rz_cons_printf (" char empty[0];");
			} else {
				rz_list_foreach (c->fields, iter2, f) {
					char *n = objc_name_toc (f->name);
					char *t = objc_type_toc (f->type);
					rz_cons_printf (" %s %s;", t, n);
					free (t);
					free (n);
				}
			}
			rz_cons_printf ("};\"\n");
		} else if (IS_MODE_JSON (mode)) {
			if (c->super) {
				rz_cons_printf ("%s{\"classname\":\"%s\",\"addr\":%"PFMT64d",\"index\":%d,\"visibility\":\"%s\",\"super\":\"%s\",\"methods\":[",
					iter->p ? "," : "", c->name, c->addr,
					c->index, c->visibility_str? c->visibility_str: "", c->super);
			} else {
				rz_cons_printf ("%s{\"classname\":\"%s\",\"addr\":%"PFMT64d",\"index\":%d,\"methods\":[",
					iter->p ? "," : "", c->name, c->addr,
					c->index);
			}
			rz_list_foreach (c->methods, iter2, sym) {
				if (sym->method_flags) {
					char *mflags = rz_core_bin_method_flags_str (sym->method_flags, mode);
					rz_cons_printf ("%s{\"name\":\"%s\",\"flags\":%s,\"addr\":%"PFMT64d"}",
						iter2->p? ",": "", sym->name, mflags, sym->vaddr);
					RZ_FREE (mflags);
				} else {
					rz_cons_printf ("%s{\"name\":\"%s\",\"addr\":%"PFMT64d"}",
						iter2->p? ",": "", sym->name, sym->vaddr);
				}
			}
			rz_cons_printf ("], \"fields\":[");
			rz_list_foreach (c->fields, iter3, f) {
				if (f->flags) {
					char *mflags = rz_core_bin_method_flags_str (f->flags, mode);
					rz_cons_printf ("%s{\"name\":\"%s\",\"flags\":%s,\"addr\":%"PFMT64d"}",
						iter3->p? ",": "", f->name, mflags, f->vaddr);
					RZ_FREE (mflags);
				} else {
					rz_cons_printf ("%s{\"name\":\"%s\",\"addr\":%"PFMT64d"}",
						iter3->p? ",": "", f->name, f->vaddr);
				}
			}
			rz_cons_printf ("]}");
		} else {
			int m = 0;
			rz_cons_printf ("0x%08"PFMT64x" [0x%08"PFMT64x" - 0x%08"PFMT64x"] %6"PFMT64d" class %d %s",
				c->addr, at_min, at_max, (at_max - at_min), c->index, c->name);
			if (c->super) {
				rz_cons_printf (" :: %s\n", c->super);
			} else {
				rz_cons_newline ();
			}
			rz_list_foreach (c->methods, iter2, sym) {
				char *mflags = rz_core_bin_method_flags_str (sym->method_flags, mode);
				rz_cons_printf ("0x%08"PFMT64x" method %d %s %s\n",
					sym->vaddr, m, mflags, sym->dname? sym->dname: sym->name);
				RZ_FREE (mflags);
				m++;
			}
		}
		free (name);
	}
	if (IS_MODE_JSON (mode)) {
		rz_cons_print ("]\n");
	}

	return true;
}

static int bin_size(RzCore *r, int mode) {
	ut64 size = rz_bin_get_size (r->bin);
	if (IS_MODE_SIMPLE (mode) || IS_MODE_JSON (mode)) {
		rz_cons_printf ("%"PFMT64u"\n", size);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_printf ("f bin_size @ %"PFMT64u"\n", size);
	} else if (IS_MODE_SET (mode)) {
		rz_core_cmdf (r, "f bin_size @ %"PFMT64u"\n", size);
	} else {
		rz_cons_printf ("%"PFMT64u"\n", size);
	}
	return true;
}

static int bin_libs(RzCore *r, int mode) {
	RzListIter *iter;
	char* lib;
	int i = 0;
	PJ *pj = NULL;

	RzList *libs = rz_bin_get_libs (r->bin);
	if (IS_MODE_JSON (mode)) {
		pj = pj_new ();
		pj_a (pj);
	} else {
		if (!libs) {
			return false;
		}
		if (IS_MODE_NORMAL (mode)) {
			rz_cons_println ("[Linked libraries]");
		}
	}
	rz_list_foreach (libs, iter, lib) {
		if (IS_MODE_SET (mode)) {
			// Nothing to set.
			// TODO: load libraries with iomaps?
		} else if (IS_MODE_RAD (mode)) {
			rz_cons_printf ("\"CCa entry0 %s\"\n", lib);
		} else if (IS_MODE_JSON (mode)) {
			pj_s (pj, lib);
		} else {
			// simple and normal print mode
			rz_cons_println (lib);
		}
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		char *s = pj_drain (pj);
		rz_cons_printf ("%s", s);
		free (s);
	} else if (IS_MODE_NORMAL (mode)) {
		const char *libstr = (i > 1)? "libraries": "library";
		rz_cons_printf ("\n%i %s\n", i, libstr);
	}
	return true;
}

static void bin_mem_print(RzList *mems, int perms, int depth, int mode) {
	RzBinMem *mem;
	RzListIter *iter;
	if (!mems) {
		return;
	}
	rz_list_foreach (mems, iter, mem) {
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("{\"name\":\"%s\",\"size\":%d,\"address\":%" PFMT64u ","
					"\"flags\":\"%s\"}", mem->name, mem->size,
					mem->addr, rz_str_rwx_i (mem->perms & perms));
		} else if (IS_MODE_SIMPLE (mode)) {
			rz_cons_printf ("0x%08"PFMT64x"\n", mem->addr);
		} else {
			rz_cons_printf ("0x%08"PFMT64x" +0x%04x %s %*s%-*s\n",
					mem->addr, mem->size, rz_str_rwx_i (mem->perms & perms),
					depth, "", 20-depth, mem->name);
		}
		if (mem->mirrors) {
			if (IS_MODE_JSON (mode)) {
				rz_cons_printf (",");
			}
			bin_mem_print (mem->mirrors, mem->perms & perms, depth + 1, mode);
		}
		if (IS_MODE_JSON (mode)) {
			if (iter->n) {
				rz_cons_printf (",");
			}
		}
	}
}

static int bin_mem(RzCore *r, int mode) {
	RzList *mem = NULL;
	if (!r) {
		return false;
	}
	if (!IS_MODE_JSON (mode)) {
		if (!(IS_MODE_RAD (mode) || IS_MODE_SET (mode))) {
			rz_cons_println ("[Memory]\n");
		}
	}
	if (!(mem = rz_bin_get_mem (r->bin))) {
		if (IS_MODE_JSON (mode)) {
			rz_cons_print("[]");
			return true;
		}
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		rz_cons_print ("[");
		bin_mem_print (mem, 7, 0, RZ_MODE_JSON);
		rz_cons_println ("]");
		return true;
	} else if (!(IS_MODE_RAD (mode) || IS_MODE_SET (mode))) {
		bin_mem_print (mem, 7, 0, mode);
	}
	return true;
}

static void bin_pe_versioninfo(RzCore *r, int mode) {
	Sdb *sdb = NULL;
	int num_version = 0;
	int num_stringtable = 0;
	int num_string = 0;
	const char *format_version = "bin/cur/info/vs_version_info/VS_VERSIONINFO%d";
	const char *format_stringtable = "%s/string_file_info/stringtable%d";
	const char *format_string = "%s/string%d";
	if (!IS_MODE_JSON (mode)) {
		rz_cons_printf ("=== VS_VERSIONINFO ===\n\n");
	} else {
		rz_cons_print ("{");
	}
	bool firstit_dowhile = true;
	do {
		char *path_version = sdb_fmt (format_version, num_version);
		if (!(sdb = sdb_ns_path (r->sdb, path_version, 0))) {
			break;
		}
		if (!firstit_dowhile && IS_MODE_JSON (mode)) {
			rz_cons_printf (",");
		}
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("\"VS_FIXEDFILEINFO\":{");
		} else {
			rz_cons_printf ("# VS_FIXEDFILEINFO\n\n");
		}
		const char *path_fixedfileinfo = sdb_fmt ("%s/fixed_file_info", path_version);
		if (!(sdb = sdb_ns_path (r->sdb, path_fixedfileinfo, 0))) {
			rz_cons_printf ("}");
			break;
		}
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("\"Signature\":%"PFMT64u",", sdb_num_get (sdb, "Signature", 0));
			rz_cons_printf ("\"StrucVersion\":%"PFMT64u",", sdb_num_get (sdb, "StrucVersion", 0));
			rz_cons_printf ("\"FileVersion\":\"%"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\",",
				sdb_num_get (sdb, "FileVersionMS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "FileVersionLS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionLS", 0) & 0xFFFF);
			rz_cons_printf ("\"ProductVersion\":\"%"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\",",
				sdb_num_get (sdb, "ProductVersionMS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "ProductVersionLS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionLS", 0) & 0xFFFF);
			rz_cons_printf ("\"FileFlagsMask\":%"PFMT64u",", sdb_num_get (sdb, "FileFlagsMask", 0));
			rz_cons_printf ("\"FileFlags\":%"PFMT64u",", sdb_num_get (sdb, "FileFlags", 0));
			rz_cons_printf ("\"FileOS\":%"PFMT64u",", sdb_num_get (sdb, "FileOS", 0));
			rz_cons_printf ("\"FileType\":%"PFMT64u",", sdb_num_get (sdb, "FileType", 0));
			rz_cons_printf ("\"FileSubType\":%"PFMT64u, sdb_num_get (sdb, "FileSubType", 0));
			rz_cons_printf ("},");
		} else {
			rz_cons_printf ("  Signature: 0x%"PFMT64x"\n", sdb_num_get (sdb, "Signature", 0));
			rz_cons_printf ("  StrucVersion: 0x%"PFMT64x"\n", sdb_num_get (sdb, "StrucVersion", 0));
			rz_cons_printf ("  FileVersion: %"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\n",
				sdb_num_get (sdb, "FileVersionMS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "FileVersionLS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionLS", 0) & 0xFFFF);
			rz_cons_printf ("  ProductVersion: %"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\n",
				sdb_num_get (sdb, "ProductVersionMS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "ProductVersionLS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionLS", 0) & 0xFFFF);
			rz_cons_printf ("  FileFlagsMask: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileFlagsMask", 0));
			rz_cons_printf ("  FileFlags: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileFlags", 0));
			rz_cons_printf ("  FileOS: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileOS", 0));
			rz_cons_printf ("  FileType: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileType", 0));
			rz_cons_printf ("  FileSubType: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileSubType", 0));
			rz_cons_newline ();
		}
#if 0
		rz_cons_printf ("  FileDate: %d.%d.%d.%d\n",
			sdb_num_get (sdb, "FileDateMS", 0) >> 16,
			sdb_num_get (sdb, "FileDateMS", 0) & 0xFFFF,
			sdb_num_get (sdb, "FileDateLS", 0) >> 16,
			sdb_num_get (sdb, "FileDateLS", 0) & 0xFFFF);
#endif
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("\"StringTable\":{");
		} else {
			rz_cons_printf ("# StringTable\n\n");
		}
		for (num_stringtable = 0; sdb; num_stringtable++) {
			char *path_stringtable = rz_str_newf (format_stringtable, path_version, num_stringtable);
			sdb = sdb_ns_path (r->sdb, path_stringtable, 0);
			bool firstit_for = true;
			for (num_string = 0; sdb; num_string++) {
				char *path_string = rz_str_newf (format_string, path_stringtable, num_string);
				sdb = sdb_ns_path (r->sdb, path_string, 0);
				if (sdb) {
					if (!firstit_for && IS_MODE_JSON (mode)) { rz_cons_printf (","); }
					int lenkey = 0;
					int lenval = 0;
					ut8 *key_utf16 = sdb_decode (sdb_const_get (sdb, "key", 0), &lenkey);
					ut8 *val_utf16 = sdb_decode (sdb_const_get (sdb, "value", 0), &lenval);
					ut8 *key_utf8 = calloc (lenkey * 2, 1);
					ut8 *val_utf8 = calloc (lenval * 2, 1);
					if (rz_str_utf16_to_utf8 (key_utf8, lenkey * 2, key_utf16, lenkey, true) < 0
						|| rz_str_utf16_to_utf8 (val_utf8, lenval * 2, val_utf16, lenval, true) < 0) {
						eprintf ("Warning: Cannot decode utf16 to utf8\n");
					} else if (IS_MODE_JSON (mode)) {
						char *escaped_key_utf8 = rz_str_escape ((char*)key_utf8);
						char *escaped_val_utf8 = rz_str_escape ((char*)val_utf8);
						rz_cons_printf ("\"%s\":\"%s\"", escaped_key_utf8, escaped_val_utf8);
						free (escaped_key_utf8);
						free (escaped_val_utf8);
					} else {
						rz_cons_printf ("  %s: %s\n", (char*)key_utf8, (char*)val_utf8);
					}
					free (key_utf8);
					free (val_utf8);
					free (key_utf16);
					free (val_utf16);
				}
				firstit_for = false;
				free (path_string);
			}
			free (path_stringtable);
		}
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("}");
		}
		num_version++;
		firstit_dowhile = false;
	} while (sdb);
	if (IS_MODE_JSON (mode)) {
		rz_cons_printf ("}");
	}
}

static void bin_elf_versioninfo(RzCore *r, int mode) {
	const char *format = "bin/cur/info/versioninfo/%s%d";
	int num_versym;
	int num_verneed = 0;
	int num_version = 0;
	Sdb *sdb = NULL;
	const char *oValue = NULL;
	PJ *pj;
	if (IS_MODE_JSON (mode)) {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ka (pj, "versym");
	}
	for (num_versym = 0;; num_versym++) {
		const char *versym_path = sdb_fmt (format, "versym", num_versym);
		if (!(sdb = sdb_ns_path (r->sdb, versym_path, 0))) {
			break;
		}
		const ut64 addr = sdb_num_get (sdb, "addr", 0);
		const ut64 offset = sdb_num_get (sdb, "offset", 0);
		const ut64 link = sdb_num_get (sdb, "link", 0);
		const ut64 num_entries = sdb_num_get (sdb, "num_entries", 0);
		const char *const section_name = sdb_const_get (sdb, "section_name", 0);
		const char *const link_section_name = sdb_const_get (sdb, "link_section_name", 0);

		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "section_name", section_name);
			pj_kn (pj, "address", addr);
			pj_kn (pj, "offset", offset);
			pj_kn (pj, "link", link);
			pj_ks (pj, "link_section_name", link_section_name);
			pj_ka (pj, "entries");
		} else {
			rz_cons_printf ("Version symbols section '%s' contains %"PFMT64u" entries:\n", section_name, num_entries);
			rz_cons_printf (" Addr: 0x%08"PFMT64x"  Offset: 0x%08"PFMT64x"  Link: %x (%s)\n",
				(ut64)addr, (ut64)offset, (ut32)link, link_section_name);
		}
		int i;
		for (i = 0; i < num_entries; i++) {
			const char *const key = sdb_fmt ("entry%d", i);
			const char *const value = sdb_const_get (sdb, key, 0);
			if (value) {
				if (oValue && !strcmp (value, oValue)) {
					continue;
				}
				if (IS_MODE_JSON (mode)) {
					char *escaped_value = rz_str_escape (value);
					pj_o (pj);
					pj_kn (pj, "idx", (ut64)i);
					pj_ks (pj, "value", escaped_value);
					pj_end (pj);
					free (escaped_value);
				} else {
					rz_cons_printf ("  0x%08"PFMT64x": ", (ut64) i);
					rz_cons_printf ("%s\n", value);
				}
				oValue = value;
			}
		}
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
			pj_end (pj);
		} else {
			rz_cons_printf ("\n\n");
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		pj_ka (pj, "verneed");
	}

	do {
		char *verneed_path = rz_str_newf (format, "verneed", num_verneed++);
		if (!(sdb = sdb_ns_path (r->sdb, verneed_path, 0))) {
			break;
		}
		const char *const section_name = sdb_const_get (sdb, "section_name", 0);
		const ut64 address = sdb_num_get (sdb, "addr", 0);
		const ut64 offset = sdb_num_get (sdb, "offset", 0);
		const ut64 link = sdb_num_get (sdb, "link", 0);
		const char *const link_section_name = sdb_const_get (sdb, "link_section_name", 0);
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "section_name", section_name);
			pj_kn (pj, "address", address);
			pj_kn (pj, "offset", offset);
			pj_kn (pj, "link", link);
			pj_ks (pj, "link_section_name", link_section_name);
			pj_ka (pj, "entries");
		} else {
			rz_cons_printf ("Version need section '%s' contains %d entries:\n",
				section_name, (int)sdb_num_get (sdb, "num_entries", 0));

			rz_cons_printf (" Addr: 0x%08"PFMT64x, address);

			rz_cons_printf ("  Offset: 0x%08"PFMT64x"  Link to section: %"PFMT64d" (%s)\n",
				offset, link, link_section_name);
		}
		for (num_version = 0;; num_version++) {
			const char *filename = NULL;
			int num_vernaux = 0;

			char *path_version = sdb_fmt ("%s/version%d", verneed_path, num_version);
			if (!(sdb = sdb_ns_path (r->sdb, path_version, 0))) {
				break;
			}
			if (IS_MODE_JSON (mode)) {
				pj_o (pj);
				pj_kn (pj, "idx", sdb_num_get (sdb, "idx", 0));
				pj_ki (pj, "vn_version", (int)sdb_num_get (sdb, "vn_version", 0));
			} else {
				rz_cons_printf ("  0x%08"PFMT64x": Version: %d",
					sdb_num_get (sdb, "idx", 0), (int)sdb_num_get (sdb, "vn_version", 0));
			}

			if ((filename = sdb_const_get (sdb, "file_name", 0))) {
				if (IS_MODE_JSON (mode)) {
					char *escaped_filename = rz_str_escape (filename);
					pj_ks (pj, "file_name", escaped_filename);
					free (escaped_filename);
				} else {
					rz_cons_printf ("  File: %s", filename);
				}
			}
			const int cnt = (int)sdb_num_get (sdb, "cnt", 0);
			if (IS_MODE_JSON (mode)) {
				pj_ki (pj, "cnt", cnt);
			} else {
				rz_cons_printf ("  Cnt: %d\n", cnt);
			}
			if (IS_MODE_JSON (mode)) {
				pj_ka (pj, "vernaux");
			}
			do {
				const char *const path_vernaux = sdb_fmt ("%s/vernaux%d", path_version, num_vernaux++);
				if (!(sdb = sdb_ns_path (r->sdb, path_vernaux, 0))) {
					break;
				}
				const ut64 idx = sdb_num_get (sdb, "idx", 0);
				const char *const name = sdb_const_get (sdb, "name", 0);
				const char *const flags = sdb_const_get (sdb, "flags", 0);
				const int version = (int)sdb_num_get (sdb, "version", 0);
				if (IS_MODE_JSON (mode)) {
					pj_o (pj);
					pj_kn (pj, "idx", idx);
					pj_ks (pj, "name", name);
					pj_ks (pj, "flags", flags);
					pj_ki (pj, "version", version);
					pj_end (pj);
				} else {
					rz_cons_printf ("  0x%08"PFMT64x":   Name: %s", idx, name);
					rz_cons_printf ("  Flags: %s Version: %d\n", flags, version);
				}
			} while (sdb);
			if (IS_MODE_JSON (mode)) {
				pj_end (pj);
				pj_end (pj);
			}
		}
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
			pj_end (pj);
		}
		free (verneed_path);
	} while (sdb);
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		pj_end (pj);
		rz_cons_print (pj_string (pj));
		pj_free (pj);
	}
}

static void bin_mach0_versioninfo(RzCore *r) {
	/* TODO */
}

static void bin_pe_resources(RzCore *r, int mode) {
	Sdb *sdb = NULL;
	int index = 0;
	PJ *pj = NULL;
	const char *pe_path = "bin/cur/info/pe_resource";
	if (!(sdb = sdb_ns_path (r->sdb, pe_path, 0))) {
		return;
	}
	if (IS_MODE_SET (mode)) {
		rz_flag_space_set (r->flags, RZ_FLAGS_FS_RESOURCES);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_printf ("fs resources\n");
	} else if (IS_MODE_JSON (mode)) {
		pj = pj_new ();
		pj_a (pj);
	}
	while (true) {
		const char *timestrKey = sdb_fmt ("resource.%d.timestr", index);
		const char *vaddrKey = sdb_fmt ("resource.%d.vaddr", index);
		const char *sizeKey  = sdb_fmt ("resource.%d.size", index);
		const char *typeKey  = sdb_fmt ("resource.%d.type", index);
		const char *languageKey = sdb_fmt ("resource.%d.language", index);
		const char *nameKey = sdb_fmt ("resource.%d.name", index);
		char *timestr = sdb_get (sdb, timestrKey, 0);
		if (!timestr) {
			break;
		}
		ut64 vaddr = sdb_num_get (sdb, vaddrKey, 0);
		int size = (int)sdb_num_get (sdb, sizeKey, 0);
		char *name = sdb_get (sdb, nameKey, 0);
		char *type = sdb_get (sdb, typeKey, 0);
		char *lang = sdb_get (sdb, languageKey, 0);

		if (IS_MODE_SET (mode)) {
			const char *name = sdb_fmt ("resource.%d", index);
			rz_flag_set (r->flags, name, vaddr, size);
		} else if (IS_MODE_RAD (mode)) {
			rz_cons_printf ("f resource.%d %d 0x%08"PFMT64x"\n", index, size, vaddr);
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "name", name);
			pj_ki (pj, "index", index);
			pj_ks (pj, "type", type);
			pj_kn (pj, "vaddr", vaddr);
			pj_ki (pj, "size", size);
			pj_ks (pj, "lang", lang);
			pj_ks (pj, "timestamp", timestr);
			pj_end (pj);
		} else {
			char humansz[8];
			rz_num_units (humansz, sizeof (humansz), size);
			rz_cons_printf ("Resource %d\n", index);
			rz_cons_printf ("  name: %s\n", name);
			rz_cons_printf ("  timestamp: %s\n", timestr);
			rz_cons_printf ("  vaddr: 0x%08"PFMT64x"\n", vaddr);
			rz_cons_printf ("  size: %s\n", humansz);
			rz_cons_printf ("  type: %s\n", type);
			rz_cons_printf ("  language: %s\n", lang);
		}

		RZ_FREE (timestr);
		RZ_FREE (name);
		RZ_FREE (type);
		RZ_FREE (lang)

		index++;
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		rz_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else if (IS_MODE_RAD (mode)) {
		rz_cons_println ("fs *");
	}
}

static void bin_no_resources(RzCore *r, int mode) {
	if (IS_MODE_JSON (mode)) {
		rz_cons_printf ("[]");
	}
}

static int bin_resources(RzCore *r, int mode) {
	const RzBinInfo *info = rz_bin_get_info (r->bin);
	if (!info || !info->rclass) {
		return false;
	}
	if (!strncmp ("pe", info->rclass, 2)) {
		bin_pe_resources (r, mode);
	} else {
		bin_no_resources (r, mode);
	}
	return true;
}

static int bin_versioninfo(RzCore *r, int mode) {
	const RzBinInfo *info = rz_bin_get_info (r->bin);
	if (!info || !info->rclass) {
		return false;
	}
	if (!strncmp ("pe", info->rclass, 2)) {
		bin_pe_versioninfo (r, mode);
	} else if (!strncmp ("elf", info->rclass, 3)) {
		bin_elf_versioninfo (r, mode);
	} else if (!strncmp ("mach0", info->rclass, 5)) {
		bin_mach0_versioninfo (r);
	} else {
		rz_cons_println ("Unknown format");
		return false;
	}
	return true;
}

static int bin_signature(RzCore *r, int mode) {
	RzBinFile *cur = rz_bin_cur (r->bin);
	RzBinPlugin *plg = rz_bin_file_cur_plugin (cur);
	if (plg && plg->signature) {
		const char *signature = plg->signature (cur, IS_MODE_JSON (mode));
		if (IS_MODE_JSON (mode)) {
			rz_cons_printf ("{\"signature\":%s}\n", signature);
		} else {
			rz_cons_println (signature);
		}
		free ((char*) signature);
		return true;
	}
	return false;
}

static int bin_header(RzCore *r, int mode) {
	RzBinFile *cur = rz_bin_cur (r->bin);
	RzBinPlugin *plg = rz_bin_file_cur_plugin (cur);
	if (plg && plg->header) {
		plg->header (cur);
		return true;
	}
	return false;
}

RZ_API int rz_core_bin_info(RzCore *core, int action, int mode, int va, RzCoreBinFilter *filter, const char *chksum) {
	int ret = true;
	const char *name = NULL;
	ut64 at = UT64_MAX, loadaddr = rz_bin_get_laddr (core->bin);
	if (filter && filter->offset) {
		at = filter->offset;
	}
	if (filter && filter->name) {
		name = filter->name;
	}

	// use our internal values for va
	va = va ? VA_TRUE : VA_FALSE;
#if 0
	if (rz_config_get_i (core->config, "anal.strings")) {
		rz_core_cmd0 (core, "aar");
	}
#endif
	if ((action & RZ_CORE_BIN_ACC_RAW_STRINGS)) {
		ret &= bin_raw_strings (core, mode, va);
	} else if ((action & RZ_CORE_BIN_ACC_STRINGS)) {
		ret &= bin_strings (core, mode, va);
	}
	if ((action & RZ_CORE_BIN_ACC_INFO)) {
		ret &= bin_info (core, mode, loadaddr);
	}
	if ((action & RZ_CORE_BIN_ACC_MAIN)) {
		ret &= bin_main (core, mode, va);
	}
	if ((action & RZ_CORE_BIN_ACC_DWARF)) {
		ret &= bin_dwarf (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_PDB)) {
		ret &= rz_core_pdb_info (core, core->bin->file, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_SOURCE)) {
		ret &= bin_source (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_ENTRIES)) {
		ret &= bin_entry (core, mode, loadaddr, va, false);
	}
	if ((action & RZ_CORE_BIN_ACC_INITFINI)) {
		ret &= bin_entry (core, mode, loadaddr, va, true);
	}
	if ((action & RZ_CORE_BIN_ACC_SECTIONS)) {
		ret &= bin_sections (core, mode, loadaddr, va, at, name, chksum, false);
	}
	if ((action & RZ_CORE_BIN_ACC_SEGMENTS)) {
		ret &= bin_sections (core, mode, loadaddr, va, at, name, chksum, true);
	}
	if ((action & RZ_CORE_BIN_ACC_SECTIONS_MAPPING)) {
		ret &= bin_map_sections_to_segments (core->bin, mode);
	}
	if (rz_config_get_i (core->config, "bin.relocs")) {
		if ((action & RZ_CORE_BIN_ACC_RELOCS)) {
			ret &= bin_relocs (core, mode, va);
		}
	}
	if ((action & RZ_CORE_BIN_ACC_LIBS)) {
		ret &= bin_libs (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_IMPORTS)) { // 5s
		ret &= bin_imports (core, mode, va, name);
	}
	if ((action & RZ_CORE_BIN_ACC_EXPORTS)) {
		ret &= bin_symbols (core, mode, loadaddr, va, at, name, true, chksum);
	}
	if ((action & RZ_CORE_BIN_ACC_SYMBOLS)) { // 6s
		ret &= bin_symbols (core, mode, loadaddr, va, at, name, false, chksum);
	}
	if ((action & RZ_CORE_BIN_ACC_CLASSES)) { // 6s
		ret &= bin_classes (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_TRYCATCH)) {
		ret &= bin_trycatch (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_SIZE)) {
		ret &= bin_size (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_MEM)) {
		ret &= bin_mem (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_VERSIONINFO)) {
		ret &= bin_versioninfo (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_RESOURCES)) {
		ret &= bin_resources (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_SIGNATURE)) {
		ret &= bin_signature (core, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_FIELDS)) {
		if (IS_MODE_SIMPLE (mode)) {
			if ((action & RZ_CORE_BIN_ACC_HEADER) || action & RZ_CORE_BIN_ACC_FIELDS) {
				/* ignore mode, just for quiet/simple here */
				ret &= bin_fields (core, 0, va);
			}
		} else {
			if (IS_MODE_NORMAL (mode)) {
				ret &= bin_header (core, mode);
			} else {
				if ((action & RZ_CORE_BIN_ACC_HEADER) || action & RZ_CORE_BIN_ACC_FIELDS) {
					ret &= bin_fields (core, mode, va);
				}
			}
		}
	}
	return ret;
}

RZ_API int rz_core_bin_set_arch_bits(RzCore *r, const char *name, const char * arch, ut16 bits) {
	int fd = rz_io_fd_get_current (r->io);
	RzIODesc *desc = rz_io_desc_get (r->io, fd);
	RzBinFile *curfile, *binfile = NULL;
	if (!name) {
		if (!desc || !desc->name) {
			return false;
		}
		name = desc->name;
	}
	/* Check if the arch name is a valid name */
	if (!rz_asm_is_valid (r->rasm, arch)) {
		return false;
	}
	/* Find a file with the requested name/arch/bits */
	binfile = rz_bin_file_find_by_arch_bits (r->bin, arch, bits);
	if (!binfile) {
		return false;
	}
	if (!rz_bin_use_arch (r->bin, arch, bits, name)) {
		return false;
	}
	curfile = rz_bin_cur (r->bin);
	//set env if the binfile changed or we are dealing with xtr
	if (curfile != binfile || binfile->curxtr) {
		rz_core_bin_set_cur (r, binfile);
		return rz_core_bin_set_env (r, binfile);
	}
	return true;
}

RZ_API int rz_core_bin_update_arch_bits(RzCore *r) {
	RzBinFile *binfile = NULL;
	const char *name = NULL, *arch = NULL;
	ut16 bits = 0;
	if (!r) {
		return 0;
	}
	if (r->rasm) {
		bits = r->rasm->bits;
		if (r->rasm->cur) {
			arch = r->rasm->cur->arch;
		}
	}
	binfile = rz_bin_cur (r->bin);
	name = binfile ? binfile->file : NULL;
	if (binfile && binfile->curxtr) {
		rz_anal_hint_clear (r->anal);
	}
	return rz_core_bin_set_arch_bits (r, name, arch, bits);
}

RZ_API bool rz_core_bin_raise(RzCore *core, ut32 bfid) {
	if (!rz_bin_select_bfid (core->bin, bfid)) {
		return false;
	}
	RzBinFile *bf = rz_bin_cur (core->bin);
	if (bf) {
		rz_io_use_fd (core->io, bf->fd);
	}
	// it should be 0 to use rz_io_use_fd in rz_core_block_read
	core->switch_file_view = 0;
	return bf && rz_core_bin_set_env (core, bf) && rz_core_block_read (core);
}

RZ_API bool rz_core_bin_delete(RzCore *core, ut32 bf_id) {
	if (bf_id == UT32_MAX) {
		return false;
	}
	rz_bin_file_delete (core->bin, bf_id);
	RzBinFile *bf = rz_bin_file_at (core->bin, core->offset);
	if (bf) {
		rz_io_use_fd (core->io, bf->fd);
	}
	core->switch_file_view = 0;
	return bf && rz_core_bin_set_env (core, bf) && rz_core_block_read (core);
}

static bool rz_core_bin_file_print(RzCore *core, RzBinFile *bf, int mode) {
	rz_return_val_if_fail (core && bf && bf->o, NULL);
	const char *name = bf ? bf->file : NULL;
	(void)rz_bin_get_info (core->bin); // XXX is this necssary for proper iniitialization
	ut32 bin_sz = bf ? bf->size : 0;
	// TODO: handle mode to print in json and r2 commands

	switch (mode) {
	case '*':
		{
			char *n = __filterShell (name);
			rz_cons_printf ("oba 0x%08"PFMT64x" %s # %d\n", bf->o->boffset, n, bf->id);
			free (n);
		}
		break;
	case 'q':
		rz_cons_printf ("%d\n", bf->id);
		break;
	case 'j':
		// XXX there's only one binobj for each bf...so we should change that json
		// TODO: use pj API
		rz_cons_printf ("{\"name\":\"%s\",\"iofd\":%d,\"bfid\":%d,\"size\":%d,\"objs\":[",
			name? name: "", bf->fd, bf->id, bin_sz);
		{
			RzBinObject *obj = bf->o;
			RzBinInfo *info = obj->info;
			ut8 bits = info ? info->bits : 0;
			const char *asmarch = rz_config_get (core->config, "asm.arch");
			const char *arch = info ? info->arch ? info->arch: asmarch : "unknown";
			rz_cons_printf ("{\"arch\":\"%s\",\"bits\":%d,\"binoffset\":%"
					PFMT64d",\"objsize\":%"PFMT64d"}",
					arch, bits, obj->boffset, obj->obj_size);
		}
		rz_cons_print ("]}");
		break;
	default:
		{
			RzBinInfo *info = bf->o->info;
			ut8 bits = info ? info->bits : 0;
			const char *asmarch = rz_config_get (core->config, "asm.arch");
			const char *arch = info ? info->arch ? info->arch: asmarch: "unknown";
			rz_cons_printf ("%d %d %s-%d ba:0x%08"PFMT64x" sz:%"PFMT64d" %s\n",
				bf->id, bf->fd, arch, bits, bf->o->baddr, bf->o->size, name);
		}
		break;
	}
	return true;
}

RZ_API int rz_core_bin_list(RzCore *core, int mode) {
	// list all binfiles and there objects and there archs
	int count = 0;
	RzListIter *iter;
	RzBinFile *binfile = NULL; //, *cur_bf = rz_bin_cur (core->bin) ;
	RzBin *bin = core->bin;
	const RzList *binfiles = bin ? bin->binfiles: NULL;
	if (!binfiles) {
		return false;
	}
	if (mode == 'j') {
		rz_cons_print ("[");
	}
	rz_list_foreach (binfiles, iter, binfile) {
		rz_core_bin_file_print (core, binfile, mode);
		if (iter->n && mode == 'j') {
			rz_cons_print (",");
		}
	}
	if (mode == 'j') {
		rz_cons_println ("]");
	}
	return count;
}

RZ_API char *rz_core_bin_method_flags_str(ut64 flags, int mode) {
	int i, len = 0;

	RzStrBuf *buf = rz_strbuf_new ("");
	if (IS_MODE_SET (mode) || IS_MODE_RAD (mode)) {
		if (!flags) {
			goto out;
		}

		for (i = 0; i < 64; i++) {
			ut64 flag = flags & (1ULL << i);
			if (flag) {
				const char *flag_string = rz_bin_get_meth_flag_string (flag, false);
				if (flag_string) {
					rz_strbuf_appendf (buf, ".%s", flag_string);
				}
			}
		}
	} else if (IS_MODE_JSON (mode)) {
		if (!flags) {
			rz_strbuf_append (buf, "[]");
			goto out;
		}

		rz_strbuf_append (buf, "[");

		for (i = 0; i < 64; i++) {
			ut64 flag = flags & (1ULL << i);
			if (flag) {
				const char *flag_string = rz_bin_get_meth_flag_string (flag, false);
				if (len != 0) {
					rz_strbuf_append (buf, ",");
				}
				if (flag_string) {
					rz_strbuf_appendf (buf, "\"%s\"", flag_string);
				} else {
					rz_strbuf_appendf (buf, "\"0x%08"PFMT64x"\"", flag);
				}
				len++;
			}
		}

		rz_strbuf_append (buf, "]");
	} else {
		int pad_len = 4; //TODO: move to a config variable

		if (!flags) {
			goto padding;
		}
		for (i = 0; i < 64; i++) {
			ut64 flag = flags & (1ULL << i);
			if (flag) {
				const char *flag_string = rz_bin_get_meth_flag_string (flag, true);
				if (flag_string) {
					rz_strbuf_append (buf, flag_string);
				} else {
					rz_strbuf_append (buf, "?");
				}
				len++;
			}
		}
padding:
		for ( ; len < pad_len; len++) {
			rz_strbuf_append (buf, " ");
		}
	}
out:
	return rz_strbuf_drain (buf);
}
