// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include "rz_bin.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "../bin/pdb/pdb_downloader.h"

static const char *help_msg_i[] = {
	"Usage: i", "", "Get info from opened file (see rz-bin's manpage)",
	"Output mode:", "", "",
	"'*'", "", "Output in rizin commands",
	"'j'", "", "Output in json",
	"'q'", "", "Simple quiet output",
	"Actions:", "", "",
	"i|ij", "", "Show info of current file (in JSON)",
	"iA", "", "List archs",
	"ia", "", "Show all info (imports, exports, sections..)",
	"ib", "", "Reload the current buffer for setting of the bin (use once only)",
	"ic", "", "List classes, methods and fields",
	"icc", "", "List classes, methods and fields in Header Format",
	"icg", "", "List classes as agn/age commands to create class hirearchy graphs",
	"icq", "", "List classes, in quiet mode (just the classname)",
	"icqq", "", "List classes, in quieter mode (only show non-system classnames)",
	"iC", "[j]", "Show signature info (entitlements, ...)",
	"id", "", "Show DWARF source lines information",
	"idp", " [file.pdb]", "Load pdb file information",
	"idpi", " [file.pdb]", "Show pdb file information",
	"idpi*", "", "Show symbols from pdb as flags (prefix with dot to import)",
	"idpd", "", "Download pdb file on remote server",
	"iD", " lang sym", "demangle symbolname for given language",
	"ie", "", "Entrypoint",
	"iee", "", "Show Entry and Exit (preinit, init and fini)",
	"iE", "", "Exports (global symbols)",
	"iE.", "", "Current export",
	"ih", "", "Headers (alias for iH)",
	"iHH", "", "Verbose Headers in raw text",
	"ii", "", "Imports",
	"iI", "", "Binary info",
	"ik", " [query]", "Key-value database from RzBinObject",
	"il", "", "Libraries",
	"iL ", "[plugin]", "List all RzBin plugins loaded or plugin details",
	"im", "", "Show info about predefined memory allocation",
	"iM", "", "Show main address",
	"io", " [file]", "Load info from file (or last opened) use bin.baddr",
	"iO", "[?]", "Perform binary operation (dump, show binary info)",
	"ir", "", "List the Relocations",
	"iR", "", "List the Resources",
	"is", "", "List the Symbols",
	"is.", "", "Current symbol",
	"iS ", "[entropy,sha1]", "Sections (choose which hash algorithm to use)",
	"iS.", "", "Current section",
	"iS=", "", "Show ascii-art color bars with the section ranges",
	"iSS", "", "List memory segments (maps with om)",
	"it", "", "File hashes",
	"iT", "", "File signature",
	"iV", "", "Display file version info",
	"iw", "", "try/catch blocks",
	"ix", "[.fj?]", "Display source file line info (from debug info)",
	"iz|izj", "", "Strings in data sections (in JSON/Base64)",
	"izz", "", "Search for Strings in the whole binary",
	"izzz", "", "Dump Strings from whole binary to rizin shell (for huge files)",
	"iz-", " [addr]", "Purge string via bin.str.purge",
	"iZ", "", "Guess size of binary program",
	NULL
};

// TODO: this command needs a refactoring
static const char *help_msg_id[] = {
	"Usage: idp", "", "Debug information",
	"id", "", "Show DWARF source lines information",
	"idp", " [file.pdb]", "Load pdb file information",
	"idpi", " [file.pdb]", "Show pdb file information",
	"idpi*", "", "Show symbols from pdb as flags (prefix with dot to import)",
	"idpd", "", "Download pdb file on remote server",
	NULL
};

static const char *help_msg_ix[] = {
	"Usage: ix", "", "Display source file line info (from debug info)",
	"ix[j]", "", "List all source line info available",
	"ix.[j]", "", "Show source line info for current address",
	"ixf[j]", "", "Show summary of all source files used",
	NULL
};

#define PAIR_WIDTH 9
// TODO: reuse implementation in core/bin.c
static void pair(const char *a, const char *b) {
	char ws[16];
	int al = strlen(a);
	if (!b) {
		return;
	}
	memset(ws, ' ', sizeof(ws));
	al = PAIR_WIDTH - al;
	if (al < 0) {
		al = 0;
	}
	ws[al] = 0;
	rz_cons_printf("%s%s%s\n", a, ws, b);
}

static bool demangle_internal(RzCore *core, const char *lang, const char *s) {
	char *res = NULL;
	int type = rz_bin_demangle_type(lang);
	switch (type) {
	case RZ_BIN_NM_CXX: res = rz_bin_demangle_cxx(core->bin->cur, s, 0); break;
	case RZ_BIN_NM_JAVA: res = rz_bin_demangle_java(s); break;
	case RZ_BIN_NM_OBJC: res = rz_bin_demangle_objc(NULL, s); break;
	case RZ_BIN_NM_SWIFT: res = rz_bin_demangle_swift(s, core->bin->demanglercmd); break;
	case RZ_BIN_NM_DLANG: res = rz_bin_demangle_plugin(core->bin, "dlang", s); break;
	case RZ_BIN_NM_MSVC: res = rz_bin_demangle_msvc(s); break;
	case RZ_BIN_NM_RUST: res = rz_bin_demangle_rust(core->bin->cur, s, 0); break;
	default:
		rz_bin_demangle_list(core->bin);
		return true;
	}
	if (res) {
		if (*res) {
			rz_cons_printf("%s\n", res);
		}
		free(res);
		return false;
	}
	return true;
}

static bool demangle(RzCore *core, const char *s) {
	rz_return_val_if_fail(core && s, false);
	const char *ss = strchr(s, ' ');
	if (!*s) {
		return false;
	}
	if (!ss) {
		const char *lang = rz_config_get(core->config, "bin.lang");
		demangle_internal(core, lang, s);
		return true;
	}
	char *p = strdup(s);
	char *q = p + (ss - s);
	*q = 0;
	demangle_internal(core, p, q + 1);
	free(p);
	return true;
}

#define STR(x) (x) ? (x) : ""
static void rz_core_file_info(RzCore *core, PJ *pj, int mode) {
	const char *fn = NULL;
	bool io_cache = rz_config_get_i(core->config, "io.cache");
	RzBinInfo *info = rz_bin_get_info(core->bin);
	RzBinFile *binfile = rz_bin_cur(core->bin);
	int fd = rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(binfile);
	if (mode == RZ_MODE_JSON) {
		pj_o(pj);
	}
	if (mode == RZ_MODE_RIZINCMD) {
		return;
	}
	if (mode == RZ_MODE_SIMPLE) {
		return;
	}
	if (info) {
		fn = info->file;
		if (mode == RZ_MODE_JSON) {
			pj_ks(pj, "type", info->type ? info->type : "");
		}
	} else {
		fn = desc ? desc->name : NULL;
	}
	if (mode == RZ_MODE_JSON) {
		const char *uri = fn;
		if (!uri) {
			if (desc && desc->uri && *desc->uri) {
				uri = desc->uri;
			} else {
				uri = "";
			}
		}
		pj_ks(pj, "file", uri);
		if (desc) {
			ut64 fsz = rz_io_desc_size(desc);
			pj_ki(pj, "fd", desc->fd);
			if (fsz != UT64_MAX) {
				char humansz[8];
				pj_kN(pj, "size", fsz);
				rz_num_units(humansz, sizeof(humansz), fsz);
				pj_ks(pj, "humansz", humansz);
			}
			pj_kb(pj, "iorw", io_cache || desc->perm & RZ_PERM_W);
			pj_ks(pj, "mode", rz_str_rwx_i(desc->perm & RZ_PERM_RWX));
			if (desc->referer && *desc->referer) {
				pj_ks(pj, "referer", desc->referer);
			}
		}
		pj_ki(pj, "block", core->blocksize);
		if (binfile) {
			if (binfile->curxtr) {
				pj_ks(pj, "packet", binfile->curxtr->name);
			}
			if (plugin) {
				pj_ks(pj, "format", plugin->name);
			}
		}
		pj_end(pj);
	} else if (desc && mode != RZ_MODE_SIMPLE) {
		if (desc) {
			pair("fd", sdb_fmt("%d", desc->fd));
		}
		if (fn || (desc && desc->uri)) {
			char *escaped = rz_str_escape_utf8_keep_printable(fn ? fn : desc->uri, false, false);
			if (escaped) {
				pair("file", escaped);
				free(escaped);
			}
		}
		if (desc) {
			ut64 fsz = rz_io_desc_size(desc);
			if (fsz != UT64_MAX) {
				char humansz[8];
				pair("size", sdb_itoca(fsz));
				rz_num_units(humansz, sizeof(humansz), fsz);
				pair("humansz", humansz);
			}
		}
		if (desc) {
			pair("mode", rz_str_rwx_i(desc->perm & RZ_PERM_RWX));
		}
		if (plugin) {
			pair("format", plugin->name);
		}
		if (desc) {
			pair("iorw", rz_str_bool(io_cache || desc->perm & RZ_PERM_W));
		}
		pair("block", sdb_fmt("0x%x", core->blocksize));

		if (binfile && binfile->curxtr) {
			pair("packet", binfile->curxtr->name);
		}
		if (desc && desc->referer && *desc->referer) {
			pair("referer", desc->referer);
		}

		if (info) {
			pair("type", info->type);
		}
	}
}

static int bin_is_executable(RzBinObject *obj) {
	RzListIter *it;
	RzBinSection *sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		rz_list_foreach (obj->sections, it, sec) {
			if (sec->perm & RZ_PERM_X) {
				return true;
			}
		}
	}
	return false;
}

static void cmd_info_bin(RzCore *core, int va, PJ *pj, int mode) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	int array = 0;
	if (core->file) {
		if (mode & RZ_MODE_JSON) {
			if (!(mode & RZ_MODE_ARRAY)) {
				pj_o(pj);
			} else {
				array = 1;
			}
			mode = RZ_MODE_JSON;
			pj_k(pj, "core");
		}
		rz_core_file_info(core, pj, mode);
		if (bin_is_executable(obj)) {
			if ((mode & RZ_MODE_JSON)) {
				pj_k(pj, "bin");
			}
			rz_core_bin_info(core, RZ_CORE_BIN_ACC_INFO, pj, mode, va, NULL, NULL);
		}
		if ((mode & RZ_MODE_JSON) && array == 0) {
			pj_end(pj);
		}
	} else {
		eprintf("No file selected\n");
	}
}

static bool is_equal_file_hashes(RzList *lfile_hashes, RzList *rfile_hashes, bool *equal) {
	rz_return_val_if_fail(lfile_hashes, false);
	rz_return_val_if_fail(rfile_hashes, false);
	rz_return_val_if_fail(equal, false);

	*equal = true;
	RzBinFileHash *fh_l, *fh_r;
	RzListIter *hiter_l, *hiter_r;
	rz_list_foreach (lfile_hashes, hiter_l, fh_l) {
		rz_list_foreach (rfile_hashes, hiter_r, fh_r) {
			if (strcmp(fh_l->type, fh_r->type)) {
				continue;
			}
			if (!!strcmp(fh_l->hex, fh_r->hex)) {
				*equal = false;
				return true;
			}
		}
	}
	return true;
}

static bool __r_core_bin_reload(RzCore *r, const char *file, ut64 baseaddr) {
	RzCoreFile *cf = rz_core_file_cur(r);
	if (!cf) {
		return false;
	}
	RzBinFile *obf = rz_bin_file_find_by_fd(r->bin, cf->fd);
	if (!obf) {
		return false;
	}
	RzBinFile *nbf = rz_bin_reload(r->bin, obf, baseaddr);
	if (!nbf) {
		return false;
	}
	rz_core_bin_apply_all_info(r, nbf);
	return true;
}

static bool isKnownPackage(const char *cn) {
	if (*cn == 'L') {
		if (rz_str_startswith(cn, "Lkotlin")) {
			return true;
		}
		if (rz_str_startswith(cn, "Lcom/google")) {
			return true;
		}
		if (rz_str_startswith(cn, "Lcom/facebook")) {
			return true;
		}
		if (rz_str_startswith(cn, "Lokhttp")) {
			return true;
		}
		if (rz_str_startswith(cn, "Landroid")) {
			return true;
		}
		if (rz_str_startswith(cn, "Lokio")) {
			return true;
		}
	}
	return false;
}

static bool source_file_collect_cb(void *user, const void *k, const void *v) {
	RzPVector *r = user;
	char *f = strdup(k);
	if (f) {
		rz_pvector_push(r, f);
	}
	return true;
}

typedef enum {
	PRINT_SOURCE_INFO_LINES_ALL,
	PRINT_SOURCE_INFO_LINES_HERE,
	PRINT_SOURCE_INFO_FILES
} PrintSourceInfoType;

static bool print_source_info(RzCore *core, PrintSourceInfoType type, RzOutputMode mode) {
	RzBinFile *binfile = core->bin->cur;
	if (!binfile || !binfile->o) {
		rz_cons_printf("No file loaded.\n");
		return false;
	}
	RzBinSourceLineInfo *li = binfile->o->lines;
	if (!li) {
		rz_cons_printf("No source info available.\n");
		return true;
	}
	PJ *j = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		j = pj_new();
	}
	switch (type) {
	case PRINT_SOURCE_INFO_FILES: {
		// collect all filenames uniquely
		HtPP *files = ht_pp_new0();
		if (!files) {
			return false;
		}
		for (size_t i = 0; i < li->samples_count; i++) {
			RzBinSourceLineSample *s = &li->samples[i];
			if (!s->line || !s->file) {
				continue;
			}
			ht_pp_insert(files, s->file, NULL);
		}
		// sort them alphabetically
		RzPVector sorter;
		rz_pvector_init(&sorter, free);
		ht_pp_foreach(files, source_file_collect_cb, &sorter);
		rz_pvector_sort(&sorter, (RzPVectorComparator)strcmp);
		ht_pp_free(files);
		// print them!
		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_a(j);
			void **it;
			rz_pvector_foreach (&sorter, it) {
				pj_s(j, *it);
			}
			pj_end(j);
		} else {
			rz_cons_printf("[Source file]\n");
			void **it;
			rz_pvector_foreach (&sorter, it) {
				const char *file = *it;
				rz_cons_printf("%s\n", file);
			}
		}
		rz_pvector_fini(&sorter);
		break;
	}
	case PRINT_SOURCE_INFO_LINES_ALL:
		rz_core_bin_print_source_line_info(core, li, mode, j);
		break;
	case PRINT_SOURCE_INFO_LINES_HERE:
		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_a(j);
		}
		for (const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(li, core->offset);
			s; s = rz_bin_source_line_info_get_next(li, s)) {
			rz_core_bin_print_source_line_sample(core, s, mode, j);
		}
		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_end(j);
		}
		break;
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		rz_cons_println(pj_string(j));
		pj_free(j);
	}
	return true;
}

RZ_IPI int rz_cmd_info(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	bool newline = rz_cons_is_interactive();
	int fd = rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	int i, va = core->io->va || core->bin->is_debugger;
	int mode = 0; //RZ_MODE_SIMPLE;
	bool rdump = false;
	int is_array = 0;
	bool is_izzzj = false;
	bool is_idpij = false;
	Sdb *db;
	PJ *pj = NULL;

	for (i = 0; input[i] && input[i] != ' '; i++)
		;
	if (i > 0) {
		switch (input[i - 1]) {
		case '*': mode = RZ_MODE_RIZINCMD; break;
		case 'j': mode = RZ_MODE_JSON; break;
		case 'q': mode = RZ_MODE_SIMPLE; break;
		}
	}
#define INIT_PJ() \
	if (!pj) { \
		pj = pj_new(); \
		if (!pj) { \
			return 1; \
		} \
	}
	if (mode == RZ_MODE_JSON) {
		INIT_PJ();
		int suffix_shift = 0;
		if (!strncmp(input, "SS", 2) || !strncmp(input, "ee", 2) || !strncmp(input, "zz", 2)) {
			suffix_shift = 1;
		}
		if (strlen(input + 1 + suffix_shift) > 1) {
			is_array = 1;
		}
		if (!strncmp(input, "zzz", 3)) {
			is_izzzj = true;
		}
		if (!strncmp(input, "dpi", 3)) {
			is_idpij = true;
		}
	}
	if (is_array && !is_izzzj && !is_idpij) {
		pj_o(pj);
	}
	if (!*input) {
		cmd_info_bin(core, va, pj, mode);
	}
	/* i* is an alias for iI* */
	if (!strcmp(input, "*")) {
		input = "I*";
	}
	char *question = strchr(input, '?');
	const char *space = strchr(input, ' ');
	if (!space && question) {
		space = question + 1;
	}
	if (question < space && question > input) {
		question--;
		char *prefix = strdup(input);
		char *tmp = strchr(prefix, '?');
		if (tmp) {
			*tmp = 0;
		}
		rz_core_cmdf(core, "i?~& i%s", prefix);
		free(prefix);
		goto done;
	}
	RZ_FREE(core->table_query);
	if (space && *space == ' ') {
		core->table_query = rz_str_trim_dup(space + 1);
	}
	while (*input) {
		if (*input == ' ') {
			break;
		}
		switch (*input) {
		case 'b': // "ib"
		{
			ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
			if (input[1] == ' ') {
				baddr = rz_num_math(core->num, input + 1);
			}
			// XXX: this will reload the bin using the buffer.
			// An assumption is made that assumes there is an underlying
			// plugin that will be used to load the bin (e.g. malloc://)
			// TODO: Might be nice to reload a bin at a specified offset?
			__r_core_bin_reload(core, NULL, baddr);
			rz_core_block_read(core);
			newline = false;
		} break;
		case 'k': // "ik"
		{
			RzBinObject *o = rz_bin_cur_object(core->bin);
			db = o ? o->kv : NULL;
			//:eprintf ("db = %p\n", db);
			switch (input[1]) {
			case 'v':
				if (db) {
					char *o = sdb_querys(db, NULL, 0, input + 3);
					if (o && *o) {
						rz_cons_print(o);
					}
					free(o);
				}
				break;
			case '*':
				rz_core_bin_export_info(core, RZ_MODE_RIZINCMD);
				break;
			case '.':
			case ' ':
				if (db) {
					char *o = sdb_querys(db, NULL, 0, input + 2);
					if (o && *o) {
						rz_cons_print(o);
					}
					free(o);
				}
				break;
			case '\0':
				if (db) {
					char *o = sdb_querys(db, NULL, 0, "*");
					if (o && *o) {
						rz_cons_print(o);
					}
					free(o);
				}
				break;
			case '?':
			default:
				eprintf("Usage: ik [sdb-query]\n");
				eprintf("Usage: ik*    # load all header information\n");
			}
			goto done;
		} break;
		case 'o': // "io"
		{
			if (!desc) {
				eprintf("Core file not open\n");
				return 0;
			}
			const char *fn = input[1] == ' ' ? input + 2 : desc->name;
			ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
			rz_core_bin_load(core, fn, baddr);
		} break;
#define RZBININFO(n, x, y) \
	if (is_array) { \
		pj_k(pj, n); \
	} \
	rz_core_bin_info(core, x, pj, mode, va, NULL, y);
		case 'E': // "iE"
		{
			if (input[1] == 'j' && input[2] == '.') {
				mode = RZ_MODE_JSON;
				INIT_PJ();
				RZBININFO("exports", RZ_CORE_BIN_ACC_EXPORTS, input + 2);
			} else {
				RZBININFO("exports", RZ_CORE_BIN_ACC_EXPORTS, input + 1);
			}
			while (*(++input))
				;
			input--;
			break;
		}
		case 't': // "it"
		{
			ut64 limit = rz_config_get_i(core->config, "bin.hashlimit");
			RzBinInfo *info = rz_bin_get_info(core->bin);
			if (!info) {
				eprintf("rz_bin_get_info: Cannot get bin info\n");
				return 0;
			}

			RzBinFile *bf = core->bin->cur;
			if (!bf) {
				RZ_LOG_ERROR("Cannot get current binary file\n");
				return 0;
			}

			RzList *new_hashes = rz_bin_file_compute_hashes(core->bin, bf, limit);
			RzList *old_hashes = rz_bin_file_set_hashes(core->bin, new_hashes);
			bool equal = true;
			if (!rz_list_empty(new_hashes) && !rz_list_empty(old_hashes)) {
				if (!is_equal_file_hashes(new_hashes, old_hashes, &equal)) {
					eprintf("is_equal_file_hashes: Cannot compare file hashes\n");
					rz_list_free(old_hashes);
					return 0;
				}
			}
			RzBinFileHash *fh_old, *fh_new;
			RzListIter *hiter_old, *hiter_new;
			const bool is_json = input[1] == 'j'; // "itj"
			if (is_json) { // "itj"
				pj_o(pj);
				rz_list_foreach (new_hashes, hiter_new, fh_new) {
					pj_ks(pj, fh_new->type, fh_new->hex);
				}
				if (!equal) {
					// print old hashes prefixed with `o` character like `omd5` and `isha1`
					rz_list_foreach (old_hashes, hiter_old, fh_old) {
						char *key = rz_str_newf("o%s", fh_old->type);
						pj_ks(pj, key, fh_old->hex);
						free(key);
					}
				}
				pj_end(pj);
			} else { // "it"
				if (!equal) {
					eprintf("File has been modified.\n");
					hiter_new = rz_list_iterator(new_hashes);
					hiter_old = rz_list_iterator(old_hashes);
					while (rz_list_iter_next(hiter_new) && rz_list_iter_next(hiter_old)) {
						fh_new = (RzBinFileHash *)rz_list_iter_get(hiter_new);
						fh_old = (RzBinFileHash *)rz_list_iter_get(hiter_old);
						if (strcmp(fh_new->type, fh_old->type)) {
							eprintf("Wrong file hashes structure");
						}
						if (!strcmp(fh_new->hex, fh_old->hex)) {
							eprintf("= %s %s\n", fh_new->type, fh_new->hex); // output one line because hash remains same `= hashtype hashval`
						} else {
							// output diff-like two lines, one with old hash val `- hashtype hashval` and one with new `+ hashtype hashval`
							eprintf("- %s %s\n+ %s %s\n",
								fh_old->type, fh_old->hex,
								fh_new->type, fh_new->hex);
						}
					}
				} else { // hashes are equal
					rz_list_foreach (new_hashes, hiter_new, fh_new) {
						rz_cons_printf("%s %s\n", fh_new->type, fh_new->hex);
					}
				}
				newline = false;
			}
			rz_list_free(old_hashes);
		} break;
		case 'Z': // "iZ"
			RZBININFO("size", RZ_CORE_BIN_ACC_SIZE, NULL);
			break;
		case 'O': // "iO"
			switch (input[1]) {
			case ' ':
				rz_sys_cmdf("rz-bin -O \"%s\" \"%s\"", rz_str_trim_head_ro(input + 1), desc ? desc->name : "");
				break;
			default:
				rz_sys_cmdf("rz-bin -O help");
				break;
			}
			return 0;
		case 'S': // "iS"
			//we comes from ia or iS
			if ((input[1] == 'm' && input[2] == 'z') || !input[1]) {
				RZBININFO("sections", RZ_CORE_BIN_ACC_SECTIONS, NULL);
			} else if (input[1] == 'S' && !input[2]) { // "iSS"
				RZBININFO("segments", RZ_CORE_BIN_ACC_SEGMENTS, NULL);
			} else { //iS/iSS entropy,sha1
				const char *name = "sections";
				int action = RZ_CORE_BIN_ACC_SECTIONS;
				int param_shift = 0;
				if (input[1] == 'S') {
					name = "segments";
					input++;
					action = RZ_CORE_BIN_ACC_SEGMENTS;
				}
				// case for iS=
				if (input[1] == '=') {
					mode = RZ_MODE_EQUAL;
				} else if (input[1] == '*') {
					mode = RZ_MODE_RIZINCMD;
				} else if (input[1] == 'q' && input[2] == '.') {
					mode = RZ_MODE_SIMPLE;
				} else if (input[1] == 'j' && input[2] == '.') {
					mode = RZ_MODE_JSON;
					INIT_PJ();
				}
				if (mode == RZ_MODE_RIZINCMD || mode == RZ_MODE_JSON || mode == RZ_MODE_SIMPLE) {
					if (input[param_shift + 1]) {
						param_shift++;
					}
				}
				RZBININFO(name, action, input + 1 + param_shift);
			}
			//we move input until get '\0'
			while (*(++input))
				;
			//input-- because we are inside a while that does input++
			// oob read if not input--
			input--;
			break;
		case 'H': // "iH"
			if (input[1] == 'H') { // "iHH"
				RZBININFO("header", RZ_CORE_BIN_ACC_HEADER, NULL);
				break;
			}
			// fallthrough
		case 'h': // "ih"
			RZBININFO("fields", RZ_CORE_BIN_ACC_FIELDS, NULL);
			break;
		case 'l': { // "il"
			RZBININFO("libs", RZ_CORE_BIN_ACC_LIBS, NULL);
			break;
		}
		case 'L': { // "iL"
			RzCmdStateOutput state = { 0 };
			char *ptr = strchr(input, ' ');
			switch (input[1]) {
			case 'j': {
				state.mode = RZ_OUTPUT_MODE_JSON;
				state.d.pj = pj_new();
				break;
			}
			case 'q': {
				state.mode = RZ_OUTPUT_MODE_QUIET;
				break;
			}
			default: {
				state.mode = RZ_OUTPUT_MODE_STANDARD;
				break;
			}
			}
			if (ptr && ptr[1]) {
				const char *plugin_name = ptr + 1;
				if (is_array) {
					pj_k(pj, "plugin");
				}
				rz_bin_list_plugin(core->bin, plugin_name, pj, 0);
			} else {
				rz_core_bin_plugins_print(core->bin, &state);
				switch (state.mode) {
				case RZ_OUTPUT_MODE_JSON: {
					rz_cons_print(pj_string(state.d.pj));
					rz_cons_flush();
					pj_free(state.d.pj);
					break;
				}
				default: {
					break;
				}
				}
			}
			newline = false;
			goto done;
		}
		case 's': { // "is"
			// Case for isj.
			if (input[1] == 'j' && input[2] == '.') {
				mode = RZ_MODE_JSON;
				INIT_PJ();
				RZBININFO("symbols", RZ_CORE_BIN_ACC_SYMBOLS, input + 2);
			} else if (input[1] == 'q' && input[2] == 'q') {
				mode = RZ_MODE_SIMPLEST;
				RZBININFO("symbols", RZ_CORE_BIN_ACC_SYMBOLS, input + 1);
			} else if (input[1] == 'q' && input[2] == '.') {
				mode = RZ_MODE_SIMPLE;
				RZBININFO("symbols", RZ_CORE_BIN_ACC_SYMBOLS, input + 2);
			} else {
				RZBININFO("symbols", RZ_CORE_BIN_ACC_SYMBOLS, input + 1);
			}
			while (*(++input))
				;
			input--;
			break;
		}
		case 'R': // "iR"
			RZBININFO("resources", RZ_CORE_BIN_ACC_RESOURCES, NULL);
			break;
		case 'r': // "ir"
			RZBININFO("relocs", RZ_CORE_BIN_ACC_RELOCS, NULL);
			break;
		case 'x':
			newline = false;
			switch (*++input) {
			case '\0': // "ix"
			case ' ':
				print_source_info(core, PRINT_SOURCE_INFO_LINES_ALL, RZ_OUTPUT_MODE_STANDARD);
				break;
			case 'j': // "ixj"
				print_source_info(core, PRINT_SOURCE_INFO_LINES_ALL, RZ_OUTPUT_MODE_JSON);
				break;
			case '.':
				if (*++input == 'j') { // "ix.j"
					print_source_info(core, PRINT_SOURCE_INFO_LINES_HERE, RZ_OUTPUT_MODE_JSON);
					mode = 0; // we do json ourselves here
					input++;
				} else { // "ix."
					print_source_info(core, PRINT_SOURCE_INFO_LINES_HERE, RZ_OUTPUT_MODE_STANDARD);
				}
				break;
			case 'f':
				if (*++input == 'j') { // "ixfj"
					print_source_info(core, PRINT_SOURCE_INFO_FILES, RZ_OUTPUT_MODE_JSON);
					mode = 0; // we do json ourselves here
					input++;
				} else { // "ixf"
					print_source_info(core, PRINT_SOURCE_INFO_FILES, RZ_OUTPUT_MODE_STANDARD);
				}
				break;
			case '?': // "ix?"
			default:
				rz_core_cmd_help(core, help_msg_ix);
				input++;
				break;
			}
			break;
		case 'd': // "id"
			if (input[1] == 'p') { // "idp"
				SPDBOptions pdbopts;
				RzBinInfo *info;
				bool file_found;
				char *filename;

				switch (input[2]) {
				case ' ': // "idp file.pdb"
					rz_core_cmdf(core, ".idpi* %s", input + 3);
					while (input[2]) {
						input++;
					}
					break;
				case '\0': // "idp"
					rz_core_cmd0(core, ".idpi*");
					break;
				case 'd': // "idpd"
					pdbopts.user_agent = (char *)rz_config_get(core->config, "pdb.useragent");
					pdbopts.extract = rz_config_get_i(core->config, "pdb.extract");
					pdbopts.symbol_store_path = (char *)rz_config_get(core->config, "pdb.symstore");
					char *str = strdup(rz_config_get(core->config, "pdb.server"));
					RzList *server_l = rz_str_split_list(str, ";", 0);
					RzListIter *it;
					char *server;
					int r = 1;
					rz_list_foreach (server_l, it, server) {
						pdbopts.symbol_server = server;
						r = rz_bin_pdb_download(core, pj, input[3] == 'j', &pdbopts);
						if (!r) {
							break;
						}
					}
					if (r > 0) {
						eprintf("Error while downloading pdb file\n");
					}
					free(str);
					rz_list_free(server_l);
					input++;
					break;
				case 'i': // "idpi"
					info = rz_bin_get_info(core->bin);
					filename = strchr(input, ' ');
					while (input[2])
						input++;
					if (filename) {
						*filename++ = '\0';
						filename = strdup(filename);
						file_found = rz_file_exists(filename);
					} else {
						/* Autodetect local file */
						if (!info || !info->debug_file_name) {
							eprintf("Cannot get file's debug information\n");
							break;
						}
						// Check raw path for debug filename
						file_found = rz_file_exists(rz_file_basename(info->debug_file_name));
						if (file_found) {
							filename = strdup(rz_file_basename(info->debug_file_name));
						} else {
							// Check debug filename basename in current directory
							char *basename = (char *)rz_file_basename(info->debug_file_name);
							file_found = rz_file_exists(basename);
							if (!file_found) {
								// Check if debug file is in file directory
								char *dir = rz_file_dirname(core->bin->cur->file);
								filename = rz_str_newf("%s/%s", dir, basename);
								file_found = rz_file_exists(filename);
							} else {
								filename = strdup(basename);
							}
						}

						// Last chance: Check if file is in downstream symbol store
						if (!file_found) {
							const char *symstore_path = rz_config_get(core->config, "pdb.symstore");
							const char *base_file = rz_file_basename(info->debug_file_name);
							char *pdb_path = rz_str_newf("%s" RZ_SYS_DIR "%s" RZ_SYS_DIR "%s" RZ_SYS_DIR "%s",
								symstore_path, base_file, info->guid, base_file);
							file_found = rz_file_exists(pdb_path);
							if (file_found) {
								filename = pdb_path;
							} else {
								RZ_FREE(pdb_path);
							}
						}
					}

					if (!file_found) {
						if (info->debug_file_name) {
							const char *fn = rz_file_basename(info->debug_file_name);
							eprintf("File '%s' not found in file directory or symbol store\n", fn);
						} else {
							eprintf("Cannot open file\n");
						}
						free(filename);
						break;
					}
					rz_core_pdb_info(core, filename, pj, mode);
					free(filename);
					break;
				case '?':
				default:
					rz_core_cmd_help(core, help_msg_id);
					input++;
					break;
				}
				input++;
			} else if (input[1] == '?') { // "id?"
				rz_core_cmd_help(core, help_msg_id);
				input++;
			} else { // "id"
				RZBININFO("dwarf", RZ_CORE_BIN_ACC_DWARF, NULL);
			}
			break;
		case 'i': { // "ii"
			RZBININFO("imports", RZ_CORE_BIN_ACC_IMPORTS, NULL);
			break;
		}
		case 'I': // "iI"
			RZBININFO("info", RZ_CORE_BIN_ACC_INFO, NULL);
			break;
		case 'e': // "ie"
			if (input[1] == 'e') {
				RZBININFO("initfini", RZ_CORE_BIN_ACC_INITFINI, NULL);
				input++;
			} else {
				RZBININFO("entries", RZ_CORE_BIN_ACC_ENTRIES, NULL);
			}
			break;
		case 'M': // "iM"
			RZBININFO("main", RZ_CORE_BIN_ACC_MAIN, NULL);
			break;
		case 'm': // "im"
			RZBININFO("memory", RZ_CORE_BIN_ACC_MEM, NULL);
			break;
		case 'w': // "iw"
			RZBININFO("trycatch", RZ_CORE_BIN_ACC_TRYCATCH, NULL);
			break;
		case 'V': // "iV"
			RZBININFO("versioninfo", RZ_CORE_BIN_ACC_VERSIONINFO, NULL);
			break;
		case 'T': // "iT"
		case 'C': // "iC" // rz-bin -C create // should be deprecated and just use iT (or find a better name)
			RZBININFO("signature", RZ_CORE_BIN_ACC_SIGNATURE, NULL);
			break;
		case 'z': // "iz"
			if (input[1] == '-') { //iz-
				char *strpurge = core->bin->strpurge;
				ut64 addr = core->offset;
				bool old_tmpseek = core->tmpseek;
				input++;
				if (input[1] == ' ') {
					const char *argstr = rz_str_trim_head_ro(input + 2);
					ut64 arg = rz_num_get(NULL, argstr);
					input++;
					if (arg != 0 || *argstr == '0') {
						addr = arg;
					}
				}
				core->tmpseek = false;
				rz_core_cmdf(core, "e bin.str.purge=%s%s0x%" PFMT64x,
					strpurge ? strpurge : "",
					strpurge && *strpurge ? "," : "",
					addr);
				core->tmpseek = old_tmpseek;
				newline = false;
			} else if (input[1] == 'z') { //izz
				switch (input[2]) {
				case 'z': //izzz
					rdump = true;
					break;
				case '*':
					mode = RZ_MODE_RIZINCMD;
					break;
				case 'j':
					mode = RZ_MODE_JSON;
					INIT_PJ();
					break;
				case 'q': //izzq
					if (input[3] == 'q') { //izzqq
						mode = RZ_MODE_SIMPLEST;
						input++;
					} else {
						mode = RZ_MODE_SIMPLE;
					}
					break;
				default:
					mode = RZ_MODE_PRINT;
					break;
				}
				input++;
				if (rdump) {
					RzBinFile *bf = rz_bin_cur(core->bin);
					int min = rz_config_get_i(core->config, "bin.minstr");
					if (bf) {
						bf->strmode = mode;
						rz_bin_dump_strings(bf, min, 2);
					}
					goto done;
				}
				RZBININFO("strings", RZ_CORE_BIN_ACC_RAW_STRINGS, NULL);
			} else {
				if (input[1] == 'q') {
					mode = (input[2] == 'q')
						? RZ_MODE_SIMPLEST
						: RZ_MODE_SIMPLE;
					input++;
				}
				RZBININFO("strings", RZ_CORE_BIN_ACC_STRINGS, NULL);
			}
			break;
		case 'c': // "ic"
			// XXX this is dupe of cbin.c:bin_classes()
			if (input[1] == '?') {
				eprintf("Usage: ic[gljqc**] [class-index or name]\n");
			} else if (input[1] == 'g') {
				RzBinClass *cls;
				RzListIter *iter;
				RzBinObject *obj = rz_bin_cur_object(core->bin);
				if (!obj) {
					break;
				}
				bool fullGraph = true;
				if (fullGraph) {
					rz_list_foreach (obj->classes, iter, cls) {
						if (cls->super) {
							rz_cons_printf("agn %s\n", cls->super);
							rz_cons_printf("agn %s\n", cls->name);
							rz_cons_printf("age %s %s\n", cls->super, cls->name);
						} else {
							rz_cons_printf("agn %s\n", cls->name);
						}
					}
				} else {
					rz_list_foreach (obj->classes, iter, cls) {
						if (cls->super && !strstr(cls->super, "NSObject")) {
							rz_cons_printf("agn %s\n", cls->super);
							rz_cons_printf("agn %s\n", cls->name);
							rz_cons_printf("age %s %s\n", cls->super, cls->name);
						}
					}
				}
				goto done;
			} else if (input[1] == ' ' || input[1] == 'q' || input[1] == 'j' || input[1] == 'l' || input[1] == 'c' || input[1] == '*') {
				RzBinClass *cls;
				RzBinSymbol *sym;
				RzListIter *iter, *iter2;
				RzBinObject *obj = rz_bin_cur_object(core->bin);
				if (!obj) {
					break;
				}
				if (input[2] && input[2] != '*' && input[2] != 'j' && !strstr(input, "qq")) {
					bool rizin = strstr(input, "**") != NULL;
					int idx = -1;
					const char *cls_name = NULL;
					if (rizin) {
						input++;
					}
					if (rz_num_is_valid_input(core->num, input + 2)) {
						idx = rz_num_math(core->num, input + 2);
					} else {
						const char *first_char = input + ((input[1] == ' ') ? 1 : 2);
						int not_space = strspn(first_char, " ");
						if (first_char[not_space]) {
							cls_name = first_char + not_space;
						}
					}
					if (rizin) {
						input++;
					}
					int count = 0;
					int mode = input[1];
					rz_list_foreach (obj->classes, iter, cls) {
						if (rizin) {
							rz_cons_printf("ac %s\n", cls->name);
							rz_list_foreach (cls->methods, iter2, sym) {
								rz_cons_printf("ac %s %s 0x%08" PFMT64x "\n", cls->name, sym->name, sym->vaddr);
							}
							continue;
						}
						if ((idx >= 0 && idx != count++) ||
							(cls_name && *cls_name && strcmp(cls_name, cls->name) != 0)) {
							continue;
						}
						switch (mode) {
						case '*':
							rz_list_foreach (cls->methods, iter2, sym) {
								rz_cons_printf("f sym.%s @ 0x%" PFMT64x "\n",
									sym->name, sym->vaddr);
							}
							input++;
							break;
						case 'l':
							rz_list_foreach (cls->methods, iter2, sym) {
								const char *comma = iter2->p ? " " : "";
								rz_cons_printf("%s0x%" PFMT64d, comma, sym->vaddr);
							}
							rz_cons_newline();
							input++;
							break;
						case 'j':
							input++;
							pj_ks(pj, "class", cls->name);
							pj_ka(pj, "methods");
							rz_list_foreach (cls->methods, iter2, sym) {
								pj_o(pj);
								pj_ks(pj, "name", sym->name);
								if (sym->method_flags) {
									char *flags = rz_core_bin_method_flags_str(sym->method_flags, RZ_MODE_JSON);
									pj_k(pj, "flags");
									pj_j(pj, flags);
									free(flags);
								}
								pj_kN(pj, "vaddr", sym->vaddr);
								pj_end(pj);
							}
							pj_end(pj);
							break;
						default:
							rz_cons_printf("class %s\n", cls->name);
							rz_list_foreach (cls->methods, iter2, sym) {
								char *flags = rz_core_bin_method_flags_str(sym->method_flags, 0);
								rz_cons_printf("0x%08" PFMT64x " method %s %s %s\n",
									sym->vaddr, cls->name, flags, sym->name);
								RZ_FREE(flags);
							}
							break;
						}
						goto done;
					}
					goto done;
				} else if (obj->classes) {
					if (strstr(input, "qq")) { // "icqq"
						rz_list_foreach (obj->classes, iter, cls) {
							if (!isKnownPackage(cls->name)) {
								rz_cons_printf("%s\n", cls->name);
							}
						}
					} else if (input[1] == 'l') { // "icl"
						rz_list_foreach (obj->classes, iter, cls) {
							rz_list_foreach (cls->methods, iter2, sym) {
								const char *comma = iter2->p ? " " : "";
								rz_cons_printf("%s0x%" PFMT64d, comma, sym->vaddr);
							}
							if (!rz_list_empty(cls->methods)) {
								rz_cons_newline();
							}
						}
					} else if (input[1] == 'c') { // "icc"
						mode = RZ_MODE_CLASSDUMP;
						if (input[2] == '*') {
							mode |= RZ_MODE_RIZINCMD;
						}
						RZBININFO("classes", RZ_CORE_BIN_ACC_CLASSES, NULL);
					} else { // "icq"
						if (input[2] == 'j') {
							mode |= RZ_MODE_JSON; // default mode is RZ_MODE_SIMPLE
						}
						RZBININFO("classes", RZ_CORE_BIN_ACC_CLASSES, NULL);
					}
					goto done;
				}
			} else { // "ic"
				RzBinObject *obj = rz_bin_cur_object(core->bin);
				if (obj && obj->classes) {
					RZBININFO("classes", RZ_CORE_BIN_ACC_CLASSES, NULL);
				}
			}
			break;
		case 'D': // "iD"
			if (input[1] != ' ' || !demangle(core, input + 2)) {
				eprintf("|Usage: iD lang symbolname\n");
			}
			return 0;
		case 'a': // "ia"
			switch (mode) {
			case RZ_MODE_RIZINCMD: rz_cmd_info(core, "IieEcsSmz*"); break;
			case RZ_MODE_JSON: rz_cmd_info(core, "IieEcsSmzj"); break;
			case RZ_MODE_SIMPLE: rz_cmd_info(core, "IieEcsSmzq"); break;
			default: rz_cmd_info(core, "IiEecsSmz"); break;
			}
			break;
		case '?': // "i?"
			rz_core_cmd_help(core, help_msg_i);
			goto redone;
		case '*': // "i*"
			if (mode == RZ_MODE_RIZINCMD) {
				// TODO:handle ** submodes
				mode = RZ_MODE_RIZINCMD;
			} else {
				mode = RZ_MODE_RIZINCMD;
			}
			goto done;
		case 'q': // "iq"
			mode = RZ_MODE_SIMPLE;
			cmd_info_bin(core, va, pj, mode);
			goto done;
		case 'j': // "ij"
			mode = RZ_MODE_JSON;
			if (is_array > 1) {
				mode |= RZ_MODE_ARRAY;
			}
			cmd_info_bin(core, va, pj, mode);
			goto done;
		default:
			cmd_info_bin(core, va, pj, mode);
			break;
		}
		// input can be overwritten like the 'input = " ";' a few lines above
		if (input[0] && input[0] != ' ') {
			input++;
			if ((*input == 'j' || *input == 'q') && (input[0] && !input[1])) {
				break;
			}
		} else {
			break;
		}
	}
done:
	if (mode & RZ_MODE_JSON) {
		if (is_array && !is_izzzj && !is_idpij) {
			pj_end(pj);
		}
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else if (newline) {
		rz_cons_newline();
	}
redone:
	return 0;
}

RZ_IPI RzCmdStatus rz_cmd_info_archs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_archs_print(core->bin, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_entry_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_entries_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_entryexits_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_initfini_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_exports_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_exports_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_symbols_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_symbols_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_imports_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_imports_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_libs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_libs_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_main_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_main_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_relocs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_relocs_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_sections_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_bin_sections_print(core, state, hashes);
	rz_list_free(hashes);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_segments_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_bin_segments_print(core, state, hashes);
	rz_list_free(hashes);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_strings_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bin_strings_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}