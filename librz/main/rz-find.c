// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>

#include <rz_core.h>
#include <rz_main.h>
#include <rz_types.h>
#include <rz_search.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_cons.h>
#include <rz_lib.h>
#include <rz_io.h>
#include <rz_bin.h>

typedef struct {
	bool showstr;
	bool rad;
	bool identify;
	bool import; /* search within import table */
	bool symbol; /* search within symbol table */
	bool quiet;
	bool hexstr;
	bool widestr;
	bool nonstop;
	bool json;
	int mode;
	int align;
	ut8 *buf;
	ut64 bsize;
	ut64 from;
	ut64 to;
	ut64 cur;
	RzPrint *pr;
	RzList /*<char *>*/ *keywords;
	const char *mask;
	const char *curfile;
	const char *comma;
	const char *exec_command;
} RzfindOptions;

static void rzfind_options_fini(RzfindOptions *ro) {
	free(ro->buf);
	ro->cur = 0;
}

static void rzfind_options_init(RzfindOptions *ro) {
	memset(ro, 0, sizeof(RzfindOptions));
	ro->mode = RZ_SEARCH_STRING;
	ro->bsize = 4096;
	ro->to = UT64_MAX;
	ro->keywords = rz_list_newf(NULL);
	ro->exec_command = NULL;
}

static int rzfind_open(RzfindOptions *ro, const char *file);

static int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	RzfindOptions *ro = (RzfindOptions *)user;
	int delta = addr - ro->cur;
	if (ro->cur > addr && (ro->cur - addr == kw->keyword_length - 1)) {
		// This case occurs when there is hit in search left over
		delta = ro->cur - addr;
	}
	if (delta < 0 || delta >= ro->bsize) {
		eprintf("Invalid delta\n");
		return 0;
	}
	char _str[128];
	char *str = _str;
	*_str = 0;
	if (ro->showstr) {
		if (ro->widestr) {
			str = _str;
			int i, j = 0;
			for (i = delta; ro->buf[i] && i < sizeof(_str); i++) {
				char ch = ro->buf[i];
				if (ch == '"' || ch == '\\') {
					ch = '\'';
				}
				if (!IS_PRINTABLE(ch)) {
					break;
				}
				str[j++] = ch;
				i++;
				if (j > 80) {
					strcpy(str + j, "...");
					j += 3;
					break;
				}
				if (ro->buf[i]) {
					break;
				}
			}
			str[j] = 0;
		} else {
			size_t i;
			for (i = 0; i < sizeof(_str) - 1; i++) {
				char ch = ro->buf[delta + i];
				if (ch == '"' || ch == '\\') {
					ch = '\'';
				}
				if (!ch || !IS_PRINTABLE(ch)) {
					break;
				}
				str[i] = ch;
			}
			str[i] = 0;
		}
	} else {
		size_t i;
		for (i = 0; i < sizeof(_str) - 1; i++) {
			char ch = ro->buf[delta + i];
			if (ch == '"' || ch == '\\') {
				ch = '\'';
			}
			if (!ch || !IS_PRINTABLE(ch)) {
				break;
			}
			str[i] = ch;
		}
		str[i] = 0;
	}
	if (ro->json) {
		const char *type = "string";
		printf("%s{\"offset\":%" PFMT64d ",\"type\":\"%s\",\"data\":\"%s\"}",
			ro->comma, addr, type, str);
		ro->comma = ",";
	} else if (ro->rad) {
		printf("f hit%d_%d @ 0x%08" PFMT64x " ; %s\n", 0, kw->count, addr, ro->curfile);
	} else {
		if (ro->showstr) {
			printf("0x%" PFMT64x " %s\n", addr, str);
		} else {
			printf("0x%" PFMT64x "\n", addr);
			if (ro->pr) {
				char *dump = rz_print_hexdump_str(ro->pr, addr, (ut8 *)ro->buf + delta, 78, 16, 1, 1);
				printf("%s", dump);
				free(dump);
			}
		}
	}
	if (ro->exec_command) {
		char *command = rz_str_newf("%s %s", ro->exec_command, ro->curfile);
		int status = rz_sys_system(command);
		if (status == -1) {
			RZ_LOG_ERROR("Failed to execute command: %s\n", command);
		}
		free(command);
		return 1;
	}
	return 1;
}

static void print_bin_string(RzBinFile *bf, RzBinString *string, PJ *pj) {
	rz_return_if_fail(bf && string);

	RzBinSection *s = rz_bin_get_section_at(bf->o, string->paddr, false);
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	string->vaddr = bf->o ? rz_bin_object_get_vaddr(bf->o, string->paddr, string->vaddr) : UT64_MAX;

	if (pj) {
		const char *section_name = s ? s->name : "";
		const char *type_string = rz_str_enc_as_string(string->type);
		pj_o(pj);
		pj_kn(pj, "vaddr", string->vaddr);
		pj_kn(pj, "paddr", string->paddr);
		pj_kn(pj, "ordinal", string->ordinal);
		pj_kn(pj, "size", string->size);
		pj_kn(pj, "length", string->length);
		pj_ks(pj, "section", section_name);
		pj_ks(pj, "type", type_string);
		pj_ks(pj, "string", string->string);
		pj_end(pj);
	} else {
		printf("%s\n", string->string);
	}
}

static int show_help(const char *argv0, int line) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("%s [-mXnzZhqv] [-a align] [-b sz] [-f/t from/to] [-[e|s|w|S|I] str] [-x hex] -|file|dir ..\n", argv0);
	if (line) {
		return 0;
	}
	const char *options[] = {
		// clang-format off
		"-a",    "[align]", "Only accept aligned hits",
		"-b",    "[size]",  "Set block size",
		"-e",    "[regex]", "Search for regex matches (can be used multiple times)",
		"-E",    "[cmd]",   "Execute command for each file found",
		"-f",    "[from]",  "Start searching from address 'from'",
		"-F",    "[file]",  "Read the contents of the file and use it as keyword",
		"-h",    "",        "Show this help",
		"-i",    "",        "Identify filetype (rizin -nqcpm file)",
		"-j",    "",        "Output in JSON",
		"-m",    "",        "Magic search, file-type carver",
		"-M",    "[str]",   "Set a binary mask to be applied on keywords",
		"-n",    "",        "Do not stop on read errors",
		"-r",    "",        "Print using rizin commands",
		"-s",    "[str]",   "Search for a specific string (can be used multiple times)",
		"-w",    "[str]",   "Search for a specific wide string (can be used multiple times). Assumes str is UTF-8.",
		"-I",    "[str]",   "Search for an entry in import table.",
		"-S",    "[str]",   "Search for a symbol in symbol table.",
		"-t",    "[to]",    "Stop search at address 'to'",
		"-q",    "",        "Quiet - do not show headings (filenames) above matching contents (default for searching a single file)",
		"-v",    "",        "Show version information",
		"-x",    "[hex]",   "Search for hexpair string (909090) (can be used multiple times)",
		"-X",    "",        "Show hexdump of search results",
		"-z",    "",        "Search for zero-terminated strings",
		"-Z",    "",        "Show string found on each search hit",
		// clang-format on
	};
	size_t maxOptionAndArgLength = 0;
	for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
		size_t optionLength = strlen(options[i]);
		size_t argLength = strlen(options[i + 1]);
		size_t totalLength = optionLength + argLength;
		if (totalLength > maxOptionAndArgLength) {
			maxOptionAndArgLength = totalLength;
		}
	}
	for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
		if (i + 1 < sizeof(options) / sizeof(options[0])) {
			rz_print_colored_help_option(options[i], options[i + 1], options[i + 2], maxOptionAndArgLength);
		}
	}
	return 0;
}

static int rzfind_open_file(RzfindOptions *ro, const char *file, const ut8 *data, int datalen) {
	RzListIter *iter;
	RzSearch *rs = NULL;
	const char *kw;
	bool last = false;
	int ret, result = 0;

	ro->buf = NULL;
	if (!ro->quiet) {
		printf("File: %s\n", file);
	}

	char *efile = rz_str_escape_sh(file);

	if (ro->identify) {
		char *cmd = rz_str_newf("rizin -e search.show=false -e search.maxhits=1 -nqcpm \"%s\"", efile);
		rz_sys_xsystem(cmd);
		free(cmd);
		free(efile);
		return 0;
	}

	if (ro->import || ro->symbol) {
		RzBinFile *bf;
		const RzPVector *symbols;
		const RzPVector *imports;
		RzListIter *iter;
		void **it;
		void **vec_it;
		RzBinSymbol *symbol;
		RzBinImport *import;
		RzBin *bin = rz_bin_new();
		RzIO *rio = rz_io_new();
		RzBinOptions opt = { 0 };

		if (!bin || !rio) {
			result = 1;
			goto sym_end;
		}

		rz_io_bind(rio, &bin->iob);
		rz_bin_options_init(&opt, 0, 0, 0, false);

		bf = rz_bin_open(bin, file, &opt);
		if (!bf) {
			result = 1;
			goto sym_end;
		}

		if (ro->import) {
			imports = rz_bin_object_get_imports(bf->o);
			rz_list_foreach (ro->keywords, iter, kw) {
				if (!kw) {
					continue;
				}
				rz_pvector_foreach (imports, vec_it) {
					import = *vec_it;
					if (!strcmp(import->name, kw)) {
						printf("ordinal: %d %s\n", import->ordinal, kw);
					}
				}
			}
		}

		if (ro->symbol) {
			symbols = rz_bin_object_get_symbols(bf->o);
			rz_list_foreach (ro->keywords, iter, kw) {
				if (!kw) {
					continue;
				}
				rz_pvector_foreach (symbols, it) {
					symbol = *it;
					if (!symbol->name) {
						continue;
					}

					if (!strcmp(symbol->name, kw)) {
						printf("paddr: 0x%08" PFMT64x " vaddr: 0x%08" PFMT64x " type: %s %s\n", symbol->paddr, symbol->vaddr, symbol->type, symbol->name);
					}
				}
			}
		}

		result = 0;

	sym_end:
		rz_bin_free(bin);
		rz_io_free(rio);
		free(efile);
		return result;
	}

	RzIO *io = rz_io_new();
	if (!io) {
		free(efile);
		return 1;
	}

	if (!rz_io_open_nomap(io, file, RZ_PERM_R, 0)) {
		eprintf("Cannot open file '%s'\n", file);
		result = 1;
		goto err;
	}

	if (data) {
		rz_io_write_at(io, 0, data, datalen);
	}

	rs = rz_search_new(ro->mode);
	if (!rs) {
		result = 1;
		goto err;
	}

	ro->buf = calloc(1, ro->bsize);
	if (!ro->buf) {
		eprintf("Cannot allocate %" PFMT64d " bytes\n", ro->bsize);
		result = 1;
		goto err;
	}
	rs->align = ro->align;
	rz_search_set_callback(rs, &hit, ro);
	ut64 to = ro->to;
	if (to == -1) {
		to = rz_io_size(io);
	}

	if (!rz_cons_new()) {
		result = 1;
		goto err;
	}

	RzBinOptions opt;
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBin *bin = rz_bin_new();
	rz_io_bind(io, &bin->iob);
	io->cb_printf = printf;
	RzBinFile *bf = rz_bin_open(bin, file, &opt);

	if (ro->mode == RZ_SEARCH_STRING) {
		PJ *pj = NULL;
		if (ro->json) {
			pj = pj_new();
			if (!pj) {
				eprintf("rz-bin: Cannot allocate buffer for json array\n");
				result = 1;
				goto err;
			}
			pj_a(pj);
		}

		RzBinStringSearchOpt opt = bin->str_search_cfg;
		// enforce raw binary search
		opt.mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;

		RzPVector *vec = rz_bin_file_strings(bf, &opt);
		void **it;
		RzBinString *string;
		rz_pvector_foreach (vec, it) {
			string = *it;
			print_bin_string(bf, string, pj);
		}
		rz_pvector_free(vec);
		if (pj) {
			pj_end(pj);
			printf("%s", pj_string(pj));
			pj_free(pj);
		}
		goto done;
	}

	if (ro->mode == RZ_SEARCH_MAGIC) {
		/* TODO: implement using api */
		char *tostr = (to && to != UT64_MAX) ? rz_str_newf("-e search.to=%" PFMT64d, to) : rz_str_dup("");
		rz_sys_cmdf("rizin"
			    " -e search.in=range"
			    " -e search.align=%d"
			    " -e search.from=%" PFMT64d
			    " %s -qnc/m%s \"%s\"",
			ro->align, ro->from, tostr, ro->json ? "j" : "", efile);
		free(tostr);
		goto done;
	}
	if (ro->mode == RZ_SEARCH_ESIL) {
		/* TODO: implement using api */
		rz_list_foreach (ro->keywords, iter, kw) {
			rz_sys_cmdf("rizin -qc \"/E %s\" \"%s\"", kw, efile);
		}
		goto done;
	}
	if (ro->mode == RZ_SEARCH_KEYWORD) {
		rz_list_foreach (ro->keywords, iter, kw) {
			if (ro->hexstr) {
				if (ro->mask) {
					rz_search_kw_add(rs, rz_search_keyword_new_hex(kw, ro->mask, NULL));
				} else {
					rz_search_kw_add(rs, rz_search_keyword_new_hexmask(kw, NULL));
				}
			} else if (ro->widestr) {
				rz_search_kw_add(rs, rz_search_keyword_new_wide(kw, ro->mask, NULL, 0));
			} else {
				rz_search_kw_add(rs, rz_search_keyword_new_str(kw, ro->mask, NULL, 0));
			}
		}
	} else if (ro->mode == RZ_SEARCH_STRING) {
		rz_search_kw_add(rs, rz_search_keyword_new_hexmask("00", NULL)); // XXX
	}

	ro->curfile = file;
	rz_search_begin(rs);
	(void)rz_io_seek(io, ro->from, RZ_IO_SEEK_SET);
	result = 0;
	ut64 bsize = ro->bsize;
	for (ro->cur = ro->from; !last && ro->cur < to; ro->cur += bsize) {
		if ((ro->cur + bsize) > to) {
			bsize = to - ro->cur;
			last = true;
		}
		ret = rz_io_pread_at(io, ro->cur, ro->buf, bsize);
		if (ret == 0) {
			if (ro->nonstop) {
				continue;
			}
			result = 1;
			break;
		}
		if (ret != bsize && ret > 0) {
			bsize = ret;
		}

		if (rz_search_update(rs, ro->cur, ro->buf, ret) == -1) {
			eprintf("search: update read error at 0x%08" PFMT64x "\n", ro->cur);
		}
	}
done:
	rz_cons_free();
	rz_bin_free(bin);
err:
	free(efile);
	rz_search_free(rs);
	rz_io_free(io);
	rzfind_options_fini(ro);
	return result;
}

static int rzfind_open_dir(RzfindOptions *ro, const char *dir) {
	RzListIter *iter;
	char *fullpath;
	char *fname = NULL;

	RzList *files = rz_sys_dir(dir);

	if (files) {
		rz_list_foreach (files, iter, fname) {
			/* Filter-out unwanted entries */
			if (*fname == '.') {
				continue;
			}
			fullpath = rz_file_path_join(dir, fname);
			(void)rzfind_open(ro, fullpath);
			free(fullpath);
		}
		rz_list_free(files);
	}
	return 0;
}

static int rzfind_open(RzfindOptions *ro, const char *file) {
	if (!strcmp(file, "-")) {
		int sz = 0;
		ut8 *buf = (ut8 *)rz_stdin_slurp(&sz);
		if (!buf) {
			return 0;
		}
		char *ff = rz_str_newf("malloc://%d", sz);
		int res = rzfind_open_file(ro, ff, buf, sz);
		free(ff);
		free(buf);
		return res;
	}
	return rz_file_is_directory(file)
		? rzfind_open_dir(ro, file)
		: rzfind_open_file(ro, file, NULL, -1);
}

RZ_API int rz_main_rz_find(int argc, const char **argv) {
	RzfindOptions ro;
	rzfind_options_init(&ro);

	int c;
	const char *file = NULL;

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "a:ie:b:jmM:s:w:S:I:x:Xzf:F:t:E:rqnhvZ");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			ro.align = rz_num_math(NULL, opt.arg);
			break;
		case 'r':
			ro.rad = true;
			break;
		case 'i':
			ro.identify = true;
			break;
		case 'j':
			ro.json = true;
			break;
		case 'n':
			ro.nonstop = 1;
			break;
		case 'm':
			ro.mode = RZ_SEARCH_MAGIC;
			break;
		case 'e':
			ro.mode = RZ_SEARCH_REGEXP;
			ro.hexstr = 0;
			rz_list_append(ro.keywords, (void *)opt.arg);
			break;
		case 'E':
			ro.quiet = true;
			ro.exec_command = opt.arg;
			break;
		case 's':
			ro.mode = RZ_SEARCH_KEYWORD;
			ro.hexstr = false;
			ro.widestr = false;
			rz_list_append(ro.keywords, (void *)opt.arg);
			break;
		case 'w':
			ro.mode = RZ_SEARCH_KEYWORD;
			ro.hexstr = false;
			ro.widestr = true;
			rz_list_append(ro.keywords, (void *)opt.arg);
			break;
		case 'I':
			ro.import = true;
			rz_list_append(ro.keywords, (void *)opt.arg);
			break;
		case 'S':
			ro.symbol = true;
			rz_list_append(ro.keywords, (void *)opt.arg);
			break;
		case 'b':
			ro.bsize = rz_num_math(NULL, opt.arg);
			break;
		case 'M':
			// XXX should be from hexbin
			ro.mask = opt.arg;
			break;
		case 'f':
			ro.from = rz_num_math(NULL, opt.arg);
			break;
		case 'F': {
			size_t data_size;
			char *data = rz_file_slurp(opt.arg, &data_size);
			if (!data) {
				eprintf("Cannot slurp '%s'\n", opt.arg);
				return 1;
			}
			char *hexdata = rz_hex_bin2strdup((ut8 *)data, data_size);
			if (hexdata) {
				ro.mode = RZ_SEARCH_KEYWORD;
				ro.hexstr = true;
				ro.widestr = false;
				rz_list_append(ro.keywords, (void *)hexdata);
			}
			free(data);
		} break;
		case 't':
			ro.to = rz_num_math(NULL, opt.arg);
			break;
		case 'x':
			ro.mode = RZ_SEARCH_KEYWORD;
			ro.hexstr = 1;
			ro.widestr = 0;
			rz_list_append(ro.keywords, (void *)opt.arg);
			break;
		case 'X':
			ro.pr = rz_print_new();
			break;
		case 'q':
			ro.quiet = true;
			break;
		case 'v':
			return rz_main_version_print("rz-find");
		case 'h':
			return show_help(argv[0], 0);
		case 'z':
			ro.mode = RZ_SEARCH_STRING;
			break;
		case 'Z':
			ro.showstr = true;
			break;
		default:
			return show_help(argv[0], 1);
		}
	}
	if (opt.ind == argc) {
		return show_help(argv[0], 1);
	}
	/* Enable quiet mode if searching just a single file */
	if (opt.ind + 1 == argc && RZ_STR_ISNOTEMPTY(argv[opt.ind]) && !rz_file_is_directory(argv[opt.ind])) {
		ro.quiet = true;
	}
	if (ro.json) {
		printf("[");
	}
	for (; opt.ind < argc; opt.ind++) {
		file = argv[opt.ind];

		if (RZ_STR_ISEMPTY(file)) {
			eprintf("Cannot open empty path\n");
			rz_list_free(ro.keywords);
			return 1;
		}
		rzfind_open(&ro, file);
	}
	rz_list_free(ro.keywords);
	if (ro.json) {
		printf("]\n");
	}
	return 0;
}
