// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_log.h>
#include <rz_util/rz_str.h>
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
#include <rz_magic.h>

typedef struct {
	bool showstr;
	bool rad;
	bool identify;
	bool import; /* search within import table */
	bool symbol; /* search within symbol table */
	bool verbose;
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

typedef struct {
	RzfindOptions *opt;
	const char *filename;
} RzfindContext;

static int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	RzfindContext *ctx = (RzfindContext *)user;
	RzfindOptions *ro = ctx->opt;
	int delta = addr - ro->cur;
	if (ro->cur > addr && (ro->cur - addr == kw->keyword_length - 1)) {
		// This case occurs when there is hit in search left over
		delta = ro->cur - addr;
	}
	if (delta < 0 || delta >= ro->bsize) {
		eprintf("Invalid delta\n");
		return 0;
	}
	if (!ro->quiet && !ro->json) {
		printf("File: %s\n", ctx->filename);
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
			rz_str_get(ro->comma), addr, type, str);
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

/**
 * \brief Print a binary string result in the appropriate output format.
 * \param bf The binary file containing the string.
 * \param string The string to print.
 * \param ro Options containing output format settings (JSON mode, comma state, quiet mode).
 *            If NULL, prints as plain text.
 */
static void print_bin_string(RzBinFile *bf, RzBinString *string, RzfindOptions *ro) {
	rz_return_if_fail(bf && string);

	RzBinSection *s = bf->o ? rz_bin_get_section_at(bf->o, string->paddr, false) : NULL;
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	string->vaddr = bf->o ? rz_bin_object_get_vaddr(bf->o, string->paddr, string->vaddr) : UT64_MAX;

	if (ro && ro->json) {
		const char *section_name = rz_str_get(s ? s->name : NULL);
		const char *type_string = rz_str_enc_as_string(string->type);
		// Escape all string fields for JSON safety
		char *escaped_section = rz_str_escape_utf8_for_json(section_name, -1);
		char *escaped_type = rz_str_escape_utf8_for_json(rz_str_get(type_string), -1);
		char *escaped_string = rz_str_escape_utf8_for_json(rz_str_get(string->string), -1);
		printf("%s{\"vaddr\":%" PFMT64u ",\"paddr\":%" PFMT64u ",\"size\":%" PFMT64u ",\"length\":%" PFMT64u ",\"section\":\"%s\",\"type\":\"%s\",\"string\":\"%s\"}",
			rz_str_get(ro->comma),
			string->vaddr, string->paddr, (ut64)string->size, (ut64)string->length,
			rz_str_get(escaped_section),
			rz_str_get(escaped_type),
			rz_str_get(escaped_string));
		free(escaped_section);
		free(escaped_type);
		free(escaped_string);
		ro->comma = ",";
	} else {
		if (ro && !ro->quiet) {
			printf("File: %s\n", rz_str_get(ro->curfile));
		}
		printf("%s\n", rz_str_get(string->string));
	}
}

static int show_help(const char *argv0, int line) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-find [-mXnzZhqvV] [-a align] [-b sz] [-f/t from/to] [-[e|s|w|S|I] str] [-x hex] -|file|dir ..\n");
	if (line) {
		return 0;
	}
	const char *options[] = {
		// clang-format off
		"-a",    "align",   "Only accept aligned hits",
		"-b",    "size",    "Set block size",
		"-e",    "regex",   "Search for regex matches (can be used multiple times)",
		"-E",    "cmd",     "Execute command for each file found",
		"-f",    "from",    "Start searching from address 'from'",
		"-F",    "file",    "Read the contents of the file and use it as keyword",
		"-h",    "",        "Show this help",
		"-i",    "",        "Identify filetype (magic signatures)",
		"-j",    "",        "Output in JSON",
		"-m",    "",        "Magic search, file-type carver",
		"-M",    "str",     "Set a binary mask to be applied on keywords",
		"-n",    "",        "Do not stop on read errors",
		"-r",    "",        "Print using rizin commands",
		"-s",    "str",     "Search for a specific string (can be used multiple times)",
		"-w",    "str",     "Search for a specific wide string (can be used multiple times). Assumes str is UTF-8.",
		"-I",    "str",     "Search for an entry in import table.",
		"-S",    "str",     "Search for a symbol in symbol table.",
		"-t",    "to",      "Stop search at address 'to'",
		"-q",    "",        "Quiet - do not show headings (filenames) above matching contents (default for searching a single file)",
		"-v",    "",        "Show version information",
		"-V",    "",        "Verbose: prints each file scanned",
		"-x",    "hex",     "Search for hexpair string (909090) (can be used multiple times)",
		"-X",    "",        "Show hexdump of search results",
		"-z",    "",        "Search for zero-terminated strings",
		"-Z",    "",        "Show string found on each search hit",
		// clang-format on
	};
	rz_print_colored_help(options, RZ_ARRAY_SIZE(options), false);
	return 0;
}

static int rzfind_open_file(RzfindOptions *ro, const char *file, const ut8 *data, int datalen) {
	RzListIter *iter;
	RzSearch *rs = NULL;
	const char *kw;
	bool last = false;
	int ret, result = 0;

	if (ro->verbose) {
		FILE *stream = ro->json ? stderr : stdout;
		fprintf(stream, "Scanning: %s\n", file);
	}

	ro->buf = NULL;
	char *efile = rz_str_escape_sh(file);

	if (ro->identify) {
		ut64 to = ro->to;
		int identify_result = 1;

		RzBuffer *buffer = rz_buf_new_file(file, O_RDONLY, 0);
		if (!buffer) {
			eprintf("Cannot open file as buffer: '%s'\n", file);
			free(efile);
			return 1;
		}

		char *magic_dir = rz_path_system(NULL, RZ_SDB_MAGIC);
		if (!magic_dir) {
			eprintf("Cannot find magic directory\n");
			rz_buf_free(buffer);
			free(efile);
			return 1;
		}

		RzSearchCollection *collection = rz_search_collection_magic(magic_dir);
		if (!collection) {
			eprintf("Cannot initialize magic search\n");
			free(magic_dir);
			rz_buf_free(buffer);
			free(efile);
			return 1;
		}

		RzSearchOpt *search_opts = rz_search_opt_new();
		if (!search_opts) {
			eprintf("Cannot create search options\n");
			rz_search_collection_free(collection);
			free(magic_dir);
			rz_buf_free(buffer);
			free(efile);
			return 1;
		}

		rz_search_opt_set_max_threads(search_opts, 1);
		rz_search_opt_set_max_hits(search_opts, 1);
		rz_search_opt_set_show_progress_from_str(search_opts, "no");
		if (!rz_search_opt_set_chunk_size(search_opts, RZ_MAGIC_BUF_SIZE)) {
			eprintf("Cannot set chunk size\n");
			rz_search_opt_free(search_opts);
			rz_search_collection_free(collection);
			free(magic_dir);
			rz_buf_free(buffer);
			free(efile);
			return 1;
		}

		RzSearchFindOpt *find_opts = rz_search_find_opt_new();
		if (!find_opts) {
			eprintf("Cannot create find options\n");
			rz_search_opt_free(search_opts);
			rz_search_collection_free(collection);
			free(magic_dir);
			rz_buf_free(buffer);
			free(efile);
			return 1;
		}
		rz_search_find_opt_set_alignment(find_opts, ro->align < 1 ? 1 : ro->align);
		rz_search_find_opt_set_overlap_match(find_opts, false);
		rz_search_opt_set_find_options(search_opts, find_opts);

		if (to == -1) {
			to = rz_buf_size(buffer);
		}
		RzList *ranges = NULL;
		if (ro->from > 0 || (to && to != UT64_MAX && to != rz_buf_size(buffer))) {
			ranges = rz_list_newf(free);
			if (ranges) {
				RzInterval *itv = RZ_NEW0(RzInterval);
				if (itv) {
					itv->addr = ro->from;
					itv->size = (to && to != UT64_MAX) ? (to - ro->from) : (rz_buf_size(buffer) - ro->from);
					rz_list_append(ranges, itv);
				}
			}
		}

		RzList *hits = rz_search_on_buffer(search_opts, collection, buffer, ranges);
		rz_list_free(ranges);
		if (hits) {
			RzListIter *it;
			RzSearchHit *hit;
			rz_list_foreach (hits, it, hit) {
				char *detail = rz_search_hit_detail_as_string(hit);
				if (ro->json) {
					char *escaped = rz_str_escape_utf8_for_json(rz_str_get(detail), -1);
					printf("%s{\"address\":%" PFMT64u ",\"magic\":\"%s\"}",
						rz_str_get(ro->comma),
						hit->address,
						rz_str_get(escaped));
					free(escaped);
					ro->comma = ",";
				} else {
					printf("0x%08" PFMT64x " %s\n", hit->address, rz_str_get(detail));
				}
				free(detail);
				identify_result = 0;
				break;
			}
			rz_list_free(hits);
		} else {
			eprintf("Cannot identify file '%s'\n", file);
		}

		rz_search_opt_free(search_opts);
		rz_search_collection_free(collection);
		free(magic_dir);
		rz_buf_free(buffer);
		free(efile);
		return identify_result;
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
						if (!ro->quiet && !ro->json) {
							printf("File: %s\n", file);
						}
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
						if (!ro->quiet && !ro->json) {
							printf("File: %s\n", file);
						}
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
	RzfindContext ctx = { .opt = ro, .filename = file };
	rz_search_set_callback(rs, &hit, &ctx);
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
		RzBinStringSearchOpt search_opt = bin->str_search_cfg;
		// enforce raw binary search
		search_opt.mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;

		ro->curfile = file;
		RzPVector *vec = rz_bin_file_strings(bf, &search_opt);
		void **it;
		RzBinString *string;
		rz_pvector_foreach (vec, it) {
			string = *it;
			print_bin_string(bf, string, ro);
		}
		rz_pvector_free(vec);
		goto done;
	}

	if (ro->mode == RZ_SEARCH_MAGIC) {
		char *magic_dir = rz_path_system(NULL, RZ_SDB_MAGIC);
		if (!magic_dir) {
			eprintf("Cannot find magic directory\n");
			result = 1;
			goto err;
		}

		RzSearchCollection *collection = rz_search_collection_magic(magic_dir);
		if (!collection) {
			eprintf("Cannot initialize magic search\n");
			free(magic_dir);
			result = 1;
			goto err;
		}

		RzSearchOpt *search_opts = rz_search_opt_new();
		if (!search_opts) {
			eprintf("Cannot create search options\n");
			rz_search_collection_free(collection);
			free(magic_dir);
			result = 1;
			goto err;
		}

		rz_search_opt_set_max_threads(search_opts, 1);
		rz_search_opt_set_show_progress_from_str(search_opts, "no");
		if (!rz_search_opt_set_chunk_size(search_opts, RZ_MAGIC_BUF_SIZE)) {
			eprintf("Cannot set chunk size\n");
			rz_search_opt_free(search_opts);
			rz_search_collection_free(collection);
			free(magic_dir);
			result = 1;
			goto err;
		}

		RzSearchFindOpt *find_opts = rz_search_find_opt_new();
		if (!find_opts) {
			eprintf("Cannot create find options\n");
			rz_search_opt_free(search_opts);
			rz_search_collection_free(collection);
			free(magic_dir);
			result = 1;
			goto err;
		}
		rz_search_find_opt_set_alignment(find_opts, ro->align < 1 ? 1 : ro->align);
		rz_search_find_opt_set_overlap_match(find_opts, false);
		rz_search_opt_set_find_options(search_opts, find_opts);

		RzBuffer *buffer = rz_buf_new_file(file, O_RDONLY, 0);
		if (!buffer) {
			eprintf("Cannot open file as buffer: '%s'\n", file);
			rz_search_opt_free(search_opts);
			rz_search_collection_free(collection);
			free(magic_dir);
			result = 1;
			goto err;
		}

		RzList *ranges = NULL;
		if (ro->from > 0 || (to && to != UT64_MAX && to != rz_buf_size(buffer))) {
			ranges = rz_list_newf(free);
			if (ranges) {
				RzInterval *itv = RZ_NEW0(RzInterval);
				if (itv) {
					itv->addr = ro->from;
					itv->size = (to && to != UT64_MAX) ? (to - ro->from) : (rz_buf_size(buffer) - ro->from);
					rz_list_append(ranges, itv);
				}
			}
		}

		RzList *hits = rz_search_on_buffer(search_opts, collection, buffer, ranges);
		rz_list_free(ranges);

		if (hits) {
			RzListIter *it;
			RzSearchHit *hit;
			size_t i = 0;
			if (ro->json) {
				rz_list_foreach (hits, it, hit) {
					char *flag = rz_search_hit_flag_name(hit, i, "hit");
					char *detail = rz_search_hit_detail_as_string(hit);
					char *escaped_flag = rz_str_escape_utf8_for_json(rz_str_get(flag), -1);
					char *escaped_detail = rz_str_escape_utf8_for_json(rz_str_get(detail), -1);
					printf("%s{\"offset\":%" PFMT64u ",\"size\":%" PFMTSZu ",\"flag\":\"%s\",\"detail\":\"%s\"}",
						rz_str_get(ro->comma),
						hit->address, hit->size,
						rz_str_get(escaped_flag),
						rz_str_get(escaped_detail));
					ro->comma = ",";
					free(escaped_flag);
					free(escaped_detail);
					free(flag);
					free(detail);
					i++;
				}
			} else {
				rz_list_foreach (hits, it, hit) {
					char *flag = rz_search_hit_flag_name(hit, i, "hit");
					char *detail = rz_search_hit_detail_as_string(hit);
					printf("0x%08" PFMT64x " %" PFMTSZu " %s %s\n",
						hit->address, hit->size, rz_str_get(flag), rz_str_get(detail));
					free(flag);
					free(detail);
					i++;
				}
			}
			rz_list_free(hits);
		}

		rz_buf_free(buffer);
		rz_search_opt_free(search_opts);
		rz_search_collection_free(collection);
		free(magic_dir);
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
	int result = 0;

	RzList *files = rz_sys_dir(dir);

	if (files) {
		rz_list_foreach (files, iter, fname) {
			/* Filter-out unwanted entries */
			if (*fname == '.') {
				continue;
			}
			fullpath = rz_file_path_join(dir, fname);
			int res = rzfind_open(ro, fullpath);
			if (res != 0) {
				result = 1;
			}
			free(fullpath);
		}
		rz_list_free(files);
	}
	return result;
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

	int n = RZ_DEFAULT_LOGLVL;
	char *log_level = rz_sys_getenv("RZ_LOGLEVEL");
	if (RZ_STR_ISNOTEMPTY(log_level)) {
		n = atoi(log_level);
		free(log_level);
	}
	if (n >= 0 && n < RZ_LOGLVL_SIZE) {
		rz_log_set_level((RzLogLevel)n);
	}

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "a:ie:b:jmM:s:w:S:I:x:Xzf:F:t:E:rqnhvVZ");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			ro.align = rz_num_math(NULL, opt.arg);
			if (rz_bits_count_ones_ut64(ro.align) != 1) {
				RZ_LOG_ERROR("Alignment must only have one bit set.\n");
				return 1;
			}
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
		case 'v': {
			RzPath *sys_path = rz_path_new();
			if (!sys_path) {
				return show_help(argv[0], 1);
			}
			size_t print_val = rz_main_version_print(sys_path, "rz-find");
			rz_path_free(sys_path);
			return print_val;
		}
		case 'V':
			ro.verbose = true;
			break;
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
		if (!ro.verbose) {
			ro.quiet = true;
		}
	}
	if (ro.json) {
		ro.comma = "";
		printf("[");
	}
	int overall_result = 0;
	for (; opt.ind < argc; opt.ind++) {
		file = argv[opt.ind];

		if (RZ_STR_ISEMPTY(file)) {
			eprintf("Cannot open empty path\n");
			overall_result = 1;
			continue;
		}
		int res = rzfind_open(&ro, file);
		if (res != 0) {
			overall_result = 1;
		}
	}
	rz_list_free(ro.keywords);
	if (ro.json) {
		printf("]\n");
	}
	return overall_result;
}
