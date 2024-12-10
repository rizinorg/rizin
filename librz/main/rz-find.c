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
#include <rz_util/rz_regex.h>

#define DEFAULT_BUFFER_SIZE 4096

typedef enum {
	RZ_FIND_OUTPUT_STANDARD = 0,
	RZ_FIND_OUTPUT_JSON,
	RZ_FIND_OUTPUT_QUIET,
	RZ_FIND_OUTPUT_HEXDUMP,
	RZ_FIND_OUTPUT_COMMAND,
} RzFindOutput;

typedef enum {
	RZ_FIND_MODE_NOT_SET = 0,
	RZ_FIND_MODE_MAGIC,
	RZ_FIND_MODE_AES_KEYS,
	RZ_FIND_MODE_PRIVATE_KEYS,
	RZ_FIND_MODE_STRINGS,
	RZ_FIND_MODE_REGEXES,
	RZ_FIND_MODE_HEX_PATTERNS,
	RZ_FIND_MODE_IMPORTS,
	RZ_FIND_MODE_SYMBOLS,
} RzFindMode;

typedef struct rz_find_options {
	PJ *pj;
	RzSearchCollection *collection;
	RzList /*<char *>*/ *keywords;
	const char *exec_command;
	const char *exec_command_at;
	size_t buffer_size;
	ut64 from;
	ut64 to;
	RzFindOutput output;
	RzFindMode mode;
	RzStrEnc encoding;
	bool ignore_read_errors;
	bool caseless;
} RzFindOptions;

typedef bool (*RzFindIsValidInput)(const char *input, int line);

static void rz_find_options_fini(RzFindOptions *ro) {
	rz_search_collection_free(ro->collection);
	rz_list_free(ro->keywords);
	pj_free(ro->pj);
}

static void rz_find_options_init(RzFindOptions *ro) {
	memset(ro, 0, sizeof(RzFindOptions));
	ro->keywords = rz_list_new();
	ro->buffer_size = DEFAULT_BUFFER_SIZE;
	ro->to = UT64_MAX;
	ro->output = RZ_FIND_OUTPUT_STANDARD;
	ro->mode = RZ_FIND_MODE_NOT_SET;
	ro->encoding = RZ_STRING_ENC_GUESS;
}

static bool rz_find_get_buffer_at(RzCore *core, RzSearchHit *hit, ut8 **buffer, size_t *size) {
	size_t buffer_size = hit->size;
	if (buffer_size < 1 || buffer_size & 0xf) {
		// align buffer.
		buffer_size = (buffer_size + 0x10) & 0xf;
	}

	ut8 *b = malloc(buffer_size);
	if (!b) {
		return false;
	}

	rz_io_read_at(core->io, hit->address, b, buffer_size);
	*buffer = b;
	*size = buffer_size;
	return true;
}

static void rz_find_output_hit_as_hexdump(RzFindOptions *ro, RzSearchHit *hit, RzCore *core) {
	ut8 *buffer = NULL;
	size_t size = 0;

	if (!rz_find_get_buffer_at(core, hit, &buffer, &size)) {
		eprintf("Error: failed to read at 0x%" PFMT64x "\n", hit->address);
		return;
	}

	char *output = rz_print_hexdump_str(core->print, hit->address, buffer, size, 16, 1, 1);
	free(buffer);
	if (!output) {
		eprintf("Error: failed to hexdump at 0x%" PFMT64x "\n", hit->address);
		return;
	}
	printf(output);
	free(output);
}

static void rz_find_output_string(RzFindOptions *ro, RzSearchHit *hit, RzCore *core) {
	switch (ro->mode) {
	case RZ_FIND_OUTPUT_HEXDUMP:
		rz_find_output_hit_as_hexdump(ro, hit, core);
		return;
	case RZ_FIND_OUTPUT_QUIET:
		printf("0x%" PFMT64x "\n", hit->address);
		return;
	default: /* RZ_FIND_OUTPUT_STANDARD */
		break;
	}

	RzBinSection *s = NULL;
	RzBinObject *bo = NULL;
	RzDetectedString *ds = NULL;
	const char *encoding = "";
	const char *section_name = "";
	ut8 *buffer = NULL;
	size_t size = 0;

	if (!rz_find_get_buffer_at(core, hit, &buffer, &size)) {
		eprintf("Error: failed to read at 0x%" PFMT64x "\n", hit->address);
		return;
	}

	RzUtilStrScanOptions opts;
	opts.buf_size = size;
	opts.max_uni_blocks = core->bin->str_search_cfg.max_uni_blocks;
	opts.min_str_length = core->bin->str_search_cfg.min_length;
	opts.prefer_big_endian = core->analysis->big_endian;
	opts.check_ascii_freq = core->bin->str_search_cfg.check_ascii_freq;

	if (!rz_scan_strings_single_raw(buffer, size, &opts, ro->encoding, &ds)) {
		eprintf("Error: failed to decode string at 0x%" PFMT64x "\n", hit->address);
		free(buffer);
		return;
	}
	free(buffer);

	if (ds) {
		bo = rz_bin_cur_object(core->bin);
		if (bo) {
			s = rz_bin_get_section_at(bo, hit->address, false);
			if (s) {
				section_name = s->name;
			}
		}
		encoding = rz_str_enc_as_string(ds->type);
	}

	switch (ro->mode) {
	case RZ_FIND_OUTPUT_JSON:
		pj_o(ro->pj);
		pj_kn(ro->pj, "address", hit->address);
		pj_kn(ro->pj, "size", ds->size);
		pj_kn(ro->pj, "length", ds->length);
		pj_ks(ro->pj, "section", section_name);
		pj_ks(ro->pj, "type", encoding);
		pj_ks(ro->pj, "string", ds->string);
		pj_end(ro->pj);
		break;
	default: /* RZ_FIND_OUTPUT_STANDARD */
		printf("0x%" PFMT64x " %" PFMTSZu "%s\n", hit->address, hit->size, ds->string);
		break;
	}
}

static void rz_find_output_hit(RzFindOptions *ro, RzSearchHit *hit, RzCore *core) {
	switch (ro->mode) {
	case RZ_FIND_OUTPUT_JSON:
		pj_o(ro->pj);
		pj_kn(ro->pj, "address", hit->address);
		pj_kn(ro->pj, "size", hit->size);
		pj_ks(ro->pj, "type", hit->metadata);
		pj_end(ro->pj);
		break;
	case RZ_FIND_OUTPUT_STANDARD:
		printf("0x%" PFMT64x " %" PFMTSZu " %s\n", hit->address, hit->size, hit->metadata);
		break;
	case RZ_FIND_OUTPUT_HEXDUMP:
		rz_find_output_hit_as_hexdump(ro, hit, core);
		break;
	default:
		printf("0x%" PFMT64x "\n", hit->address);
		break;
	}
}

static void rz_find_output_import(RzFindOptions *ro, RzBinImport *import) {
	switch (ro->mode) {
	case RZ_FIND_OUTPUT_JSON:
		pj_o(ro->pj);
		pj_ks(ro->pj, "name", rz_str_get(import->name));
		pj_ks(ro->pj, "dname", rz_str_get(import->dname));
		pj_ks(ro->pj, "libname", rz_str_get(import->libname));
		pj_ks(ro->pj, "bind", rz_str_get(import->bind));
		pj_ks(ro->pj, "type", rz_str_get(import->type));
		pj_ks(ro->pj, "classname", rz_str_get(import->classname));
		pj_ks(ro->pj, "descriptor", rz_str_get(import->descriptor));
		pj_kn(ro->pj, "ordinal", import->ordinal);
		pj_kn(ro->pj, "visibility", import->visibility);
		pj_end(ro->pj);
		break;
	default:
		printf("%s\n", import->name);
		break;
	}
}

static void rz_find_output_symbol(RzFindOptions *ro, RzBinSymbol *symbol) {
	switch (ro->mode) {
	case RZ_FIND_OUTPUT_JSON:
		pj_o(ro->pj);
		pj_ks(ro->pj, "name", rz_str_get(symbol->name));
		pj_ks(ro->pj, "dname", rz_str_get(symbol->dname));
		pj_ks(ro->pj, "libname", rz_str_get(symbol->libname));
		pj_ks(ro->pj, "class", rz_str_get(symbol->classname));
		pj_ks(ro->pj, "visibility", rz_str_get(symbol->visibility_str));
		pj_kn(ro->pj, "vaddr", symbol->vaddr);
		pj_kn(ro->pj, "paddr", symbol->paddr);
		pj_kn(ro->pj, "size", symbol->size);
		pj_end(ro->pj);
		break;
	case RZ_FIND_OUTPUT_STANDARD:
		printf("0x%" PFMT64x " %u %s\n", symbol->vaddr, symbol->size, symbol->name);
		break;
	default:
		printf("%s\n", symbol->name);
		break;
	}
}

static void rz_find_output_command(RzFindOptions *ro, const char *filename) {
	char *command = NULL;
	if (ro->exec_command_at) {
		command = rz_str_dup(ro->exec_command);
		command = rz_str_replace(command, ro->exec_command_at, filename, 1);
	} else {
		command = rz_str_newf("%s %s", ro->exec_command, filename);
	}
	int status = rz_sys_system(command);
	if (status == -1) {
		eprintf("Error: Failed to execute command: %s\n", command);
	}
	free(command);
}

static inline RzBinFile *core_get_file(RzCoreFile *cfile) {
	return rz_pvector_at(&cfile->binfiles, 0);
}

static bool rz_find_search_progress_cancel(void *user, size_t n_hits) {
	return rz_cons_is_breaked();
}

static bool rz_find_match_string(const char *string, size_t slen, const char *find, bool caseless) {
	size_t flen = strlen(find);
	if (slen < flen) {
		// ignore strings that are smaller than the one we are looking for.
		return false;
	}

	size_t len = RZ_MIN(slen, flen);
	if ((caseless && rz_str_ncasecmp(string, find, len)) ||
		(!caseless && strncmp(string, find, len))) {
		return false;
	}
	return true;
}

static void rz_find_over_imports(RzFindOptions *ro, RzCore *core) {
	void **vit;
	RzListIter *it = NULL;
	const char *find;
	RzBinImport *import;
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	const RzPVector *imports = bo ? rz_bin_object_get_imports(bo) : NULL;
	rz_pvector_foreach (imports, vit) {
		import = *vit;
		size_t slen = strlen(import->name);

		rz_list_foreach (ro->keywords, it, find) {
			if (rz_find_match_string(import->name, slen, find, ro->caseless)) {
				rz_find_output_import(ro, import);
			}
		}
	}
}

static void rz_find_over_symbols(RzFindOptions *ro, RzCore *core) {
	void **vit;
	const char *find;
	RzListIter *it = NULL;
	RzBinSymbol *symbol;
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	const RzPVector *symbols = bo ? rz_bin_object_get_symbols(bo) : NULL;
	rz_pvector_foreach (symbols, vit) {
		symbol = *vit;
		size_t slen = strlen(symbol->name);

		rz_list_foreach (ro->keywords, it, find) {
			if (rz_find_match_string(symbol->name, slen, find, ro->caseless)) {
				rz_find_output_symbol(ro, symbol);
			}
		}
	}
}

static bool rz_find_init_collection(RzFindOptions *ro) {
	RzSearchHit *hit = NULL;
	const char *find;

	switch(ro->mode) {
	case RZ_FIND_MODE_MAGIC: {
		char *sys_magic = rz_path_system(RZ_SDB_MAGIC);
		ro->collection = rz_search_collection_magic(sys_magic);
		free(sys_magic);
		return ro->collection != NULL;
	}
	case RZ_FIND_MODE_AES_KEYS:
		ro->collection = rz_search_collection_aes_keys();
		return ro->collection != NULL;
	case RZ_FIND_MODE_PRIVATE_KEYS:
		ro->collection = rz_search_collection_private_keys();
		return ro->collection != NULL;
	case RZ_FIND_MODE_STRINGS:
		
		ro->collection = rz_search_collection_strings(RZ_NONNULL RzUtilStrScanOptions *opts, RzStrEnc expected, bool caseless);
		if (ro->collection == NULL){
			return false;
		}
		break;
	case RZ_FIND_MODE_REGEXES:
		ro->collection = rz_search_collection_private_keys();
		if (ro->collection == NULL){
			return false;
		}
		break;
	case RZ_FIND_MODE_HEX_PATTERNS:
		ro->collection = rz_search_collection_private_keys();
		if (ro->collection == NULL){
			return false;
		}
		break;
	default:
		// nothing to initialize
		return true;
	}

	rz_list_foreach (ro->keywords, it, find) {
		if (rz_find_match_string(symbol->name, slen, find, ro->caseless)) {
			rz_find_output_symbol(ro, symbol);
		}
	}
}

static void rz_find_over_collection(RzFindOptions *ro, RzCore *core) {
	// use RzSearch
	RzListIter *it = NULL;
	RzList *hits = NULL;
	RzSearchHit *hit = NULL;

	rz_search_opt_set_buffer_size(core->search_opts, ro->buffer_size);
	rz_search_opt_set_cancel_cb(core->search_opts, rz_find_search_progress_cancel, NULL);

	hits = rz_core_search_collection(core, core->search_opts, ro->collection);
	if (hits && !rz_cons_is_breaked()) {
		rz_list_foreach (hits, it, hit) {
			if (ro->mode == RZ_FIND_MODE_STRINGS) {
				rz_find_output_string(ro, hit, core);
			} else {
				rz_find_output_hit(ro, hit, core);
			}
		}
	}

	rz_list_free(hits);
}

static bool rz_find_search_in_file(RzFindOptions *ro, const char *filename) {
	RzCore *core = NULL;
	RzCoreFile *cfile = NULL;
	RzBinFile *bfile = NULL;
	bool res = false;

	core = rz_core_new();
	if (!core) {
		eprintf("rzfind: Cannot allocate RzCore\n");
		goto rz_diff_load_file_with_core_fail;
	}
	rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL);

	rz_config_set_i(core->config, "scr.color", true);
	rz_config_set_b(core->config, "scr.interactive", false);
	rz_config_set_b(core->config, "cfg.debug", false);
	rz_config_set_b(core->config, "scr.prompt", false);
	core->print->scr_prompt = false;
	cfile = rz_core_file_open(core, filename, 0, 0);
	if (!cfile) {
		eprintf("rzfind: Cannot open file '%s'\n", filename);
		goto rz_diff_load_file_with_core_fail;
	}

	if (!rz_core_bin_load(core, NULL, UT64_MAX)) {
		eprintf("rzfind: Cannot load file '%s'\n", filename);
		goto rz_diff_load_file_with_core_fail;
	}

	if (!rz_core_bin_update_arch_bits(core)) {
		eprintf("rzfind: Cannot set architecture with bits\n");
		goto rz_diff_load_file_with_core_fail;
	}

	bfile = core_get_file(cfile);
	if (!bfile) {
		eprintf("rzfind: Cannot get RzBinFile\n");
		goto rz_diff_load_file_with_core_fail;
	}

	if (rz_pvector_empty(bfile->o->maps)) {
		// if there are no maps, then must be loaded as raw
		rz_config_set_b(core->config, "io.va", false);
	}

	if (ro->output == RZ_FIND_OUTPUT_COMMAND) {
		// stop after 1 hit
		rz_search_opt_set_max_hits(core->search_opts, 1);
	} else if (ro->output == RZ_FIND_OUTPUT_JSON) {
		pj_o(ro->pj); // {
		pj_ks(ro->pj, "file", filename);
		pj_ka(ro->pj, "hits");
	}

	if (ro->output == RZ_FIND_OUTPUT_COMMAND) {
		rz_find_output_command(ro, filename);
	} else if (ro->mode == RZ_FIND_MODE_IMPORTS) {
		// loop over imports
		rz_find_over_imports(ro, core);
	} else if (ro->mode == RZ_FIND_MODE_SYMBOLS) {
		// loop over symbols
		rz_find_over_symbols(ro, core);
	} else {
		rz_find_over_collection(ro, core);
	}

	if (ro->output == RZ_FIND_OUTPUT_JSON) {
		pj_end(ro->pj); // ]
		pj_end(ro->pj); // }
	}

	res = true;
rz_diff_load_file_with_core_fail:
	rz_core_free(core);
	return res;
}

static void rz_find_open(RzFindOptions *ro, const char *path);

static void rz_find_open_dir(RzFindOptions *ro, const char *dir) {
	RzListIter *iter;
	char *fullpath;
	char *path = NULL;

	RzList *files = rz_sys_dir(dir);

	if (!files) {
		return;
	}

	rz_list_foreach (files, iter, path) {
		/* filter-out unwanted entries */
		if (*path == '.') {
			continue;
		}
		fullpath = rz_file_path_join(dir, path);
		rz_find_open_dir(ro, fullpath);
		free(fullpath);
	}
	rz_list_free(files);
}

static void rz_find_open(RzFindOptions *ro, const char *path) {
	if (rz_file_is_directory(path)) {
		rz_find_open_dir(ro, path);
	} else {
		rz_find_search_in_file(ro, path);
	}
}

static bool rz_find_is_valid_regex(const char *input, int line) {
	RzRegex *compiled = rz_regex_new(input, RZ_REGEX_EXTENDED, 0);
	if (compiled) {
		rz_regex_free(compiled);
		return true;
	}
	if (line < 1) {
		eprintf("rzfind: cannot compile '%s' regex.\n", input);
	} else {
		eprintf("rzfind: cannot compile '%s' regex at line %d.\n", input, line);
	}
	return false;
}

static bool rz_find_is_valid_string(const char *input, int line) {
	if (RZ_STR_ISNOTEMPTY(input)) {
		return true;
	}
	if (line < 1) {
		eprintf("rzfind: '%s' is not a valid string.\n", input);
	} else {
		eprintf("rzfind: '%s' is not a valid string at line %d.\n", input, line);
	}
	return false;
}

static bool rz_find_is_valid_hex_pattern(const char *input, int line) {
	if (RZ_STR_ISNOTEMPTY(input) || !(strlen(input) & 1)) {
		// must be a len mod 2 == 0 string
		return true;
	}
	if (line < 1) {
		eprintf("rzfind: '%s' is not a valid hex pattern.\n", input);
	} else {
		eprintf("rzfind: '%s' is not a valid hex pattern at line %d.\n", input, line);
	}
	return false;
}

static bool rz_find_read_keywords_from_file(const char *file, RzList /*<char *>*/ *keywords, RzFindIsValidInput validator) {
	RzListIter *it;
	char *line = NULL;
	char *buffer = rz_file_slurp(file, NULL);
	if (!buffer) {
		eprintf("rzfind: failed to read '%s'.\n", file);
		return false;
	}
	// free(buffer) must be called at the end since rz_str_split_list does NOT dup strings.
	RzList *lines = rz_str_split_list(buffer, "\n", 0);

	int n_line = 1;
	rz_list_foreach (lines, it, line) {
		if (!validator(line, n_line)) {
			free(buffer);
			return false;
		}
		rz_list_append(keywords, line);
		n_line++;
	}

	free(buffer);
	return true;
}

static bool rz_find_add_keyword(const char *input, RzList /*<char *>*/ *keywords, RzFindIsValidInput validator) {
	if (!validator(input, 0)) {
		return false;
	}
	rz_list_append(keywords, (void *)input);
	return true;
}

static int show_help(const char *argv0, bool only_usage) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("%s -[bcfthjnCEmAPzrxisZRXISqvX] [file|directory]\n", argv0);
	if (only_usage) {
		return 1;
	}
	const char *options[] = {
		// clang-format off
		"-b",    "[size]",   "Set buffer size (default: " RZ_STR(DEFAULT_BUFFER_SIZE) ")",
		"-c",    "[cmd]",    "Execute command for each file found (filename is passed as argument)",
		"-k",    "[key]",    "Replace a certain keyword with the filename with the command (requires -c)",
		"-f",    "[from]",   "Start search offset (default 0)",
		"-t",    "[to]",     "Stop search offset (default file size)",
		"-h",    "",         "Show this help",
		"-d",    "",         "Show this help",
		"-n",    "",         "Ignore read errors",
		"-C",    "",         "Ignore case (only used by -s -r -I -S)",
		"-E",    "[enc]",    "Forces a specific string encoding (see -h output).",
		"-m",    "",         "Search for magic signatures in the whole file",
		"-A",    "",         "Search for AES keys in the whole file",
		"-P",    "",         "Search for private RSA/ECC/EdDSA keys in the whole file",
		"-z",    "[str]",    "Search for one or multiple strings in the whole file",
		"-r",    "[regex]",  "Search via one or multiple regexes in the whole file",
		"-x",    "[hex]",    "Search for one or multiple hex patterns in the whole file",
		"-i",    "[import]", "Search for one or multiple strings in the import table.",
		"-s",    "[symbol]", "Search for one or multiple strings in the symbol table.",
		"-Z",    "[file]",   "Search for strings in the whole file (use file lines as input)",
		"-R",    "[file]",   "Search via regex (use file lines as input)",
		"-X",    "[file]",   "Search for hex patterns (use file lines as input)",
		"-I",    "[file]",   "Search for strings in the import table (use file lines as input).",
		"-S",    "[file]",   "Search for strings in the symbol table (use file lines as input).",
		"-j",    "",         "JSON output (outputs the matching filenames or offsets)",
		"-q",    "",         "Quiet output (outputs the matching filenames or offsets)",
		"-D",    "",         "Hexdump output of the matching region.",
		"-v",    "",         "Show version information",
		// clang-format on
	};
	size_t max_arg_len = 0;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(options); i += 3) {
		size_t flag = strlen(options[i]);
		size_t arg = strlen(options[i + 1]);
		size_t sum = flag + arg;
		if (sum > max_arg_len) {
			max_arg_len = sum;
		}
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(options); i += 3) {
		rz_print_colored_help_option(options[i], options[i + 1], options[i + 2], max_arg_len);
	}

	printf("Supported encodings (-E option):\n");
	const char *encodings[] = {
		// clang-format off
		"ascii",    "ASCII from 0 to 0x7f"
		"mutf8",    "Modified UTF-8"
		"utf8",     "UTF-8"
		"utf16le",  "UTF-16 little endian"
		"utf32le",  "UTF-32 little endian"
		"utf16be",  "UTF-16 big endian"
		"utf32be",  "UTF-32 big endian"
		"ibm037",   "IBM037"
		"ibm290",   "IBM290"
		"ebcdices", "ebcdic ES"
		"ebcdicuk", "ebcdic UK"
		"ebcdicus", "ebcdic US"
		// clang-format on
	};
	max_arg_len = 0;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(encodings) && i + 1 < RZ_ARRAY_SIZE(encodings); i += 2) {
		size_t encoding = strlen(encodings[i]);
		if (encoding > max_arg_len) {
			max_arg_len = encoding;
		}
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(encodings) && i + 1 < RZ_ARRAY_SIZE(encodings); i += 2) {
		rz_print_colored_help_option(encodings[i], "", encodings[i + 1], max_arg_len);
	}
	return 0;
}

#define ERROR_USAGE_ONLY_ONCE(test) \
	do { \
		if (test) { \
			eprintf("Error: -%c can be set only once.\n", c); \
			return 1; \
		} \
	} while (0)

#define ERROR_ON_NOT_MODE(umode, bad_flags) \
	ERROR_USAGE_INCOMPATIBLE_WITH((ro.mode == RZ_FIND_MODE_NOT_SET || ro.mode == umode), bad_flags)

#define ERROR_USAGE_INCOMPATIBLE_WITH(test, bad_flags) \
	do { \
		if (test) { \
			eprintf("Error: -%c be set only once and is incompatible with " bad_flags ".\n", c); \
			return 1; \
		} \
	} while (0)

RZ_API int rz_main_rz_find(int argc, const char **argv) {
	RzFindOptions ro;
	rz_find_options_init(&ro);

	int c;
	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "c:k:f:t:E:z:r:x:i:s:Z:R:X:I:S:C:njqDvhb");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'b': // Set buffer size
			ERROR_USAGE_ONLY_ONCE(ro.buffer_size != DEFAULT_BUFFER_SIZE);
			ro.buffer_size = rz_num_math(NULL, opt.arg);
			if (ro.buffer_size < 1) {
				eprintf("Error: invalid buffer size: %" PFMTSZu "\n", ro.buffer_size);
				return 1;
			}
			break;
		case 'c': // Execute command for each file found (filename is passed as argument)
			ERROR_USAGE_ONLY_ONCE(ro.exec_command);
			ro.output = RZ_FIND_OUTPUT_COMMAND;
			ro.exec_command = opt.arg;
			break;
		case 'k': // Replace a certain keyword with the filename with the command (requires -c)
			ERROR_USAGE_ONLY_ONCE(ro.exec_command_at);
			ro.exec_command_at = opt.arg;
			break;
		case 'f': // Start search offset
			ERROR_USAGE_ONLY_ONCE(ro.from != 0);
			ro.from = rz_num_math(NULL, opt.arg);
			break;
		case 't': // Stop search offset
			ERROR_USAGE_ONLY_ONCE(ro.from != UT64_MAX);
			ro.to = rz_num_math(NULL, opt.arg);
			break;
		case 'n': // Ignore read errors
			ERROR_USAGE_ONLY_ONCE(ro.ignore_read_errors);
			ro.ignore_read_errors = true;
			break;
		case 'C': // Ignore case (only used by -s -r -I -S)
			ERROR_USAGE_ONLY_ONCE(ro.caseless);
			ro.caseless = true;
			break;
		case 'E': // Forces a specific string encoding (see -h output).
			ERROR_USAGE_ONLY_ONCE(ro.encoding != RZ_STRING_ENC_GUESS);
			if (!strcmp(opt.arg, "base64") || !strncmp(opt.arg, "guess", 5)) {
				// forbid base64 and guess encoding
				eprintf("Error: encoding '%s' is unsupported.\n", opt.arg);
				return 1;
			}
			ro.encoding = rz_str_enc_string_as_type(opt.arg);
			if (ro.encoding == RZ_STRING_ENC_GUESS) {
				eprintf("Error: invalid '%s' encoding.\n", opt.arg);
				return 1;
			}
			break;
		case 'm': // Search for magic signatures in the whole file",
			ERROR_USAGE_INCOMPATIBLE_WITH(ro.mode != RZ_FIND_MODE_NOT_SET, "-A -P -z -r -x -i -s -Z -R -X -I -S");
			ro.mode = RZ_FIND_MODE_MAGIC;
			break;
		case 'A': // Search for AES keys in the whole file",
			ERROR_USAGE_INCOMPATIBLE_WITH(ro.mode != RZ_FIND_MODE_NOT_SET, "-m -P -z -r -x -i -s -Z -R -X -I -S");
			ro.mode = RZ_FIND_MODE_AES_KEYS;
			break;
		case 'P': // Search for private RSA/ECC/EdDSA keys in the whole file
			ERROR_USAGE_INCOMPATIBLE_WITH(ro.mode != RZ_FIND_MODE_NOT_SET, "-m -A -z -r -x -i -s -Z -R -X -I -S");
			ro.mode = RZ_FIND_MODE_PRIVATE_KEYS;
			break;
		case 'z': // Search for one or multiple strings in the whole file
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -r -x -i -s -R -X -I -S");
			ro.mode = RZ_FIND_MODE_STRINGS;
			if (!rz_find_add_keyword(opt.arg, ro.keywords, rz_find_is_valid_string)) {
				return 1;
			}
			break;
		case 'r': // Search via one or multiple regexes in the whole file
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -x -i -s -Z -X -I -S");
			ro.mode = RZ_FIND_MODE_REGEXES;
			if (!rz_find_add_keyword(opt.arg, ro.keywords, rz_find_is_valid_regex)) {
				return 1;
			}
			break;
		case 'x': // Search for one or multiple hex patterns in the whole file
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -r -i -s -Z -R -I -S");
			ro.mode = RZ_FIND_MODE_HEX_PATTERNS;
			if (!rz_find_add_keyword(opt.arg, ro.keywords, rz_find_is_valid_hex_pattern)) {
				return 1;
			}
			break;
		case 'i': // Search for one or multiple strings in the import table.
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -r -x -s -Z -R -X -S");
			ro.mode = RZ_FIND_MODE_IMPORTS;
			if (!rz_find_add_keyword(opt.arg, ro.keywords, rz_find_is_valid_string)) {
				return 1;
			}
			break;
		case 's': // Search for one or multiple strings in the symbol table.
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -r -x -i -Z -R -X -I");
			ro.mode = RZ_FIND_MODE_SYMBOLS;
			if (!rz_find_add_keyword(opt.arg, ro.keywords, rz_find_is_valid_string)) {
				return 1;
			}
			break;
		case 'Z': // Search for strings in the whole file (use file lines as input)
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -r -x -i -s -R -X -I -S");
			ro.mode = RZ_FIND_MODE_STRINGS;
			if (rz_find_read_keywords_from_file(opt.arg, ro.keywords, rz_find_is_valid_string)) {
				return 1;
			}
			break;
		case 'R': // Search via regex (use file lines as input)
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -x -i -s -Z -X -I -S");
			ro.mode = RZ_FIND_MODE_REGEXES;
			if (rz_find_read_keywords_from_file(opt.arg, ro.keywords, rz_find_is_valid_regex)) {
				return 1;
			}
			break;
		case 'X': // Search for hex patterns (use file lines as input)
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -r -i -s -Z -R -I -S");
			ro.mode = RZ_FIND_MODE_HEX_PATTERNS;
			if (rz_find_read_keywords_from_file(opt.arg, ro.keywords, rz_find_is_valid_hex_pattern)) {
				return 1;
			}
			break;
		case 'I': // Search for strings in the import table (use file lines as input).
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -r -x -s -Z -R -X -S");
			ro.mode = RZ_FIND_MODE_IMPORTS;
			if (rz_find_read_keywords_from_file(opt.arg, ro.keywords, rz_find_is_valid_string)) {
				return 1;
			}
			break;
		case 'S': // Search for strings in the symbol table (use file lines as input).
			ERROR_ON_NOT_MODE(RZ_FIND_MODE_NOT_SET, "-m -A -P -z -r -x -i -Z -R -X -I");
			ro.mode = RZ_FIND_MODE_SYMBOLS;
			if (rz_find_read_keywords_from_file(opt.arg, ro.keywords, rz_find_is_valid_string)) {
				return 1;
			}
			break;
		case 'j': // JSON output (outputs the matching filenames or offsets)
			ERROR_USAGE_INCOMPATIBLE_WITH(ro.output != RZ_FIND_OUTPUT_STANDARD, "-q -D");
			ro.output = RZ_FIND_OUTPUT_JSON;
			break;
		case 'q': // Quiet output (outputs the matching filenames or offsets)
			ERROR_USAGE_INCOMPATIBLE_WITH(ro.output != RZ_FIND_OUTPUT_STANDARD, "-j -D");
			ro.output = RZ_FIND_OUTPUT_QUIET;
			break;
		case 'D': // Hexdump output of the matching region.
			ERROR_USAGE_INCOMPATIBLE_WITH(ro.output != RZ_FIND_OUTPUT_STANDARD, "-j -q");
			ro.output = RZ_FIND_OUTPUT_HEXDUMP;
			break;
		case 'v': // Show version information
			return rz_main_version_print("rz-find");
		case 'h': // Show this help
			/* fall-thru */
		default:
			return show_help(argv[0], false);
		}
	}
	if (opt.ind == argc) {
		return show_help(argv[0], true);
	}

	if (ro.output == RZ_FIND_OUTPUT_JSON) {
		ro.pj = pj_new();
		pj_a(ro.pj); // [
	}

	for (; opt.ind < argc; opt.ind++) {
		const char *file = argv[opt.ind];
		if (RZ_STR_ISEMPTY(file)) {
			continue;
		}
		rz_find_open(&ro, file);
	}

	if (ro.output == RZ_FIND_OUTPUT_JSON) {
		pj_end(ro.pj); // ]
		printf("%s\n", pj_string(ro.pj));
	}

	rz_find_options_fini(&ro);
	return 0;
}
