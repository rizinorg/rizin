// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_io.h>
#include <rz_bin.h>
#include <rz_diff.h>
#include <rz_util.h>
#include <rz_main.h>

#define MEGABYTE(x)        (x << 20)
#define SAFE_STR_DEF(x, y) (x ? x : y)
#define SAFE_STR(x)        (x ? x : "")
#define IF_STRCMP_S(ret, x, y) \
	do { \
		if ((x) != (y) && (!(x) || !(y))) { \
			return !(y) ? 1 : -1; \
		} else if ((x) && (y) && (ret = strcmp((x), (y)))) { \
			return ret; \
		} \
	} while (0)

typedef enum {
	DIFF_MODE_STANDARD = 0,
	DIFF_MODE_JSON,
	DIFF_MODE_QUIET,
} DiffMode;

typedef enum {
	DIFF_DISTANCE_UNKNOWN = 0,
	DIFF_DISTANCE_MYERS,
	DIFF_DISTANCE_LEVENSHTEIN,
} DiffDistance;

typedef enum {
	DIFF_TYPE_UNKNOWN = 0,
	DIFF_TYPE_BYTES,
	DIFF_TYPE_CLASSES,
	DIFF_TYPE_COMMAND,
	DIFF_TYPE_ENTRIES,
	DIFF_TYPE_FIELDS,
	DIFF_TYPE_FUNCTIONS,
	DIFF_TYPE_IMPORTS,
	DIFF_TYPE_LIBRARIES,
	DIFF_TYPE_LINES,
	DIFF_TYPE_SECTIONS,
	DIFF_TYPE_STRINGS,
	DIFF_TYPE_SYMBOLS,
} DiffType;

typedef enum {
	DIFF_OPT_UNKNOWN = 0,
	DIFF_OPT_ERROR,
	DIFF_OPT_HELP,
	DIFF_OPT_USAGE,
	DIFF_OPT_VERSION,
	DIFF_OPT_DISTANCE,
	DIFF_OPT_UNIFIED,
} DiffOption;

typedef struct diff_context_t {
	DiffType type;
	DiffMode mode;
	DiffOption option;
	DiffDistance distance;
	ut32 arch_bits;
	bool compare_addresses;
	bool show_time;
	bool colors;
	const char *architecture;
	const char *command_a;
	const char *command_b;
	const char *file_a;
	const char *file_b;
} DiffContext;

typedef struct diff_file_t {
	/* const */
	const char *filename;
	RzBinFile *file;
	RzBinPlugin *plugin;
	/* to free */
	RzBin *bin;
	RzIODesc *desc;
	RzIO *io;
} DiffFile;

typedef struct diff_function_t {
	char *name;
	int bits;
	ut64 address;
	int n_instructions;
} DiffFunction;

#define rz_diff_error(f, ...) \
	RZ_LOG_ERROR("rz-diff: error, " f, ##__VA_ARGS__)

#define rz_diff_error_ret(fail, f, ...) \
	RZ_LOG_ERROR("rz-diff: error, " f, ##__VA_ARGS__); \
	return (fail)

#define rz_diff_error_opt(x, o, f, ...) \
	(x)->option = o; \
	RZ_LOG_ERROR("rz-diff: error, " f, ##__VA_ARGS__); \
	return

#define rz_diff_ctx_set(x, k, v) (x)->k = (v)

#define rz_diff_set_def(x, d, v) \
	do { \
		if ((x) != (d)) { \
			RZ_LOG_ERROR("rz-diff: error, invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
			return; \
		} \
		(x) = (v); \
	} while (0)

#define rz_diff_ctx_set_def(x, k, d, v) \
	do { \
		if ((x)->k != (d)) { \
			rz_diff_error_opt(x, DIFF_OPT_UNKNOWN, "invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
		} \
		(x)->k = (v); \
	} while (0)

#define rz_diff_ctx_set_val(x, k, d, v) \
	do { \
		if ((x)->k != (d)) { \
			rz_diff_error_opt(x, DIFF_OPT_UNKNOWN, "invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
		} \
		(x)->k = (v); \
	} while (0)

#define rz_diff_ctx_set_unsigned(x, k, i) \
	do { \
		(x)->k = strtoull((i), NULL, 0); \
		if ((x)->k < 1) { \
			rz_diff_error_opt(x, DIFF_OPT_UNKNOWN, "argument must be > 0\n"); \
		} \
	} while (0)

#define rz_diff_ctx_set_dist(x, t) rz_diff_ctx_set_def(x, distance, DIFF_DISTANCE_UNKNOWN, t)
#define rz_diff_ctx_set_type(x, t) rz_diff_ctx_set_def(x, type, DIFF_TYPE_UNKNOWN, t)
#define rz_diff_ctx_set_mode(x, m) rz_diff_ctx_set_def(x, mode, DIFF_MODE_STANDARD, m)
#define rz_diff_ctx_set_opt(x, o)  rz_diff_ctx_set_def(x, option, DIFF_OPT_UNKNOWN, o)

static void rz_diff_show_help(bool usage_only) {
	printf("Usage: rz-diff [options] <file0> <file1>\n");
	if (usage_only) {
		return;
	}
	printf(
		"  -a [arch] specify architecture plugin to use (x86, arm, ..)\n"
		"  -b [bits] specify register size for arch (16 (thumb), 32, 64, ..)\n"
		"  -d [algo] compute edit distance based on the choosen algorithm:\n"
		"              myers | Eugene W. Myers' O(ND) algorithm (no substitution)\n"
		"              leven | Levenshtein O(N^2) algorithm (with substitution)\n"
		"  -h        this help message\n"
		"  -j        json output\n"
		"  -q        quite output\n"
		"  -v        show version information\n"
		"  -A        compare virtual and physical addresses\n"
		"  -C        show colors\n"
		"  -T        show timestamp information\n"
		"  -0 [cmd]  command to execute for file0 when option -t 'commands' is given.\n"
		"            if -1 is not set, it will execute the same cmd for file1.\n"
		"  -1 [cmd]  command to execute for file1 when option -t 'commands' is given.\n"
		"  -t [type] compute the difference between two files based on its type:\n"
		"              bytes      | compares raw bytes in the files (only for small files)\n"
		"              lines      | compares text files\n"
		"              functions  | compares functions found in the files\n"
		"              classes    | compares classes found in the files\n"
		"              command    | compares command output returned when executed in both files\n"
		"                         | requires -0 <cmd> and -1 <cmd> is optional\n"
		"              entries    | compares entries found in the files\n"
		"              fields     | compares fields found in the files\n"
		"              imports    | compares imports found in the files\n"
		"              libraries  | compares libraries found in the files\n"
		"              sections   | compares sections found in the files\n"
		"              strings    | compares strings found in the files\n"
		"              symbols    | compares symbols found in the files\n"
		"");
}

static bool rz_diff_is_file(const char *file) {
	if (IS_NULLSTR(file)) {
		rz_diff_error_ret(false, "cannot open a file without a name.\n");
	}
	if (rz_file_is_directory(file)) {
		rz_diff_error_ret(false, "cannot open directories (%s).\n", file);
	}
	return true;
}

static void rz_diff_parse_arguments(int argc, const char **argv, DiffContext *ctx) {
	const char *type = NULL;
	const char *algorithm = NULL;
	memset((void *)ctx, 0, sizeof(DiffContext));

	RzGetopt opt;
	int c;
	rz_getopt_init(&opt, argc, argv, "hjqvACTa:b:d:t:0:1:");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case '0': rz_diff_ctx_set_def(ctx, command_a, NULL, opt.arg); break;
		case '1': rz_diff_ctx_set_def(ctx, command_b, NULL, opt.arg); break;
		case 'A': rz_diff_ctx_set_def(ctx, compare_addresses, false, true); break;
		case 'C': rz_diff_ctx_set_def(ctx, colors, false, true); break;
		case 'T': rz_diff_ctx_set_def(ctx, show_time, false, true); break;
		case 'a': rz_diff_ctx_set_def(ctx, architecture, NULL, opt.arg); break;
		case 'b': rz_diff_ctx_set_unsigned(ctx, arch_bits, opt.arg); break;
		case 'd': rz_diff_set_def(algorithm, NULL, opt.arg); break;
		case 'h': rz_diff_ctx_set_opt(ctx, DIFF_OPT_HELP); break;
		case 'j': rz_diff_ctx_set_mode(ctx, DIFF_MODE_JSON); break;
		case 'q': rz_diff_ctx_set_mode(ctx, DIFF_MODE_QUIET); break;
		case 't': rz_diff_set_def(type, NULL, opt.arg); break;
		case 'v': rz_diff_ctx_set_opt(ctx, DIFF_OPT_VERSION); break;

		default:
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "unknown flag '%c'\n", c);
		}
	}

	if (ctx->option == DIFF_OPT_HELP ||
		ctx->option == DIFF_OPT_VERSION) {
		return;
	}

	if (opt.ind >= argc || (argc - opt.ind) != 2) {
		rz_diff_error_opt(ctx, DIFF_OPT_USAGE, "expected 2 files but got %d.\n", (argc - opt.ind));
	}

	ctx->file_a = argv[opt.ind + 0];
	ctx->file_b = argv[opt.ind + 1];

	if (!rz_diff_is_file(ctx->file_a) ||
		!rz_diff_is_file(ctx->file_b)) {
		ctx->option = DIFF_OPT_USAGE;
		return;
	}

	if (algorithm) {
		if (type) {
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t argument is not compatible with -d.\n");
		} else if (ctx->show_time) {
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -T argument is not compatible with -d.\n");
		}

		rz_diff_ctx_set_opt(ctx, DIFF_OPT_DISTANCE);
		if (!strcmp(algorithm, "myers")) {
			rz_diff_ctx_set_dist(ctx, DIFF_DISTANCE_MYERS);
		} else if (!strcmp(algorithm, "leven")) {
			rz_diff_ctx_set_dist(ctx, DIFF_DISTANCE_LEVENSHTEIN);
		} else {
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -d argument '%s' is not a recognized algorithm.\n", algorithm);
		}
	} else if (type) {
		rz_diff_ctx_set_opt(ctx, DIFF_OPT_UNIFIED);

		if (!strcmp(type, "bytes")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_BYTES);
		} else if (!strcmp(type, "lines")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_LINES);
		} else if (!strcmp(type, "functions")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_FUNCTIONS);
		} else if (!strcmp(type, "classes")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_CLASSES);
		} else if (!strcmp(type, "command")) {
			if (!ctx->command_a) {
				rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t '%s' requires -0 <command>.\n", type);
			}
			if (!ctx->command_b) {
				ctx->command_b = ctx->command_a;
			}
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_COMMAND);
		} else if (!strcmp(type, "entries")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_ENTRIES);
		} else if (!strcmp(type, "fields")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_FIELDS);
		} else if (!strcmp(type, "imports")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_IMPORTS);
		} else if (!strcmp(type, "libraries")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_LIBRARIES);
		} else if (!strcmp(type, "sections")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_SECTIONS);
		} else if (!strcmp(type, "strings")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_STRINGS);
		} else if (!strcmp(type, "symbols")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_SYMBOLS);
		} else {
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t argument '%s' is not a recognized type.\n", type);
		}
	} else {
		rz_diff_error_opt(ctx, DIFF_OPT_USAGE, "option -t or -d is required to be specified.\n");
	}
}

/* This is terrible because can eat a lot of memory */
static ut8 *rz_diff_slurp_file(const char *file, size_t *size) {
	ut8 *buffer = NULL;
	ssize_t read = 0;
	size_t filesize = 0;
	RzIODesc *desc = NULL;
	RzIO *io = rz_io_new();
	if (!io) {
		rz_diff_error("cannot allocate io\n");
		goto rz_diff_slurp_file_end;
	}

	desc = rz_io_open_nomap(io, file, RZ_PERM_R, 0);
	if (!desc) {
		rz_diff_error("cannot open file '%s'\n", file);
		goto rz_diff_slurp_file_end;
	}

	filesize = rz_io_desc_size(io->desc);
	if (filesize > MEGABYTE(100)) {
		rz_diff_error("cannot open file '%s' because its size is above 100Mb\n", file);
		goto rz_diff_slurp_file_end;
	}

	buffer = malloc(filesize);
	if (!buffer) {
		rz_diff_error("cannot allocate buffer\n");
		goto rz_diff_slurp_file_end;
	}

	read = rz_io_pread_at(io, 0, buffer, filesize);
	if (read != filesize) {
		free(buffer);
		buffer = NULL;
		rz_diff_error("cannot read buffer correctly\n");
		goto rz_diff_slurp_file_end;
	}

	*size = filesize;

rz_diff_slurp_file_end:
	rz_io_desc_close(desc);
	rz_io_free(io);
	return buffer;
}

static bool rz_diff_calculate_distance(DiffContext *ctx) {
	size_t a_size = 0;
	size_t b_size = 0;
	ut8 *a_buffer = NULL;
	ut8 *b_buffer = NULL;
	ut32 distance = 0;
	double similarity = 0.0;

	if (!(a_buffer = rz_diff_slurp_file(ctx->file_a, &a_size))) {
		goto rz_diff_calculate_distance_bad;
	}

	if (!(b_buffer = rz_diff_slurp_file(ctx->file_b, &b_size))) {
		goto rz_diff_calculate_distance_bad;
	}

	switch (ctx->distance) {
	case DIFF_DISTANCE_MYERS:
		if (!rz_diff_myers_distance(a_buffer, a_size, b_buffer, b_size, &distance, &similarity)) {
			rz_diff_error("failed to calculate distance with myers algorithm\n");
			goto rz_diff_calculate_distance_bad;
		}
		break;
	case DIFF_DISTANCE_LEVENSHTEIN:
		if (!rz_diff_levenstein_distance(a_buffer, a_size, b_buffer, b_size, &distance, &similarity)) {
			rz_diff_error("failed to calculate distance with levenstein algorithm\n");
			goto rz_diff_calculate_distance_bad;
		}
		break;
	default:
		rz_diff_error("unknown distance algorithm\n");
		goto rz_diff_calculate_distance_bad;
	}

	if (ctx->mode == DIFF_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			rz_diff_error("failed to allocate json\n");
			goto rz_diff_calculate_distance_bad;
		}
		pj_o(pj);
		pj_kd(pj, "similarity", similarity);
		pj_kn(pj, "distance", distance);
		pj_end(pj);
		printf("%s\n", pj_string(pj));
		pj_free(pj);
	} else if (ctx->mode == DIFF_MODE_QUIET) {
		printf("%.3f\n", similarity);
		printf("%d\n", distance);
	} else {
		// DIFF_MODE_STANDARD
		printf("similarity: %.3f\n", similarity);
		printf("distance: %d\n", distance);
	}
	free(a_buffer);
	free(b_buffer);
	return true;

rz_diff_calculate_distance_bad:
	free(a_buffer);
	free(b_buffer);
	return false;
}

static inline RzBinFile *core_get_file(RzCoreFile *cfile) {
	return rz_pvector_at(&cfile->binfiles, 0);
}

static RzCoreFile *rz_diff_load_file_with_core(const char *filename, const char *architecture, ut32 arch_bits) {
	RzCore *core = NULL;
	RzCoreFile *cfile = NULL;
	RzBinFile *bfile = NULL;

	core = rz_core_new();
	if (!core) {
		rz_diff_error("cannot allocate core\n");
		goto rz_diff_load_file_with_core_fail;
	}
	rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL, NULL);

	rz_config_set_i(core->config, "scr.color", 0);
	rz_config_set_b(core->config, "scr.interactive", false);
	rz_config_set_b(core->config, "cfg.debug", false);
	core->print->scr_prompt = false;

#if __WINDOWS__
	char *winpath = rz_acp_to_utf8(filename);
	cfile = rz_core_file_open(core, winpath, 0, 0);
	free(winpath);
#else
	cfile = rz_core_file_open(core, filename, 0, 0);
#endif
	if (!cfile) {
		rz_diff_error("cannot open file '%s'\n", filename);
		goto rz_diff_load_file_with_core_fail;
	}

	if (!rz_core_bin_load(core, NULL, UT64_MAX)) {
		rz_diff_error("cannot load file '%s'\n", filename);
		goto rz_diff_load_file_with_core_fail;
	}

	if (!rz_core_bin_update_arch_bits(core)) {
		rz_diff_error("cannot set architecture with bits\n");
		goto rz_diff_load_file_with_core_fail;
	}

	bfile = core_get_file(cfile);
	if (!bfile) {
		rz_diff_error("cannot get architecture with bits\n");
		goto rz_diff_load_file_with_core_fail;
	}

	if (rz_list_empty(bfile->o->sections)) {
		rz_config_set_i(core->config, "io.va", false);
	}

	if (architecture) {
		rz_config_set(core->config, "asm.arch", architecture);
	}

	if (arch_bits) {
		rz_config_set_i(core->config, "asm.bits", arch_bits);
	}

	if (!rz_core_analysis_everything(core, false, NULL)) {
		rz_diff_error("cannot set analyze binary '%s'\n", filename);
		goto rz_diff_load_file_with_core_fail;
	}

	return cfile;

rz_diff_load_file_with_core_fail:
	rz_core_free(core);
	return NULL;
}

static bool rz_diff_file_open(DiffFile *dfile, const char *filename) {
	memset((void *)dfile, 0, sizeof(DiffFile));
	RzBinOptions opt = { 0 };
	RzBinFile *file = NULL;
	RzBin *bin = NULL;
	RzIODesc *desc = NULL;
	RzIO *io = NULL;

	io = rz_io_new();
	if (!io) {
		rz_diff_error("cannot allocate io\n");
		goto rz_diff_file_open_bad;
	}

	desc = rz_io_open_nomap(io, filename, RZ_PERM_R, 0);
	if (!desc) {
		rz_diff_error("cannot open file '%s'\n", filename);
		goto rz_diff_file_open_bad;
	}

	bin = rz_bin_new();
	if (!bin) {
		rz_diff_error("cannot allocate bin\n");
		goto rz_diff_file_open_bad;
	}

	rz_io_bind(io, &bin->iob);

	rz_bin_options_init(&opt, desc->fd, 0, 0, false);
	opt.sz = rz_io_desc_size(desc);

	file = rz_bin_open_io(bin, &opt);
	if (!file) {
		rz_diff_error("cannot open bin file via io\n");
		goto rz_diff_file_open_bad;
	}

	dfile->filename = filename;
	dfile->plugin = rz_bin_file_cur_plugin(file);
	dfile->file = file;
	dfile->bin = bin;
	dfile->desc = desc;
	dfile->io = io;
	return true;

rz_diff_file_open_bad:
	rz_bin_free(bin);
	rz_io_desc_close(desc);
	rz_io_free(io);
	return false;
}

static void rz_diff_file_close(DiffFile *file) {
	// plugin and file are freed by rz_bin_free
	rz_bin_free(file->bin);
	rz_io_desc_close(file->desc);
	rz_io_free(file->io);
}

#define rz_diff_file_get(df, n) ((df)->file->o->n)

/**************************************** rzlists ***************************************/

static const void *rz_diff_list_elem_at(const RzList *array, ut32 index) {
	return rz_list_get_n(array, index);
}

/**************************************** imports ***************************************/

static ut32 import_hash(const RzBinImport *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= rz_diff_hash_data((const ut8 *)elem->bind, strlen(SAFE_STR(elem->bind)));
	hash ^= rz_diff_hash_data((const ut8 *)elem->type, strlen(SAFE_STR(elem->type)));
	return hash;
}

static void import_stringify(const RzBinImport *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%-7s %-7s %s\n", SAFE_STR_DEF(elem->bind, RZ_BIN_BIND_UNKNOWN_STR),
		SAFE_STR_DEF(elem->type, RZ_BIN_TYPE_UNKNOWN_STR), elem->name);
}

static int import_compare(const RzBinImport *a, const RzBinImport *b) {
	int ret;
	IF_STRCMP_S(ret, a->name, b->name);
	IF_STRCMP_S(ret, a->bind, b->bind);
	IF_STRCMP_S(ret, a->type, b->type);
	return 0;
}

static RzDiff *rz_diff_imports_new(DiffFile *dfile_a, DiffFile *dfile_b) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, imports);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get imports from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, imports);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get imports from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)import_compare);
	rz_list_sort(list_b, (RzListComparator)import_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)import_hash,
		.compare = (RzDiffMethodCompare)import_compare,
		.stringify = (RzDiffMethodStringify)import_stringify,
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** symbols ***************************************/

static ut32 symbol_hash_addr(const RzBinSymbol *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= (ut32)(elem->vaddr >> 32);
	hash ^= (ut32)elem->vaddr;
	hash ^= (ut32)(elem->paddr >> 32);
	hash ^= (ut32)elem->paddr;
	return hash;
}

static int symbol_compare_addr(const RzBinSymbol *a, const RzBinSymbol *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->name, b->name);
	ret = ((st64)b->paddr) - ((st64)a->paddr);
	if (ret) {
		return ret;
	}
	return ((st64)b->vaddr) - ((st64)a->vaddr);
}

static void symbol_stringify_addr(const RzBinSymbol *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "virt: 0x%016" PFMT64x " phys: 0x%016" PFMT64x " %s\n", elem->vaddr, elem->paddr, elem->name);
}

static ut32 symbol_hash(const RzBinSymbol *elem) {
	return rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
}

static int symbol_compare(const RzBinSymbol *a, const RzBinSymbol *b) {
	int ret;
	IF_STRCMP_S(ret, a->name, b->name);
	return 0;
}

static void symbol_stringify(const RzBinSymbol *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s\n", elem->name);
}

static RzDiff *rz_diff_symbols_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, symbols);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get symbols from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, symbols);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get symbols from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)symbol_compare);
	rz_list_sort(list_b, (RzListComparator)symbol_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? symbol_hash_addr : symbol_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? symbol_compare_addr : symbol_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? symbol_stringify_addr : symbol_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** strings ***************************************/

static ut32 string_hash_addr(const RzBinString *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->string, elem->size);
	hash ^= (ut32)(elem->vaddr >> 32);
	hash ^= (ut32)elem->vaddr;
	hash ^= (ut32)(elem->paddr >> 32);
	hash ^= (ut32)elem->paddr;
	return hash;
}

static int string_compare_addr(const RzBinString *a, const RzBinString *b) {
	st64 ret;
	ret = ((st64)b->size) - ((st64)a->size);
	if (ret) {
		return ret;
	}
	IF_STRCMP_S(ret, a->string, b->string);
	ret = ((st64)b->paddr) - ((st64)a->paddr);
	if (ret) {
		return ret;
	}
	return ((st64)b->vaddr) - ((st64)a->vaddr);
}

static void string_stringify_addr(const RzBinString *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "virt: 0x%016" PFMT64x " phys: 0x%016" PFMT64x " %s\n", elem->vaddr, elem->paddr, elem->string);
}

static ut32 string_hash(const RzBinString *elem) {
	return rz_diff_hash_data((const ut8 *)elem->string, elem->size);
}

static int string_compare(const RzBinString *a, const RzBinString *b) {
	st64 ret;
	ret = ((st64)b->size) - ((st64)a->size);
	if (ret) {
		return ret;
	}
	IF_STRCMP_S(ret, a->string, b->string);
	return 0;
}

static void string_stringify(const RzBinString *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s\n", elem->string);
}

static RzDiff *rz_diff_strings_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, strings);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get strings from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, strings);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get strings from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)string_compare);
	rz_list_sort(list_b, (RzListComparator)string_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? string_hash_addr : string_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? string_compare_addr : string_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? string_stringify_addr : string_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** classes ***************************************/

static ut32 class_hash_addr(const RzBinClass *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= rz_diff_hash_data((const ut8 *)elem->super, strlen(elem->super));
	hash ^= (ut32)(elem->addr >> 32);
	hash ^= (ut32)elem->addr;
	return hash;
}

static int class_compare_addr(const RzBinClass *a, const RzBinClass *b) {
	int ret;
	IF_STRCMP_S(ret, a->super, b->super);
	IF_STRCMP_S(ret, a->name, b->name);
	return a->addr - b->addr;
}

static void class_stringify_addr(const RzBinClass *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "0x%016" PFMT64x " %s %s\n", elem->addr, SAFE_STR(elem->super), elem->name);
}

static ut32 class_hash(const RzBinClass *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= rz_diff_hash_data((const ut8 *)elem->super, strlen(elem->super));
	return hash;
}

static int class_compare(const RzBinClass *a, const RzBinClass *b) {
	int ret;
	IF_STRCMP_S(ret, a->super, b->super);
	IF_STRCMP_S(ret, a->name, b->name);
	return 0;
}

static void class_stringify(const RzBinClass *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s %s\n", SAFE_STR(elem->super), elem->name);
}

static RzDiff *rz_diff_classes_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, classes);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get classes from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, classes);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get classes from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)class_compare);
	rz_list_sort(list_b, (RzListComparator)class_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? class_hash_addr : class_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? class_compare_addr : class_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? class_stringify_addr : class_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** entries ***************************************/

static ut32 entry_hash(const RzBinAddr *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)"entry", strlen("entry"));
	hash ^= (ut32)(elem->vaddr >> 32);
	hash ^= (ut32)elem->vaddr;
	hash ^= (ut32)(elem->paddr >> 32);
	hash ^= (ut32)elem->paddr;
	hash ^= (ut32)elem->type;
	return hash;
}

static int entry_compare(const RzBinAddr *a, const RzBinAddr *b) {
	st64 ret;
	ret = ((st64)b->paddr) - ((st64)a->paddr);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->vaddr) - ((st64)a->vaddr);
	if (ret) {
		return ret;
	}
	return b->type - a->type;
}

static void entry_stringify(const RzBinAddr *elem, RzStrBuf *sb) {
	const char *name = NULL;
	switch (elem->type) {
	case RZ_BIN_ENTRY_TYPE_PROGRAM:
		name = "program";
		break;
	case RZ_BIN_ENTRY_TYPE_MAIN:
		name = "main";
		break;
	case RZ_BIN_ENTRY_TYPE_INIT:
		name = "init";
		break;
	case RZ_BIN_ENTRY_TYPE_FINI:
		name = "fini";
		break;
	case RZ_BIN_ENTRY_TYPE_TLS:
		name = "tls";
		break;
	case RZ_BIN_ENTRY_TYPE_PREINIT:
		name = "preinit";
		break;
	default:
		name = "unknown";
		break;
	}
	rz_strbuf_setf(sb, "virt: 0x%016" PFMT64x " phys: 0x%016" PFMT64x " entry %s\n", elem->vaddr, elem->paddr, name);
}

static RzDiff *rz_diff_entries_new(DiffFile *dfile_a, DiffFile *dfile_b) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, entries);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get entries from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, entries);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get entries from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)entry_compare);
	rz_list_sort(list_b, (RzListComparator)entry_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)entry_hash,
		.compare = (RzDiffMethodCompare)entry_compare,
		.stringify = (RzDiffMethodStringify)entry_stringify,
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** libraries ***************************************/

static ut32 libs_hash(const char *elem) {
	return rz_diff_hash_data((const ut8 *)elem, strlen(elem));
}

static int libs_compare(const char *a, const char *b) {
	int ret;
	IF_STRCMP_S(ret, a, b);
	return 0;
}

static void libs_stringify(const char *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s\n", SAFE_STR(elem));
}

static RzDiff *rz_diff_libraries_new(DiffFile *dfile_a, DiffFile *dfile_b) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, libs);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get libraries from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, libs);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get libraries from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)libs_compare);
	rz_list_sort(list_b, (RzListComparator)libs_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)libs_hash,
		.compare = (RzDiffMethodCompare)libs_compare,
		.stringify = (RzDiffMethodStringify)libs_stringify,
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** sections ***************************************/

static ut32 section_hash_addr(const RzBinSection *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= elem->perm;
	hash ^= (ut32)(elem->align >> 32);
	hash ^= (ut32)elem->align;
	hash ^= (ut32)(elem->vsize >> 32);
	hash ^= (ut32)elem->vsize;
	hash ^= (ut32)(elem->size >> 32);
	hash ^= (ut32)elem->size;
	hash ^= (ut32)(elem->vaddr >> 32);
	hash ^= (ut32)elem->vaddr;
	hash ^= (ut32)(elem->paddr >> 32);
	hash ^= (ut32)elem->paddr;
	return hash;
}

static int section_compare_addr(const RzBinSection *a, const RzBinSection *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->name, b->name);
	ret = ((st64)b->size) - ((st64)a->size);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->vsize) - ((st64)a->vsize);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->paddr) - ((st64)a->paddr);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->vaddr) - ((st64)a->vaddr);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->perm) - ((st64)a->perm);
	if (ret) {
		return ret;
	}
	return ((st64)b->align) - ((st64)a->align);
}

static void section_stringify_addr(const RzBinSection *elem, RzStrBuf *sb) {
	char perm[5];

	perm[0] = elem->perm & RZ_PERM_SHAR ? 's' : '-';
	perm[1] = elem->perm & RZ_PERM_R ? 'r' : '-';
	perm[2] = elem->perm & RZ_PERM_W ? 'w' : '-';
	perm[3] = elem->perm & RZ_PERM_X ? 'x' : '-';
	perm[4] = 0;

	rz_strbuf_setf(sb, "virt: 0x%016" PFMT64x ":0x%04" PFMT64x " phys: 0x%016" PFMT64x ":0x%04" PFMT64x " align: 0x%08" PFMT64x " %s %s\n",
		elem->vaddr, elem->vsize, elem->paddr, elem->size, elem->align, perm, elem->name);
}

static ut32 section_hash(const RzBinSection *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= elem->perm;
	hash ^= (ut32)(elem->align >> 32);
	hash ^= (ut32)elem->align;
	return hash;
}

static int section_compare(const RzBinSection *a, const RzBinSection *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->name, b->name);
	ret = ((st64)b->perm) - ((st64)a->perm);
	if (ret) {
		return ret;
	}
	return ((st64)b->align) - ((st64)a->align);
}

static void section_stringify(const RzBinSection *elem, RzStrBuf *sb) {
	char perm[5];

	perm[0] = elem->perm & RZ_PERM_SHAR ? 's' : '-';
	perm[1] = elem->perm & RZ_PERM_R ? 'r' : '-';
	perm[2] = elem->perm & RZ_PERM_W ? 'w' : '-';
	perm[3] = elem->perm & RZ_PERM_X ? 'x' : '-';
	perm[4] = 0;

	rz_strbuf_setf(sb, "align: 0x%08" PFMT64x " %s %s\n", elem->align, perm, elem->name);
}

static RzDiff *rz_diff_sections_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, sections);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get sections from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, sections);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get sections from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)section_compare);
	rz_list_sort(list_b, (RzListComparator)section_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? section_hash_addr : section_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? section_compare_addr : section_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? section_stringify_addr : section_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** fields ***************************************/

static ut32 field_hash_addr(const RzBinField *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= rz_diff_hash_data((const ut8 *)elem->type, strlen(SAFE_STR(elem->type)));
	hash ^= (ut32)(elem->paddr >> 32);
	hash ^= (ut32)elem->paddr;
	hash ^= (ut32)(elem->vaddr >> 32);
	hash ^= (ut32)elem->vaddr;
	return hash;
}

static int field_compare_addr(const RzBinField *a, const RzBinField *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->name, b->name);
	IF_STRCMP_S(ret, a->type, b->type);
	ret = ((st64)b->size) - ((st64)a->size);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->paddr) - ((st64)a->paddr);
	if (ret) {
		return ret;
	}
	return ((st64)b->vaddr) - ((st64)a->vaddr);
}

static void field_stringify_addr(const RzBinField *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "virt: 0x%016" PFMT64x " phys: 0x%016" PFMT64x " %-8s %s\n",
		elem->vaddr, elem->paddr, SAFE_STR(elem->type), elem->name);
}

static ut32 field_hash(const RzBinField *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= rz_diff_hash_data((const ut8 *)elem->type, strlen(SAFE_STR(elem->type)));
	return hash;
}

static int field_compare(const RzBinField *a, const RzBinField *b) {
	int ret;
	IF_STRCMP_S(ret, a->name, b->name);
	IF_STRCMP_S(ret, a->type, b->type);
	return 0;
}

static void field_stringify(const RzBinField *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s %s\n", SAFE_STR(elem->type), elem->name);
}

static RzDiff *rz_diff_fields_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = rz_diff_file_get(dfile_a, fields);
	if (!list_a) {
		rz_diff_error_ret(NULL, "cannot get fields from '%s'\n", dfile_a->filename);
	}

	list_b = rz_diff_file_get(dfile_b, fields);
	if (!list_b) {
		rz_diff_error_ret(NULL, "cannot get fields from '%s'\n", dfile_b->filename);
	}

	rz_list_sort(list_a, (RzListComparator)field_compare);
	rz_list_sort(list_b, (RzListComparator)field_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? field_hash_addr : field_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? field_compare_addr : field_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? field_stringify_addr : field_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** functions ***************************************/

static ut32 func_hash_addr(const DiffFunction *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= (ut32)(elem->address >> 32);
	hash ^= (ut32)elem->address;
	hash ^= (ut32)elem->bits;
	hash ^= (ut32)elem->n_instructions;
	return hash;
}

static int func_compare_addr(const DiffFunction *a, const DiffFunction *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->name, b->name);
	ret = ((st64)b->address) - ((st64)a->address);
	if (ret) {
		return ret;
	}
	ret = ((st64)b->n_instructions) - ((st64)a->n_instructions);
	if (ret) {
		return ret;
	}
	return ((st64)b->bits) - ((st64)a->bits);
}

static void func_stringify_addr(const DiffFunction *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "0x%016" PFMT64x " instrs: %-4d bits: %-2d %s\n",
		elem->address, elem->n_instructions, elem->bits, elem->name);
}

static ut32 func_hash(const DiffFunction *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
	hash ^= (ut32)elem->bits;
	hash ^= (ut32)elem->n_instructions;
	return hash;
}

static int func_compare(const DiffFunction *a, const DiffFunction *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->name, b->name);
	ret = ((st64)b->n_instructions) - ((st64)a->n_instructions);
	if (ret) {
		return ret;
	}
	return ((st64)b->bits) - ((st64)a->bits);
}

static void func_stringify(const DiffFunction *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "instrs: %-4d bits: %-2d %s\n", elem->n_instructions, elem->bits, elem->name);
}

static DiffFunction *func_new(RzAnalysisFunction *function) {
	DiffFunction *df = RZ_NEW(DiffFunction);
	if (!df) {
		return NULL;
	}
	df->name /*     */ = strdup(function->name);
	df->bits /*     */ = function->bits;
	df->address /*  */ = function->addr;
	df->n_instructions = function->ninstr;
	return df;
}

static void func_free(DiffFunction *func) {
	if (!func) {
		return;
	}
	free(func->name);
	free(func);
}

static RzList *func_get_all_functions(const char *filename, const char *architecture, ut32 arch_bits) {
	RzList *list = NULL;
	RzList *functions = NULL;
	RzCoreFile *cfile = NULL;
	RzListIter *it = NULL;
	RzAnalysisFunction *fcn;
	DiffFunction *df = NULL;

	cfile = rz_diff_load_file_with_core(filename, architecture, arch_bits);
	if (!cfile) {
		return NULL;
	}

	functions = rz_analysis_function_list(cfile->core->analysis);
	if (!functions) {
		rz_diff_error("cannot get function list\n");
		goto func_get_all_functions_fail;
	}

	list = rz_list_newf((RzListFree)func_free);
	if (!list) {
		rz_diff_error("cannot allocate list for functions\n");
		goto func_get_all_functions_fail;
	}

	rz_list_foreach (functions, it, fcn) {
		if (!fcn) {
			continue;
		}
		df = func_new(fcn);
		if (!df) {
			rz_diff_error("cannot allocate function\n");
			goto func_get_all_functions_fail;
		}
		if (!rz_list_append(list, df)) {
			func_free(df);
			rz_diff_error("cannot insert function in list\n");
			goto func_get_all_functions_fail;
		}
	}

	rz_core_free(cfile->core);
	return list;

func_get_all_functions_fail:
	if (cfile) {
		rz_core_free(cfile->core);
	}
	return NULL;
}

static RzDiff *rz_diff_functions_new(DiffContext *ctx) {
	RzList *list_a = NULL;
	RzList *list_b = NULL;

	list_a = func_get_all_functions(ctx->file_a, ctx->architecture, ctx->arch_bits);
	if (!list_a) {
		return NULL;
	}

	list_b = func_get_all_functions(ctx->file_b, ctx->architecture, ctx->arch_bits);
	if (!list_b) {
		return NULL;
	}

	rz_list_sort(list_a, (RzListComparator)func_compare);
	rz_list_sort(list_b, (RzListComparator)func_compare);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_list_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(ctx->compare_addresses ? func_hash_addr : func_hash),
		.compare = (RzDiffMethodCompare)(ctx->compare_addresses ? func_compare_addr : func_compare),
		.stringify = (RzDiffMethodStringify)(ctx->compare_addresses ? func_stringify_addr : func_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(list_a, rz_list_length(list_a), list_b, rz_list_length(list_b), &methods);
}

/**************************************** commands ***************************************/

static char *execute_command(const char *command, const char *filename, const char *architecture, ut32 arch_bits) {
	RzCoreFile *cfile = rz_diff_load_file_with_core(filename, architecture, arch_bits);
	if (!cfile) {
		return NULL;
	}

	char *output = rz_core_cmd_str(cfile->core, command);
	rz_core_free(cfile->core);
	return output;
}

static RzDiff *rz_diff_command_new(DiffContext *ctx) {
	char *output_a = NULL;
	char *output_b = NULL;

	output_a = execute_command(ctx->command_a, ctx->file_a, ctx->architecture, ctx->arch_bits);
	if (!output_a) {
		rz_diff_error_ret(NULL, "cannot execute command '%s' on file '%s'\n", ctx->command_a, ctx->file_a);
	}

	output_b = execute_command(ctx->command_b, ctx->file_b, ctx->architecture, ctx->arch_bits);
	if (!output_b) {
		free(output_a);
		rz_diff_error_ret(NULL, "cannot execute command '%s' on file '%s'\n", ctx->command_b, ctx->file_b);
	}

	RzDiff *diff = rz_diff_lines_new(output_a, output_b, NULL);
	free(output_a);
	free(output_b);
	return diff;
}

/**************************************** rz-diff ***************************************/

static bool rz_diff_unified_files(DiffContext *ctx) {
	size_t a_size = 0;
	size_t b_size = 0;
	ut8 *a_buffer = NULL;
	ut8 *b_buffer = NULL;
	DiffFile dfile_a = { 0 };
	DiffFile dfile_b = { 0 };
	RzDiff *diff = NULL;
	bool result = false;

	if (ctx->type == DIFF_TYPE_BYTES ||
		ctx->type == DIFF_TYPE_LINES) {
		if (!(a_buffer = rz_diff_slurp_file(ctx->file_a, &a_size))) {
			goto rz_diff_unified_files_bad;
		}

		if (!(b_buffer = rz_diff_slurp_file(ctx->file_b, &b_size))) {
			goto rz_diff_unified_files_bad;
		}
	} else if (ctx->type != DIFF_TYPE_FUNCTIONS && ctx->type != DIFF_TYPE_COMMAND) {
		if (!rz_diff_file_open(&dfile_a, ctx->file_a)) {
			goto rz_diff_unified_files_bad;
		}
		if (!rz_diff_file_open(&dfile_b, ctx->file_b)) {
			goto rz_diff_unified_files_bad;
		}
	}

	switch (ctx->type) {
	case DIFF_TYPE_BYTES:
		diff = rz_diff_bytes_new(a_buffer, a_size, b_buffer, b_size, NULL);
		break;
	case DIFF_TYPE_CLASSES:
		diff = rz_diff_classes_new(&dfile_a, &dfile_b, ctx->compare_addresses);
		break;
	case DIFF_TYPE_COMMAND:
		diff = rz_diff_command_new(ctx);
		break;
	case DIFF_TYPE_ENTRIES:
		diff = rz_diff_entries_new(&dfile_a, &dfile_b);
		break;
	case DIFF_TYPE_FIELDS:
		diff = rz_diff_fields_new(&dfile_a, &dfile_b, ctx->compare_addresses);
		break;
	case DIFF_TYPE_FUNCTIONS:
		diff = rz_diff_functions_new(ctx);
		break;
	case DIFF_TYPE_IMPORTS:
		diff = rz_diff_imports_new(&dfile_a, &dfile_b);
		break;
	case DIFF_TYPE_LIBRARIES:
		diff = rz_diff_libraries_new(&dfile_a, &dfile_b);
		break;
	case DIFF_TYPE_LINES:
		diff = rz_diff_lines_new((const char *)a_buffer, (const char *)b_buffer, NULL);
		break;
	case DIFF_TYPE_SECTIONS:
		diff = rz_diff_sections_new(&dfile_a, &dfile_b, ctx->compare_addresses);
		break;
	case DIFF_TYPE_STRINGS:
		diff = rz_diff_strings_new(&dfile_a, &dfile_b, ctx->compare_addresses);
		break;
	case DIFF_TYPE_SYMBOLS:
		diff = rz_diff_symbols_new(&dfile_a, &dfile_b, ctx->compare_addresses);
		break;
	default:
		rz_diff_error("unknown type\n");
		goto rz_diff_unified_files_bad;
	}

	if (!diff) {
		goto rz_diff_unified_files_bad;
	}

	if (ctx->mode == DIFF_MODE_JSON) {
		PJ *pj = rz_diff_unified_json(diff, ctx->file_a, ctx->file_b, ctx->show_time);
		if (!pj) {
			goto rz_diff_unified_files_bad;
		}
		printf("%s\n", pj_string(pj));
		pj_free(pj);
	} else {
		// DIFF_MODE_STANDARD & DIFF_MODE_QUIET
		char *result = rz_diff_unified_text(diff, ctx->file_a, ctx->file_b, ctx->show_time, ctx->colors);
		if (!result) {
			goto rz_diff_unified_files_bad;
		}
		puts(result);
		free(result);
	}

	result = true;

rz_diff_unified_files_bad:
	if (ctx->type == DIFF_TYPE_FUNCTIONS) {
		rz_list_free((RzList *)rz_diff_get_a(diff));
		rz_list_free((RzList *)rz_diff_get_b(diff));
	}

	rz_diff_free(diff);
	rz_diff_file_close(&dfile_a);
	rz_diff_file_close(&dfile_b);
	free(a_buffer);
	free(b_buffer);
	return result;
}

RZ_API int rz_main_rz_diff(int argc, const char **argv) {
	bool success = false;
	DiffContext ctx;

	rz_diff_parse_arguments(argc, argv, &ctx);

	switch (ctx.option) {
	case DIFF_OPT_DISTANCE:
		success = rz_diff_calculate_distance(&ctx);
		break;
	case DIFF_OPT_UNIFIED:
		success = rz_diff_unified_files(&ctx);
		break;
	case DIFF_OPT_VERSION:
		rz_main_version_print("rz-diff");
		break;
	case DIFF_OPT_USAGE:
		rz_diff_show_help(true);
		goto rz_main_rz_diff_end;
	case DIFF_OPT_ERROR:
		goto rz_main_rz_diff_end;
	case DIFF_OPT_HELP:
		success = true;
	default:
		rz_diff_show_help(false);
		goto rz_main_rz_diff_end;
	}

	success = true;

rz_main_rz_diff_end:
	return success ? 0 : 1;
}
