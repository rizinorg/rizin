// SPDX-FileCopyrightText: 2021 deroad <wargiof@libero.it>
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
	DIFF_DISTANCE_SSDEEP,
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
	DIFF_TYPE_PLOTDIFF,
} DiffType;

typedef enum {
	DIFF_OPT_UNKNOWN = 0,
	DIFF_OPT_ERROR,
	DIFF_OPT_HELP,
	DIFF_OPT_USAGE,
	DIFF_OPT_VERSION,
	DIFF_OPT_DISTANCE,
	DIFF_OPT_UNIFIED,
	DIFF_OPT_GRAPH,
	DIFF_OPT_HEX_VISUAL,
} DiffOption;

typedef struct diff_screen_t {
	int width;
	int height;
} DiffScreen;

typedef struct diff_context_t {
	DiffType type;
	DiffMode mode;
	DiffOption option;
	DiffDistance distance;
	ut32 arch_bits;
	bool compare_addresses;
	bool show_time;
	bool colors;
	bool analyze_all;
	bool command_line;
	bool verbose;
	const char *architecture;
	const char *input_a;
	const char *input_b;
	const char *file_a;
	const char *file_b;
	DiffScreen screen;
	RzList /*<char *>*/ *evars;
} DiffContext;

typedef struct diff_io_t {
	const char *filename;
	ut64 filesize;
	RzIO *io;
} DiffIO;

typedef struct diff_file_t {
	/* const */
	RzBinFile *file;
	RzBinPlugin *plugin;
	/* to free */
	RzBin *bin;
	DiffIO *dio;
} DiffFile;

typedef struct diff_function_t {
	char *name;
	int bits;
	ut64 address;
	int n_instructions;
} DiffFunction;

typedef struct diff_colors_t {
	const char *number;
	const char *match;
	const char *unmatch;
	const char *legenda;
	const char *reset;
} DiffColors;

typedef struct diff_hex_view_t {
	char *line;
	ut8 *buffer_a;
	ut8 *buffer_b;
	ut64 size_a;
	ut64 size_b;
	ut64 address_a;
	ut64 address_b;
	DiffIO *io_a;
	DiffIO *io_b;
	bool column_descr;
	DiffColors colors;
	RzConsCanvas *canvas;
	DiffScreen screen;
} DiffHexView;

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

#define rz_diff_ctx_add_evar(x, o) \
	do { \
		char *copy = rz_str_dup(o); \
		if (!copy || !rz_list_append((x)->evars, copy)) { \
			free(copy); \
			rz_diff_error_opt(x, DIFF_OPT_ERROR, "cannot add evar '%s' to list\n", o); \
		} \
	} while (0)

#define rz_diff_ctx_set_dist(x, t) rz_diff_ctx_set_def(x, distance, DIFF_DISTANCE_UNKNOWN, t)
#define rz_diff_ctx_set_type(x, t) rz_diff_ctx_set_def(x, type, DIFF_TYPE_UNKNOWN, t)
#define rz_diff_ctx_set_mode(x, m) rz_diff_ctx_set_def(x, mode, DIFF_MODE_STANDARD, m)
#define rz_diff_ctx_set_opt(x, o)  rz_diff_ctx_set_def(x, option, DIFF_OPT_UNKNOWN, o)

static void rz_diff_show_help(bool usage_only) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-diff [options] <file0> <file1>\n");
	if (usage_only) {
		return;
	}
	const char *options[] = {
		// clang-format off
		"-a",       "[arch]",       "Specify architecture plugin to use (x86, arm, ..)",
		"-b",       "[bits]",       "Specify register size for arch (16 (thumb), 32, 64, ..)",
		"-d",       "[algo]",       "Compute edit distance based on the chosen algorithm:",
		"",         "",             "   myers  | Eugene W. Myers' O(ND) algorithm (no substitution)",
		"",         "",             "   leven  | Levenshtein O(N^2) algorithm (with substitution)",
		"",         "",             "   ssdeep | Context triggered piecewise hashing comparison",
		"-i",       "",             "Use command line arguments instead of files (only for -d)",
		"-H",       "",             "Hexadecimal visual mode",
		"-h",       "",             "Show this help",
		"-j",       "",             "JSON output",
		"-q",       "",             "Quite output",
		"-V",       "",             "Show version information",
		"-v",       "",             "Be more verbose (stderr output)",
		"-e",       "[k=v]",        "Set an evaluable config variable",
		"-A",       "",             "Compare virtual and physical addresses",
		"-B",       "",             "Run 'aaa' when loading the bin",
		"-C",       "",             "Disable colors",
		"-T",       "",             "Show timestamp information",
		"-S",       "[WxH]",        "Set the width and height of the terminal for visual mode",
		"-0",       "[cmd]",        "Input for file0 when option -t 'commands' is given.",
		"",         "",             "The same value will be set for file1, if -1 is not set.",
		"-1",       "[cmd]",        "Input for file1 when option -t 'commands' is given.",
		"-t",       "[type]",       "Compute the difference between two files based on its type:",
		"",         "",             "   bytes      | compare raw bytes in the files (only for small files)",
		"",         "",             "   lines      | compare text files",
		"",         "",             "   functions  | compare functions found in the files",
		"",         "",             "   classes    | compare classes found in the files",
		"",         "",             "   command    | compare command output returned when executed in both files",
		"",         "",             "              | require -0 <cmd> and -1 <cmd> is optional",
		"",         "",             "   entries    | compare entries found in the files",
		"",         "",             "   fields     | compare fields found in the files",
		"",         "",             "   graphs     | compare 2 functions and outputs in graphviz/dot format",
		"",         "",             "              | require -0 <fcn name|offset> and -1 <fcn name|offset> is optional",
		"",         "",             "   imports    | compare imports found in the files",
		"",         "",             "   libraries  | compare libraries found in the files",
		"",         "",             "   sections   | compare sections found in the files",
		"",         "",             "   strings    | compare strings found in the files",
		"",         "",             "   symbols    | compare symbols found in the files",
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

	printf(
		"palette colors can be changed by adding the following lines\n"
		"inside the $HOME/.rizinrc file\n"
		"ec diff.unknown blue   | offset color\n"
		"ec diff.match   green  | match color\n"
		"ec diff.unmatch red    | mismatch color\n");
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
	const char *screen = NULL;
	memset((void *)ctx, 0, sizeof(DiffContext));
	ctx->colors = true;
	ctx->evars = rz_list_newf(free);

	if (!ctx->evars) {
		rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "cannot allocate list for evars");
		return;
	}

	RzGetopt opt;
	int c;
	rz_getopt_init(&opt, argc, argv, "hHjqvViABCTa:b:e:d:t:0:1:S:");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case '0': rz_diff_ctx_set_def(ctx, input_a, NULL, opt.arg); break;
		case '1': rz_diff_ctx_set_def(ctx, input_b, NULL, opt.arg); break;
		case 'A': rz_diff_ctx_set_def(ctx, compare_addresses, false, true); break;
		case 'B': rz_diff_ctx_set_def(ctx, analyze_all, false, true); break;
		case 'C': rz_diff_ctx_set_def(ctx, colors, true, false); break;
		case 'T': rz_diff_ctx_set_def(ctx, show_time, false, true); break;
		case 'a': rz_diff_ctx_set_def(ctx, architecture, NULL, opt.arg); break;
		case 'b': rz_diff_ctx_set_unsigned(ctx, arch_bits, opt.arg); break;
		case 'd': rz_diff_set_def(algorithm, NULL, opt.arg); break;
		case 'h': rz_diff_ctx_set_opt(ctx, DIFF_OPT_HELP); break;
		case 'i': rz_diff_ctx_set_def(ctx, command_line, false, true); break;
		case 'j': rz_diff_ctx_set_mode(ctx, DIFF_MODE_JSON); break;
		case 'q': rz_diff_ctx_set_mode(ctx, DIFF_MODE_QUIET); break;
		case 't': rz_diff_set_def(type, NULL, opt.arg); break;
		case 'V': rz_diff_ctx_set_opt(ctx, DIFF_OPT_VERSION); break;
		case 'v': rz_diff_ctx_set_def(ctx, verbose, false, true); break;
		case 'S': rz_diff_set_def(screen, NULL, opt.arg); break;
		case 'H': rz_diff_ctx_set_opt(ctx, DIFF_OPT_HEX_VISUAL); break;
		case 'e': rz_diff_ctx_add_evar(ctx, opt.arg); break;
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
		} else if (!strcmp(algorithm, "ssdeep")) {
			rz_diff_ctx_set_dist(ctx, DIFF_DISTANCE_SSDEEP);
		} else {
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -d argument '%s' is not a recognized algorithm.\n", algorithm);
		}
	} else if (type) {
		rz_diff_ctx_set_opt(ctx, DIFF_OPT_UNIFIED);

		if (ctx->command_line) {
			rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -i is not supported with -t flag.\n");
		}

		if (!strcmp(type, "bytes")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_BYTES);
		} else if (!strcmp(type, "lines")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_LINES);
		} else if (!strcmp(type, "functions")) {
			if (ctx->input_a) {
				rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t '%s' does not support -0.\n", type);
			} else if (ctx->input_b) {
				rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t '%s' does not support -1.\n", type);
			}
			ctx->option = DIFF_OPT_GRAPH;
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_FUNCTIONS);
		} else if (!strcmp(type, "classes")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_CLASSES);
		} else if (!strcmp(type, "command")) {
			if (!ctx->input_a) {
				rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t '%s' requires -0 <command>.\n", type);
			}
			if (!ctx->input_b) {
				ctx->input_b = ctx->input_a;
			}
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_COMMAND);
		} else if (!strcmp(type, "entries")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_ENTRIES);
		} else if (!strcmp(type, "fields")) {
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_FIELDS);
		} else if (!strcmp(type, "graphs")) {
			if (!ctx->input_a) {
				rz_diff_error_opt(ctx, DIFF_OPT_ERROR, "option -t '%s' requires -0 <fcn name|address>.\n", type);
			} else if (ctx->input_a && !ctx->input_b) {
				ctx->input_b = ctx->input_a;
			}
			ctx->option = DIFF_OPT_GRAPH;
			rz_diff_ctx_set_type(ctx, DIFF_TYPE_PLOTDIFF);
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
	} else if (screen) {
		const char *hp = NULL;
		if (!(hp = strchr(screen, 'x'))) {
			rz_diff_error_opt(ctx, DIFF_OPT_USAGE, "invalid format for -S; example 120x20 where width=120 and height=20.\n");
		}
		ut64 height = strtoull(screen, NULL, 0);
		ut64 width = strtoull(hp + 1, NULL, 0);
		if (width < 1 || width > 0xFFFF || height < 1 || height > 0xFFFF) {
			rz_diff_error_opt(ctx, DIFF_OPT_USAGE, "invalid format for -S; example 120x20 where width=120 and height=20.\n");
		} else if (width < 20 || height < 120) {
			rz_diff_error_opt(ctx, DIFF_OPT_USAGE, "Min width=120, Min height=20.\n");
		}
		ctx->screen.width = (int)width;
		ctx->screen.height = (int)height;
	} else if (ctx->option == DIFF_OPT_UNKNOWN) {
		rz_diff_error_opt(ctx, DIFF_OPT_USAGE, "option -t or -d is required to be specified.\n");
	}
}

static void rz_diff_get_colors(DiffColors *dcolors, RzConsContext *ctx, bool colors) {
	dcolors->number = colors ? ctx->pal.diff_unknown : "";
	dcolors->match = colors ? ctx->pal.diff_match : "";
	dcolors->unmatch = colors ? ctx->pal.diff_unmatch : Color_INVERT;
	dcolors->legenda = colors ? ctx->pal.comment : "";
	dcolors->reset = Color_RESET;
}

static DiffIO *rz_diff_io_open(const char *file) {
	RzIODesc *desc = NULL;
	RzIO *io = NULL;
	DiffIO *dio = NULL;

	dio = RZ_NEW0(DiffIO);
	if (!dio) {
		rz_diff_error("cannot allocate diff io\n");
		goto rz_diff_io_open_end;
	}

	io = rz_io_new();
	if (!io) {
		rz_diff_error("cannot allocate io\n");
		goto rz_diff_io_open_end;
	}

	desc = rz_io_open_nomap(io, file, RZ_PERM_R, 0);
	if (!desc) {
		rz_diff_error("cannot open file '%s'\n", file);
		goto rz_diff_io_open_end;
	}

	dio->filename = file;
	dio->filesize = rz_io_desc_size(desc);
	dio->io = io;
	return dio;

rz_diff_io_open_end:
	rz_io_desc_close(desc);
	rz_io_free(io);
	free(dio);
	return NULL;
}

static void rz_diff_io_close(DiffIO *dio) {
	if (!dio) {
		return;
	}
	rz_io_desc_close(dio->io->desc);
	rz_io_free(dio->io);
	free(dio);
}

/* This is terrible because can eat a lot of memory */
static ut8 *rz_diff_slurp_file(const char *file, size_t *size) {
	ut8 *buffer = NULL;
	ssize_t read = 0;
	DiffIO *dio = NULL;

	dio = rz_diff_io_open(file);
	if (!dio) {
		goto rz_diff_slurp_file_end;
	}

	if (dio->filesize > MEGABYTE(5)) {
		rz_diff_error("cannot open file '%s' because its size is above 5Mb\n", file);
		goto rz_diff_slurp_file_end;
	}

	buffer = malloc(dio->filesize + 1);
	if (!buffer) {
		rz_diff_error("cannot allocate buffer\n");
		goto rz_diff_slurp_file_end;
	}
	buffer[dio->filesize] = 0;

	read = rz_io_pread_at(dio->io, 0, buffer, dio->filesize);
	if (read != dio->filesize) {
		free(buffer);
		buffer = NULL;
		rz_diff_error("cannot read buffer correctly\n");
		goto rz_diff_slurp_file_end;
	}

	*size = dio->filesize;

rz_diff_slurp_file_end:
	rz_diff_io_close(dio);
	return buffer;
}

static bool rz_diff_calculate_distance(DiffContext *ctx) {
	size_t a_size = 0;
	size_t b_size = 0;
	ut8 *a_buffer = NULL;
	ut8 *b_buffer = NULL;
	ut32 distance = 0;
	double similarity = 0.0;

	if (ctx->command_line) {
		if (!(a_buffer = (ut8 *)strdup(ctx->file_a))) {
			goto rz_diff_calculate_distance_bad;
		}
		a_size = strlen((const char *)a_buffer);
		if (!(b_buffer = (ut8 *)strdup(ctx->file_b))) {
			goto rz_diff_calculate_distance_bad;
		}
		b_size = strlen((const char *)b_buffer);
	} else {
		if (!(a_buffer = rz_diff_slurp_file(ctx->file_a, &a_size))) {
			goto rz_diff_calculate_distance_bad;
		}
		if (!(b_buffer = rz_diff_slurp_file(ctx->file_b, &b_size))) {
			goto rz_diff_calculate_distance_bad;
		}
	}

	switch (ctx->distance) {
	case DIFF_DISTANCE_MYERS:
		if (!rz_diff_myers_distance(a_buffer, a_size, b_buffer, b_size, &distance, &similarity)) {
			rz_diff_error("failed to calculate distance with myers algorithm\n");
			goto rz_diff_calculate_distance_bad;
		}
		break;
	case DIFF_DISTANCE_LEVENSHTEIN:
		if (!rz_diff_levenshtein_distance(a_buffer, a_size, b_buffer, b_size, &distance, &similarity)) {
			rz_diff_error("failed to calculate distance with levenshtein algorithm\n");
			goto rz_diff_calculate_distance_bad;
		}
		break;
	case DIFF_DISTANCE_SSDEEP:
		if ((similarity = rz_hash_ssdeep_compare((const char *)a_buffer, (const char *)b_buffer)) < 0) {
			rz_diff_error("failed to calculate distance with ssdeep compare algorithm\n");
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
		if (ctx->distance != DIFF_DISTANCE_SSDEEP) {
			pj_kn(pj, "distance", distance);
		}
		pj_end(pj);
		printf("%s\n", pj_string(pj));
		pj_free(pj);
	} else if (ctx->mode == DIFF_MODE_QUIET) {
		printf("%.3f\n", similarity);
		if (ctx->distance != DIFF_DISTANCE_SSDEEP) {
			printf("%d\n", distance);
		}
	} else {
		// DIFF_MODE_STANDARD
		printf("similarity: %.3f\n", similarity);
		if (ctx->distance != DIFF_DISTANCE_SSDEEP) {
			printf("distance: %d\n", distance);
		}
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

static RzCoreFile *rz_diff_load_file_with_core(const char *filename, const char *architecture, ut32 arch_bits, RzList /*<char *>*/ *evars, bool colors, bool verbose) {
	RzCore *core = NULL;
	RzCoreFile *cfile = NULL;
	RzBinFile *bfile = NULL;
	RzListIter *it;
	char *config;

	if (verbose) {
		fprintf(stderr, "rz-diff: loading file '%s'\n", filename);
	}

	core = rz_core_new();
	if (!core) {
		rz_diff_error("cannot allocate core\n");
		goto rz_diff_load_file_with_core_fail;
	}
	rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL);

	rz_config_set_i(core->config, "scr.color", colors ? 1 : 0);
	rz_config_set_b(core->config, "scr.interactive", false);
	rz_config_set_b(core->config, "cfg.debug", false);
	rz_config_set_b(core->config, "scr.prompt", false);
	core->print->scr_prompt = false;
	cfile = rz_core_file_open(core, filename, 0, 0);
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

	if (rz_pvector_empty(bfile->o->maps)) {
		rz_config_set_i(core->config, "io.va", false);
	}

	if (architecture) {
		rz_config_set(core->config, "asm.arch", architecture);
	}

	if (arch_bits) {
		rz_config_set_i(core->config, "asm.bits", arch_bits);
	}

	rz_list_foreach (evars, it, config) {
		rz_config_eval(core->config, config);
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
	DiffIO *dio = NULL;

	dio = rz_diff_io_open(filename);
	if (!dio) {
		goto rz_diff_file_open_bad;
	}

	bin = rz_bin_new();
	if (!bin) {
		rz_diff_error("cannot allocate bin\n");
		goto rz_diff_file_open_bad;
	}

	rz_io_bind(dio->io, &bin->iob);

	// TODO: no RzConfig ???
	rz_bin_options_init(&opt, dio->io->desc->fd, 0, 0, false);
	opt.obj_opts.elf_load_sections = true;
	opt.obj_opts.elf_checks_sections = true;
	opt.obj_opts.elf_checks_segments = true;
	opt.sz = rz_io_desc_size(dio->io->desc);

	file = rz_bin_open_io(bin, &opt);
	if (!file) {
		rz_diff_error("cannot open bin file via io\n");
		goto rz_diff_file_open_bad;
	}

	dfile->plugin = rz_bin_file_cur_plugin(file);
	dfile->file = file;
	dfile->bin = bin;
	dfile->dio = dio;
	return true;

rz_diff_file_open_bad:
	rz_bin_free(bin);
	rz_diff_io_close(dio);
	return false;
}

static void rz_diff_file_close(DiffFile *file) {
	// plugin and file are freed by rz_bin_free
	rz_bin_free(file->bin);
	rz_diff_io_close(file->dio);
}

#define rz_diff_file_get(df, n) ((df)->file->o->n)

/**************************************** rzpvector ***************************************/

static const void *rz_diff_pvector_elem_at(const RzPVector /*<void *>*/ *array, ut32 index) {
	return rz_pvector_at(array, index);
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

static int import_compare_vec(const RzBinImport *a, const RzBinImport *b, void *user) {
	return import_compare(a, b);
}

static RzDiff *rz_diff_imports_new(DiffFile *dfile_a, DiffFile *dfile_b) {
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, imports);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get imports from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, imports);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get imports from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)import_compare_vec, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)import_compare_vec, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)import_hash,
		.compare = (RzDiffMethodCompare)import_compare,
		.stringify = (RzDiffMethodStringify)import_stringify,
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
}

/**************************************** symbols ***************************************/

static ut32 symbol_hash_addr(const RzBinSymbol *elem) {
	ut32 hash = rz_diff_hash_data((const ut8 *)elem->name, elem->name ? strlen(elem->name) : 0);
	hash ^= rz_diff_hash_data((const ut8 *)elem->dname, elem->dname ? strlen(elem->dname) : 0);
	hash ^= rz_diff_hash_data((const ut8 *)elem->libname, elem->libname ? strlen(elem->libname) : 0);
	hash ^= rz_diff_hash_data((const ut8 *)elem->classname, elem->classname ? strlen(elem->classname) : 0);
	hash ^= (ut32)(elem->vaddr >> 32);
	hash ^= (ut32)elem->vaddr;
	hash ^= (ut32)(elem->paddr >> 32);
	hash ^= (ut32)elem->paddr;
	return hash;
}

static int symbol_compare_addr(const RzBinSymbol *a, const RzBinSymbol *b) {
	st64 ret;
	IF_STRCMP_S(ret, a->classname, b->classname);
	IF_STRCMP_S(ret, a->libname, b->libname);
	IF_STRCMP_S(ret, a->dname, b->dname);
	IF_STRCMP_S(ret, a->name, b->name);
	ret = ((st64)b->paddr) - ((st64)a->paddr);
	if (ret) {
		return ret;
	}
	return ((st64)b->vaddr) - ((st64)a->vaddr);
}

static void symbol_stringify_addr(const RzBinSymbol *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "virt: 0x%016" PFMT64x " phys: 0x%016" PFMT64x " %s %s %s\n", elem->vaddr, elem->paddr, elem->libname, elem->classname, elem->name);
}

static ut32 symbol_hash(const RzBinSymbol *elem) {
	return rz_diff_hash_data((const ut8 *)elem->name, strlen(elem->name));
}

static int symbol_compare(const RzBinSymbol *a, const RzBinSymbol *b) {
	int ret;
	IF_STRCMP_S(ret, a->name, b->name);
	return 0;
}

static int symbol_compare_vec(const RzBinSymbol *a, const RzBinSymbol *b, void *user) {
	return symbol_compare(a, b);
}

static void symbol_stringify(const RzBinSymbol *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s %s %s\n", elem->libname, elem->classname, elem->name);
}

static RzDiff *rz_diff_symbols_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, symbols);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get symbols from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, symbols);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get symbols from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)symbol_compare_vec, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)symbol_compare_vec, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? symbol_hash_addr : symbol_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? symbol_compare_addr : symbol_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? symbol_stringify_addr : symbol_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
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

static int string_compare_vec(const RzBinString *a, const RzBinString *b, void *user) {
	return string_compare(a, b);
}

static RzDiff *rz_diff_strings_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = (RzPVector *)rz_bin_object_get_strings(dfile_a->file->o);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get strings from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = (RzPVector *)rz_bin_object_get_strings(dfile_b->file->o);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get strings from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)string_compare_vec, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)string_compare_vec, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? string_hash_addr : string_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? string_compare_addr : string_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? string_stringify_addr : string_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
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

static int class_compare_vec(const RzBinClass *a, const RzBinClass *b, void *user) {
	return class_compare(a, b);
}

static void class_stringify(const RzBinClass *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s %s\n", SAFE_STR(elem->super), elem->name);
}

static RzDiff *rz_diff_classes_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, classes);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get classes from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, classes);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get classes from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)class_compare_vec, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)class_compare_vec, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? class_hash_addr : class_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? class_compare_addr : class_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? class_stringify_addr : class_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
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

static int entry_compare(const RzBinAddr *a, const RzBinAddr *b, void *user) {
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
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, entries);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get entries from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, entries);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get entries from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)entry_compare, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)entry_compare, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)entry_hash,
		.compare = (RzDiffMethodCompare)entry_compare,
		.stringify = (RzDiffMethodStringify)entry_stringify,
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
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

static int libs_compare_vec(const char *a, const char *b, void *user) {
	return libs_compare(a, b);
}

static void libs_stringify(const char *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s\n", SAFE_STR(elem));
}

static RzDiff *rz_diff_libraries_new(DiffFile *dfile_a, DiffFile *dfile_b) {
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, libs);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get libraries from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, libs);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get libraries from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)libs_compare_vec, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)libs_compare_vec, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)libs_hash,
		.compare = (RzDiffMethodCompare)libs_compare,
		.stringify = (RzDiffMethodStringify)libs_stringify,
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
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
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, sections);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get sections from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, sections);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get sections from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)section_compare, NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)section_compare, NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? section_hash_addr : section_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? section_compare_addr : section_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? section_stringify_addr : section_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
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

static int field_compare_addr_vec(const RzBinField *a, const RzBinField *b, void *user) {
	return field_compare_addr(a, b);
}

static int field_compare_vec(const RzBinField *a, const RzBinField *b, void *user) {
	return field_compare(a, b);
}

static void field_stringify(const RzBinField *elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s %s\n", SAFE_STR(elem->type), elem->name);
}

static RzDiff *rz_diff_fields_new(DiffFile *dfile_a, DiffFile *dfile_b, bool compare_addr) {
	RzPVector *vec_a = NULL;
	RzPVector *vec_b = NULL;

	vec_a = rz_diff_file_get(dfile_a, fields);
	if (!vec_a) {
		rz_diff_error_ret(NULL, "cannot get fields from '%s'\n", dfile_a->dio->filename);
	}

	vec_b = rz_diff_file_get(dfile_b, fields);
	if (!vec_b) {
		rz_diff_error_ret(NULL, "cannot get fields from '%s'\n", dfile_b->dio->filename);
	}

	rz_pvector_sort(vec_a, (RzPVectorComparator)(compare_addr ? field_compare_addr_vec : field_compare_vec), NULL);
	rz_pvector_sort(vec_b, (RzPVectorComparator)(compare_addr ? field_compare_addr_vec : field_compare_vec), NULL);

	RzDiffMethods methods = {
		.elem_at = (RzDiffMethodElemAt)rz_diff_pvector_elem_at,
		.elem_hash = (RzDiffMethodElemHash)(compare_addr ? field_hash_addr : field_hash),
		.compare = (RzDiffMethodCompare)(compare_addr ? field_compare_addr : field_compare),
		.stringify = (RzDiffMethodStringify)(compare_addr ? field_stringify_addr : field_stringify),
		.ignore = NULL,
	};

	return rz_diff_generic_new(vec_a, rz_pvector_len(vec_a), vec_b, rz_pvector_len(vec_b), &methods);
}

/**************************************** commands ***************************************/

static char *execute_command(const char *command, const char *filename, DiffContext *ctx) {
	RzCoreFile *cfile = rz_diff_load_file_with_core(filename, ctx->architecture, ctx->arch_bits, ctx->evars, ctx->colors, ctx->verbose);
	if (!cfile) {
		return NULL;
	}

	if (ctx->analyze_all) {
		if (ctx->verbose) {
			fprintf(stderr, "rz-diff: analysing file '%s'\n", filename);
		}
		if (!rz_core_analysis_everything(cfile->core, false, NULL)) {
			rz_diff_error("cannot analyze binary '%s'\n", filename);
		}
	}

	char *output = rz_core_cmd_str(cfile->core, command);
	rz_core_free(cfile->core);
	return output;
}

static RzDiff *rz_diff_command_new(DiffContext *ctx) {
	char *output_a = NULL;
	char *output_b = NULL;

	output_a = execute_command(ctx->input_a, ctx->file_a, ctx);
	if (!output_a) {
		rz_diff_error_ret(NULL, "cannot execute command '%s' on file '%s'\n", ctx->input_a, ctx->file_a);
	}

	output_b = execute_command(ctx->input_b, ctx->file_b, ctx);
	if (!output_b) {
		free(output_a);
		rz_diff_error_ret(NULL, "cannot execute command '%s' on file '%s'\n", ctx->input_b, ctx->file_b);
	}

	RzDiff *diff = rz_diff_lines_new(output_a, output_b, NULL);
	free(output_a);
	free(output_b);
	return diff;
}

/**************************************** unified ***************************************/

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
	rz_diff_free(diff);
	rz_diff_file_close(&dfile_a);
	rz_diff_file_close(&dfile_b);
	free(a_buffer);
	free(b_buffer);
	return result;
}

/**************************************** graphs ***************************************/

static const char *get_config_or_default(RzCore *core, const char *key, const char *def_value) {
	const char *value = rz_config_get(core->config, key);
	if (RZ_STR_ISEMPTY(value)) {
		return def_value;
	}
	return value;
}

static void graphviz_dot_header(RzCore *core_a) {
	const char *font = get_config_or_default(core_a, "graph.font", "Courier");
	const char *gv_edge = get_config_or_default(core_a, "graph.gv.edge", "arrowhead=\"normal\"");
	const char *gv_node = get_config_or_default(core_a, "graph.gv.node", "fillcolor=gray style=filled shape=box");
	const char *gv_spline = get_config_or_default(core_a, "graph.gv.spline", "splines=\"ortho\"");
	rz_cons_printf("digraph code {\n"
		       "\tgraph [bgcolor=azure fontsize=8 fontname=\"%s\" %s];\n"
		       "\tnode [%s];\n"
		       "\tedge [%s];\n",
		font, gv_spline, gv_node, gv_edge);
}

static void print_color_node(RzCore *core, RzAnalysisBlock *bbi) {
	bool color_current = rz_config_get_b(core->config, "graph.gv.current");
	bool current = rz_analysis_block_contains(bbi, core->offset);
	if (current && color_current) {
		rz_cons_printf("\t\"0x%08" PFMT64x "\" ", bbi->addr);
		rz_cons_printf("\t[fillcolor=gray style=filled shape=box];\n");
	}
}

static char *basic_block_opcodes(RzCore *core, RzAnalysisBlock *bbi) {
	char *opcodes = NULL;
	RzConfigHold *hc = NULL;
	ut8 *block = NULL;

	if (!(hc = rz_config_hold_new(core->config))) {
		return NULL;
	}
	rz_config_hold_i(hc, "scr.color", "scr.utf8", "asm.offset", "asm.lines", "asm.cmt.right", "asm.lines.fcn", "asm.bytes", "asm.comments", NULL);
	rz_config_set_i(core->config, "scr.utf8", 0);
	rz_config_set_i(core->config, "asm.offset", 0);
	rz_config_set_i(core->config, "asm.lines", 0);
	rz_config_set_i(core->config, "asm.cmt.right", 0);
	rz_config_set_i(core->config, "asm.lines.fcn", 0);
	rz_config_set_i(core->config, "asm.bytes", 0);
	rz_config_set_i(core->config, "asm.comments", 0);
	rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);

	rz_cons_push();
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, bbi->addr);
	if (!b) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", bbi->addr);
		goto exit;
	}

	block = malloc(b->size + 1);
	if (!block) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		goto exit;
	}

	rz_io_read_at(core->io, b->addr, block, b->size);
	RzCoreDisasmOptions disasm_options = {
		.cbytes = 2,
	};
	rz_core_print_disasm(core, b->addr, block, b->size, 9999, NULL, &disasm_options);
	rz_cons_filter();
	const char *retstr = rz_str_get(rz_cons_get_buffer());
	opcodes = strdup(retstr);
exit:
	rz_cons_pop();
	rz_cons_echo(NULL);
	free(block);
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return opcodes;
}

static const char *pair_color(RzAnalysisMatchPair *pair) {
	if (pair->similarity >= 1.0) {
		return "lightgray";
	} else if (pair->similarity >= RZ_ANALYSIS_SIMILARITY_THRESHOLD) {
		return "yellow";
	}
	return "red";
}

static void graphviz_dot_nodes(RzCore *core_a, RzAnalysisFunction *fcn_a, RzCore *core_b, RzAnalysisFunction *fcn_b, RzAnalysisMatchResult *result) {
	char addr_a[32], addr_b[32];

	RzAnalysisMatchPair *pair = NULL;
	RzAnalysisBlock *bbi = NULL;
	RzListIter *iter = NULL;
	const char *font = get_config_or_default(core_a, "graph.font", "Courier");

	rz_strf(addr_a, "0x%08" PFMT64x, fcn_a->addr);
	rz_strf(addr_b, "0x%08" PFMT64x, fcn_b->addr);

	const char *norig = fcn_a->name ? fcn_a->name : addr_a;
	const char *nmodi = fcn_b->name ? fcn_b->name : addr_b;

	// we add all the matching basic block first
	rz_list_foreach (result->matches, iter, pair) {
		bbi = (RzAnalysisBlock *)pair->pair_a;

		const char *fillcolor = pair_color(pair);
		char *original = basic_block_opcodes(core_a, bbi);
		if (!original) {
			break;
		}

		if (pair->similarity >= RZ_ANALYSIS_SIMILARITY_THRESHOLD) {
			// if they are similar then we diff the opcodes.

			char *modified = basic_block_opcodes(core_b, (RzAnalysisBlock *)pair->pair_b);
			if (modified && strcmp(original, modified) != 0) {
				RzDiff *dff = rz_diff_lines_new(original, modified, NULL);
				char *diffstr = rz_diff_unified_text(dff, norig, nmodi, false, false);
				rz_diff_free(dff);
				free(modified);

				rz_str_replace_char(diffstr, '"', '\'');
				diffstr = rz_str_replace(diffstr, "\n", "\\l", 1);
				rz_cons_printf("\t\"0x%08" PFMT64x "\" [fillcolor=\"%s\","
					       "color=\"black\", fontname=\"%s\","
					       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
					bbi->addr, fillcolor, font, diffstr, fcn_a->name,
					bbi->addr);
				free(diffstr);
				free(original);
				continue;
			}

			// sometimes the mismatch is on a call value
			// but the output is actually the same due sym./imp.
			// thus we ignore the similarity check and consider this
			// as a perfect match.
			free(modified);
		}

		rz_str_replace_char(original, '"', '\'');
		original = rz_str_replace(original, "\n", "\\l", 1);
		rz_cons_printf("\t\"0x%08" PFMT64x "\" [fillcolor=\"%s\","
			       "color=\"black\", fontname=\"%s\","
			       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
			bbi->addr, fillcolor, font, original, fcn_a->name, bbi->addr);
		free(original);
	}

	// we then add all the unmatched basic blocks
	rz_list_foreach (result->unmatch_a, iter, bbi) {
		char *opcodes = basic_block_opcodes(core_a, bbi);
		if (!opcodes) {
			break;
		}

		rz_str_replace_char(opcodes, '"', '\'');
		opcodes = rz_str_replace(opcodes, "\n", "\\l", 1);
		rz_cons_printf("\t\"0x%08" PFMT64x "\" [fillcolor=\"white\","
			       "color=\"black\", fontname=\"%s\","
			       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
			bbi->addr, font, opcodes, fcn_a->name, bbi->addr);
		free(opcodes);
	}
}

#define PAL_JUMP "#0037da"
#define PAL_FAIL "#c50f1f"
#define PAL_TRUE "#13a10e"
static void graphviz_dot_edges(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bbi;
	void **iter;

	rz_pvector_foreach (fcn->bbs, iter) {
		bbi = (RzAnalysisBlock *)*iter;
		if (bbi->jump != UT64_MAX) {
			rz_cons_printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color=\"%s\"];\n",
				bbi->addr, bbi->jump,
				bbi->fail != UT64_MAX ? PAL_TRUE : PAL_JUMP);
			print_color_node(core, bbi);
		}
		if (bbi->fail != UT64_MAX) {
			rz_cons_printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color=\"" PAL_FAIL "\"];\n",
				bbi->addr, bbi->fail);
			print_color_node(core, bbi);
		}
		if (bbi->switch_op) {
			RzAnalysisCaseOp *caseop;
			RzListIter *iter2;

			if (bbi->fail != UT64_MAX) {
				rz_cons_printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color=\"" PAL_FAIL "\"];\n",
					bbi->addr, bbi->fail);
				print_color_node(core, bbi);
			}
			rz_list_foreach (bbi->switch_op->cases, iter2, caseop) {
				rz_cons_printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color2=\"" PAL_FAIL "\"];\n",
					caseop->addr, caseop->jump);
				print_color_node(core, bbi);
			}
		}
	}
}
#undef PAL_JUMP
#undef PAL_FAIL
#undef PAL_TRUE

static void graphviz_dot_graph(RzCore *core_a, RzAnalysisFunction *fcn_a, RzCore *core_b, RzAnalysisFunction *fcn_b, RzAnalysisMatchResult *result) {
	graphviz_dot_header(core_a);
	if (fcn_a->bbs) {
		graphviz_dot_nodes(core_a, fcn_a, core_b, fcn_b, result);
		graphviz_dot_edges(core_a, fcn_a);
	} else {
		rz_cons_printf("\t\"0x%08" PFMT64x "\";\n", fcn_a->addr);
	}
	rz_cons_printf("}\n");
}

static void graph_basic_block_json(const char *name, RzAnalysisBlock *bbi, PJ *pj) {
	pj_ko(pj, name); // "<name>": { -- object begin
	pj_kn(pj, "address", bbi->addr);
	if (bbi->jump != UT64_MAX) {
		pj_kn(pj, "jump", bbi->jump);
	}
	if (bbi->fail != UT64_MAX) {
		pj_kn(pj, "fail", bbi->fail);
	}
	if (!bbi->switch_op) {
		pj_end(pj); // } -- object end
		return;
	}

	RzAnalysisCaseOp *caseop;
	RzListIter *iter;
	pj_ka(pj, "switch"); // [ -- "switch" begin
	rz_list_foreach (bbi->switch_op->cases, iter, caseop) {
		pj_o(pj); // { -- caseop object begin
		pj_kn(pj, "address", caseop->addr);
		pj_kn(pj, "jump", caseop->jump);
		pj_end(pj); // } -- caseop object end
	}
	pj_end(pj); // ] -- "switch" end
	pj_end(pj); // } -- object end
}

static void diff_graph_result_as_json(RzCore *core_a, RzAnalysisFunction *fcn_a, RzCore *core_b, RzAnalysisFunction *fcn_b, RzAnalysisMatchResult *result, PJ *pj) {
	RzAnalysisMatchPair *pair = NULL;
	RzAnalysisBlock *bbi_a = NULL, *bbi_b = NULL;
	RzListIter *iter = NULL;
	char *opcodes_a = NULL, *opcodes_b = NULL;
	char addr_a[32], addr_b[32];

	rz_strf(addr_a, "0x%08" PFMT64x, fcn_a->addr);
	rz_strf(addr_b, "0x%08" PFMT64x, fcn_b->addr);

	const char *norig = fcn_a->name ? fcn_a->name : addr_a;
	const char *nmodi = fcn_b->name ? fcn_b->name : addr_b;

	pj_ka(pj, "result"); // "result": { -- array object begin

	// we add all the matching basic block first
	rz_list_foreach (result->matches, iter, pair) {
		bbi_a = (RzAnalysisBlock *)pair->pair_a;
		bbi_b = (RzAnalysisBlock *)pair->pair_b;

		opcodes_a = basic_block_opcodes(core_a, bbi_a);
		if (!opcodes_a) {
			break;
		}

		pj_o(pj); // { -- array object begin

		pj_ko(pj, "pair"); // "pair": {
		graph_basic_block_json("source", bbi_a, pj);
		graph_basic_block_json("match", bbi_b, pj);
		pj_end(pj); // } -- "pair" end

		pj_ko(pj, "similarity"); // "similarity": {
		pj_ks(pj, "type", RZ_ANALYSIS_SIMILARITY_TYPE_STR(pair->similarity));
		pj_kd(pj, "score", pair->similarity);
		pj_end(pj); // } -- "similarity" end

		if (pair->similarity >= RZ_ANALYSIS_SIMILARITY_THRESHOLD) {
			// if they are similar then we diff the opcodes.

			opcodes_b = basic_block_opcodes(core_b, bbi_b);
			if (opcodes_b && strcmp(opcodes_a, opcodes_b) != 0) {
				RzDiff *dff = rz_diff_lines_new(opcodes_a, opcodes_b, NULL);
				char *diffstr = rz_diff_unified_text(dff, norig, nmodi, false, false);
				rz_diff_free(dff);
				if (diffstr) {
					free(opcodes_a);
					opcodes_a = diffstr;
				}
			}

			// sometimes the mismatch is on a call value
			// but the output is actually the same due sym./imp.
			// thus we ignore the similarity check and consider this
			// as a perfect match.
			free(opcodes_b);
		}

		pj_ks(pj, "opcodes", opcodes_a);
		pj_end(pj); // } -- array object end
		free(opcodes_a);
	}

	// we then add all the unmatched basic blocks
	// first from the source function
	rz_list_foreach (result->unmatch_a, iter, bbi_a) {
		opcodes_a = basic_block_opcodes(core_a, bbi_a);
		if (!opcodes_a) {
			break;
		}

		pj_o(pj); // { -- array object begin

		pj_ko(pj, "pair"); // "pair": {
		graph_basic_block_json("source", bbi_a, pj);
		pj_knull(pj, "match");
		pj_end(pj); // } -- "pair" end

		pj_ko(pj, "similarity"); // "similarity": {
		pj_ks(pj, "type", RZ_ANALYSIS_SIMILARITY_UNLIKE_STR);
		pj_kd(pj, "score", 0.0);
		pj_end(pj); // } -- "similarity" end

		pj_ks(pj, "opcodes", opcodes_a);
		pj_end(pj); // } -- array object end
		free(opcodes_a);
	}

	// then from the match function
	rz_list_foreach (result->unmatch_b, iter, bbi_b) {
		opcodes_b = basic_block_opcodes(core_b, bbi_b);
		if (!opcodes_b) {
			break;
		}

		pj_o(pj); // { -- array object begin

		pj_ko(pj, "pair"); // "pair": {
		pj_knull(pj, "source");
		graph_basic_block_json("match", bbi_b, pj);
		pj_end(pj); // } -- "pair" end

		pj_ko(pj, "similarity"); // "similarity": {
		pj_ks(pj, "type", RZ_ANALYSIS_SIMILARITY_UNLIKE_STR);
		pj_kd(pj, "score", 0.0);
		pj_end(pj); // } -- "similarity" end

		pj_ks(pj, "opcodes", opcodes_b);
		pj_end(pj); // } -- array object end
		free(opcodes_b);
	}

	pj_end(pj); // } -- result object end
}

static void diff_graph_function_detail_as_json(const char *object_name, RzAnalysisFunction *fcn, PJ *pj) {
	pj_ko(pj, object_name); // "<object_name>: {" -- object begin

	char *fcn_name = rz_str_escape_utf8_for_json(fcn->name, -1);
	pj_ks(pj, "name", rz_str_get_null(fcn_name));
	free(fcn_name);
	pj_kn(pj, "offset", fcn->addr);
	pj_ki(pj, "ninstr", fcn->ninstr);
	pj_kn(pj, "nargs", rz_analysis_arg_count(fcn));
	pj_kn(pj, "nlocals", rz_analysis_var_local_count(fcn));
	pj_kn(pj, "size", rz_analysis_function_linear_size(fcn));
	pj_ki(pj, "stack", fcn->maxstack);
	pj_ks(pj, "type", rz_analysis_fcntype_tostring(fcn->type));

	pj_end(pj); // } -- <object_name> object end
}

static void diff_graph_as_json(RzCore *core_a, RzAnalysisFunction *fcn_a, RzCore *core_b, RzAnalysisFunction *fcn_b, RzAnalysisMatchResult *result, PJ *pj) {
	pj_o(pj);
	diff_graph_function_detail_as_json("source", fcn_a, pj);
	diff_graph_function_detail_as_json("match", fcn_a, pj);
	diff_graph_result_as_json(core_a, fcn_a, core_b, fcn_b, result, pj);
	pj_end(pj);
}

static bool diff_progess_status(const size_t n_left, const size_t n_matches, void *user) {
	rz_cons_clear_line(true);
	fprintf(stderr, "rz-diff: to check %" PFMTSZu " | matches %" PFMTSZu "\r", n_left, n_matches);
	return !rz_cons_is_breaked();
}

static bool diff_check_ctrl_c(const size_t n_left, const size_t n_matches, void *user) {
	return !rz_cons_is_breaked();
}

static RzAnalysisFunction *find_best_matching_function(RzAnalysis *analysis_a, RzAnalysis *analysis_b, RzAnalysisFunction *find, bool verbose) {
	RzAnalysisMatchPair *pair = NULL;
	RzAnalysisFunction *match = NULL;
	RzAnalysisMatchResult *result = NULL;
	RzAnalysisMatchOpt opts = { 0 };
	RzPVector *pvec_a = rz_pvector_new(NULL);
	if (!pvec_a || !rz_pvector_push(pvec_a, find)) {
		RZ_LOG_ERROR("rz-diff: cannot allocate and initialize RzPVector for function search\n");
		goto fail;
	}

	opts.callback = verbose ? diff_progess_status : diff_check_ctrl_c;
	opts.analysis_a = analysis_a;
	opts.analysis_b = analysis_b;

	result = rz_analysis_match_functions(pvec_a, analysis_b->fcns, &opts);
	if (result && rz_list_length(result->matches) > 0) {
		pair = (RzAnalysisMatchPair *)rz_list_first(result->matches);
		match = (RzAnalysisFunction *)pair->pair_b;
	}

fail:
	rz_analysis_match_result_free(result);
	rz_pvector_free(pvec_a);
	return match;
}

static int compareBlocks(const RzAnalysisBlock *a, const RzAnalysisBlock *b, void *user) {
	return (a && b && a->addr && b->addr ? (a->addr > b->addr) - (a->addr < b->addr) : 0);
}

static int comparePairBlocks(const RzAnalysisMatchPair *ma, const RzAnalysisMatchPair *mb, void *user) {
	const RzAnalysisBlock *a = ma->pair_a;
	const RzAnalysisBlock *b = mb->pair_a;
	return compareBlocks(a, b, user);
}

/**
 * \brief Generate a json or graphviz dot output of the graph and its data.
 *
 * Each node that doesn't match 100% with the other function will include
 * a unified diff of the assembly of the same basic block.
 * */
static void core_show_function_diff(RzCore *core_a, ut64 addr_a, RzCore *core_b, ut64 addr_b, DiffMode mode, bool verbose) {
	rz_return_if_fail(core_a && core_b);

	PJ *pj = NULL;
	RzAnalysisFunction *fcn_b = NULL, *fcn_a = NULL;
	RzAnalysisMatchResult *result = NULL;
	RzAnalysisMatchOpt opts = { 0 };

	// find function
	fcn_a = rz_analysis_get_function_at(core_a->analysis, addr_a);
	if (!fcn_a) {
		RZ_LOG_ERROR("rz-diff: cannot get function at 0x%" PFMT64x "\n", addr_a);
		return;
	}

	if (addr_b == UT64_MAX) {
		// find matching function on core B
		fcn_b = find_best_matching_function(core_a->analysis, core_b->analysis, fcn_a, verbose);
		if (!fcn_b) {
			RZ_LOG_ERROR("rz-diff: cannot find best matching function for function at 0x%" PFMT64x "\n", addr_a);
			return;
		}
	} else {
		fcn_b = rz_analysis_get_function_at(core_b->analysis, addr_b);
		if (!fcn_b) {
			RZ_LOG_ERROR("rz-diff: cannot get function at 0x%" PFMT64x "\n", addr_b);
			return;
		}
	}

	opts.callback = verbose ? diff_progess_status : diff_check_ctrl_c;
	opts.analysis_a = core_a->analysis;
	opts.analysis_b = core_b->analysis;

	// calculate all the matches between the basic blocks of the 2 functions.
	result = rz_analysis_match_basic_blocks(fcn_a, fcn_b, &opts);
	if (!result) {
		RZ_LOG_ERROR("rz-diff: cannot calculate matching basic blocks for function at 0x%" PFMT64x "\n", addr_a);
		return;
	}

	rz_list_sort(result->matches, (RzListComparator)comparePairBlocks, NULL);
	rz_list_sort(result->unmatch_a, (RzListComparator)compareBlocks, NULL);
	rz_list_sort(result->unmatch_b, (RzListComparator)compareBlocks, NULL);

	switch (mode) {
	case DIFF_MODE_JSON:
		pj = pj_new();
		if (!pj) {
			RZ_LOG_ERROR("rz-diff: cannot allocate json structure for function matching\n");
			rz_analysis_match_result_free(result);
			return;
		}

		diff_graph_as_json(core_a, fcn_a, core_b, fcn_b, result, pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
		break;
	default:
		graphviz_dot_graph(core_a, fcn_a, core_b, fcn_b, result);
		break;
	}
	rz_cons_flush();

	rz_analysis_match_result_free(result);
}

static void diff_function_as_json(const char *obj_name, RzAnalysisFunction *fcn, PJ *pj) {
	if (!fcn) {
		pj_knull(pj, obj_name);
		return;
	}
	pj_ko(pj, obj_name); // "<obj_name>": { -- object end
	pj_ks(pj, "name", fcn->name);
	pj_kn(pj, "addr", fcn->addr);
	pj_kn(pj, "size", rz_analysis_function_realsize(fcn));
	pj_end(pj); // } -- <obj_name> object end
}

static void diff_similarity_as_json(RzAnalysisFunction *fcn_a, RzAnalysisFunction *fcn_b, double similarity, PJ *pj) {
	pj_o(pj); // { -- match object begin
	pj_kd(pj, "similarity", similarity);
	pj_ks(pj, "type", RZ_ANALYSIS_SIMILARITY_TYPE_STR(similarity));
	diff_function_as_json("original", fcn_a, pj);
	diff_function_as_json("modified", fcn_b, pj);
	pj_end(pj); // } -- match object end
}

static void diff_similarity_as_table(RzAnalysisFunction *fcn_a, RzAnalysisFunction *fcn_b, double similarity, bool color, bool no_name, RzTable *table) {
	char tmp[128];
	const char *type_s = NULL;
	const char *type_n = NULL;

	ut64 size_a = fcn_a ? rz_analysis_function_realsize(fcn_a) : 0;
	ut64 size_b = fcn_b ? rz_analysis_function_realsize(fcn_b) : 0;

	if (similarity > 0.0 && fcn_a && fcn_b) {
		type_n = tmp;
		if (similarity >= 1.0) {
			rz_strf(tmp, color ? Color_BGREEN "%.6f" Color_RESET : "%.6f", similarity);
			type_s = color ? Color_BGREEN "COMPLETE" Color_RESET : "COMPLETE";
		} else if (similarity >= RZ_ANALYSIS_SIMILARITY_THRESHOLD) {
			rz_strf(tmp, color ? Color_BYELLOW "%.6f" Color_RESET : "%.6f", similarity);
			type_s = color ? Color_BYELLOW "PARTIAL " Color_RESET : "PARTIAL ";
		} else {
			rz_strf(tmp, color ? Color_BRED "%.4f" Color_RESET : "%.4f", similarity);
			type_s = color ? Color_BRED "UNLIKE  " Color_RESET : "UNLIKE  ";
		}
	} else {
		type_n = color ? Color_BRED "0.000000" Color_RESET : "0.000000";
		type_s = color ? Color_BRED "UNLIKE  " Color_RESET : "UNLIKE  ";
	}

	if (no_name) {
		if (fcn_a && fcn_b) {
			rz_table_add_rowf(table, "nXssXn", size_a, fcn_a->addr, type_s, type_n, fcn_b->addr, fcn_b->addr, size_b);
		} else if (fcn_a) {
			rz_table_add_rowf(table, "nXssXn", size_a, fcn_a->addr, type_s, type_n, UT64_MAX, size_b);
		} else {
			rz_table_add_rowf(table, "nXssXn", size_a, UT64_MAX, type_s, type_n, size_b, fcn_b->addr);
		}
		return;
	}

	// with names
	if (fcn_a && fcn_b) {
		rz_table_add_rowf(table, "snXssXns", fcn_a->name, size_a, fcn_a->addr, type_s, type_n, fcn_b->addr, size_b, fcn_b->name);
	} else if (fcn_a) {
		rz_table_add_rowf(table, "snXssXns", fcn_a->name, size_a, fcn_a->addr, type_s, type_n, UT64_MAX, size_b, "");
	} else {
		rz_table_add_rowf(table, "snXssXns", "", size_a, UT64_MAX, type_s, type_n, fcn_b->addr, size_b, fcn_b->name);
	}
}

static int comparePairFunctions(const RzAnalysisMatchPair *ma, const RzAnalysisMatchPair *mb, void *user) {
	const RzAnalysisFunction *a = ma->pair_a;
	const RzAnalysisFunction *b = mb->pair_a;
	return (a && b && a->addr && b->addr ? (a->addr > b->addr) - (a->addr < b->addr) : 0);
}

/**
 * \brief Performs function matching and shows the result in a table.
 *
 * Takes 2 cores and tries to match all the functions with eachother;
 * Then the scores are shown in a table (when in quiet mode, the table
 * is headerless)
 * */
static void core_diff_show(RzCore *core_a, RzCore *core_b, DiffMode mode, bool verbose) {
	rz_return_if_fail(core_a && core_b);

	char *output = NULL;
	RzPVector *fcns_a = NULL, *fcns_b = NULL;
	PJ *pj = NULL;
	RzTable *table = NULL;
	RzAnalysisMatchResult *result = NULL;
	RzAnalysisMatchPair *pair = NULL;
	RzAnalysisMatchOpt opts = { 0 };
	RzAnalysisFunction *fcn_a = NULL, *fcn_b = NULL;
	RzListIter *iter = NULL;
	bool color = false, no_name = false;

	fcns_a = rz_pvector_clone(rz_analysis_function_list(core_a->analysis));
	if (rz_pvector_empty(fcns_a)) {
		RZ_LOG_ERROR("rz-diff: No functions found in file0.\n");
		goto fail;
	}

	fcns_b = rz_pvector_clone(rz_analysis_function_list(core_b->analysis));
	if (rz_pvector_empty(fcns_b)) {
		RZ_LOG_ERROR("rz-diff: No functions found in file1.\n");
		goto fail;
	}

	opts.callback = verbose ? diff_progess_status : diff_check_ctrl_c;
	opts.analysis_a = core_a->analysis;
	opts.analysis_b = core_b->analysis;

	// calculate all the matches between the functions of the 2 different core files.
	result = rz_analysis_match_functions(fcns_a, fcns_b, &opts);
	if (!result) {
		RZ_LOG_ERROR("rz-diff: cannot perform matching functions search\n");
		goto fail;
	}

	rz_list_sort(result->matches, (RzListComparator)comparePairFunctions, NULL);
	rz_list_sort(result->unmatch_a, core_a->analysis->columnSort, NULL);
	rz_list_sort(result->unmatch_b, core_b->analysis->columnSort, NULL);

	if (mode == DIFF_MODE_JSON) {
		pj = pj_new();
		if (!pj) {
			RZ_LOG_ERROR("rz-diff: cannot allocate json structure for function matching\n");
			goto fail;
		}
		pj_a(pj); // [ -- list of pairs begin
	} else {
		color = rz_config_get_i(core_a->config, "scr.color") > 0 || rz_config_get_i(core_b->config, "scr.color") > 0;
		no_name = rz_config_get_b(core_a->config, "diff.bare") || rz_config_get_b(core_b->config, "diff.bare");

		table = rz_table_new();
		if (!table) {
			RZ_LOG_ERROR("rz-diff: cannot allocate table structure for function matching\n");
			goto fail;
		}

		if (no_name) {
			rz_table_set_columnsf(table, "nXssXn", "size0", "addr0", "type", "similarity", "addr1", "size1");
		} else {
			rz_table_set_columnsf(table, "snXssXns", "name0", "size0", "addr0", "type", "similarity", "addr1", "size1", "name1");
		}
	}

	// first the matching functions.
	rz_list_foreach (result->matches, iter, pair) {
		fcn_a = (RzAnalysisFunction *)pair->pair_a;
		fcn_b = (RzAnalysisFunction *)pair->pair_b;
		if (fcn_a->type != RZ_ANALYSIS_FCN_TYPE_FCN && fcn_a->type != RZ_ANALYSIS_FCN_TYPE_SYM) {
			continue;
		}
		if (mode == DIFF_MODE_JSON) {
			diff_similarity_as_json(fcn_a, fcn_b, pair->similarity, pj);
		} else {
			diff_similarity_as_table(fcn_a, fcn_b, pair->similarity, color, no_name, table);
		}
	}

	// then the unmatched functions from list A.
	rz_list_foreach (result->unmatch_a, iter, fcn_a) {
		if (fcn_a->type != RZ_ANALYSIS_FCN_TYPE_FCN && fcn_a->type != RZ_ANALYSIS_FCN_TYPE_SYM) {
			continue;
		}
		if (mode == DIFF_MODE_JSON) {
			diff_similarity_as_json(fcn_a, NULL, 0.0, pj);
		} else {
			diff_similarity_as_table(fcn_a, NULL, 0.0, color, no_name, table);
		}
	}

	// then the unmatched functions from list B.
	rz_list_foreach (result->unmatch_b, iter, fcn_b) {
		if (fcn_b->type != RZ_ANALYSIS_FCN_TYPE_FCN && fcn_b->type != RZ_ANALYSIS_FCN_TYPE_SYM) {
			continue;
		}
		if (mode == DIFF_MODE_JSON) {
			diff_similarity_as_json(NULL, fcn_b, 0.0, pj);
		} else {
			diff_similarity_as_table(NULL, fcn_b, 0.0, color, no_name, table);
		}
	}

	switch (mode) {
	case DIFF_MODE_JSON:
		pj_end(pj); // ] -- list of pairs end
		output = pj_drain(pj);
		rz_cons_printf("%s\n", output);
		pj = NULL;
		break;
	case DIFF_MODE_STANDARD:
		output = rz_table_tofancystring(table);
		rz_cons_printf("%s", output);
		break;
	default: // DIFF_MODE_QUIET
		rz_table_align(table, 0, RZ_TABLE_ALIGN_RIGHT);
		rz_table_hide_header(table);
		output = rz_table_tosimplestring(table);
		rz_cons_printf("%s", output);
		break;
	}

	rz_cons_flush();

fail:
	free(output);
	rz_table_free(table);
	rz_analysis_match_result_free(result);
	rz_pvector_free(fcns_a);
	rz_pvector_free(fcns_b);
}

static bool convert_offset_from_input(RzCore *core, const char *input, ut64 *offset) {
	if (rz_num_is_valid_input(NULL, input)) {
		*offset = rz_num_get_input_value(NULL, input);
		return true;
	}

	RzFlagItem *fi = rz_flag_get(core->flags, input);
	if (fi) {
		*offset = fi->offset;
		return true;
	}

	return false;
}

static bool rz_diff_graphs_files(DiffContext *ctx) {
	bool success = false;
	RzCoreFile *a = NULL;
	RzCoreFile *b = NULL;

	a = rz_diff_load_file_with_core(ctx->file_a, ctx->architecture, ctx->arch_bits, ctx->evars, ctx->colors, ctx->verbose);
	if (!a) {
		goto rz_diff_graphs_files_bad;
	}

	b = rz_diff_load_file_with_core(ctx->file_b, ctx->architecture, ctx->arch_bits, ctx->evars, ctx->colors, ctx->verbose);
	if (!b) {
		goto rz_diff_graphs_files_bad;
	}

	if (ctx->type == DIFF_TYPE_PLOTDIFF) {
		ut64 address_a = UT64_MAX;
		ut64 address_b = UT64_MAX;

		if (!convert_offset_from_input(a->core, ctx->input_a, &address_a)) {
			rz_diff_error("cannot convert '%s' into an offset\n", ctx->input_a);
			goto rz_diff_graphs_files_bad;
		}

		if (!convert_offset_from_input(b->core, ctx->input_b, &address_b)) {
			rz_diff_error("cannot convert '%s' into an offset\n", ctx->input_b);
			goto rz_diff_graphs_files_bad;
		}

		if (ctx->analyze_all) {
			if (ctx->verbose) {
				fprintf(stderr, "rz-diff: analysing file '%s'\n", ctx->file_a);
			}
			if (!rz_core_analysis_everything(a->core, false, NULL)) {
				rz_diff_error("cannot analyze binary '%s'\n", ctx->file_a);
				goto rz_diff_graphs_files_bad;
			}
			if (ctx->verbose) {
				fprintf(stderr, "rz-diff: analysing file '%s'\n", ctx->file_b);
			}
			if (!rz_core_analysis_everything(b->core, false, NULL)) {
				rz_diff_error("cannot analyze binary '%s'\n", ctx->file_b);
				goto rz_diff_graphs_files_bad;
			}
		} else {
			bool analyze_recursively = rz_config_get_i(a->core->config, "analysis.calls");
			if (!rz_core_analysis_function_add(a->core, NULL, address_a, analyze_recursively)) {
				rz_diff_error("cannot find function at '%s' in '%s' \n", ctx->input_a, ctx->file_a);
				goto rz_diff_graphs_files_bad;
			}
			if (!rz_core_analysis_function_add(b->core, NULL, address_b, analyze_recursively)) {
				rz_diff_error("cannot find function at '%s' in '%s' \n", ctx->input_b, ctx->file_b);
				goto rz_diff_graphs_files_bad;
			}
		}
		if (ctx->verbose) {
			fprintf(stderr, "rz-diff: start diffing.\n");
		}
		core_show_function_diff(a->core, address_a, b->core, address_b, ctx->mode, ctx->verbose);
	} else {
		if (ctx->verbose) {
			fprintf(stderr, "rz-diff: analysing file '%s'\n", ctx->file_a);
		}
		if (!rz_core_analysis_everything(a->core, false, NULL)) {
			rz_diff_error("cannot analyze binary '%s'\n", ctx->file_a);
			goto rz_diff_graphs_files_bad;
		}
		if (ctx->verbose) {
			fprintf(stderr, "rz-diff: analysing file '%s'\n", ctx->file_b);
		}
		if (!rz_core_analysis_everything(b->core, false, NULL)) {
			rz_diff_error("cannot analyze binary '%s'\n", ctx->file_b);
			goto rz_diff_graphs_files_bad;
		}
		if (ctx->verbose) {
			fprintf(stderr, "rz-diff: start diffing.\n");
		}
		core_diff_show(a->core, b->core, ctx->mode, ctx->verbose);
	}

	success = true;

rz_diff_graphs_files_bad:
	rz_core_free(a ? a->core : NULL);
	rz_core_free(b ? b->core : NULL);
	return success;
}

/********************************************************************************/

typedef enum diff_hex_len_t {
	DIFF_HEX_8 = 58,
	DIFF_HEX_16 = 90,
	DIFF_HEX_32 = 154,
} DiffHexLen;

static inline int diff_hexdump_partial(DiffHexView *hview, int hexlen, int lp, int lsize, const ut8 *bytes_a, const ut8 *bytes_b, ut64 address_a, ut64 address_b, ut64 size_a, ut64 size_b, ut64 pos, ssize_t read_a, ssize_t read_b, ssize_t skip_a, ssize_t skip_b) {
	const char *number = hview->colors.number;
	const char *match = hview->colors.match;
	const char *unmatch = hview->colors.unmatch;
	const char *reset = hview->colors.reset;
	ssize_t i;
	char *line = hview->line;

#define P(x)                (IS_PRINTABLE(x) ? x : '.')
#define printline(fmt, ...) snprintf(line + lp, RZ_MAX(lsize - lp, 0), fmt, ##__VA_ARGS__)
	// write to buffer fileA offset + hex bytes
	lp += printline("%s0x%016" PFMT64x "%s | ", number, address_a + pos, reset);
	for (i = 0; i < hexlen && i < read_a; ++i) {
		if (pos + i >= size_a || pos + i < skip_a) {
			// if the byte is outside the range [0 - fileA size) then do not write any hex
			memset(line + lp, ' ', 3);
			lp += 3;
		} else if (i < read_b && pos + i >= skip_b) {
			// if the byte is inside the range [0 - fileA size) check bytes_b for match/mismatch
			const char *color = bytes_a[pos + i] == bytes_b[pos + i] ? match : unmatch;
			lp += printline("%s%02x%s ", color, bytes_a[pos + i], reset);
		} else {
			// if the byte is inside the range [0 - fileA size) but address_b
			// is outside [0 - fileB size) then is a mismatch
			lp += printline("%s%02x%s ", unmatch, bytes_a[pos + i], reset);
		}
	}
	if (i < hexlen) {
		// fill any missing space to have fileA bytes aligned
		memset(line + lp, ' ', (hexlen - i) * 3);
		lp += (hexlen - i) * 3;
	}

	// print now printable chars of the printed hex values
	lp += printline(" | ");
	for (i = 0; i < hexlen && i < read_a; ++i) {
		if (pos + i >= size_a || pos + i < skip_a) {
			// if the byte is outside the range [0 - fileA size) then do not write any hex
			line[lp] = ' ';
			lp++;
		} else if (i < read_b && pos + i >= skip_b) {
			// if the byte is inside the range [0 - fileA size) check bytes_b for match/mismatch
			const char *color = bytes_a[pos + i] == bytes_b[pos + i] ? match : unmatch;
			lp += printline("%s%c%s", color, P(bytes_a[pos + i]), reset);
		} else {
			// if the byte is inside the range [0 - fileA size) but address_b
			// is outside [0 - fileB size) then is a mismatch
			lp += printline("%s%c%s", unmatch, P(bytes_a[pos + i]), reset);
		}
	}
	if (i < hexlen) {
		// fill any missing space to have fileA bytes aligned
		memset(line + lp, ' ', (hexlen - i));
		lp += (hexlen - i);
	}
	return lp;
#undef printline
#undef P
}

static inline void diff_hexdump_line(DiffHexView *hview, DiffHexLen hlen, ut64 pos, ssize_t read_a, ssize_t read_b, ssize_t skip_a, ssize_t skip_b) {
	int width = hview->screen.width;
	int height = hview->screen.height;
	char *line = hview->line;
	const ut8 *buffer_a = hview->buffer_a;
	const ut8 *buffer_b = hview->buffer_b;
	ut64 address_a = hview->address_a;
	ut64 address_b = hview->address_b;
	int lp = 0;
	int lsize = width * height;
	int hexlen = 0;

	switch (hlen) {
	case DIFF_HEX_16:
		hexlen = 16;
		break;
	case DIFF_HEX_32:
		hexlen = 32;
		break;
	default:
		hexlen = 8;
		break;
	}

#define printline(fmt, ...) snprintf(line + lp, RZ_MAX(lsize - lp, 0), fmt, ##__VA_ARGS__)
	lp = diff_hexdump_partial(hview, hexlen, 0, lsize, buffer_a, buffer_b, address_a, address_b, hview->size_a, hview->size_b, pos, read_a, read_b, skip_a, skip_b);
	lp += printline(" | ");
	lp = diff_hexdump_partial(hview, hexlen, lp, lsize, buffer_b, buffer_a, address_b, address_a, hview->size_b, hview->size_a, pos, read_b, read_a, skip_b, skip_a);
	lp += printline(" |");
#undef printline
}

static inline int len_draw_hexdump(DiffHexView *hview) {
	int width = hview->screen.width;
	if (width >= (DIFF_HEX_32 * 2)) {
		return DIFF_HEX_32;
	} else if (width >= (DIFF_HEX_16 * 2)) {
		return DIFF_HEX_16;
	}
	return DIFF_HEX_8;
}

static inline int seek_min_shift(DiffHexView *hview) {
	int width = hview->screen.width;
	if (width >= (DIFF_HEX_32 * 2)) {
		return 5;
	} else if (width >= (DIFF_HEX_16 * 2)) {
		return 4;
	}
	return 3;
}

static inline int seek_min_value(DiffHexView *hview) {
	int width = hview->screen.width;
	if (width >= (DIFF_HEX_32 * 2)) {
		return 32;
	} else if (width >= (DIFF_HEX_16 * 2)) {
		return 16;
	}
	return 8;
}

static inline int offset_len(DiffHexView *hview) {
	ut64 filesize = RZ_MAX(hview->io_a->filesize, hview->io_b->filesize);
	if (filesize > UT32_MAX) {
		return 16;
	} else if (filesize > UT16_MAX) {
		return 8;
	}
	return 4;
}

static bool rz_diff_draw_tui(DiffHexView *hview, bool show_help) {
	ssize_t read_a = 0, read_b = 0;
	char *line = hview->line;
	int shift = 8, offlen = 16, xpos = 0;
	int width = hview->screen.width;
	int height = hview->screen.height;
	int lsize = width * height;
	DiffHexLen hlen = 0;
	DiffIO *io_a = hview->io_a;
	DiffIO *io_b = hview->io_b;
	ut64 filesize_a = hview->io_a->filesize;
	ut64 filesize_b = hview->io_b->filesize;
	ut64 max_rows = height - 2;
	ut64 skip_a = 0;
	ut64 skip_b = 0;
	RzConsCanvas *canvas = hview->canvas;
	const char *reset = hview->colors.reset;
	const char *legenda = hview->colors.legenda;
	const char *toolbar = NULL;
	bool utf8 = rz_cons_singleton()->use_utf8;
	const char *arrow_up = utf8 ? RUNE_ARROW_UP " " : "/\\";
	const char *arrow_down = utf8 ? RUNE_ARROW_DOWN " " : "\\/";
	const char *arrow_right = utf8 ? RUNE_ARROW_RIGHT " " : "> ";
	const char *arrow_left = utf8 ? RUNE_ARROW_LEFT " " : "< ";

	if (!line || !hview->buffer_a || !hview->buffer_b) {
		return false;
	}

	offlen = offset_len(hview);
	hlen = len_draw_hexdump(hview);
	xpos = RZ_MAX((width / 2) - hlen, 0);

	const char *p = NULL;
	const char *file_a = io_a->filename;
	const char *file_b = io_b->filename;

	p = io_a->filename;
	while ((p = strstr(file_a, RZ_SYS_DIR))) {
		file_a = p + 1;
	}

	p = io_b->filename;
	while ((p = strstr(file_b, RZ_SYS_DIR))) {
		file_b = p + 1;
	}

	if (hview->column_descr) {
		max_rows--;
	}

	if (hview->address_a > hview->size_a && (hview->address_a + hview->size_a) < hview->size_a) {
		// underflow
		ut64 size = hview->address_a + hview->size_a;
		ut64 offset_p = hview->size_a - size;
		read_a = rz_io_pread_at(io_a->io, 0, hview->buffer_a + offset_p, size);
		if (read_a > 0) {
			// include also excluded bytes from underflow
			read_a += offset_p;
			skip_a = offset_p;
		}
	} else {
		read_a = rz_io_pread_at(io_a->io, hview->address_a, hview->buffer_a, hview->size_a);
	}

	if (hview->address_b > hview->size_b && (hview->address_b + hview->size_b) < hview->size_b) {
		// underflow
		ut64 size = hview->address_b + hview->size_b;
		ut64 offset_p = hview->size_b - size;
		read_b = rz_io_pread_at(io_b->io, 0, hview->buffer_b + offset_p, size);
		if (read_b > 0) {
			// include also excluded bytes from underflow
			read_b += offset_p;
			skip_b = offset_p;
		}
	} else {
		read_b = rz_io_pread_at(io_b->io, hview->address_b, hview->buffer_b, hview->size_b);
	}

	rz_cons_goto_origin_reset();
	rz_cons_clear();
	rz_cons_canvas_clear(canvas);
	shift = seek_min_shift(hview);
	for (ut64 h = 0, pos = 0; h < max_rows; ++h) {
		// draw hexadecimal values
		pos = h << shift;
		diff_hexdump_line(hview, hlen, pos, read_a - pos, read_b - pos, skip_a, skip_b);
		rz_cons_canvas_gotoxy(canvas, xpos, h + (hview->column_descr ? 2 : 1));
		rz_cons_canvas_write(canvas, line);
	}

	switch (len_draw_hexdump(hview)) {
	case DIFF_HEX_32: toolbar = " 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"; break;
	case DIFF_HEX_16: toolbar = " 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F"; break;
	default: toolbar = " 0  1  2  3  4  5  6  7"; break;
	}

	rz_cons_canvas_box(canvas, 0, 0, width, height - 1, reset);
	if (hview->column_descr) {
		rz_cons_canvas_gotoxy(canvas, xpos + 21, 1);
		rz_cons_canvas_write(canvas, toolbar);
		rz_cons_canvas_gotoxy(canvas, xpos, 0);
	} else {
		rz_cons_canvas_gotoxy(canvas, xpos, 0);
	}
	snprintf(line, lsize, " [%*" PFMT64x "]( %.42s )", offlen, filesize_a, file_a);
	rz_cons_canvas_write(canvas, line);

	if (hview->column_descr) {
		rz_cons_canvas_gotoxy(canvas, xpos + hlen + 22, 1);
		rz_cons_canvas_write(canvas, toolbar);
		rz_cons_canvas_gotoxy(canvas, xpos + hlen, 0);
	} else {
		rz_cons_canvas_gotoxy(canvas, xpos + hlen, 0);
	}
	snprintf(line, lsize, " [%*" PFMT64x "]( %.42s )", offlen, filesize_b, file_b);
	rz_cons_canvas_write(canvas, line);

	// clang-format off
	toolbar = " "
		"%s1 2%s -/+0x%x | "
		"%sZ A%s file0 +/-1 | "
		"%sC D%s file1 +/-1 | "
		"%sG B%s end/begin | "
		"%sN M%s next/prev | "
		"%s%s%s%s +/-%u | "
		"%s%s%s%s +/-1 | "
		"%s:%s seek";
	snprintf(line, lsize, toolbar
			, legenda, reset, (1 << shift) * max_rows
			, legenda, reset
			, legenda, reset
			, legenda, reset
			, legenda, reset
			, legenda, arrow_down, arrow_up, reset, 1 << shift
			, legenda, arrow_left, arrow_right, reset
			, legenda, reset);
	// clang-format on

	rz_cons_canvas_gotoxy(canvas, 0, height);
	rz_cons_canvas_write(canvas, line);

	if (show_help) {
		rz_cons_canvas_fill(canvas, 4, 2, 56, 16, ' ');
		rz_cons_canvas_box(canvas, 4, 2, 56, 16, legenda);

		snprintf(line, lsize, "%sHelp page%s\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 3);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s1 2%s   increase/decrease the offsets by 0x%x\n", legenda, reset, (1 << shift) * (height - 2));
		rz_cons_canvas_gotoxy(canvas, 6, 5);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%sZ A%s   increase/decrease the offset of the file0 by 1\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 6);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%sC D%s   increase/decrease the offset of the file1 by 1\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 7);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%sN M%s   next/previous difference\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 8);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%sG B%s   seek to end/begin\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 9);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s9%s     sets both offsets to a common value\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 10);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s0%s     shows/hides the column legenda\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 11);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s%s %s%s increase/decrease both offsets by %u\n", legenda, arrow_down, arrow_up, reset, 1 << shift);
		rz_cons_canvas_gotoxy(canvas, 6, 12);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s%s %s%s increase/decrease both offsets by 1\n", legenda, arrow_left, arrow_right, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 13);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s:%s     seek at offset (relative via +-)\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 14);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s3%s     file0 seek at offset (relative via +-)\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 15);
		rz_cons_canvas_write(canvas, line);

		snprintf(line, lsize, "%s4%s     file1 seek at offset (relative via +-)\n", legenda, reset);
		rz_cons_canvas_gotoxy(canvas, 6, 16);
		rz_cons_canvas_write(canvas, line);
	}

	rz_cons_canvas_print(canvas);
	rz_cons_flush();

	// allow to refresh the terminal
	// before printing again the ui
	rz_sys_usleep(200);
	return true;
}

static char *visual_prompt(DiffHexView *hview, const char *prompt) {
	char buf[1024];
	rz_cons_gotoxy(0, hview->screen.height);
	rz_cons_clear_line(0);
	rz_cons_printf("%s%s ", hview->colors.reset, prompt);
	rz_line_set_prompt(rz_cons_singleton()->line, ":> ");
	rz_cons_flush();
	rz_cons_fgets(buf, sizeof(buf), 0, NULL);
	if (*buf) {
		return strdup(buf);
	}
	return NULL;
}

static void prompt_offset_and_seek(DiffHexView *hview, ut64 minseek) {
	char *value = visual_prompt(hview, " you can input an absolute offset or a relative offset by adding the prefix + or -\n offset");
	if (value) {
		const char *p = rz_str_trim_head_ro(value);
		if (!IS_DIGIT(*p) && *p != '-' && *p != '+') {
			free(value);
			return;
		}
		st64 number = strtoll((*p == '+' || *p == '-') ? p + 1 : p, NULL, 0);
		if (*p == '-') {
			hview->address_a -= number;
			hview->address_b -= number;
		} else if (*p == '+') {
			hview->address_a += number;
			hview->address_b += number;
		} else {
			hview->address_a = number;
			hview->address_b = number;
		}
	}
	free(value);
}

static void prompt_offset_and_seek_file(DiffHexView *hview, ut64 minseek, bool is_file0) {
	char *value = visual_prompt(hview, " you can input an absolute offset or a relative offset by adding the prefix + or -\n offset");
	if (value) {
		const char *p = rz_str_trim_head_ro(value);
		if (!IS_DIGIT(*p) && *p != '-' && *p != '+') {
			free(value);
			return;
		}
		st64 number = strtoll((*p == '+' || *p == '-') ? p + 1 : p, NULL, 0);
		if (*p == '-') {
			if (is_file0) {
				hview->address_a -= number;
			} else {
				hview->address_b -= number;
			}
		} else if (*p == '+') {
			if (is_file0) {
				hview->address_a += number;
			} else {
				hview->address_b += number;
			}
		} else {
			if (is_file0) {
				hview->address_a = number;
			} else {
				hview->address_b = number;
			}
		}
	}
	free(value);
}

static void find_next_diff(DiffHexView *hview, ut64 seek) {
	if (!hview->buffer_a || !hview->buffer_b) {
		return;
	}

	DiffIO *io_a = hview->io_a;
	DiffIO *io_b = hview->io_b;
	ssize_t read_a = 0, read_b = 0;
	ssize_t minread = 0, minseek = 0;
	ut64 address_a = hview->address_a + seek;
	ut64 address_b = hview->address_b + seek;
	ut64 minsize = RZ_MIN(hview->size_a, hview->size_b);
	if (RZ_MIN(io_a->filesize, io_b->filesize) < seek) {
		hview->address_a = 0;
		hview->address_b = 0;
		return;
	}
	do {
		read_a = rz_io_pread_at(io_a->io, address_a, hview->buffer_a, minsize);
		read_b = rz_io_pread_at(io_b->io, address_b, hview->buffer_b, minsize);
		if (read_a < 1 || read_b < 1) {
			break;
		}
		minread = RZ_MIN(read_a, read_b);
		if (minread != minsize && !memcmp(hview->buffer_a, hview->buffer_b, minread)) {
			address_a += RZ_MAX(minread - seek, 0);
			address_b += RZ_MAX(minread - seek, 0);
			break;
		} else if (minread == minsize && !memcmp(hview->buffer_a, hview->buffer_b, minsize)) {
			address_a += minsize;
			address_b += minsize;
			continue;
		}
		minread = RZ_MIN(minsize, minread);
		minseek = RZ_MIN(seek, minread);
		for (ssize_t i = 0; i < minread; i += minseek) {
			if (memcmp(&hview->buffer_a[i], &hview->buffer_b[i], minseek)) {
				hview->address_a = address_a;
				hview->address_b = address_b;
				return;
			}
			address_a += minseek;
			address_b += minseek;
		}
	} while (1);

	if (address_a >= io_a->filesize) {
		address_a = io_a->filesize - seek;
	}

	if (address_b >= io_b->filesize) {
		address_b = io_b->filesize - seek;
	}

	hview->address_a = address_a;
	hview->address_b = address_b;
}

static void find_prev_diff(DiffHexView *hview, ut64 seek) {
	if (!hview->buffer_a || !hview->buffer_b) {
		return;
	}

	DiffIO *io_a = hview->io_a;
	DiffIO *io_b = hview->io_b;
	ssize_t read_a = 0, read_b = 0;
	st64 address_a = hview->address_a;
	st64 address_b = hview->address_b;

	do {
		address_a -= seek;
		address_b -= seek;
		if (address_a < 0) {
			address_a = 0;
		}
		if (address_b < 0) {
			address_b = 0;
		}
		read_a = rz_io_pread_at(io_a->io, address_a, hview->buffer_a, seek);
		read_b = rz_io_pread_at(io_b->io, address_b, hview->buffer_b, seek);
		if (read_a < 1 || read_b < 1) {
			break;
		}
		if (memcmp(hview->buffer_a, hview->buffer_b, seek)) {
			break;
		}
		if (address_a == 0 || address_b == 0) {
			break;
		}
	} while (1);
	hview->address_a = RZ_MAX(address_a, 0);
	hview->address_b = RZ_MAX(address_b, 0);
}

static void rz_diff_resize_buffer(DiffHexView *hview) {
	int height, width = rz_cons_get_size(&height);

	ut64 size_a = ((st64)(width / 2) * (height - 2));
	ut64 size_b = ((st64)(width / 2) * (height - 2));
	st64 video_size = width;
	video_size *= height;

	hview->line = realloc(hview->line, video_size);
	hview->buffer_a = realloc(hview->buffer_a, size_a);
	hview->buffer_b = realloc(hview->buffer_b, size_b);
	hview->size_a = size_a;
	hview->size_b = size_b;
	hview->screen.width = width;
	hview->screen.height = height;

	rz_cons_canvas_free(hview->canvas);
	hview->canvas = rz_cons_canvas_new(width, height);
	hview->canvas->color = true;
	hview->canvas->linemode = 1;

	rz_diff_draw_tui(hview, false);
}

static bool rz_diff_hex_visual(DiffContext *ctx) {
	RzCons *console = NULL;
	DiffIO *io_a = NULL;
	DiffIO *io_b = NULL;
	RzConsCanvas *canvas = NULL;
	DiffHexView hview;
	bool draw_visual = true;
	bool show_help = false;
	int read, pressed;
	int height = ctx->screen.width;
	int width = ctx->screen.height;
	ut64 size_a = 0;
	ut64 size_b = 0;

	hview.line = NULL;
	hview.buffer_a = NULL;
	hview.buffer_b = NULL;

	RzCore *core = rz_core_new();
	if (!core) {
		rz_diff_error("cannot allocate core\n");
		goto rz_diff_hex_visual_fail;
	}

	rz_core_parse_rizinrc(core);

	console = rz_cons_singleton();
	if (!console) {
		rz_diff_error("cannot get console.\n");
		goto rz_diff_hex_visual_fail;
	}

	rz_cons_set_interactive(false);

	io_a = rz_diff_io_open(ctx->file_a);
	if (!io_a) {
		goto rz_diff_hex_visual_fail;
	}

	io_b = rz_diff_io_open(ctx->file_b);
	if (!io_b) {
		goto rz_diff_hex_visual_fail;
	}

	if (width < 1 && height < 1) {
		width = rz_cons_get_size(&height);
		if (width < 1 && height < 1) {
			rz_diff_error("invalid screen size; use -S WxH to define the sizes.\n");
			goto rz_diff_hex_visual_fail;
		}
	}

	canvas = rz_cons_canvas_new(width, height);
	if (!canvas) {
		rz_diff_error("cannot allocate canvas. try to use -S WxH to define the sizes.\n");
		goto rz_diff_hex_visual_fail;
	}

	size_a = ((width / 2) * (height - 2));
	size_b = ((width / 2) * (height - 2));

	canvas->color = true;
	canvas->linemode = 1;

	st64 video_size = width;
	video_size *= height;
	hview.line = malloc(video_size);
	if (!hview.line) {
		rz_diff_error("cannot allocate line buffer.\n");
		goto rz_diff_hex_visual_fail;
	}
	hview.buffer_a = malloc(size_a);
	if (!hview.buffer_a) {
		rz_diff_error("cannot allocate buffer for %s.\n", io_a->filename);
		goto rz_diff_hex_visual_fail;
	}
	hview.buffer_b = malloc(size_b);
	if (!hview.buffer_b) {
		rz_diff_error("cannot allocate buffer for %s.\n", io_b->filename);
		goto rz_diff_hex_visual_fail;
	}

	hview.size_a = size_a;
	hview.size_b = size_b;
	hview.io_a = io_a;
	hview.io_b = io_b;
	hview.canvas = canvas;
	hview.screen.width = width;
	hview.screen.height = height;
	hview.address_a = 0;
	hview.address_b = 0;
	hview.column_descr = true;
	rz_diff_get_colors(&hview.colors, console->context, ctx->colors);

	rz_cons_show_cursor(false);
	rz_cons_enable_mouse(false);

	console->event_data = &hview;
	console->event_resize = (RzConsEvent)rz_diff_resize_buffer;

	int seekmin = 0;
	while (draw_visual && !rz_cons_is_breaked()) {
		if (!rz_diff_draw_tui(&hview, show_help)) {
			break;
		}
		seekmin = seek_min_value(&hview);
		read = rz_cons_readchar();
		pressed = rz_cons_arrow_to_hjkl(read);

		if (show_help && (pressed == 'q' || pressed == 'Q')) {
			// allow to close the help without closing the util
			pressed = 0;
		}

		show_help = false;
		switch (pressed) {
		case '0':
			hview.column_descr = !hview.column_descr;
			break;
		case '?':
			show_help = true;
			break;
		case ':':
			prompt_offset_and_seek(&hview, seekmin);
			break;
		case '3':
			prompt_offset_and_seek_file(&hview, seekmin, true);
			break;
		case '4':
			prompt_offset_and_seek_file(&hview, seekmin, false);
			break;
		case '9':
			hview.address_a = hview.address_b = RZ_MIN(hview.address_a, hview.address_b);
			break;
		case 'G':
		case 'g':
			hview.address_a = io_a->filesize - seekmin;
			hview.address_b = io_b->filesize - seekmin;
			break;
		case 'B':
		case 'b':
			hview.address_a = 0;
			hview.address_b = 0;
			break;
		case 'A':
		case 'a':
			hview.address_a--;
			break;
		case 'N':
		case 'n':
			find_next_diff(&hview, seekmin);
			break;
		case 'M':
		case 'm':
			find_prev_diff(&hview, seekmin);
			break;
		case 'Z':
		case 'z':
			hview.address_a++;
			break;
		case 'D':
		case 'd':
			hview.address_b--;
			break;
		case 'C':
		case 'c':
			hview.address_b++;
			break;
		/* ARROWS */
		case '1':
			hview.address_a -= (seekmin * (height - 2));
			hview.address_b -= (seekmin * (height - 2));
			break;
		case '2':
			hview.address_a += (seekmin * (height - 2));
			hview.address_b += (seekmin * (height - 2));
			break;
		case 'K':
		case 'k':
			hview.address_a -= seekmin;
			hview.address_b -= seekmin;
			break;
		case 'J':
		case 'j':
			hview.address_a += seekmin;
			hview.address_b += seekmin;
			break;
		case 'L':
		case 'l':
			hview.address_a--;
			hview.address_b--;
			break;
		case 'H':
		case 'h':
			hview.address_a++;
			hview.address_b++;
			break;
		case -1: // EOF
		case 'Q':
		case 'q':
			draw_visual = false;
		default:
			break;
		}
	}
	canvas = hview.canvas;
	console->event_data = NULL;
	console->event_resize = NULL;

	rz_cons_show_cursor(true);
	rz_cons_goto_origin_reset();
	rz_cons_clear();
	rz_cons_print(Color_RESET_TERMINAL);
	rz_cons_flush();

rz_diff_hex_visual_fail:
	free(hview.line);
	free(hview.buffer_a);
	free(hview.buffer_b);
	rz_cons_canvas_free(canvas);
	rz_diff_io_close(io_a);
	rz_diff_io_close(io_b);
	rz_core_free(core);
	rz_cons_free();
	return true;
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
	case DIFF_OPT_GRAPH:
		success = rz_diff_graphs_files(&ctx);
		break;
	case DIFF_OPT_HEX_VISUAL:
		success = rz_diff_hex_visual(&ctx);
		break;
	case DIFF_OPT_VERSION:
		rz_main_version_print("rz-diff");
		success = true;
		break;
	case DIFF_OPT_USAGE:
		rz_diff_show_help(true);
		break;
	case DIFF_OPT_ERROR:
		break;
	case DIFF_OPT_HELP:
		success = true;
		// fallthrough
	default:
		rz_diff_show_help(false);
		break;
	}

	rz_list_free(ctx.evars);
	return success ? 0 : 1;
}
