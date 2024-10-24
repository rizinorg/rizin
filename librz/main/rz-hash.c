// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_io.h>
#include <rz_main.h>
#include <rz_hash.h>
#include <rz_util/rz_print.h>
#include <rz_util.h>
#include <rz_crypto.h>
#include <rz_lib.h>

#define RZ_HASH_DEFAULT_BLOCK_SIZE 0x1000

typedef struct {
	ut8 *buf;
	size_t len;
} RzHashBuffer;

typedef enum {
	RZ_HASH_MODE_STANDARD = 0,
	RZ_HASH_MODE_JSON,
	RZ_HASH_MODE_RANDOMART,
	RZ_HASH_MODE_QUIET,
	RZ_HASH_MODE_VERY_QUIET,
} RzHashMode;

typedef enum {
	RZ_HASH_OP_UNKNOWN = 0,
	RZ_HASH_OP_ERROR,
	RZ_HASH_OP_HELP,
	RZ_HASH_OP_USAGE,
	RZ_HASH_OP_VERSION,
	RZ_HASH_OP_LIST_ALGO,
	RZ_HASH_OP_HASH,
	RZ_HASH_OP_DECRYPT,
	RZ_HASH_OP_ENCRYPT,
	RZ_HASH_OP_LUHN,
} RzHashOp;

typedef struct {
	ut64 from;
	ut64 to;
} RzHashOffset;

typedef struct rz_hash_context {
	RzHash *rh;
	RzCrypto *rc;
	bool as_prefix;
	bool little_endian;
	bool show_blocks;
	bool use_stdin;
	char *algorithm;
	char *compare;
	char *input;
	char *iv;
	const char **files;
	RzHashBuffer key;
	RzHashBuffer seed;
	RzHashMode mode;
	RzHashOffset offset;
	RzHashOp operation;
	ut32 nfiles;
	ut64 block_size;
	ut64 iterate;
	/* Output here */
	PJ *pj;
} RzHashContext;

typedef bool (*RzHashRun)(RzHashContext *ctx, RzIO *io, const char *filename);

static void rz_hash_show_help(bool usage_only) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-hash [-vhBkjLq] [-b S] [-a A] [-c H] [-E A] [-D A] [-s S] [-x S] [-f O] [-t O] [files|-] ...\n");
	if (usage_only) {
		return;
	}
	const char *options[] = {
		// clang-format off
		"-v",     "",       "Show version information",
		"-h",     "",       "Show this help",
		"-",      "",       "Input read from stdin instead from a file",
		"-a",     "algo",   "Hash algorithm to use and you can specify multiple ones by",
		"",       "",       "Appending a comma (example: sha1,md4,md5,sha256)",
		"-B",     "",       "Output the calculated value for each block",
		"-b",     "size",   "Set the block size",
		"-c",     "value",  "Compare calculated value with a given one (hexadecimal)",
		"-e",     "endian", "Set the endianness (default: 'big' accepted: 'big' or 'little')",
		"-D",     "algo",   "Decrypt the given input; use -S to set key and -I to set IV (if needed)",
		"-E",     "algo",   "Encrypt the given input; use -S to set key and -I to set IV (if needed)",
		"-f",     "from",   "Start the calculation at given offset",
		"-t",     "to",     "Stop the calculation at given offset",
		"-I",     "iv",     "Set the initialization vector (IV)",
		"-i",     "times",  "Repeat the calculation N times",
		"-j",     "",       "Output the result as a JSON structure",
		"-k",     "",       "Output the calculated value using openssh's randomkey algorithm",
		"-L",     "",       "List all algorithms",
		"-q",     "",       "Set quiet mode (use -qq to get only the calculated value)",
		"-S",     "seed",   "Set the seed for -a, use '^' to append it before the input, use '@'",
		"",       "",       "Prefix to load it from a file and '-' from read it",
		"-K",     "key",    "Set the hmac key for -a and the key for -E/-D, use '@' prefix to",
		"",       "",       "Load it from a file and '-' from read it",
		"",       "",       "From stdin (you can combine them)",
		"-s",     "string", "Input read from a zero-terminated string instead from a file",
		"-x",     "hex",    "Input read from a hexadecimal value instead from a file",
		"",       "",       "",
		"",       "",       "All the input (besides -s/-x/-c) can be hexadecimal or strings",
		"",       "",       "If 's:' prefix is specified",
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
}

static void rz_hash_show_algorithms(RzHashContext *ctx) {
	char flags[7] = { 0 };

	printf("flags  algorithm      license    author\n");

	RzIterator *iter = ht_sp_as_iter(ctx->rh->plugins);
	RzList *plugin_list = rz_list_new_from_iterator(iter);
	if (!plugin_list) {
		rz_iterator_free(iter);
		return;
	}
	rz_list_sort(plugin_list, (RzListComparator)rz_hash_plugin_cmp, NULL);
	RzListIter *it;
	const RzHashPlugin *rmdp;
	rz_list_foreach (plugin_list, it, rmdp) {
		snprintf(flags, sizeof(flags), "____h%c", rmdp->support_hmac ? 'm' : '_');
		printf("%6s %-14s %-10s %s\n", flags, rmdp->name, rmdp->license, rmdp->author);
	}
	rz_list_free(plugin_list);
	rz_iterator_free(iter);

	const RzCryptoPlugin *rcp;
	for (size_t i = 0; (rcp = rz_crypto_plugin_by_index(ctx->rc, i)); i++) {
		if (!strncmp("base", rcp->name, 4) || !strcmp("punycode", rcp->name)) {
			snprintf(flags, sizeof(flags), "__ed__");
		} else if (!strcmp("rol", rcp->name)) {
			snprintf(flags, sizeof(flags), "E_____");
		} else if (!strcmp("ror", rcp->name)) {
			snprintf(flags, sizeof(flags), "_D____");
		} else {
			snprintf(flags, sizeof(flags), "ED____");
		}
		printf("%6s %-14s %-10s %s\n", flags, rcp->name, rcp->license, rcp->author);
	}
	printf(
		"\n"
		"flags legenda:\n"
		"    E = encryption, D = decryption\n"
		"    e = encoding, d = encoding\n"
		"    h = hash, m = hmac\n");
}

#define rz_hash_bool_error(x, o, f, ...) \
	(x)->operation = o; \
	RZ_LOG_ERROR("rz-hash: error, " f, ##__VA_ARGS__); \
	return false;

#define rz_hash_error(x, o, f, ...) \
	(x)->operation = o; \
	RZ_LOG_ERROR("rz-hash: error, " f, ##__VA_ARGS__); \
	return;

#define rz_hash_set_val(x, k, d, v) \
	do { \
		if ((k) != (d)) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
		} \
		(k) = (v); \
	} while (0)

#define rz_hash_ctx_set_val(x, k, d, v) \
	do { \
		if ((x)->k != (d)) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
		} \
		(x)->k = (v); \
	} while (0)

#define rz_hash_ctx_set_bool(x, k, i, t, f) \
	do { \
		if (i && !strcmp(i, t)) { \
			(x)->k = true; \
		} else if (i && !strcmp(i, f)) { \
			(x)->k = false; \
		} else { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "expected '%s' or '%s' but got '%s'\n", t, f, i); \
		} \
	} while (0)

#define rz_hash_ctx_set_quiet(x) \
	do { \
		if ((x)->mode == RZ_HASH_MODE_STANDARD) { \
			(x)->mode = RZ_HASH_MODE_QUIET; \
		} else if ((x)->mode == RZ_HASH_MODE_QUIET) { \
			(x)->mode = RZ_HASH_MODE_VERY_QUIET; \
		} else if ((x)->mode == RZ_HASH_MODE_JSON) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "can't be quiet when json mode is selected\n"); \
		} else if ((x)->mode == RZ_HASH_MODE_RANDOMART) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "can't be quiet when openssh mode is selected\n"); \
		} \
	} while (0)

#define rz_hash_ctx_set_signed(x, k, i) \
	do { \
		(x)->k = strtoll((i), NULL, 0); \
		if ((x)->k < 1) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "argument must be > 0\n"); \
		} \
	} while (0)

#define rz_hash_ctx_set_unsigned(x, k, i) \
	do { \
		(x)->k = strtoull((i), NULL, 0); \
		if ((x)->k < 1) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "argument must be > 0\n"); \
		} \
	} while (0)

#define rz_hash_ctx_set_input(x, k, s, h) \
	do { \
		if ((x)->k) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "invalid combination of arguments for '-%c'\n", c); \
		} else if (h || strlen(s) < 1) { \
			(x)->k = rz_str_dup(s); \
		} else { \
			(x)->k = rz_str_newf("s:%s", s); \
		} \
	} while (0)

#define rz_hash_ctx_set_mode(x, m)   rz_hash_ctx_set_val(x, mode, RZ_HASH_MODE_STANDARD, m)
#define rz_hash_ctx_set_op(x, o)     rz_hash_ctx_set_val(x, operation, RZ_HASH_OP_UNKNOWN, o)
#define rz_hash_ctx_set_str(x, k, s) rz_hash_ctx_set_val(x, k, NULL, rz_str_dup(s))

static bool hash_parse_string(const char *option, const char *string, ut8 **buffer, size_t *bufsize) {
	char *sstdin = NULL;
	int stringlen = 0;
	if (!strcmp(string, "-")) {
		string = sstdin = rz_stdin_slurp(&stringlen);
	} else {
		stringlen = strlen(string);
	}
	if (stringlen < 1 || !string) {
		RZ_LOG_ERROR("rz-hash: error, option %s is empty.\n", option);
		free(sstdin);
		return false;
	}

	ut8 *b = (ut8 *)malloc(stringlen + 1);
	if (!b) {
		RZ_LOG_ERROR("rz-hash: error, failed to allocate string in memory.\n");
		free(sstdin);
		return false;
	}

	memcpy(b, string, stringlen);
	b[stringlen] = 0;
	stringlen = rz_str_unescape((char *)b);

	*buffer = b;
	*bufsize = stringlen;
	free(sstdin);

	return true;
}

static bool hash_parse_hexadecimal(const char *option, const char *hexadecimal, ut8 **buffer, size_t *bufsize) {
	char *sstdin = NULL;
	int hexlen = 0;
	if (!strcmp(hexadecimal, "-")) {
		hexadecimal = sstdin = rz_stdin_slurp(&hexlen);
	} else {
		hexlen = strlen(hexadecimal);
	}

	if (hexlen < 1 || !hexadecimal) {
		RZ_LOG_ERROR("rz-hash: error, option %s is empty.\n", option);
		free(sstdin);
		return false;
	} else if (hexlen & 1) {
		RZ_LOG_ERROR("rz-hash: error, option %s is not a valid hexadecimal (len is not pair: %d).\n", option, hexlen);
		free(sstdin);
		return false;
	}
	*buffer = NULL;
	st64 binlen = hexlen >> 1;
	ut8 *b = (ut8 *)malloc(binlen);
	if (b) {
		*bufsize = rz_hex_str2bin(hexadecimal, b);
		if (*bufsize < 1) {
			RZ_LOG_ERROR("rz-hash: error, option %s is not a valid hexadecimal.\n", option);
			free(b);
			free(sstdin);
			return false;
		}
		*buffer = b;
	}

	free(sstdin);
	return true;
}

static bool hash_parse_any(RzHashContext *ctx, const char *option, const char *arg, RzHashBuffer *hb) {
	ssize_t arglen = strlen(arg);
	if (arglen < 1) {
		rz_hash_bool_error(ctx, RZ_HASH_OP_ERROR, "option %s is empty.\n", option);
	}
	if (!strcmp(arg, "-")) {
		int stdinlen = 0;
		hb->buf = (ut8 *)rz_stdin_slurp(&stdinlen);
		hb->len = stdinlen;
	} else if (arg[0] == '@') {
		hb->buf = (ut8 *)rz_file_slurp(arg + 1, &hb->len);
	} else if (!strncmp(arg, "s:", 2)) {
		if (!hash_parse_string(option, arg + 2, &hb->buf, &hb->len)) {
			ctx->operation = RZ_HASH_OP_ERROR;
			return false;
		}
	} else {
		if (!hash_parse_hexadecimal(option, arg, &hb->buf, &hb->len)) {
			ctx->operation = RZ_HASH_OP_ERROR;
			return false;
		}
	}
	if (!hb->buf) {
		rz_hash_bool_error(ctx, RZ_HASH_OP_ERROR, "failed to allocate buffer memory for %s option.\n", option);
	}
	return true;
}

static void hash_parse_cmdline(int argc, const char **argv, RzHashContext *ctx) {
	const char *seed = NULL;
	const char *key = NULL;

	RzGetopt opt;
	int c;
	rz_getopt_init(&opt, argc, argv, "jD:e:vE:a:i:I:S:K:s:x:b:nBhf:t:kLqc:");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'q': rz_hash_ctx_set_quiet(ctx); break;
		case 'i': rz_hash_ctx_set_signed(ctx, iterate, opt.arg); break;
		case 'j': rz_hash_ctx_set_mode(ctx, RZ_HASH_MODE_JSON); break;
		case 'S': rz_hash_set_val(ctx, seed, NULL, opt.arg); break;
		case 'K': rz_hash_set_val(ctx, key, NULL, opt.arg); break;
		case 'I': rz_hash_ctx_set_str(ctx, iv, opt.arg); break;
		case 'D':
			rz_hash_ctx_set_str(ctx, algorithm, opt.arg);
			rz_hash_ctx_set_op(ctx, RZ_HASH_OP_DECRYPT);
			break;
		case 'E':
			rz_hash_ctx_set_str(ctx, algorithm, opt.arg);
			rz_hash_ctx_set_op(ctx, RZ_HASH_OP_ENCRYPT);
			break;
		case 'L': rz_hash_ctx_set_op(ctx, RZ_HASH_OP_LIST_ALGO); break;
		case 'e': rz_hash_ctx_set_bool(ctx, little_endian, opt.arg, "little", "big"); break;
		case 'k': rz_hash_ctx_set_mode(ctx, RZ_HASH_MODE_RANDOMART); break;
		case 'a':
			rz_hash_ctx_set_str(ctx, algorithm, opt.arg);
			rz_hash_ctx_set_op(ctx, RZ_HASH_OP_HASH);
			break;
		case 'B': ctx->show_blocks = true; break;
		case 'b': rz_hash_ctx_set_unsigned(ctx, block_size, opt.arg); break;
		case 'f': rz_hash_ctx_set_unsigned(ctx, offset.from, opt.arg); break;
		case 't': rz_hash_ctx_set_unsigned(ctx, offset.to, opt.arg); break;
		case 'v': ctx->operation = RZ_HASH_OP_VERSION; break;
		case 'h': ctx->operation = RZ_HASH_OP_HELP; break;
		case 's': rz_hash_ctx_set_input(ctx, input, opt.arg, false); break;
		case 'x': rz_hash_ctx_set_input(ctx, input, opt.arg, true); break;
		case 'c': rz_hash_ctx_set_str(ctx, compare, opt.arg); break;
		default:
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "unknown flag '%c'\n", c);
		}
	}

	if (ctx->operation == RZ_HASH_OP_HELP ||
		ctx->operation == RZ_HASH_OP_VERSION ||
		ctx->operation == RZ_HASH_OP_LIST_ALGO) {
		return;
	}

	if (opt.ind >= argc && !ctx->input) {
		ctx->operation = RZ_HASH_OP_USAGE;
		return;
	}

	if (!ctx->algorithm) {
		rz_hash_ctx_set_str(ctx, algorithm, "sha256");
		rz_hash_ctx_set_op(ctx, RZ_HASH_OP_HASH);
	}

	if (!ctx->input && !strcmp(argv[argc - 1], "-")) {
		ctx->use_stdin = true;
	} else {
		ctx->files = RZ_NEWS(const char *, argc - opt.ind);
		if (!ctx->files) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "failed to allocate file array memory.\n");
		}
		ctx->nfiles = 0;
		for (int i = opt.ind; i < argc; ++i) {
			if (IS_NULLSTR(argv[i])) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "cannot open a file without a name.\n");
			}
			if (rz_file_is_directory(argv[i])) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "cannot open directories (%s).\n", argv[i]);
			}
			ctx->files[ctx->nfiles++] = argv[i];
		}
	}

	if (ctx->nfiles < 1 && !ctx->use_stdin && !ctx->input) {
		ctx->operation = RZ_HASH_OP_USAGE;
		return;
	}

	if (strstr(ctx->algorithm, "luhn")) {
		if (strchr(ctx->algorithm, ',')) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' is incompatible with multiple algorithms.\n");
		}
		if (!ctx->input || strncmp(ctx->input, "s:", 2)) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' requires -s option.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' is incompatible with -k option.\n");
		}
		if (ctx->show_blocks) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' is incompatible with -B option.\n");
		}
		if (ctx->block_size < strlen(ctx->algorithm + 2)) {
			ctx->block_size = strlen(ctx->algorithm + 2);
		}
		if (ctx->compare) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' is incompatible with -c option.\n");
		}
		if (seed) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' is incompatible with -S option.\n");
		}
		if (key) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "algorithm 'luhn' is incompatible with -K option.\n");
		}
		ctx->operation = RZ_HASH_OP_LUHN;
	} else if (ctx->operation == RZ_HASH_OP_ENCRYPT || ctx->operation == RZ_HASH_OP_DECRYPT) {
		if (!key && strncmp("base", ctx->algorithm, 4) && strcmp("punycode", ctx->algorithm)) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -K is required for algorithm '%s'.\n", ctx->algorithm);
		}
		if (ctx->compare) {
			ssize_t len = strlen(ctx->compare);
			if (!strncmp(ctx->algorithm, "base", 4)) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c is incompatible with -E or -D with algorithm base64 or base91.\n");
			} else if (strchr(ctx->algorithm, ',')) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c incompatible with multiple algorithms.\n");
			} else if (len < 1 || c & 1) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c value length is not multiple of 2 (expected hexadecimal value).\n");
			}
		}
		if (ctx->show_blocks) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -B is incompatible with -E/-D.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -k is incompatible with -E/-D.\n");
		}
	} else if (ctx->operation == RZ_HASH_OP_HASH) {
		if (ctx->iv) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -I is incompatible with -a; use -S to define a seed or -K to define an hmac key.\n");
		}
		if (ctx->show_blocks && ctx->compare) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -B is incompatible with -c option.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART && ctx->compare) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c is incompatible with -k option.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART && strchr(ctx->algorithm, ',')) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -a with multiple algorithms is incompatible with -k option.\n");
		}
	}

	if (ctx->offset.from && ctx->offset.to && ctx->offset.from >= ctx->offset.to) {
		rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -f value (%" PFMT64u ") is greater or equal to -t value (%" PFMT64u ").\n", ctx->offset.from, ctx->offset.to);
	}
	if (ctx->block_size && ctx->offset.from && ctx->offset.to && (ctx->offset.to - ctx->offset.from) % ctx->block_size) {
		rz_hash_error(ctx, RZ_HASH_OP_ERROR, "range between %" PFMT64u " and %" PFMT64u " is not a multiple of %" PFMT64u ".\n", ctx->offset.from, ctx->offset.to, ctx->block_size);
	}

	if (seed) {
		if (seed[0] == '^') {
			seed++;
			ctx->as_prefix = true;
		}
		if (!hash_parse_any(ctx, "-S", seed, &ctx->seed)) {
			return;
		}
	}

	if (key && !hash_parse_any(ctx, "-K", key, &ctx->key)) {
		return;
	}

	if (!ctx->block_size) {
		ctx->block_size = RZ_HASH_DEFAULT_BLOCK_SIZE;
	}
}

static void hash_context_fini(RzHashContext *ctx) {
	free(ctx->key.buf);
	free(ctx->algorithm);
	free(ctx->compare);
	free(ctx->iv);
	free(ctx->input);
	free((char **)ctx->files);
	free(ctx->seed.buf);
	pj_free(ctx->pj);
	rz_hash_free(ctx->rh);
	rz_crypto_free(ctx->rc);
}

static RzIODesc *hash_context_create_desc_io_stdin(RzIO *io) {
	RzIODesc *desc = NULL;
	int size;
	char *uri = NULL;
	ut8 *buffer = NULL;

	buffer = (ut8 *)rz_stdin_slurp(&size);
	if (size < 1 || !buffer) {
		goto rz_hash_context_create_desc_io_stdin_end;
	}

	uri = rz_str_newf("malloc://%d", size);
	if (!uri) {
		rz_warn_if_reached();
		goto rz_hash_context_create_desc_io_stdin_end;
	}

	desc = rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	if (!desc) {
		RZ_LOG_ERROR("rz-hash: error, cannot open malloc://%d\n", size);
		goto rz_hash_context_create_desc_io_stdin_end;
	}

	if (rz_io_pwrite_at(io, 0, buffer, size) != size) {
		RZ_LOG_ERROR("rz-hash: error, cannot write into malloc://%d buffer\n", size);
		rz_io_desc_close(desc);
		desc = NULL;
		goto rz_hash_context_create_desc_io_stdin_end;
	}

rz_hash_context_create_desc_io_stdin_end:
	free(buffer);
	free(uri);
	return desc;
}

static RzIODesc *hash_context_create_desc_io_string(RzIO *io, const char *input) {
	RzIODesc *desc = NULL;
	char *uri = NULL;
	ut8 *buffer = NULL;
	size_t size;

	bool is_string = !strncmp(input, "s:", 2);

	if (is_string) {
		if (!hash_parse_string("-s", input + 2, &buffer, &size)) {
			goto rz_hash_context_create_desc_io_string_end;
		}
	} else {
		if (!hash_parse_hexadecimal("-x", input, &buffer, &size)) {
			goto rz_hash_context_create_desc_io_string_end;
		}
	}
	if (!buffer || (!is_string && size < 1)) {
		rz_warn_if_reached();
		goto rz_hash_context_create_desc_io_string_end;
	} else if (is_string && size < 1) {
		goto rz_hash_context_create_desc_io_string_end;
	}

	uri = rz_str_newf("malloc://%" PFMTSZu, size);
	if (!uri) {
		rz_warn_if_reached();
		goto rz_hash_context_create_desc_io_string_end;
	}

	desc = rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	if (!desc) {
		RZ_LOG_ERROR("rz-hash: error, cannot open malloc://%" PFMTSZu "\n", size);
		goto rz_hash_context_create_desc_io_string_end;
	}

	if (rz_io_pwrite_at(io, 0, buffer, size) != size) {
		RZ_LOG_ERROR("rz-hash: error, cannot write into malloc://%" PFMTSZu " buffer\n", size);
		rz_io_desc_close(desc);
		desc = NULL;
		goto rz_hash_context_create_desc_io_string_end;
	}

rz_hash_context_create_desc_io_string_end:
	free(buffer);
	free(uri);
	return desc;
}

static bool hash_context_run(RzHashContext *ctx, RzHashRun run) {
	bool result = false;
	RzIODesc *desc = NULL;

	RzIO *io = rz_io_new();
	if (!io) {
		rz_warn_if_reached();
		return false;
	}

	if (ctx->mode == RZ_HASH_MODE_JSON) {
		ctx->pj = pj_new();
		if (!ctx->pj) {
			RZ_LOG_ERROR("rz-hash: error, failed to allocate JSON memory.\n");
			goto rz_hash_context_run_end;
		}
		pj_o(ctx->pj);
	}
	if (ctx->use_stdin) {
		desc = hash_context_create_desc_io_stdin(io);
		if (!desc) {
			RZ_LOG_ERROR("rz-hash: error, cannot read stdin\n");
			goto rz_hash_context_run_end;
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_ka(ctx->pj, "stdin");
		}
		if (!run(ctx, io, "stdin")) {
			goto rz_hash_context_run_end;
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_end(ctx->pj);
		}
	} else if (ctx->input) {
		if (strlen(ctx->input) > 0) {
			desc = hash_context_create_desc_io_string(io, ctx->input);
			if (!desc) {
				RZ_LOG_ERROR("rz-hash: error, cannot read string\n");
				goto rz_hash_context_run_end;
			}
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_ka(ctx->pj, !strncmp(ctx->input, "s:", 2) ? "string" : "hexadecimal");
		}
		if (!run(ctx, io, !strncmp(ctx->input, "s:", 2) ? "string" : "hexadecimal")) {
			goto rz_hash_context_run_end;
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_end(ctx->pj);
		}
	} else {
		for (ut32 i = 0; i < ctx->nfiles; ++i) {
			desc = rz_io_open_nomap(io, ctx->files[i], RZ_PERM_R, 0);
			if (!desc) {
				RZ_LOG_ERROR("rz-hash: error, cannot open file '%s'\n", ctx->files[i]);
				goto rz_hash_context_run_end;
			}
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_ka(ctx->pj, ctx->files[i]);
			}
			if (!run(ctx, io, ctx->files[i])) {
				goto rz_hash_context_run_end;
			}
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_end(ctx->pj);
			}
			rz_io_desc_close(desc);
			desc = NULL;
		}
	}
	if (ctx->mode == RZ_HASH_MODE_JSON) {
		pj_end(ctx->pj);
		printf("%s\n", pj_string(ctx->pj));
	}
	result = true;

rz_hash_context_run_end:
	rz_io_desc_close(desc);
	rz_io_free(io);
	return result;
}

static void hash_print_crypto(RzHashContext *ctx, const char *hname, const ut8 *buffer, int len, ut64 from, ut64 to) {
	char *value = ctx->operation == RZ_HASH_OP_ENCRYPT ? malloc(len * 2 + 1) : malloc(len + 1);
	if (!value) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate value memory\n");
		return;
	}

	if (ctx->operation == RZ_HASH_OP_ENCRYPT) {
		for (int i = 0, bsize; i < len; i++) {
			bsize = (len - i) * 2 + 1;
			snprintf(value + (i * 2), bsize, "%02x", buffer[i]);
		}
	} else {
		memcpy(value, buffer, len);
		value[len] = 0;
	}

	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		pj_kn(ctx->pj, "from", from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", hname);
		pj_ks(ctx->pj, "value", value);
		break;
	case RZ_HASH_MODE_RANDOMART:
	case RZ_HASH_MODE_STANDARD:
		printf("0x%08" PFMT64x "-0x%08" PFMT64x " %s: ", from, to, hname);
		fflush(stdout);
		if (write(1, buffer, len) != len) {
			RZ_LOG_ERROR("rz-hash: error, cannot write on stdout\n");
		}
		printf("\n");
		break;
	case RZ_HASH_MODE_QUIET:
		printf("%s: ", hname);
		fflush(stdout);
		if (write(1, buffer, len) != len) {
			RZ_LOG_ERROR("rz-hash: error, cannot write on stdout\n");
		}
		printf("\n");
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		if (write(1, buffer, len) != len) {
			RZ_LOG_ERROR("rz-hash: error, cannot write on stdout\n");
		}
		break;
	}
	free(value);
}

static void hash_print_digest(RzHashContext *ctx, RzHashCfg *md, const char *hname, ut64 from, ut64 to, const char *filename) {
	RzHashSize len = 0;
	char *value = NULL;
	char *rndart = NULL;
	const ut8 *buffer;

	buffer = rz_hash_cfg_get_result(md, hname, &len);
	value = rz_hash_cfg_get_result_string(md, hname, NULL, ctx->little_endian);
	if (!value || !buffer) {
		free(value);
		return;
	}

	bool has_seed = !ctx->iv && ctx->seed.len > 0;
	const char *hmac = ctx->key.len > 0 ? "hmac-" : "";

	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		pj_kb(ctx->pj, "seed", has_seed);
		pj_kb(ctx->pj, "hmac", ctx->key.len > 0);
		pj_kn(ctx->pj, "from", from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", hname);
		pj_ks(ctx->pj, "value", value);
		break;
	case RZ_HASH_MODE_STANDARD:
		printf("%s: 0x%08" PFMT64x "-0x%08" PFMT64x " %s%s: %s%s\n", filename, from, to, hmac, hname, value, has_seed ? " with seed" : "");
		break;
	case RZ_HASH_MODE_RANDOMART:
		rndart = rz_hash_cfg_randomart(buffer, len, from);
		printf("%s%s\n%s\n", hmac, hname, rndart);
		break;
	case RZ_HASH_MODE_QUIET:
		printf("%s: %s%s: %s\n", filename, hmac, hname, value);
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		puts(value);
		break;
	}
	free(value);
	free(rndart);
}

static void hash_context_compare_hashes(RzHashContext *ctx, size_t filesize, bool result, const char *hname, const char *filename) {
	ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
	const char *hmac = ctx->key.len > 0 ? "hmac-" : "";
	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		pj_kb(ctx->pj, "seed", ctx->seed.len > 0);
		pj_kb(ctx->pj, "hmac", ctx->key.len > 0);
		pj_kb(ctx->pj, "compare", result);
		pj_kn(ctx->pj, "from", ctx->offset.from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", hname);
		break;
	case RZ_HASH_MODE_RANDOMART:
	case RZ_HASH_MODE_STANDARD:
		printf("%s: 0x%08" PFMT64x "-0x%08" PFMT64x " %s%s: computed hash %s the expected one\n", filename, ctx->offset.from, to, hmac, hname, result ? "matches" : "doesn't match");
		break;
	case RZ_HASH_MODE_QUIET:
		printf("%s: %s%s: computed hash %s the expected one\n", filename, hmac, hname, result ? "matches" : "doesn't match");
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		printf("%s", result ? "true" : "false");
		break;
	}
}

static RzList /*<char *>*/ *parse_hash_algorithms(RzHashContext *ctx) {
	if (strcmp(ctx->algorithm, "all")) {
		return rz_str_split_list(ctx->algorithm, ",", 0);
	}

	RzList *list = rz_list_newf(NULL);
	if (!list) {
		return NULL;
	}
	RzIterator *iter = ht_sp_as_iter(ctx->rh->plugins);
	RzList *plugin_list = rz_list_new_from_iterator(iter);
	if (!plugin_list) {
		rz_iterator_free(iter);
		return NULL;
	}
	rz_list_sort(plugin_list, (RzListComparator)rz_hash_plugin_cmp, NULL);
	RzListIter *it;
	const RzHashPlugin *rmdp;
	rz_list_foreach (plugin_list, it, rmdp) {
		rz_list_append(list, (void *)rmdp->name);
	}
	rz_list_free(plugin_list);
	rz_iterator_free(iter);
	return list;
}

static bool calculate_hash(RzHashContext *ctx, RzIO *io, const char *filename) {
	bool result = false;
	const char *algorithm;
	RzList *algorithms = NULL;
	RzListIter *it;
	RzHashCfg *md = NULL;
	ut64 bsize = 0;
	ut64 filesize;
	ut8 *block = NULL;
	ut8 *cmphash = NULL;
	const ut8 *digest = NULL;
	RzHashSize digest_size = 0;

	algorithms = parse_hash_algorithms(ctx);
	if (!algorithms || rz_list_length(algorithms) < 1) {
		RZ_LOG_ERROR("rz-hash: error, empty list of hash algorithms\n");
		goto calculate_hash_end;
	}

	filesize = rz_io_desc_size(io->desc);

	md = rz_hash_cfg_new(ctx->rh);
	if (!md) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate hash context memory\n");
		goto calculate_hash_end;
	}

	if (ctx->offset.to > filesize) {
		RZ_LOG_ERROR("rz-hash: error, -t value is greater than file size\n");
		goto calculate_hash_end;
	}

	if (ctx->offset.from > filesize) {
		RZ_LOG_ERROR("rz-hash: error, -f value is greater than file size\n");
		goto calculate_hash_end;
	}

	bsize = ctx->block_size;
	block = malloc(bsize);
	if (!block) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
		goto calculate_hash_end;
	}

	rz_list_foreach (algorithms, it, algorithm) {
		if (!rz_hash_cfg_configure(md, algorithm)) {
			goto calculate_hash_end;
		}
	}

	if (ctx->key.len > 0 && !rz_hash_cfg_hmac(md, ctx->key.buf, ctx->key.len)) {
		goto calculate_hash_end;
	}

	if (ctx->compare) {
		ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
		size_t cmphashlen = 0;
		bool result = false;

		if (!hash_parse_hexadecimal("-c", ctx->compare, &cmphash, &cmphashlen)) {
			// RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
			goto calculate_hash_end;
		}

		if (!rz_hash_cfg_init(md)) {
			goto calculate_hash_end;
		}

		if (ctx->as_prefix && ctx->seed.buf &&
			!rz_hash_cfg_update(md, ctx->seed.buf, ctx->seed.len)) {
			goto calculate_hash_end;
		}

		for (ut64 j = ctx->offset.from; j < to; j += bsize) {
			int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
			if (!rz_hash_cfg_update(md, block, read)) {
				goto calculate_hash_end;
			}
		}

		if (!ctx->as_prefix && ctx->seed.buf &&
			!rz_hash_cfg_update(md, ctx->seed.buf, ctx->seed.len)) {
			goto calculate_hash_end;
		}
		if (!rz_hash_cfg_final(md) ||
			!rz_hash_cfg_iterate(md, ctx->iterate)) {
			goto calculate_hash_end;
		}

		rz_list_foreach (algorithms, it, algorithm) {
			digest = rz_hash_cfg_get_result(md, algorithm, &digest_size);
			if (digest_size != cmphashlen) {
				result = false;
			} else {
				result = !memcmp(cmphash, digest, digest_size);
			}

			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_o(ctx->pj);
			}
			hash_context_compare_hashes(ctx, filesize, result, algorithm, filename);
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_end(ctx->pj);
			}
		}
	} else if (ctx->show_blocks) {
		ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
		for (ut64 j = ctx->offset.from; j < to; j += bsize) {
			int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
			if (!rz_hash_cfg_init(md) ||
				!rz_hash_cfg_update(md, block, read) ||
				!rz_hash_cfg_final(md) ||
				!rz_hash_cfg_iterate(md, ctx->iterate)) {
				goto calculate_hash_end;
			}

			rz_list_foreach (algorithms, it, algorithm) {
				digest = rz_hash_cfg_get_result(md, algorithm, &digest_size);
				if (ctx->mode == RZ_HASH_MODE_JSON) {
					pj_o(ctx->pj);
				}
				hash_print_digest(ctx, md, algorithm, j, j + bsize, filename);
				if (ctx->mode == RZ_HASH_MODE_JSON) {
					pj_end(ctx->pj);
				}
			}
		}
	} else {
		ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
		if (!rz_hash_cfg_init(md)) {
			goto calculate_hash_end;
		}

		if (ctx->as_prefix && ctx->seed.buf &&
			!rz_hash_cfg_update(md, ctx->seed.buf, ctx->seed.len)) {
			goto calculate_hash_end;
		}

		for (ut64 j = ctx->offset.from; j < to; j += bsize) {
			int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
			if (!rz_hash_cfg_update(md, block, read)) {
				goto calculate_hash_end;
			}
		}

		if (!ctx->as_prefix && ctx->seed.buf &&
			!rz_hash_cfg_update(md, ctx->seed.buf, ctx->seed.len)) {
			goto calculate_hash_end;
		}

		if (!rz_hash_cfg_final(md) ||
			!rz_hash_cfg_iterate(md, ctx->iterate)) {
			goto calculate_hash_end;
		}

		rz_list_foreach (algorithms, it, algorithm) {
			digest = rz_hash_cfg_get_result(md, algorithm, &digest_size);

			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_o(ctx->pj);
			}
			hash_print_digest(ctx, md, algorithm, ctx->offset.from, to, filename);
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_end(ctx->pj);
			}
		}
	}
	result = true;

calculate_hash_end:
	rz_list_free(algorithms);
	free(block);
	free(cmphash);
	rz_hash_cfg_free(md);
	return result;
}

static bool calculate_decrypt(RzHashContext *ctx, RzIO *io, const char *filename) {
	bool result = false;
	ut8 *iv = NULL;
	size_t ivlen = 0;
	ut64 filesize = 0;
	ut64 bsize = 0;
	ut8 *block = NULL;

	if (ctx->iv) {
		if (!strncmp(ctx->iv, "s:", 2)) {
			if (!hash_parse_string("-I", ctx->iv + 2, &iv, &ivlen)) {
				goto calculate_decrypt_end;
			}
		} else {
			if (!hash_parse_hexadecimal("-I", ctx->iv, &iv, &ivlen)) {
				goto calculate_decrypt_end;
			}
		}
	}

	rz_crypto_reset(ctx->rc);
	if (!rz_crypto_use(ctx->rc, ctx->algorithm)) {
		RZ_LOG_ERROR("rz-hash: error, unknown encryption algorithm '%s'\n", ctx->algorithm);
		goto calculate_decrypt_end;
	}

	if (!rz_crypto_set_key(ctx->rc, ctx->key.buf, ctx->key.len, 0, RZ_CRYPTO_DIR_DECRYPT)) {
		RZ_LOG_ERROR("rz-hash: error, invalid key\n");
		goto calculate_decrypt_end;
	}

	if (iv && !rz_crypto_set_iv(ctx->rc, iv, ivlen)) {
		RZ_LOG_ERROR("rz-hash: error, invalid IV.\n");
		goto calculate_decrypt_end;
	}

	filesize = rz_io_desc_size(io->desc);
	if (filesize < 1) {
		RZ_LOG_ERROR("rz-hash: error, file size is less than 1\n");
		goto calculate_decrypt_end;
	}

	bsize = ctx->block_size;
	block = malloc(bsize);
	if (!block) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
		goto calculate_decrypt_end;
	}

	ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
	for (ut64 j = ctx->offset.from; j < to; j += bsize) {
		int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
		rz_crypto_update(ctx->rc, block, read);
	}

	rz_crypto_final(ctx->rc, NULL, 0);

	int plaintext_size = 0;
	const ut8 *plaintext = rz_crypto_get_output(ctx->rc, &plaintext_size);

	hash_print_crypto(ctx, ctx->algorithm, plaintext, plaintext_size, ctx->offset.from, to);
	result = true;

calculate_decrypt_end:
	free(block);
	free(iv);
	return result;
}

static bool calculate_encrypt(RzHashContext *ctx, RzIO *io, const char *filename) {
	bool result = false;
	ut8 *iv = NULL;
	size_t ivlen = 0;
	ut64 filesize = 0;
	ut64 bsize = 0;
	ut8 *block = NULL;

	bool requires_key = !strncmp("base", ctx->algorithm, 4) || !strcmp("punycode", ctx->algorithm);
	if (!requires_key && ctx->key.len < 1) {
		RZ_LOG_ERROR("rz-hash: error, cannot encrypt without a key\n");
		goto calculate_encrypt_end;
	}

	if (ctx->iv) {
		if (!strncmp(ctx->iv, "s:", 2)) {
			if (!hash_parse_string("-I", ctx->iv + 2, &iv, &ivlen)) {
				goto calculate_encrypt_end;
			}
		} else {
			if (!hash_parse_hexadecimal("-I", ctx->iv, &iv, &ivlen)) {
				goto calculate_encrypt_end;
			}
		}
	}

	rz_crypto_reset(ctx->rc);
	if (!rz_crypto_use(ctx->rc, ctx->algorithm)) {
		RZ_LOG_ERROR("rz-hash: error, unknown encryption algorithm '%s'\n", ctx->algorithm);
		goto calculate_encrypt_end;
	}

	if (!rz_crypto_set_key(ctx->rc, ctx->key.buf, ctx->key.len, 0, RZ_CRYPTO_DIR_ENCRYPT)) {
		RZ_LOG_ERROR("rz-hash: error, invalid key\n");
		goto calculate_encrypt_end;
	}

	if (iv && !rz_crypto_set_iv(ctx->rc, iv, ivlen)) {
		RZ_LOG_ERROR("rz-hash: error, invalid IV.\n");
		goto calculate_encrypt_end;
	}

	filesize = rz_io_desc_size(io->desc);
	if (filesize < 1) {
		RZ_LOG_ERROR("rz-hash: error, file size is less than 1\n");
		goto calculate_encrypt_end;
	}

	bsize = ctx->block_size;
	block = malloc(bsize);
	if (!block) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
		goto calculate_encrypt_end;
	}

	ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
	for (ut64 j = ctx->offset.from; j < to; j += bsize) {
		int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
		rz_crypto_update(ctx->rc, block, read);
	}

	rz_crypto_final(ctx->rc, NULL, 0);

	int ciphertext_size = 0;
	const ut8 *ciphertext = rz_crypto_get_output(ctx->rc, &ciphertext_size);

	hash_print_crypto(ctx, ctx->algorithm, ciphertext, ciphertext_size, ctx->offset.from, to);
	result = true;

calculate_encrypt_end:
	free(block);
	free(iv);
	return result;
}

static bool calculate_luhn(RzHashContext *ctx, RzIO *io, const char *filename) {
	char value[128];
	const char *input = ctx->input + 2;
	ut64 to = ctx->offset.to ? ctx->offset.to : strlen(input);
	ut64 from = ctx->offset.from;
	ut64 result = 0;

	if (!rz_calculate_luhn_value(input, &result)) {
		RZ_LOG_ERROR("rz-hash: error, input string is not a number\n");
		return false;
	}

	snprintf(value, sizeof(value), "%" PFMT64u, result);
	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		pj_o(ctx->pj);
		pj_kb(ctx->pj, "seed", false);
		pj_kb(ctx->pj, "hmac", false);
		pj_kn(ctx->pj, "from", from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", ctx->algorithm);
		pj_ks(ctx->pj, "value", value);
		pj_end(ctx->pj);
		break;
	case RZ_HASH_MODE_STANDARD:
		printf("%s: 0x%08" PFMT64x "-0x%08" PFMT64x " %s: %s\n", filename, from, to, ctx->algorithm, value);
		break;
	case RZ_HASH_MODE_RANDOMART:
	case RZ_HASH_MODE_QUIET:
		printf("%s: %s: %s\n", filename, ctx->algorithm, value);
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		puts(value);
		break;
	}
	return true;
}

static bool lib_hash_cb(RzLibPlugin *pl, void *user, void *data) {
	RzHashPlugin *hand = (RzHashPlugin *)data;
	RzHashContext *ctx = (RzHashContext *)user;
	return rz_hash_plugin_add(ctx->rh, hand);
}

static bool lib_crypto_cb(RzLibPlugin *pl, void *user, void *data) {
	RzHashContext *ctx = (RzHashContext *)user;
	return rz_crypto_plugin_add(ctx->rc, data);
}

static void hash_load_plugins(RzHashContext *ctx) {
	char *tmp = rz_sys_getenv("RZ_NOPLUGINS");
	if (tmp) {
		free(tmp);
		return;
	}
	RzLib *rl = rz_lib_new(NULL, NULL);
	rz_lib_add_handler(rl, RZ_LIB_TYPE_HASH, "hash plugins", &lib_hash_cb, NULL, ctx);
	rz_lib_add_handler(rl, RZ_LIB_TYPE_CRYPTO, "crypto plugins", &lib_crypto_cb, NULL, ctx);

	char *path = rz_sys_getenv(RZ_LIB_ENV);
	if (!RZ_STR_ISEMPTY(path)) {
		rz_lib_opendir(rl, path, false);
	}

	char *homeplugindir = rz_path_home_prefix(RZ_PLUGINS);
	char *sysplugindir = rz_path_system(RZ_PLUGINS);
	char *extraplugindir = rz_path_system(RZ_PLUGINS);
	rz_lib_opendir(rl, homeplugindir, false);
	rz_lib_opendir(rl, sysplugindir, false);
	if (extraplugindir) {
		rz_lib_opendir(rl, extraplugindir, false);
	}
	free(homeplugindir);
	free(sysplugindir);
	free(extraplugindir);

	free(path);
	rz_lib_free(rl);
	free(tmp);
}

RZ_API int rz_main_rz_hash(int argc, const char **argv) {
	int result = 1;
	RzHashContext ctx = { 0 };
	ctx.rh = rz_hash_new();
	ctx.rc = rz_crypto_new();
	hash_load_plugins(&ctx);

	hash_parse_cmdline(argc, argv, &ctx);

	switch (ctx.operation) {
	case RZ_HASH_OP_LIST_ALGO:
		rz_hash_show_algorithms(&ctx);
		break;
	case RZ_HASH_OP_LUHN:
		if (!hash_context_run(&ctx, calculate_luhn)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_HASH:
		if (!hash_context_run(&ctx, calculate_hash)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_DECRYPT:
		if (!hash_context_run(&ctx, calculate_decrypt)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_ENCRYPT:
		if (!hash_context_run(&ctx, calculate_encrypt)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_VERSION:
		rz_main_version_print("rz-hash");
		break;
	case RZ_HASH_OP_USAGE:
		rz_hash_show_help(true);
		goto rz_main_rz_hash_end;
	case RZ_HASH_OP_ERROR:
		goto rz_main_rz_hash_end;
	case RZ_HASH_OP_HELP:
		result = 0;
		/* fall-thru */
	default:
		rz_hash_show_help(false);
		goto rz_main_rz_hash_end;
	}

	result = 0;

rz_main_rz_hash_end:
	hash_context_fini(&ctx);
	return result;
}
