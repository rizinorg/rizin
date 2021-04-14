typedef struct assembly_text_t {
	ut32 nlines;
	char **lines;
	ut32 *lsizes;
	ut8 **binary;
	ut32 *bsizes;
} AsmText;

typedef struct assembler_ctx_t {
	AsmText assembly;
	AsmText enriched;
	HtPP *expressions;
} AssemblerCtx;

static void assembler_sanitize_line(char *line, st32 size) {
	for (st32 i = 0; i < size; ++i) {
		if (!IS_PRINTABLE(line[i])) {
			line[i] = ' ';
		}
	}
}

static bool assembler_text_bin(AsmText *at, ut32 idx, ut8 *binary, st32 size) {
	if (size < 1 || !(at->binary[idx] = malloc(size))) {
		return false;
	}

	memcpy(at->binary[idx], binary, size);
	at->bsizes[idx] = size;
	return true;
}

static bool assembler_text_line(AsmText *at, ut32 idx, const char *line, st32 size, bool trim) {
	char *copy = rz_str_ndup(line, size);
	if (size > 0 && !copy) {
		return false;
	}
	if (trim) {
		rz_str_trim(copy);
		size = strlen(copy);
		if (size < 1) {
			free(copy);
			copy = NULL;
		}
	}
	assembler_sanitize_line(copy, size);
	at->lines[idx] = copy;
	at->lsizes[idx] = size;
	return true;
}

static void assembler_text_fini(AsmText *at) {
	for (ut32 i = 0; i < at->nlines; ++i) {
		free(at->lines[i]);
	}
	if (at->binary) {
		for (ut32 i = 0; i < at->nlines; ++i) {
			free(at->binary[i]);
		}
		free(at->bsizes);
		free(at->binary);
	}
	free(at->lsizes);
	free(at->lines);
}

static bool assembler_text_init(AsmText *at, ut32 nlines, bool binary) {
	if (!(at->lsizes = RZ_NEWS0(ut32, nlines))) {
		goto assembler_text_init_fail;
	}

	if (!(at->lines = RZ_NEWS0(char *, nlines))) {
		goto assembler_text_init_fail;
	}

	if (binary) {
		if (!(at->bsizes = RZ_NEWS0(ut32, nlines))) {
			goto assembler_text_init_fail;
		}

		if (!(at->binary = RZ_NEWS0(ut8 *, nlines))) {
			goto assembler_text_init_fail;
		}
	}

	at->nlines = nlines;
	return true;

assembler_text_init_fail:
	assembler_text_fini(at);
	return false;
}

static void assembler_ctx_free(AssemblerCtx *actx) {
	if (!actx) {
		return;
	}
	assembler_text_fini(&actx->assembly);
	assembler_text_fini(&actx->enriched);
	ht_pp_free(actx->expressions);
	free(actx);
}

#define SPACE_PADDING      "                                                               "
#define ERROR_PADDING      "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#define ERROR_PADDING_SIZE (sizeof(ERROR_PADDING) - 1)
#define assembler_error_nline(nline, error, ...) \
	do { \
		RZ_LOG_ERROR("[!] assembler: line %u: " error "\n", nline + 1, ##__VA_ARGS__); \
	} while (0)
#define assembler_error_line(line, size, where, nline, error, ...) \
	do { \
		if (size > 0) { \
			RZ_LOG_ERROR("[!] assembler: line %u: %.*s\n", nline + 1, size, line); \
			if (size < ERROR_PADDING_SIZE) { \
				const char *spc = SPACE_PADDING; \
				const char *pad = ERROR_PADDING; \
				RZ_LOG_ERROR("[!] assembler: line %u: %.*s%.*s\n", nline + 1, where, spc, size - where, pad); \
			} \
		} \
		RZ_LOG_ERROR("[!] assembler: line %u: " error "\n", nline + 1, ##__VA_ARGS__); \
	} while (0)


static void assembler_expr_free(HtPPKv *kv) {
	free(kv->key);
	free(kv->value);
}


static AssemblerCtx *assembler_ctx_new(const char *input) {
	ut32 nlines;
	ut32 nullsz, lsize;
	AssemblerCtx *actx = NULL;

	for (nullsz = 0, nlines = 0; input[nullsz]; ++nullsz) {
		if (input[nullsz] == '\n') {
			nlines++;
		}
	}

	if (nullsz < 1) {
		rz_warn_if_reached();
		return NULL;
	}
	nlines++; // always have at least 1 line
	nullsz++; // include null terminator

	if (!(actx = RZ_NEW0(AssemblerCtx))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!assembler_text_init(&actx->assembly, nlines, false)) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!assembler_text_init(&actx->enriched, nlines, true)) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!(actx->expressions = ht_pp_new((HtPPDupValue)strdup, (HtPPKvFreeFunc)assembler_expr_free, NULL))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

#define ASM_IS_EOL(x)            (!(x) || (x) == '\n')
#define ASM_IS_COMMENT(x)        ((x) == ';' || (x) == '#')
#define ASM_IS_EOL_OR_COMMENT(x) (ASM_IS_EOL(x) || ASM_IS_COMMENT(x))
#define ASM_IS_STRING_DELIM(x)   ((x) == '\'' || (x) == '"')
	bool is_comment = false;
	ut32 delim = 0;
	for (ut32 i = 0, lastnl = 0, line = 0; i < nullsz; ++i) {
		if (!i && ASM_IS_STRING_DELIM(input[i])) {
			assembler_error_nline(line, "invalid assembly");
			goto assembler_ctx_new_fail;

		} else if (!delim && ASM_IS_STRING_DELIM(input[i])) {
			delim = i;

		} else if (delim && ASM_IS_EOL(input[i])) {
			lsize = i - lastnl;
			ut32 where = delim - lastnl;
			assembler_error_line(input + lastnl, lsize, where, line,
				" missing string delim %c at position %u", input[delim], where);
			goto assembler_ctx_new_fail;

		} else if (delim && ASM_IS_STRING_DELIM(input[i])) {
			delim = 0;

		} else if (is_comment && ASM_IS_EOL(input[i])) {
			is_comment = false;
			lsize = i - lastnl;
			if (!assembler_text_line(&actx->assembly, line, input + lastnl, lsize, false)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

			line++;
			lastnl = i + 1;

		} else if (!is_comment && ASM_IS_COMMENT(input[i])) {
			is_comment = true;
			lsize = i - lastnl;
			if (!assembler_text_line(&actx->enriched, line, input + lastnl, lsize, true)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

		} else if (!is_comment && !delim && ASM_IS_EOL_OR_COMMENT(input[i])) {
			lsize = i - lastnl;
			if (!assembler_text_line(&actx->assembly, line, input + lastnl, lsize, false)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

			if (!assembler_text_line(&actx->enriched, line, input + lastnl, lsize, true)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

			line++;
			lastnl = i + 1;
		}
	}
#undef ASM_IS_STRING_DELIM
#undef ASM_IS_EOL_OR_COMMENT
#undef ASM_IS_COMMENT
#undef ASM_IS_EOL

	return actx;

assembler_ctx_new_fail:
	assembler_ctx_free(actx);
	return NULL;
}

static void assembler_ctx_debug(AssemblerCtx *actx, bool enriched) {
	if (enriched) {
		for (ut32 i = 0; i < actx->enriched.nlines; ++i) {
			const char* p = actx->enriched.lines[i];
			eprintf("+++ %4u: %-5d '%s'\n", i + 1, actx->enriched.lsizes[i], p ? p : "");
		}
	} else {
		for (ut32 i = 0; i < actx->assembly.nlines; ++i) {
			eprintf("--- %4u: %-5d '%s'\n", i + 1, actx->assembly.lsizes[i], actx->assembly.lines[i]);
		}
	}
}

#include "assembler_directives.c"

static bool assembler_parse_directives_and_labels(RzAsm *a, AssemblerCtx *actx) {
	const char *line, *directive;
	ut32 lsize, dsize;
	// resolve expressions
	for (ut32 i = 0; i < actx->enriched.nlines; ++i) {
		lsize = actx->enriched.lsizes[i];
		line = actx->enriched.lines[i];
		if (lsize < 1 || line[0] != '.') {
			continue;
		}

		for (ut32 k = 0; k < RZ_ARRAY_SIZE(assembler_directives_expression); ++k) {
			dsize = assembler_directives_expression[k].dirsize;
			if (dsize > lsize) {
				continue;
			}
			directive = assembler_directives_expression[k].directive;
			if (!rz_str_ncasecmp(line, directive, dsize)) {
				eprintf("exp %4u: %-5d '%s'\n", i + 1, lsize, line);
				if (!assembler_directives_expression[k].parse(a, actx, line, lsize)) {
					return false;
				}
			}
		}
	}
	// resolve labels
	for (ut32 i = 0; i < actx->enriched.nlines; ++i) {
		if (actx->enriched.lsizes[i] < 1) {
			continue;
		}
		eprintf("lab %4u: %-5d '%s'\n", i + 1, actx->enriched.lsizes[i], actx->enriched.lines[i]);
	}
	return true;
}

RZ_API RzAsmCode *rz_asm_massemble(RzAsm *a, const char *assembly) {
	RzAsmCode *acode = NULL;
	AssemblerCtx *actx = assembler_ctx_new(assembly);

	if (!actx) {
		return NULL;
	}

	if (!(acode = rz_asm_code_new())) {
		goto rz_asm_massemble_fail;
	}

	//assembler_ctx_debug(actx, true);

	if (!assembler_parse_directives_and_labels(a, actx)) {
		goto rz_asm_massemble_fail;
	}


	assembler_ctx_free(actx);
	return rz_asm_code_free(acode); //acode;

rz_asm_massemble_fail:
	assembler_ctx_free(actx);
	rz_asm_code_free(acode);
	return NULL;
}