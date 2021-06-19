typedef struct assembly_line_t {
	char *line;
	ut32 size;
} AsmLine;

typedef struct assembly_bin_t {
	ut8 *binary;
	ut32 size;
} AsmBin;

typedef struct assembly_label_t {
	AsmLine *aline;
	ut32 index;
} AsmLabel;

typedef struct assembler_ctx_t {
	ut32 nlines;
	AsmLine *assembly;
	AsmLine *enriched;
	AsmBin *binary;
	HtPP *expressions;
	HtPP *labels;
} AssemblerCtx;

#define assembler_ctx_bin(actx,nline) (actx->binary[nline].binary)
#define assembler_ctx_size(actx,nline) (actx->binary[nline].size)
#define assembler_ctx_line(actx,nline) (actx->enriched[nline].line)
#define assembler_ctx_line2(actx,nline) (actx->assembly[nline].line)
#define assembler_ctx_length(actx,nline) (actx->enriched[nline].size)

static void assembler_sanitize_line(char *line, st32 size) {
	for (st32 i = 0; i < size; ++i) {
		if (!IS_PRINTABLE(line[i])) {
			line[i] = ' ';
		}
	}
}

static bool assembler_bin_cpy(AsmBin *ab, ut32 idx, const ut8 *binary, st32 size) {
	if (size < 1 || !(ab[idx].binary = malloc(size))) {
		return false;
	}

	memcpy(ab[idx].binary, binary, size);
	ab[idx].size = size;
	return true;
}

static bool assembler_bin_set(AsmBin *ab, ut32 idx, ut8 *binary, st32 size) {
	if (!binary) {
		return false;
	}
	ab[idx].binary = binary;
	ab[idx].size = size;
	return true;
}

static void assembler_bin_free(AsmBin *ab, ut32 nlines) {
	for (ut32 i = 0; i < nlines; ++i) {
		free(ab[i].binary);
	}
	free(ab);
}

static bool assembler_line_set(AsmLine *al, ut32 idx, const char *line, st32 size, bool trim) {
	char *copy = rz_str_ndup(line, size);
	if (size > 0 && !copy) {
		rz_warn_if_reached();
		return false;
	}
	assembler_sanitize_line(copy, size);
	if (trim) {
		rz_str_trim(copy);
		size = strlen(copy);
		if (size < 1) {
			free(copy);
			copy = NULL;
		}
	}
	al[idx].line = copy;
	al[idx].size = size;
	return true;
}

static void assembler_line_free(AsmLine *al, ut32 nlines) {
	for (ut32 i = 0; i < nlines; ++i) {
		free(al[i].line);
	}
	free(al);
}

static bool assembler_line_apply_label(AssemblerCtx *actx, const char *label, AsmLabel *current) {
	char* p = NULL;
	char number[32] = {0};
	ut64 pc = 0;
	ut32 index = current->index;
	ut32 nlines = actx->nlines;
	if (!current->aline->line || !label) {
		return false;
	}

	const char *substr = strstr(current->aline->line, label);
	if (!substr) {
		return false;
	}
	ut32 prefix = substr - current->aline->line;
	for (ut32 i = 0; i < nlines; ++i) {
		if (index == i) {
			continue;
		}
		char *line = actx->enriched[i].line;
		if (line && (p = strstr(line, label))) {
			// verify that is not a mnemonic or in the middle of a word.
			if (line == p || !IS_WHITECHAR(p[-1])) {
				continue;
			}
			p += strlen(label);
			// verify that ends with \0 or space
			if (RZ_STR_ISNOTEMPTY(p) && !IS_WHITECHAR(p[0])) {
				continue;
			}

			pc = 0;
			if (i < index) {
				eprintf("i < index %s\n", line);
				for (ut32 j = i + 1; j < index && j < nlines; ++j) {
					if (RZ_STR_ISEMPTY(actx->enriched[j].line)) {
						continue;
					}
					ut32 size = actx->binary[j].size;
					eprintf("%d/%d PC: %llx '%s': bytes: %u\n", j, index, pc, actx->enriched[j].line, size);
					if (!size) {
						eprintf("invalid size '%s'\n", actx->enriched[j].line);
						return false;
					}
					pc += size;
				}
				snprintf(number, sizeof(number), "0x%" PFMT64x, pc);
			} else {
				eprintf("index < i %s\n", line);
				for (ut32 j = index + 1; j < i && j < nlines; ++j) {
					if (RZ_STR_ISEMPTY(actx->enriched[j].line)) {
						continue;
					}
					ut32 size = actx->binary[j].size;
					eprintf("PC: %llx '%s': bytes: %u\n", pc, actx->enriched[j].line, size);
					if (!size) {
						eprintf("invalid size '%s'\n", actx->enriched[j].line);
						return false;
					}
					pc += size;
				}
				snprintf(number, sizeof(number), "-0x%" PFMT64x, pc);
			}
			actx->enriched[i].line = rz_str_replace(line, label, number, 0);
		}
	}
	return true;
}

static bool assembler_line_is_label(AssemblerCtx *actx, ut32 nline) {
	const char *p = assembler_ctx_line(actx, nline);
	ut32 s = assembler_ctx_length(actx, nline);

	if (!p || p[s - 1] != ':') {
		return false;
	}
	for (st32 i = 0; i < (s - 1); ++i) {
		if (!IS_DIGIT(p[i]) && !IS_UPPER(p[i]) &&
			!IS_LOWER(p[i]) && p[i] != '_') {
			return false;
		}
	}

	return true;
}

static void assembler_ctx_free(AssemblerCtx *actx) {
	if (!actx) {
		return;
	}
	assembler_line_free(actx->assembly, actx->nlines);
	assembler_line_free(actx->enriched, actx->nlines);
	assembler_bin_free(actx->binary, actx->nlines);
	ht_pp_free(actx->expressions);
	ht_pp_free(actx->labels);
	free(actx);
}

#define SPACE_PADDING      "                                                               "
#define ERROR_PADDING      "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#define ERROR_PADDING_SIZE (sizeof(ERROR_PADDING) - 1)
#define assembler_error_nline(nline, error, ...) \
	do { \
		RZ_LOG_ERROR("[!] assembler: line %u: " error "\n", nline + 1, ##__VA_ARGS__); \
	} while (0)
#define assembler_error_sline(line, size, where, nline, error, ...) \
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
#define assembler_error_line(actx, nline, where, error, ...) \
	do { \
		ut32 size = assembler_ctx_length(actx, nline); \
		const char* line = assembler_ctx_line(actx, nline); \
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

static void assembler_kv_free(HtPPKv *kv) {
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

	if (!(actx->assembly = RZ_NEWS0(AsmLine, nlines))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!(actx->enriched = RZ_NEWS0(AsmLine, nlines))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!(actx->binary = RZ_NEWS0(AsmBin, nlines))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!(actx->expressions = ht_pp_new((HtPPDupValue)strdup, (HtPPKvFreeFunc)assembler_kv_free, NULL))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}

	if (!(actx->labels = ht_pp_new((HtPPDupValue)strdup, (HtPPKvFreeFunc)assembler_kv_free, NULL))) {
		rz_warn_if_reached();
		goto assembler_ctx_new_fail;
	}
	actx->nlines = nlines;

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
			assembler_error_sline(input + lastnl, lsize, where, line,
				" missing string delim %c at position %u", input[delim], where);
			goto assembler_ctx_new_fail;

		} else if (delim && ASM_IS_STRING_DELIM(input[i])) {
			delim = 0;

		} else if (is_comment && ASM_IS_EOL(input[i])) {
			is_comment = false;
			lsize = i - lastnl;
			if (!assembler_line_set(actx->assembly, line, input + lastnl, lsize, false)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

			line++;
			lastnl = i + 1;

		} else if (!is_comment && ASM_IS_COMMENT(input[i])) {
			is_comment = true;
			lsize = i - lastnl;
			if (!assembler_line_set(actx->enriched, line, input + lastnl, lsize, true)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

		} else if (!is_comment && !delim && ASM_IS_EOL_OR_COMMENT(input[i])) {
			lsize = i - lastnl;
			if (!assembler_line_set(actx->assembly, line, input + lastnl, lsize, false)) {
				rz_warn_if_reached();
				goto assembler_ctx_new_fail;
			}

			if (!assembler_line_set(actx->enriched, line, input + lastnl, lsize, true)) {
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
		for (ut32 i = 0; i < actx->nlines; ++i) {
			const char* p = assembler_ctx_line(actx, i);
			eprintf("+++ %4u: %-5d '%s'\n", i + 1, assembler_ctx_length(actx, i), p ? p : "");
		}
	} else {
		for (ut32 i = 0; i < actx->nlines; ++i) {
			eprintf("--- %4u: %-5d '%s'\n", i + 1, assembler_ctx_length(actx, i), assembler_ctx_line2(actx, i));
		}
	}
}

static void assembler_ctx_hex(AssemblerCtx *actx, ut32 nline) {
	const ut8 *bin = (ut8 *)assembler_ctx_bin(actx, nline);
	ut32 size = assembler_ctx_size(actx, nline);
	for (ut32 i = 0; i < size; i++) {
		eprintf("%02x", bin[i]);
	}
	eprintf("\n");
}

#include "assembler_directives.c"

RZ_API RzAsmCode *rz_asm_massemble(RzAsm *a, const char *assembly) {
	RzAsmCode *acode = NULL;
	AssemblerCtx *actx = assembler_ctx_new(assembly);

	if (!actx) {
		rz_warn_if_reached();
		return NULL;
	}

	if (!(acode = rz_asm_code_new())) {
		rz_warn_if_reached();
		goto rz_asm_massemble_fail;
	}

	//assembler_ctx_debug(actx, false);
	assembler_ctx_debug(actx, true);
	char *line = NULL;
	const char *directive = NULL;
	const ut8 *bin = NULL;
	int opsize = 0;
	ut32 size = 0, dsize = 0;
	ut64 pc = 0;
	RzAsmOp op = { 0 };
	bool complete = false;
	bool inserted = false;

	// resolve expressions
	for (ut32 i = 0; i < actx->nlines; ++i) {
		size = assembler_ctx_length(actx, i);
		line = assembler_ctx_line(actx, i);
		if (size < 1 || line[0] != '.') {
			continue;
		}

		for (ut32 k = 0; k < RZ_ARRAY_SIZE(assembler_directives_expression); ++k) {
			dsize = assembler_directives_expression[k].dirsize;
			if (dsize > size) {
				continue;
			}
			directive = assembler_directives_expression[k].directive;
			if (!rz_str_ncasecmp(line, directive, dsize)) {
				eprintf("exp  %4u: %-5d '%s'\n", i + 1, size, line);
				if (!assembler_directives_expression[k].parse(a, actx, i, dsize + 1, pc)) {
					goto rz_asm_massemble_fail;
				}
			}
		}
	}

	// resolve data directives
	for (ut32 i = 0; i < actx->nlines; ++i) {
		if (assembler_ctx_length(actx, i) < 1) {
			continue;
		}
		size = assembler_ctx_length(actx, i);
		line = assembler_ctx_line(actx, i);
		if (size < 1 || line[0] != '.') {
			continue;
		}

		for (ut32 k = 0; k < RZ_ARRAY_SIZE(assembler_directives_data); ++k) {
			dsize = assembler_directives_data[k].dirsize;
			if (dsize > size) {
				continue;
			}
			directive = assembler_directives_data[k].directive;
			if (!rz_str_ncasecmp(line, directive, dsize)) {
				eprintf("dir  %4u: %-5d '%s'\n", i + 1, size, line);
				if (!assembler_directives_data[k].parse(a, actx, i, dsize + 1, pc)) {
					goto rz_asm_massemble_fail;
				}
			}
		}
	}

	// resolve assemble
	pc = 0;
	complete = true;
	for (ut32 i = 0; i < actx->nlines; ++i) {
		size = assembler_ctx_length(actx, i);
		line = assembler_ctx_line(actx, i);
		if (size < 1) {
			continue;
		}

		if (line[0] == '.') {
			for (ut32 k = 0; k < RZ_ARRAY_SIZE(assembler_directives_text); ++k) {
				dsize = assembler_directives_text[k].dirsize;
				if (dsize > size) {
					continue;
				}
				directive = assembler_directives_text[k].directive;
				if (!rz_str_ncasecmp(line, directive, dsize)) {
					eprintf("txt0 %4u: %-5d '%s'\n", i + 1, size, line);
					if (!assembler_directives_text[k].parse(a, actx, i, dsize + 1, pc)) {
						goto rz_asm_massemble_fail;
					}
				}
			}
			continue;
		}

		if (assembler_line_is_label(actx, i)) {
			AsmLabel *al = RZ_NEW0(AsmLabel);
			if (!al) {
				assembler_error_line(actx, i, 0, "cannot allocate label for hashmap.\n");
				goto rz_asm_massemble_fail;
			}
			al->aline = &actx->enriched[i];
			al->index = i;

			line[size - 1] = 0;
			inserted = ht_pp_insert(actx->labels, line, al);
			line[size - 1] = ':';
			if (!inserted) {
				assembler_error_line(actx, i, 0, "cannot insert label in hashmap.\n");
				goto rz_asm_massemble_fail;
			}
			continue;
		}

		if (!a->cur) {
			assembler_error_line(actx, i, 0, " cannot compile without knowing the architecture\n");
			goto rz_asm_massemble_fail;
		}

		rz_asm_op_init(&op);
		ht_pp_foreach(actx->labels, (HtPPForeachCallback)assembler_line_apply_label, actx);
		if ((opsize = rz_asm_assemble(a, &op, assembler_ctx_line(actx, i))) < 1) {
			rz_asm_op_fini(&op);
			complete = false;
			continue;
		}
		const ut8 *bin = (ut8 *)rz_strbuf_get(&op.buf);
		assembler_bin_cpy(actx->binary, i, bin, opsize);
		eprintf("lab0 %4u: %-5u '%s' -> opsize: %d\n", i + 1, size, line, opsize);
		rz_asm_op_fini(&op);
		pc += opsize;
	}

	// resolve initial labels and assembly
	if (!complete) {
		pc = 0;
		complete = true;
		for (ut32 i = 0; i < actx->nlines; ++i) {
			size = assembler_ctx_length(actx, i);
			line = assembler_ctx_line(actx, i);
			if (size < 1 || line[0] == '.' || assembler_ctx_bin(actx, i)) {
				continue;
			}
			eprintf("lab1 %4u: %-5u '%s'\n", i + 1, size, line);
			ht_pp_foreach(actx->labels, (HtPPForeachCallback)assembler_line_apply_label, actx);
		}
	}

	// resolve remaining labels and assembly
	if (!complete) {
		pc = 0;
		complete = true;
		for (ut32 i = 0; i < actx->nlines; ++i) {
			size = assembler_ctx_length(actx, i);
			line = assembler_ctx_line(actx, i);
			if (size < 1 || line[0] == '.' || assembler_ctx_bin(actx, i)) {
				continue;
			}
			eprintf("lab2 %4u: %-5u '%s'\n", i + 1, size, line);
			ht_pp_foreach(actx->labels, (HtPPForeachCallback)assembler_line_apply_label, actx);
		}
	}


	// resolve calculate size and concat
	size = 0;
	for (ut32 i = 0; i < actx->nlines; ++i) {
		if (!assembler_ctx_bin(actx, i)) {
			continue;
		}
		size += assembler_ctx_size(actx, i);
	}

	if (!(acode->bytes = malloc(size))) {
		rz_warn_if_reached();
		goto rz_asm_massemble_fail;
	}
	acode->len = size;

	for (ut64 i = 0, offset = 0; i < actx->nlines; ++i) {
		if (!assembler_ctx_bin(actx, i)) {
			continue;
		}
		size = assembler_ctx_length(actx, i);
		line = assembler_ctx_line(actx, i);
		eprintf("bin  %4llu: %-5u %-10s ", i + 1, size, line);

		bin = (ut8 *)assembler_ctx_bin(actx, i);
		size = assembler_ctx_size(actx, i);
		assembler_ctx_hex(actx, i);

		memcpy(acode->bytes + offset, bin, size);

		offset += size;
	}

	assembler_ctx_free(actx);
	return acode;

rz_asm_massemble_fail:
	assembler_ctx_free(actx);
	rz_asm_code_free(acode);
	return NULL;
}