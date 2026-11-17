// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>
#include <rz_bin.h>
#include <ctype.h>

typedef struct egg_c_config {
	const char *triplet; ///< `<os>-<arch>-<bits>`
	const char *exe_compiler; ///< special compiler to override the normal one.
	const char *add_cflags; ///< CFLAGS to append
	const char *add_ldflags; ///< LDFLAGS to append
	const char *asm_text_segment; ///< hardcoded `.text` segment name to use for dumping the compiled code.
	const char *asm_text_header; ///< hardcoded header of the assembly.
} egg_c_config_t;

// compilation environment
typedef struct c_env_s {
	const char *asm_text_segment; ///< hardcoded `.text` segment name to use for dumping the compiled code.
	const char *asm_text_header; ///< hardcoded header of the assembly.
	char *exe_objcopy; ///< objcopy exec
	char *exe_compiler; ///< compiler exec
	char *cflags; ///< compiler CFLAGS
	char *ldflags; ///< compiler LDFLAGS
} c_env_t;

const egg_c_config_t c_configs[] = {
	{
		/* triplet          */ "ios-arm-32",
		/* exe_compiler     */ "xcrun --sdk iphoneos gcc -arch armv7 -miphoneos-version-min=0.0",
		/* add_cflags       */ "-shared -c -pie -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-shared -c -pie",
		/* asm_text_segment */ "0.__TEXT.__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "b _main\n",
	},
	{
		/* triplet          */ "ios-arm-64",
		/* exe_compiler     */ "xcrun --sdk iphoneos gcc -arch arm64 -miphoneos-version-min=0.0",
		/* add_cflags       */ "-shared -c -pie -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-shared -c -pie",
		/* asm_text_segment */ "0.__TEXT.__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "b _main\n",
	},
	{
		/* triplet          */ "darwin-arm-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-O1 -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-shared -c -pie",
		/* asm_text_segment */ "0..__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "b _main\n",
	},
	{
		/* triplet          */ "darwin-x86-32",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-arch i386 -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-arch i386 -shared -c -pie",
		/* asm_text_segment */ "0..__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "jmp _main\n",
	},
	{
		/* triplet          */ "darwin-x86-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-arch x86_64 -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-arch x86_64 -shared -c -pie",
		/* asm_text_segment */ "0..__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "jmp _main\n",
	},
	{
		/* triplet          */ "linux-arm-32",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -nostartfiles -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -nostartfiles",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "b main\n",
	},
	{
		/* triplet          */ "linux-arm-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -nostartfiles -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -nostartfiles",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "b main\n",
	},
	{
		/* triplet          */ "linux-x86-32",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -m32 -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -m32",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "jmp main\n",
	},
	{
		/* triplet          */ "linux-x86-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -m64 -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -m64",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "jmp main\n",
	},
};

static char *egg_find_executable(const char *env_name, const char *exes[], const size_t length) {
	char *output = rz_sys_getenv(env_name);
	if (RZ_STR_ISNOTEMPTY(output)) {
		return output;
	}

	for (size_t i = 0; i < length; i++) {
		output = rz_file_path(exes[i]);
		if (!output || RZ_STR_EQ(output, exes[i])) {
			free(output);
			continue;
		}
		return output;
	}
	return NULL;
}

static char *egg_find_compiler(const egg_c_config_t *config) {
	if (config->exe_compiler) {
		return rz_str_dup(config->exe_compiler);
	}

	const char *cc_exes[] = { "llvm-gcc", "clang", "gcc" };
	char *found = egg_find_executable("CC", cc_exes, RZ_ARRAY_SIZE(cc_exes));
	if (found) {
		return found;
	}
	RZ_LOG_ERROR("egg: Couldn't find a compiler! Please, set the 'CC' environment variable.\n");
	return NULL;
}

static char *egg_find_objcopy(void) {
	const char *objcopy_exes[] = { "objcopy", "gobjcopy" };
	char *found = egg_find_executable("OBJCOPY", objcopy_exes, RZ_ARRAY_SIZE(objcopy_exes));
	if (found) {
		return found;
	}
	RZ_LOG_WARN("egg: Couldn't find a objcopy! You can set the 'OBJCOPY' environment variable.\n");
	return NULL;
}

static char *egg_find_sflib(RzPath *sys_path, const char *triplet) {
	char *sflib_path = rz_sys_getenv("SFLIBPATH");
	if (RZ_STR_ISNOTEMPTY(sflib_path)) {
		return sflib_path;
	}
	RZ_FREE(sflib_path);
	char *incdir = rz_path_incdir(sys_path);
	sflib_path = rz_str_newf(RZ_JOIN_4_PATHS("%s", "sflib", "%s", "sflib.h"), incdir, triplet);
	free(incdir);

	return sflib_path;
}

static char *egg_get_cflags(const egg_c_config_t *config, RzPath *sys_path, const char *triplet) {
	char *sflib_path = egg_find_sflib(sys_path, triplet);
	char *env_cflags = rz_sys_getenv("CFLAGS");
	char *cflags = rz_str_newf("%s %s"
				   " -fno-stack-protector"
				   " -nostdinc"
				   " -fPIC"
				   " -fPIE"
				   " -include '%s'",
		rz_str_get(env_cflags), rz_str_get(config->add_cflags), rz_str_get(sflib_path));
	free(sflib_path);
	free(env_cflags);
	return cflags;
}

static char *egg_get_ldflags(const egg_c_config_t *config, RzPath *sys_path) {
	char *env_ldflags = rz_sys_getenv("LDFLAGS");
	char *ldflags = rz_str_newf("%s %s"
				    " -fno-stack-protector"
				    " -nostdlib"
				    " -fPIC"
				    " -fPIE",
		rz_str_get(env_ldflags), rz_str_get(config->add_ldflags));
	free(env_ldflags);
	return ldflags;
}

static void egg_c_env_free(c_env_t *env) {
	if (!env) {
		return;
	}

	free(env->exe_objcopy);
	free(env->exe_compiler);
	free(env->cflags);
	free(env->ldflags);
	free(env);
}

static c_env_t *egg_c_env_new(RzPath *sys_path, const char *arch, const char *os, int bits) {
	char triplet[256] = { 0 };
	const egg_c_config_t *config = NULL;

	rz_strf(triplet, "%s-%s-%d", os, arch, bits);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(c_configs); ++i) {
		config = &c_configs[i];
		if (RZ_STR_EQ(triplet, config->triplet)) {
			break;
		}
		config = NULL;
	}

	if (!config) {
		return NULL;
	}

	c_env_t *env = RZ_NEW0(c_env_t);
	if (!env) {
		return NULL;
	}

	env->asm_text_segment = config->asm_text_segment;
	env->asm_text_header = config->asm_text_header;
	// heap allocated below
	env->exe_objcopy = egg_find_objcopy();
	env->exe_compiler = egg_find_compiler(config);
	env->cflags = egg_get_cflags(config, sys_path, triplet);
	env->ldflags = egg_get_ldflags(config, sys_path);

	if (!env->exe_compiler ||
		!env->cflags ||
		!env->ldflags) {
		egg_c_env_free(env);
		return NULL;
	}

	rz_str_sanitize(env->exe_compiler);
	return env;
}

static inline bool is_hws(char c) {
	return c == ' ' || c == '\t';
}

static inline bool is_asm_ident(char c) {
	return isalnum((unsigned char)c) || c == '_' || c == '.' || c == '$';
}

static const char *skip_hws(const char *p, const char *end) {
	while (p < end && is_hws(*p)) {
		p++;
	}
	return p;
}

static bool token_eq(const char *tok, size_t len, const char *lit) {
	return len == strlen(lit) && !strncmp(tok, lit, len);
}

/**
 * \brief Skip optional leading assembly labels and trailing horizontal whitespace.
 * \param p Start of the trimmed line.
 * \param end End of the line (exclusive).
 * \return Pointer to the token after any leading `label:` prefixes (and whitespace), or \p p if none.
 */
static const char *skip_leading_label(const char *p, const char *end) {
	const char *pos = p;
	while (pos < end && is_asm_ident(*pos)) {
		const char *cur = pos;
		while (cur < end && is_asm_ident(*cur)) {
			cur++;
		}
		if (cur < end && *cur == ':' && (cur + 1 == end || is_hws(cur[1]))) {
			pos = skip_hws(cur + 1, end);
			continue;
		}
		break;
	}
	return pos;
}

/**
 * \brief Check whether an assembly directive token emits literal/constant data.
 * \param tok Pointer to the directive token starting with `.`.
 * \param len Byte length of \p tok.
 * \return true if \p tok is a data-emission directive (e.g. `.string`, `.byte`), false otherwise.
 */
static bool is_data_directive(const char *tok, size_t len) {
	static const char *const data_dirs[] = {
		".ascii", ".asciz", ".string", ".string8", ".string16", ".string32",
		".byte", ".short", ".word", ".hword", ".long", ".int",
		".quad", ".octa", ".value", ".2byte", ".4byte", ".8byte"
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(data_dirs); i++) {
		if (token_eq(tok, len, data_dirs[i])) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Parse a single (optionally quoted) section token up to a delimiter or comment.
 * \param p Start of the slice to parse.
 * \param end End of the line (exclusive).
 * \param out_start Receives pointer to the unquoted token start.
 * \param out_len Receives byte length of the unquoted token.
 * \return Pointer to the delimiter or end of line immediately following the token.
 */
static const char *parse_section_token(const char *p, const char *end,
	const char **out_start, size_t *out_len) {
	p = skip_hws(p, end);
	const char *start = p;
	bool in_quote = false;
	bool escaped = false;
	while (p < end) {
		if (in_quote) {
			if (escaped) {
				escaped = false;
			} else if (*p == '\\') {
				escaped = true;
			} else if (*p == '"') {
				in_quote = false;
			}
		} else if (*p == '"') {
			in_quote = true;
		} else if (*p == ',' || is_hws(*p) || *p == '#' || *p == ';' ||
			(*p == '/' && p + 1 < end && p[1] == '/')) {
			break;
		}
		p++;
	}
	const char *tok_start = start;
	const char *tok_end = p;
	if (tok_end - tok_start >= 2 && *tok_start == '"' && tok_end[-1] == '"') {
		tok_start++;
		tok_end--;
	}
	*out_start = tok_start;
	*out_len = (size_t)(tok_end - tok_start);
	return p;
}

/**
 * \brief Check whether a section name is a Mach-O `__literal<N>` section.
 * \param s Pointer to the section name slice.
 * \param len Byte length of \p s.
 * \return true if \p s is `__literal` followed by one or more ASCII digits.
 */
static bool is_macho_literal_section(const char *s, size_t len) {
	static const char prefix[] = "__literal";
	const size_t plen = sizeof(prefix) - 1;
	if (len <= plen || strncmp(s, prefix, plen) != 0) {
		return false;
	}
	for (size_t i = plen; i < len; i++) {
		if (!isdigit((unsigned char)s[i])) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Determine whether a `.section` argument targets a read-only/text section to fold.
 * \param args Pointer immediately after `.section`.
 * \param end End of the line (exclusive).
 * \return true if the section should be folded into `.text`, false otherwise.
 */
static bool section_targets_text_fold(const char *args, const char *end) {
	// Stop at trailing line comments; section names and flags may use quoted strings.
	static const char *const sec_names[] = {
		".rodata", "rodata", ".rdata", "rdata",
		"__cstring", ".cstring", "__const", ".text", "__text"
	};
	const char *seg_start = NULL;
	size_t seg_len = 0;
	const char *p = parse_section_token(args, end, &seg_start, &seg_len);
	if (seg_len == 0) {
		return false;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(sec_names); i++) {
		size_t nlen = strlen(sec_names[i]);
		if (seg_len >= nlen && !strncmp(seg_start, sec_names[i], nlen) &&
			(seg_len == nlen || seg_start[nlen] == '.' ||
				seg_start[nlen] == '$')) {
			return true;
		}
	}
	if (is_macho_literal_section(seg_start, seg_len)) {
		return true;
	}
	// Check Mach-O style ".section __TEXT,<sect>,..." (comma-separated segment and section).
	const char *comma = skip_hws(p, end);
	if (token_eq(seg_start, seg_len, "__TEXT") && comma < end && *comma == ',') {
		const char *sect = NULL;
		size_t sect_len = 0;
		parse_section_token(comma + 1, end, &sect, &sect_len);
		static const char *const macho_sects[] = {
			"__cstring", "__const", "__text"
		};
		for (size_t i = 0; i < RZ_ARRAY_SIZE(macho_sects); i++) {
			if (token_eq(sect, sect_len, macho_sects[i])) {
				return true;
			}
		}
		if (is_macho_literal_section(sect, sect_len)) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Check whether a standalone identifier appears outside quotes and comments.
 * \param p Start of operand/text slice to scan.
 * \param end End of the line (exclusive).
 * \param sym NUL-terminated symbol identifier to look for.
 * \return true if \p sym occurs with non-identifier boundaries outside quotes/comments.
 */
static bool line_has_standalone_symbol(const char *p, const char *end, const char *sym) {
	size_t slen = strlen(sym);
	bool in_quote = false;
	bool escaped = false;
	const char *cur = p;
	while (cur < end) {
		char c = *cur;
		if (in_quote) {
			if (escaped) {
				escaped = false;
			} else if (c == '\\') {
				escaped = true;
			} else if (c == '"') {
				in_quote = false;
			}
			cur++;
			continue;
		}
		if (c == '"') {
			in_quote = true;
			cur++;
			continue;
		}
		if (c == '#' || c == ';' || c == '@' ||
			(c == '/' && cur + 1 < end && cur[1] == '/')) {
			break;
		}
		if ((size_t)(end - cur) >= slen && !strncmp(cur, sym, slen)) {
			bool left_ok = (cur == p) || !is_asm_ident(cur[-1]);
			bool right_ok = (cur + slen == end) || !is_asm_ident(cur[slen]);
			if (left_ok && right_ok) {
				return true;
			}
		}
		cur++;
	}
	return false;
}

/**
 * \brief Check whether an instruction line calls or branches to a runtime startup/probe stub.
 * \param p Start of the trimmed instruction line.
 * \param end End of the line (exclusive).
 * \return true if the line invokes `___main` or `__alloca`, false otherwise.
 */
static bool is_branch_or_call_to_stub(const char *p, const char *end) {
	static const char *const mnemonics[] = {
		"call", "callq", "calll", "jmp", "jmpq", "b", "bl", "blx"
	};
	static const char *const stubs[] = { "___main", "__alloca" };
	const char *m_end = p;
	while (m_end < end && !is_hws(*m_end)) {
		m_end++;
	}
	if (m_end == p) {
		return false;
	}
	bool is_branch = false;
	size_t m_len = (size_t)(m_end - p);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(mnemonics); i++) {
		if (token_eq(p, m_len, mnemonics[i])) {
			is_branch = true;
			break;
		}
	}
	if (!is_branch) {
		return false;
	}
	const char *args = skip_hws(m_end, end);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(stubs); i++) {
		if (line_has_standalone_symbol(args, end, stubs[i])) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Append an assembly slice while rewriting `get_pc_thunk.bx` tokens to `__getesp__`.
 * \param sb Output string buffer.
 * \param line Start of the line or label prefix to rewrite.
 * \param len Byte length of \p line.
 * \return true on success, false on allocation failure.
 */
static bool append_with_thunk_rewrite(RzStrBuf *sb, const char *line, size_t len) {
	static const char needle[] = "get_pc_thunk.bx";
	static const char repl[] = "__getesp__";
	const size_t nlen = sizeof(needle) - 1;
	const char *end = line + len;
	const char *cur = line;
	bool in_quote = false;
	bool escaped = false;
	while (cur < end) {
		char c = *cur;
		if (in_quote) {
			if (!rz_strbuf_append_n(sb, cur, 1)) {
				return false;
			}
			if (escaped) {
				escaped = false;
			} else if (c == '\\') {
				escaped = true;
			} else if (c == '"') {
				in_quote = false;
			}
			cur++;
			continue;
		}
		if (c == '"') {
			in_quote = true;
			if (!rz_strbuf_append_n(sb, cur, 1)) {
				return false;
			}
			cur++;
			continue;
		}
		if (c == '#' || c == ';' || (c == '/' && cur + 1 < end && cur[1] == '/')) {
			return rz_strbuf_append_n(sb, cur, (size_t)(end - cur));
		}
		if ((size_t)(end - cur) >= nlen && !strncmp(cur, needle, nlen)) {
			// Allow preceding '.' (e.g. __x86.get_pc_thunk.bx).
			bool left_ok = (cur == line) ||
				(!isalnum((unsigned char)cur[-1]) && cur[-1] != '_');
			bool right_ok = (cur + nlen == end) || !is_asm_ident(cur[nlen]);
			if (left_ok && right_ok) {
				if (!rz_strbuf_append(sb, repl)) {
					return false;
				}
				cur += nlen;
				continue;
			}
		}
		if (!rz_strbuf_append_n(sb, cur, 1)) {
			return false;
		}
		cur++;
	}
	return true;
}

/**
 * \brief Append a leading label prefix (trimmed of trailing horizontal whitespace) with thunk rewriting.
 * \param sb Output string buffer.
 * \param cur Start of the line (including any leading indentation before the label).
 * \param after_lbl Pointer immediately after the leading label(s) and trailing whitespace.
 * \param append_nl Whether to append a trailing newline after the label prefix.
 * \return true on success, false on allocation failure.
 */
static bool append_leading_label(RzStrBuf *sb, const char *cur, const char *after_lbl, bool append_nl) {
	const char *lbl_end = after_lbl;
	while (lbl_end > cur && is_hws(lbl_end[-1])) {
		lbl_end--;
	}
	if (!append_with_thunk_rewrite(sb, cur, (size_t)(lbl_end - cur))) {
		return false;
	}
	if (append_nl && !rz_strbuf_append_n(sb, "\n", 1)) {
		return false;
	}
	return true;
}

/**
 * \brief Filter compiler-generated assembly for embedding into a single-section shellcode object.
 *
 * Redirects read-only data sections to \c .text, strips metadata directives (\c .size, \c .zero,
 * \c .cfi*) and runtime startup/stack-probe calls (\c ___main, \c __alloca), and rewrites
 * \c get_pc_thunk.bx references to \c __getesp__ without altering quoted string literals or
 * data-emission directives.
 *
 * \param asm_str NUL-terminated assembly source generated by the C compiler.
 * \return Newly allocated filtered assembly string, or NULL on error.
 */
RZ_API RZ_OWN char *rz_egg_filter_c_assembly(RZ_NONNULL const char *asm_str) {
	rz_return_val_if_fail(asm_str, NULL);
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}

	const char *cur = asm_str;
	while (*cur != '\0') {
		const char *nl = strchr(cur, '\n');
		size_t raw_len = nl ? (size_t)(nl - cur) : strlen(cur);
		size_t line_len = (raw_len > 0 && cur[raw_len - 1] == '\r')
			? raw_len - 1
			: raw_len;
		const char *line_end = cur + line_len;
		const char *next_cur = nl ? nl + 1 : cur + raw_len;
		const char *p = skip_hws(cur, line_end);
		const char *after_lbl = skip_leading_label(p, line_end);

		const char *verbatim_from = NULL;
		if (p >= line_end || *p == '#' || *p == ';' || *p == '@' ||
			(p + 1 < line_end && p[0] == '/' && p[1] == '/')) {
			verbatim_from = cur;
		} else if (after_lbl < line_end &&
			(*after_lbl == '#' || *after_lbl == ';' || *after_lbl == '@' ||
				(after_lbl + 1 < line_end && after_lbl[0] == '/' &&
					after_lbl[1] == '/'))) {
			verbatim_from = after_lbl;
		} else if (after_lbl < line_end && *after_lbl == '.') {
			const char *tok_end = after_lbl + 1;
			while (tok_end < line_end && !is_hws(*tok_end) &&
				*tok_end != ',' && *tok_end != '#' && *tok_end != ';') {
				tok_end++;
			}
			size_t tok_len = (size_t)(tok_end - after_lbl);
			if (is_data_directive(after_lbl, tok_len)) {
				verbatim_from = (after_lbl > p) ? after_lbl : cur;
			} else if (token_eq(after_lbl, tok_len, ".size") ||
				token_eq(after_lbl, tok_len, ".zero") ||
				(tok_len >= 4 && !strncmp(after_lbl, ".cfi", 4))) {
				if (after_lbl > p && !append_leading_label(sb, cur, after_lbl, nl != NULL)) {
					goto oom;
				}
				cur = next_cur;
				continue;
			} else if (token_eq(after_lbl, tok_len, ".cstring") ||
				token_eq(after_lbl, tok_len, ".rdata") ||
				token_eq(after_lbl, tok_len, ".rodata") ||
				(token_eq(after_lbl, tok_len, ".section") &&
					section_targets_text_fold(tok_end, line_end))) {
				if (after_lbl > p && !append_leading_label(sb, cur, after_lbl, true)) {
					goto oom;
				}
				if (!rz_strbuf_append(sb, "\t.text") ||
					(nl && !rz_strbuf_append_n(sb, "\n", 1))) {
					goto oom;
				}
				cur = next_cur;
				continue;
			}
		} else if (is_branch_or_call_to_stub(after_lbl, line_end)) {
			if (after_lbl > p && !append_leading_label(sb, cur, after_lbl, nl != NULL)) {
				goto oom;
			}
			cur = next_cur;
			continue;
		}

		if (verbatim_from) {
			if (verbatim_from > cur &&
				!append_with_thunk_rewrite(sb, cur, (size_t)(verbatim_from - cur))) {
				goto oom;
			}
			if (!rz_strbuf_append_n(sb, verbatim_from, (size_t)(line_end - verbatim_from))) {
				goto oom;
			}
		} else if (!append_with_thunk_rewrite(sb, cur, line_len)) {
			goto oom;
		}
		if (nl && !rz_strbuf_append_n(sb, "\n", 1)) {
			goto oom;
		}
		cur = next_cur;
	}

	return rz_strbuf_drain(sb);

oom:
	rz_strbuf_free(sb);
	return NULL;
}

static bool egg_append_tmp_to_assembly_file(const char *outfile_tmp, const char *assembly_file) {
	char *buffer = rz_file_slurp(outfile_tmp, NULL);
	if (!buffer) {
		RZ_LOG_ERROR("egg: Could not open '%s'.\n", outfile_tmp);
		return false;
	}

	char *filtered = rz_egg_filter_c_assembly(buffer);
	free(buffer);
	if (!filtered) {
		RZ_LOG_ERROR("egg: Failed to filter '%s'.\n", outfile_tmp);
		return false;
	}

	bool dumped = rz_file_dump(assembly_file, (const ut8 *)filtered, strlen(filtered), true);
	free(filtered);
	if (!dumped) {
		RZ_LOG_ERROR("egg: Error while opening %s\n", assembly_file);
		return false;
	}
	return true;
}

static bool egg_compile_c_source_to_assembly(const c_env_t *env, const char *infile_C, const char *outfile_tmp) {
	char *cmd = rz_str_newf("'%s' %s -o '%s' -S '%s'", env->exe_compiler, env->cflags, outfile_tmp, infile_C);
	RZ_LOG_INFO("egg: executing sys command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

static bool egg_compile_assembly_to_object(const c_env_t *env, const char *infile_asm, const char *outfile_obj) {
	char *cmd = rz_str_newf("'%s' %s -o '%s' '%s'", env->exe_compiler, env->ldflags, outfile_obj, infile_asm);
	RZ_LOG_INFO("egg: executing command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

/**
 * \brief Writes the bytes of the text section of \p infile_obj to \p outfile_text.
 *
 * \return false when the section is missing, empty or cut short by the end of the file.
 */
static bool egg_link_object_via_rz_bin(const c_env_t *env, const char *infile_obj, const char *outfile_text) {
	bool ok = false;
	RzBin *bin = rz_bin_new();
	RzBuffer *buf = rz_buf_new_slurp(infile_obj);
	if (!bin || !buf) {
		goto end;
	}
	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.filename = infile_obj;
	RzBinFile *bf = rz_bin_open_buf(bin, buf, &opt);
	const RzPVector *sections = bf ? rz_bin_object_get_sections_all(bf->o) : NULL;
	if (!sections) {
		goto end;
	}
	void **it;
	rz_pvector_foreach (sections, it) {
		RzBinSection *section = *it;
		if (!RZ_STR_EQ(section->name, env->asm_text_segment)) {
			continue;
		}
		RzBuffer *text = rz_buf_new_slice(bf->buf, section->paddr, section->size);
		// A slice ends with the file, so a shorter one means a truncated section
		ok = text && section->size && rz_buf_size(text) == section->size && rz_buf_dump(text, outfile_text);
		rz_buf_free(text);
		break;
	}
end:
	rz_buf_free(buf);
	rz_bin_free(bin);
	return ok;
}

static bool egg_link_object_via_objdump(const c_env_t *env, const char *infile_obj, const char *outfile_text) {
	char *cmd = rz_str_newf("'%s' -j .text -O binary '%s' '%s'", env->exe_objcopy, infile_obj, outfile_text);
	RZ_LOG_INFO("egg: executing command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

static bool egg_link_object(const c_env_t *env, const char *infile_obj, const char *outfile_text) {
	if (egg_link_object_via_rz_bin(env, infile_obj, outfile_text)) {
		return true;
	} else if (RZ_STR_ISEMPTY(env->exe_objcopy)) {
		return false;
	}
	RZ_LOG_WARN("egg: cannot dump the '%s' section of %s, using objcopy instead.\n", env->asm_text_segment, infile_obj);
	return egg_link_object_via_objdump(env, infile_obj, outfile_text);
}

/**
 * \brief      Compiles a given C source and returns the file path hexdump of the compiled code.
 *
 * \param[in]  source_file  The file
 * \param[in]  arch         The arch name
 * \param[in]  os           The operating system
 * \param[in]  bits         The arch bits
 * \param      sys_path     The system path
 *
 * \return     { description_of_the_return_value }
 */
RZ_API RZ_OWN char *rz_egg_compile_c_source(RZ_NONNULL const char *source_file, RZ_NONNULL const char *arch, RZ_NONNULL const char *os, int bits, RZ_BORROW RZ_NONNULL RzPath *sys_path) {
	rz_return_val_if_fail(sys_path && source_file && arch && os, NULL);

	bool ok = true;
	c_env_t *env = NULL;
	char *outfile_tmp = rz_str_newf("%s.tmp", source_file);
	char *outfile_asm = rz_str_newf("%s.s", source_file);
	char *outfile_obj = rz_str_newf("%s.o", source_file);
	char *outfile_text = rz_str_newf("%s.text", source_file);
	if (!outfile_tmp || !outfile_asm || !outfile_obj || !outfile_text) {
		RZ_LOG_ERROR("egg: failed to allocate memory\n");
		ok = false;
		goto fail;
	}

	if (!(env = egg_c_env_new(sys_path, arch, os, bits))) {
		RZ_LOG_ERROR("egg: failed to initialize C environment for '%s-%s-%d'\n", os, arch, bits);
		ok = false;
		goto fail;
	}

	// prepare assembly file.
	if (!rz_file_dump(outfile_asm, (const ut8 *)env->asm_text_header, strlen(env->asm_text_header), false)) {
		RZ_LOG_ERROR("egg: Error while opening %s\n", outfile_asm);
		ok = false;
	} else if (!egg_compile_c_source_to_assembly(env, source_file, outfile_tmp)) {
		RZ_LOG_ERROR("egg: failed to compile source file: %s\n", source_file);
		ok = false;
	} else if (!egg_append_tmp_to_assembly_file(outfile_tmp, outfile_asm)) {
		RZ_LOG_ERROR("egg: failed to append '%s' to %s\n", outfile_tmp, outfile_asm);
		ok = false;
	} else if (!egg_compile_assembly_to_object(env, outfile_asm, outfile_obj)) {
		RZ_LOG_ERROR("egg: failed to compile to object file: %s\n", outfile_asm);
		ok = false;
	} else if (!egg_link_object(env, outfile_obj, outfile_text)) {
		RZ_LOG_ERROR("egg: failed to link object: %s\n", outfile_obj);
		ok = false;
	}

	// cleanup.
	rz_file_rm(outfile_tmp);
	rz_file_rm(outfile_asm);
	rz_file_rm(outfile_obj);

fail:
	free(outfile_tmp);
	free(outfile_asm);
	free(outfile_obj);
	if (!ok) {
		RZ_FREE(outfile_text)
	}
	egg_c_env_free(env);

	return outfile_text;
}
