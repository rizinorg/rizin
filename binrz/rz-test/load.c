// SPDX-FileCopyrightText: 2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test.h"

#include <assert.h>

#define LINEFMT "%s, line %" PFMT64u ": "

RZ_API RzCmdTest *rz_test_cmd_test_new(void) {
	return RZ_NEW0(RzCmdTest);
}

RZ_API void rz_test_cmd_test_free(RzCmdTest *test) {
	if (!test) {
		return;
	}
#define DO_KEY_STR(key, field) free(test->field.value);
	RZ_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, RZ_CMD_TEST_FOREACH_RECORD_NOP, RZ_CMD_TEST_FOREACH_RECORD_NOP)
#undef DO_KEY_STR
	free(test);
}

static char *readline(char *buf, size_t *linesz) {
	char *end = strchr(buf, '\n');
	if (end) {
		size_t len = end - buf;
		*end = '\0';
		if (len > 0 && buf[len - 1] == '\r') {
			buf[len - 1] = '\0';
			len--;
		}
		*linesz = len;
		return end + 1;
	} else {
		*linesz = strlen(buf);
		return NULL;
	}
}

// read the (possibly multiline) string value of some key in the file
// e.g. for
//
// 0    CMDS=<<EOF
// 1    Hello
// 2    World
// 3    EOF
// 4    ...
//
// if nextline is at the beginning of line 1,
// read_string_val(&nextline, "<<EOF\0")
// will return "Hello\nWorld\n" with nextline being at the beginning of line 4 afterwards.
static char *read_string_val(char **nextline, const char *val, ut64 *linenum) {
	if (val[0] == '\'') {
		size_t len = strlen(val);
		if (len > 1 && val[len - 1] == '\'') {
			eprintf("Error: Invalid string syntax, use <<EOF instead of '...'\n");
			return NULL;
		}
	}
	if (val[0] == '<' && val[1] == '<') {
		// <<EOF syntax
		const char *endtoken = val + 2;
		if (!*endtoken) {
			eprintf("Error: Missing opening end token after <<\n");
			return NULL;
		}
		if (strcmp(endtoken, "EOF") != 0) {
			// In case there will be strings containing "EOF" inside of them, this requirement
			// can be weakened to only apply for strings which do not contain "EOF".
			eprintf("Error: End token must be \"EOF\", got \"%s\" instead.", endtoken);
			return NULL;
		}
		RzStrBuf *buf = rz_strbuf_new("");
		char *line = *nextline;
		size_t linesz = 0;
		do {
			*nextline = readline(line, &linesz);
			(*linenum)++;
			char *end = strstr(line, endtoken);
			if (end != line) {
				// Require the EOF to be at the beginning of the line.
				// This means makes it impossible to write multiline tests without a trailing newline.
				// This requirement could be lifted later if necessary.
				end = NULL;
			}
			if (end) {
				*end = '\0';
			}
			rz_strbuf_append(buf, line);
			if (end) {
				return rz_strbuf_drain(buf);
			} else {
				rz_strbuf_append(buf, "\n");
			}
		} while ((line = *nextline));
		eprintf("Error: Missing closing end token %s\n", endtoken);
		rz_strbuf_free(buf);
		return NULL;
	}

	return strdup(val);
}

RZ_API RzPVector /*<RzCmdTest *>*/ *rz_test_load_cmd_test_file(const char *file) {
	char *contents = rz_file_slurp(file, NULL);
	if (!contents) {
		eprintf("Failed to open file \"%s\"\n", file);
		return NULL;
	}

	RzPVector *ret = rz_pvector_new(NULL);
	if (!ret) {
		free(contents);
		return NULL;
	}
	RzCmdTest *test = rz_test_cmd_test_new();
	if (!test) {
		free(contents);
		rz_pvector_free(ret);
		return NULL;
	}

	ut64 linenum = 0;
	char *line = contents;
	size_t linesz;
	char *nextline;
	do {
		nextline = readline(line, &linesz);
		linenum++;
		if (!linesz) {
			continue;
		}
		if (*line == '#') {
			continue;
		}

		char *val = strchr(line, '=');
		if (val) {
			*val = '\0';
			val++;
		} else if (!val && !(strcmp(line, "RUN") == 0)) {
			eprintf("Error: No value for key \"%s\".\n", line);
			goto fail;
		}

		// RUN is the only cmd without value
		if (strcmp(line, "RUN") == 0) {
			test->run_line = linenum;
			if (!test->cmds.value) {
				eprintf(LINEFMT "Error: Test without CMDS key\n", file, linenum);
				goto fail;
			}
			if (!(test->expect.value || test->expect_err.value)) {
				eprintf(LINEFMT "Error: Test without EXPECT or EXPECT_ERR key"
						" (did you forget an EOF?)\n",
					file, linenum);
				goto fail;
			}
			rz_pvector_push(ret, test);
			test = rz_test_cmd_test_new();
			if (!test) {
				eprintf("Error: Failed to allocate RzCmdTest\n");
				goto beach;
			}
			continue;
		}

#define DO_KEY_STR(key, field) \
	if (strcmp(line, key) == 0) { \
		if (test->field.value) { \
			free(test->field.value); \
			eprintf(LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
		} \
		test->field.line_begin = linenum; \
		test->field.value = read_string_val(&nextline, val, &linenum); \
		test->field.line_end = linenum + 1; \
		if (!test->field.value) { \
			eprintf(LINEFMT "Error: Failed to read value for key \"%s\"\n", file, linenum, key); \
			goto fail; \
		} \
		continue; \
	}

#define DO_KEY_BOOL(key, field) \
	if (strcmp(line, key) == 0) { \
		if (test->field.value) { \
			eprintf(LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
		} \
		test->field.set = true; \
		/* Strip comment */ \
		char *cmt = strchr(val, '#'); \
		if (cmt) { \
			*cmt = '\0'; \
			cmt--; \
			while (cmt > val && *cmt == ' ') { \
				*cmt = '\0'; \
				cmt--; \
			} \
		} \
		if (!strcmp(val, "1")) { \
			test->field.value = true; \
		} else if (!strcmp(val, "0")) { \
			test->field.value = false; \
		} else { \
			eprintf(LINEFMT "Error: Invalid value \"%s\" for boolean key \"%s\", only \"1\" or \"0\" allowed.\n", file, linenum, val, key); \
			goto fail; \
		} \
		continue; \
	}

#define DO_KEY_NUM(key, field) \
	if (strcmp(line, key) == 0) { \
		if (test->field.value) { \
			eprintf(LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
		} \
		test->field.set = true; \
		/* Strip comment */ \
		char *cmt = strchr(val, '#'); \
		if (cmt) { \
			*cmt = '\0'; \
			cmt--; \
			while (cmt > val && *cmt == ' ') { \
				*cmt = '\0'; \
				cmt--; \
			} \
		} \
		char *endval; \
		test->field.value = strtol(val, &endval, 0); \
		if (!endval || *endval) { \
			eprintf(LINEFMT "Error: Invalid value \"%s\" for numeric key \"%s\", only numbers allowed.\n", file, linenum, val, key); \
			goto fail; \
		} \
		continue; \
	}

		RZ_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, DO_KEY_BOOL, DO_KEY_NUM)
#undef DO_KEY_STR
#undef DO_KEY_BOOL
#undef DO_KEY_NUM

		eprintf(LINEFMT "Unknown key \"%s\".\n", file, linenum, line);
	} while ((line = nextline));
beach:
	free(contents);

	if (test && (test->name.value || test->cmds.value || test->expect.value)) {
		eprintf("Warning: found test tokens at the end of \"%s\" without RUN (line: %" PFMT64u ").\n", file, linenum);
	}
	rz_test_cmd_test_free(test);
	return ret;
fail:
	rz_test_cmd_test_free(test);
	test = NULL;
	rz_pvector_free(ret);
	ret = NULL;
	goto beach;
}

RZ_API RzAsmTest *rz_test_asm_test_new(void) {
	return RZ_NEW0(RzAsmTest);
}

RZ_API void rz_test_asm_test_free(RzAsmTest *test) {
	if (!test) {
		return;
	}
	free(test->disasm);
	free(test->bytes);
	free(test->il);
	free(test);
}

static bool parse_asm_path(const char *path, RzStrConstPool *strpool, const char **arch_out, const char **cpuout, int *bitsout) {
	RzList *file_tokens = rz_str_split_duplist(path, RZ_SYS_DIR, true);
	if (!file_tokens || rz_list_empty(file_tokens)) {
		rz_list_free(file_tokens);
		return false;
	}

	// Possibilities:
	// arm
	// arm_32
	// arm_cortex_32

	char *arch = rz_list_last(file_tokens);
	if (!*arch) {
		rz_list_free(file_tokens);
		return false;
	}
	char *second = strchr(arch, '_');
	if (second) {
		*second = '\0';
		second++;
		char *third = strchr(second, '_');
		if (third) {
			*third = '\0';
			third++;
			*cpuout = rz_str_constpool_get(strpool, second);
			*bitsout = atoi(third);
		} else {
			*cpuout = NULL;
			*bitsout = atoi(second);
		}
	} else {
		*cpuout = NULL;
		*bitsout = 0;
	}
	*arch_out = rz_str_constpool_get(strpool, arch);
	rz_list_free(file_tokens);
	return true;
}

RZ_API RzPVector /*<RzAsmTest *>*/ *rz_test_load_asm_test_file(RzStrConstPool *strpool, const char *file) {
	const char *arch;
	const char *cpu;
	int bits;
	if (!parse_asm_path(file, strpool, &arch, &cpu, &bits)) {
		eprintf("Failed to parse arch/cpu/bits from path %s\n", file);
		return NULL;
	}

	char *contents = rz_file_slurp(file, NULL);
	if (!contents) {
		eprintf("Failed to open file \"%s\"\n", file);
		return NULL;
	}

	RzPVector *ret = rz_pvector_new(NULL);
	if (!ret) {
		return NULL;
	}

	ut64 linenum = 0;
	char *line = contents;
	size_t linesz;
	char *nextline;
	do {
		nextline = readline(line, &linesz);
		linenum++;
		if (!linesz) {
			continue;
		}
		if (*line == '#') {
			continue;
		}

		// mode flags
		int mode = 0;
		while (*line && *line != ' ') {
			switch (*line) {
			case 'a':
				mode |= RZ_ASM_TEST_MODE_ASSEMBLE;
				break;
			case 'd':
				mode |= RZ_ASM_TEST_MODE_DISASSEMBLE;
				break;
			case 'E':
				mode |= RZ_ASM_TEST_MODE_BIG_ENDIAN;
				break;
			case 'B':
				mode |= RZ_ASM_TEST_MODE_BROKEN;
				break;
			default:
				eprintf(LINEFMT "Warning: Invalid mode char '%c'\n", file, linenum, *line);
				goto fail;
			}
			line++;
		}
		if (!(mode & RZ_ASM_TEST_MODE_ASSEMBLE) && !(mode & RZ_ASM_TEST_MODE_DISASSEMBLE)) {
			eprintf(LINEFMT "Warning: Mode specifies neither assemble nor disassemble.\n", file, linenum);
			continue;
		}

		// disasm
		char *disasm = strchr(line, '"');
		if (!disasm) {
			eprintf(LINEFMT "Error: Expected \" to begin disassembly.\n", file, linenum);
			goto fail;
		}
		disasm++;
		char *hex = strchr(disasm, '"');
		if (!hex) {
			eprintf(LINEFMT "Error: Expected \" to end disassembly.\n", file, linenum);
			goto fail;
		}
		*hex = '\0';
		hex++;
		rz_str_trim(disasm);

		// hex
		while (*hex && *hex == ' ') {
			hex++;
		}

		// remove comment at the end of the line
		char *latecmt = strchr(hex, '#');
		if (latecmt) {
			*latecmt = '\0';
		}

		// offset (optional)
		char *offset = strchr(hex, ' ');
		char *il = NULL;
		if (offset) {
			*offset = '\0';
			offset++;

			// IL (optional, the entire rest)
			il = strchr(offset, ' ');
			if (il) {
				*il = '\0';
				il++;
			}
		}

		size_t hexlen = strlen(hex);
		if (!hexlen) {
			eprintf(LINEFMT "Error: Expected hex chars.\n", file, linenum);
			goto fail;
		}
		ut8 *bytes = malloc(hexlen);
		if (!bytes) {
			break;
		}
		int bytesz = rz_hex_str2bin(hex, bytes);
		if (bytesz == 0) {
			eprintf(LINEFMT "Error: Expected hex chars.\n", file, linenum);
			free(bytes);
			goto fail;
		}
		if (bytesz < 0) {
			eprintf(LINEFMT "Error: Odd number of hex chars: %s\n", file, linenum, hex);
			free(bytes);
			goto fail;
		}

		RzAsmTest *test = rz_test_asm_test_new();
		if (!test) {
			free(bytes);
			goto fail;
		}
		test->line = linenum;
		test->bits = bits;
		test->arch = arch;
		test->cpu = cpu;
		test->mode = mode;
		char *endptr = NULL;
		test->offset = offset ? (ut64)strtoull(offset, &endptr, 0) : 0;
		if (endptr && *endptr) {
			eprintf(LINEFMT "Error: Invalid offset string: \"%s\"\n", file, linenum, offset);
			free(bytes);
			goto fail;
		}
		test->disasm = strdup(disasm);
		test->bytes = bytes;
		test->bytes_size = (size_t)bytesz;
		test->il = il ? strdup(il) : NULL;
		rz_pvector_push(ret, test);
	} while ((line = nextline));

beach:
	free(contents);
	return ret;
fail:
	rz_pvector_free(ret);
	ret = NULL;
	goto beach;
}

RZ_API RzJsonTest *rz_test_json_test_new(void) {
	return RZ_NEW0(RzJsonTest);
}

RZ_API void rz_test_json_test_free(RzJsonTest *test) {
	if (!test) {
		return;
	}
	free(test->cmd);
	free(test);
}

RZ_API RzPVector /*<RzJsonTest *>*/ *rz_test_load_json_test_file(const char *file) {
	char *contents = rz_file_slurp(file, NULL);
	if (!contents) {
		eprintf("Failed to open file \"%s\"\n", file);
		return NULL;
	}

	RzPVector *ret = rz_pvector_new(NULL);
	if (!ret) {
		free(contents);
		return NULL;
	}

	ut64 linenum = 0;
	char *line = contents;
	size_t linesz;
	char *nextline;
	do {
		nextline = readline(line, &linesz);
		linenum++;
		if (!linesz) {
			continue;
		}
		if (*line == '#') {
			continue;
		}

		char *broken_token = strstr(line, "BROKEN");
		if (broken_token) {
			*broken_token = '\0';
		}

		rz_str_trim(line);
		if (!*line) {
			// empty line
			continue;
		}

		RzJsonTest *test = rz_test_json_test_new();
		if (!test) {
			break;
		}
		test->line = linenum;
		test->cmd = strdup(line);
		if (!test->cmd) {
			rz_test_json_test_free(test);
			break;
		}
		test->broken = broken_token ? true : false;
		rz_pvector_push(ret, test);
	} while ((line = nextline));

	free(contents);
	return ret;
}

RZ_API void rz_test_fuzz_test_free(RzFuzzTest *test) {
	if (!test) {
		return;
	}
	free(test->file);
	free(test);
}

RZ_API void rz_test_test_free(RzTest *test) {
	if (!test) {
		return;
	}
	switch (test->type) {
	case RZ_TEST_TYPE_CMD:
		rz_test_cmd_test_free(test->cmd_test);
		break;
	case RZ_TEST_TYPE_ASM:
		rz_test_asm_test_free(test->asm_test);
		break;
	case RZ_TEST_TYPE_JSON:
		rz_test_json_test_free(test->json_test);
		break;
	case RZ_TEST_TYPE_FUZZ:
		rz_test_fuzz_test_free(test->fuzz_test);
		break;
	}
	free(test);
}

RZ_API RzTestDatabase *rz_test_test_database_new(void) {
	RzTestDatabase *db = RZ_NEW(RzTestDatabase);
	if (!db) {
		return NULL;
	}
	rz_pvector_init(&db->tests, (RzPVectorFree)rz_test_test_free);
	rz_str_constpool_init(&db->strpool);
	return db;
}

RZ_API void rz_test_test_database_free(RzTestDatabase *db) {
	if (!db) {
		return;
	}
	rz_pvector_clear(&db->tests);
	rz_str_constpool_fini(&db->strpool);
	free(db);
}

static RzTestType test_type_for_path(const char *path, bool *load_plugins) {
	RzTestType ret = RZ_TEST_TYPE_CMD;
	char *pathdup = strdup(path);
	RzList *tokens = rz_str_split_list(pathdup, RZ_SYS_DIR, 0);
	if (!tokens) {
		return ret;
	}
	if (!rz_list_empty(tokens)) {
		rz_list_pop(tokens);
	}
	RzListIter *it;
	char *token;
	*load_plugins = false;
	rz_list_foreach (tokens, it, token) {
		if (!strcmp(token, "asm")) {
			ret = RZ_TEST_TYPE_ASM;
			continue;
		}
		if (!strcmp(token, "json")) {
			ret = RZ_TEST_TYPE_JSON;
			continue;
		}
		if (!strcmp(token, "extras")) {
			*load_plugins = true;
		}
	}
	rz_list_free(tokens);
	free(pathdup);
	return ret;
}

static inline bool skip_archos(const char *subname) {
	rz_return_val_if_fail(subname, true);
	if (!strcmp(subname, RZ_TEST_ARCH_OS)) {
		return false;
	}
	if (rz_str_startswith(subname, "not-")) {
		const char *neg_subname = subname + strlen("not-");
		const char *second_dash = strchr(neg_subname, '-');
		rz_return_val_if_fail(second_dash, true);
		if (strncmp(neg_subname, RZ_TEST_ARCH_OS, second_dash - neg_subname) &&
			(rz_str_endswith(RZ_TEST_ARCH_OS, strrchr(subname, '-')) || rz_str_endswith(subname, "-any"))) {
			return false;
		}
	} else {
		if (rz_str_endswith(subname, "-any")) {
			if (!strncmp(subname, RZ_TEST_ARCH_OS, strlen(subname) - strlen("-any"))) {
				return false;
			}
		}
	}
	return true;
}

static bool database_load(RzTestDatabase *db, const char *path, int depth) {
	if (depth <= 0) {
		eprintf("Directories for loading tests too deep: %s\n", path);
		return false;
	}
	if (rz_file_is_directory(path)) {
		RzList *dir = rz_sys_dir(path);
		if (!dir) {
			return false;
		}
		RzListIter *it;
		const char *subname;
		RzStrBuf subpath;
		rz_strbuf_init(&subpath);
		bool ret = true;
		rz_list_foreach (dir, it, subname) {
			if (*subname == '.') {
				continue;
			}
			if (!strcmp(subname, "extras")) {
				// Only load "extras" dirs if explicitly specified
				eprintf("Skipping %s" RZ_SYS_DIR "%s because it requires additional dependencies.\n", path, subname);
				continue;
			}
			if ((!strcmp(path, "archos") || rz_str_endswith(path, RZ_SYS_DIR "archos")) && skip_archos(subname)) {
				eprintf("Skipping %s" RZ_SYS_DIR "%s because it does not match the current platform.\n", path, subname);
				continue;
			}
			rz_strbuf_setf(&subpath, "%s%s%s", path, RZ_SYS_DIR, subname);
			if (!database_load(db, rz_strbuf_get(&subpath), depth - 1)) {
				ret = false;
				break;
			}
		}
		rz_strbuf_fini(&subpath);
		rz_list_free(dir);
		return ret;
	}

	if (!rz_file_exists(path)) {
		eprintf("Path \"%s\" does not exist\n", path);
		return false;
	}

	// Not a directory but exists, load a file
	const char *pooled_path = rz_str_constpool_get(&db->strpool, path);
	bool load_plugins = false;
	RzTestType test_type = test_type_for_path(path, &load_plugins);
	switch (test_type) {
	case RZ_TEST_TYPE_CMD: {
		RzPVector *cmd_tests = rz_test_load_cmd_test_file(path);
		if (!cmd_tests) {
			return false;
		}
		void **it;
		rz_pvector_foreach (cmd_tests, it) {
			RzTest *test = RZ_NEW(RzTest);
			if (!test) {
				continue;
			}
			test->type = RZ_TEST_TYPE_CMD;
			test->path = pooled_path;
			test->cmd_test = *it;
			test->cmd_test->load_plugins = load_plugins;
			rz_pvector_push(&db->tests, test);
		}
		rz_pvector_free(cmd_tests);
		break;
	}
	case RZ_TEST_TYPE_ASM: {
		RzPVector *asm_tests = rz_test_load_asm_test_file(&db->strpool, path);
		if (!asm_tests) {
			return false;
		}
		void **it;
		rz_pvector_foreach (asm_tests, it) {
			RzTest *test = RZ_NEW(RzTest);
			if (!test) {
				continue;
			}
			test->type = RZ_TEST_TYPE_ASM;
			test->path = pooled_path;
			test->asm_test = *it;
			rz_pvector_push(&db->tests, test);
		}
		rz_pvector_free(asm_tests);
		break;
	}
	case RZ_TEST_TYPE_JSON: {
		RzPVector *json_tests = rz_test_load_json_test_file(path);
		if (!json_tests) {
			return false;
		}
		void **it;
		rz_pvector_foreach (json_tests, it) {
			RzTest *test = RZ_NEW(RzTest);
			if (!test) {
				continue;
			}
			test->type = RZ_TEST_TYPE_JSON;
			test->path = pooled_path;
			test->json_test = *it;
			test->json_test->load_plugins = load_plugins;
			rz_pvector_push(&db->tests, test);
		}
		rz_pvector_free(json_tests);
		break;
	}
	case RZ_TEST_TYPE_FUZZ:
		// shouldn't come here, fuzz tests are loaded differently
		break;
	}

	return true;
}

RZ_API bool rz_test_test_database_load(RzTestDatabase *db, const char *path) {
	return database_load(db, path, 4);
}

static void database_load_fuzz_file(RzTestDatabase *db, const char *path, const char *file) {
	RzFuzzTest *fuzz_test = RZ_NEW(RzFuzzTest);
	if (!fuzz_test) {
		return;
	}
	fuzz_test->file = strdup(file);
	if (!fuzz_test->file) {
		free(fuzz_test);
		return;
	}
	RzTest *test = RZ_NEW(RzTest);
	if (!test) {
		free(fuzz_test->file);
		free(fuzz_test);
		return;
	}
	test->type = RZ_TEST_TYPE_FUZZ;
	test->fuzz_test = fuzz_test;
	test->path = rz_str_constpool_get(&db->strpool, path);
	rz_pvector_push(&db->tests, test);
}

RZ_API bool rz_test_test_database_load_fuzz(RzTestDatabase *db, const char *path) {
	if (rz_file_is_directory(path)) {
		RzList *dir = rz_sys_dir(path);
		if (!dir) {
			return false;
		}
		RzListIter *it;
		const char *subname;
		RzStrBuf subpath;
		rz_strbuf_init(&subpath);
		bool ret = true;
		rz_list_foreach (dir, it, subname) {
			if (*subname == '.') {
				continue;
			}
			rz_strbuf_setf(&subpath, "%s%s%s", path, RZ_SYS_DIR, subname);
			if (rz_file_is_directory(rz_strbuf_get(&subpath))) {
				// only load 1 level deep
				continue;
			}
			database_load_fuzz_file(db, path, rz_strbuf_get(&subpath));
		}
		rz_strbuf_fini(&subpath);
		rz_list_free(dir);
		return ret;
	}

	if (!rz_file_exists(path)) {
		eprintf("Path \"%s\" does not exist\n", path);
		return false;
	}

	// Just a single file
	database_load_fuzz_file(db, path, path);
	return true;
}
