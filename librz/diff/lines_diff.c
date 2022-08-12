// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/* Helpers for handling lines */
#define DIFF_IS_LINES_METHOD(x) (x.elem_at == methods_lines.elem_at)

static RzList /*<char *>*/ *tokenize_lines(const char *string) {
	RzList *lines = NULL;
	size_t last = 0;
	size_t size = 0;
	char *line = NULL;

	lines = rz_list_newf((RzListFree)free);
	if (!lines) {
		RZ_LOG_ERROR("rz_diff_line_new: cannot allocate list of lines\n");
		goto tokenize_newlines_fail;
	}

	size = strlen(string);
	for (size_t i = 0; i < size; ++i) {
		if (string[i] == '\n') {
			line = rz_str_ndup(string + last, (i + 1) - last);
			if (!line || !rz_list_append(lines, line)) {
				RZ_LOG_ERROR("rz_diff_line_new: cannot allocate line or add it to the list\n");
				free(line);
				goto tokenize_newlines_fail;
			}
			last = i + 1;
		}
	}

	if (last < size) {
		line = rz_str_ndup(string + last, size - last);
		if (!line || !rz_list_append(lines, line)) {
			RZ_LOG_ERROR("rz_diff_line_new: cannot allocate last line or add it to the list\n");
			free(line);
			goto tokenize_newlines_fail;
		}
	}

	return lines;

tokenize_newlines_fail:
	rz_list_free(lines);
	return NULL;
}

static const void *line_elem_at(const RzList /*<char *>*/ *array, ut32 index) {
	return rz_list_get_n(array, index);
}

static int line_compare(const char *a_elem, const char *b_elem) {
	return strcmp(a_elem, b_elem);
}

static ut32 line_hash(const char *elem) {
	ut32 size = strlen(elem);
	return rz_diff_hash_data((const ut8 *)elem, size);
}

static void line_stringify(const char *a_elem, RzStrBuf *sb) {
	rz_strbuf_set(sb, a_elem);
}

static void line_free(RzList /*<char *>*/ *array) {
	rz_list_free(array);
}

static const MethodsInternal methods_lines = {
	.elem_at /*  */ = (RzDiffMethodElemAt)line_elem_at,
	.elem_hash /**/ = (RzDiffMethodElemHash)line_hash,
	.compare /*  */ = (RzDiffMethodCompare)line_compare,
	.stringify /**/ = (RzDiffMethodStringify)line_stringify,
	.ignore /*   */ = fake_ignore,
	.free /*     */ = (RzDiffMethodFree)line_free,
};
