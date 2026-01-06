// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file pat.c
 * FLIRT uncompressed file format.
 *
 * An example of uncompressed format is shown below:
 *
 * ```
 * # some comment
 * 4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E 07 FAEE 003B :0000@ Curl_gethostname ^0027 strchr ........4885C07403C600004489E05B5D415CC3
 * 31C04885D2741F488D4417FF4839C77610EB1D0F1F4400004883E8014839C777 13 9867 0033 :0000 Curl_memrchr
 * ---
 *
 * ```
 *
 * The '---' is the pat file terminator
 * Some files may contain comments using hashtag (#) as prefix but it is not the standard format.
 *
 * 4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E
 *   `----- Each line starts with a pattern mask (usually 32 bytes long)
 *
 * 07 FAEE
 *  |    `---- CRC16 value
 *  `--------- CRC16 length
 *
 * 003B
 *    ^------- Function size (min 2 bytes, but can be bigger)
 *
 * :0000@ Curl_gethostname
 * |   ||     `-------------- Symbol name
 * |   |`-------------------- If set, then is local symbol
 * |   `--------------------- Symbol offset and type (: -> public)
 * `------------------------- Symbol type (: -> public, ^ -> reference)
 *
 * This symbol, is a list and can be repeated N-times
 *
 * ........4885C07403C600004489E05B5D415CC3
 *   `----- The line can end with another pattern mask
 */

#include <rz_flirt.h>
#include <rz_util.h>

#if 0
#define pat_dbg(...) eprintf(__VA_ARGS__)
#else
#define pat_dbg(...)
#endif

#define PAT_LINE_BUFFER_SIZE 1024

extern void module_free(RzFlirtModule *module);
extern bool flirt_node_optimize(RzFlirtNode *root);
extern int flirt_compare_node(const RzFlirtNode *a, const RzFlirtNode *b, void *user);

static inline ut8 decode_byte(char b) {
	if (b >= '0' && b <= '9') {
		return b - '0';
	} else if (b >= 'A' && b <= 'F') {
		return (b - 'A') + 10;
	}
	return (b - 'a') + 10;
}

static inline ut8 parse_byte(char high, char low) {
	ut8 value = decode_byte(high) << 4;
	return value | decode_byte(low);
}

static bool flirt_pat_parse_pattern_mask(const char *in_pattern, RzFlirtNode *child) {
	size_t length = 0;
	ut8 *bytes = NULL, *mask = NULL;

	if (RZ_STR_ISEMPTY(in_pattern)) {
		return false;
	}

	length = strlen(in_pattern);
	if (length & 1) {
		return false;
	}

	ut32 n_bytes = length >> 1;

	bytes = RZ_NEWS(ut8, n_bytes);
	if (!bytes) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child bytes\n");
		return false;
	}

	mask = RZ_NEWS(ut8, n_bytes);
	if (!mask) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child mask\n");
		goto err;
	}

	child->variant_mask = 0;
	for (ut32 i = 0; i < n_bytes; ++i) {
		child->variant_mask <<= 1;
		ut32 p = i << 1;
		char high = in_pattern[p];
		char low = in_pattern[p + 1];
		if (IS_HEXCHAR(high) && IS_HEXCHAR(low)) {
			bytes[i] = parse_byte(high, low);
			mask[i] = 0xFF;
		} else if (high == '.' && low == '.') {
			bytes[i] = 0;
			mask[i] = 0;
			child->variant_mask |= 1;
		} else {
			goto err;
		}
	}

	child->pattern_bytes = bytes;
	child->pattern_mask = mask;
	child->length = n_bytes;
	return true;

err:
	child->variant_mask = 0;
	free(mask);
	free(bytes);
	return false;
}

/**
 * Expects one of these line formats and lines may end with '\r'
 *
 * 4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E 07 FAEE 003B :0000@ Curl_gethostname ^000E gethostname ^0027 strchr ........4885C07403C600004489E05B5D415CC3
 * 31C04885D2741F488D4417FF4839C77610EB1D0F1F4400004883E8014839C777 13 9867 0033 :0000 Curl_memrchr
 * # some comment line
 * ---
 *
 * The '---' are the pat file terminator
 * Some files may contain comments using hashtag (#) as prefix
 */
static bool flirt_pat_parse_line(RzFlirtNode *root, RzStrBuf *sb, ut32 line_num, bool tail_bytes) {
	RzFlirtNode *child = NULL;
	RzFlirtModule *module = NULL;
	char *tmp_tok = NULL;

	int line_len = rz_strbuf_length(sb);
	char *line = rz_strbuf_get(sb);
	if (!strncmp(line, "---", strlen("---"))) {
		return false;
	} else if (line[0] == '#') {
		return true;
	}

	if (line[line_len - 1] == '\r') {
		line_len--;
		line[line_len] = 0;
		if (!*line || line_len < 1) {
			RZ_LOG_WARN("FLIRT: line %u is empty\n", line_num);
			return true;
		}
	}

	RzList *tokens = rz_str_split_list(line, " ", 0);
	if (rz_list_empty(tokens)) {
		RZ_LOG_ERROR("FLIRT: cannot tokenize line %u\n", line_num);
		goto err;
	}

	child = RZ_NEW0(RzFlirtNode);
	if (!child) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child node\n");
		goto err;
	}

	child->module_list = rz_list_newf((RzListFree)module_free);
	if (!child->module_list) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child module list\n");
		goto err;
	}

	module = RZ_NEW0(RzFlirtModule);
	if (!module || !rz_list_append(child->module_list, module)) {
		free(module);
		RZ_LOG_ERROR("FLIRT: cannot allocate or append child module\n");
		goto err;
	}

	module->public_functions = rz_list_newf((RzListFree)free);
	if (!module->public_functions) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child module public function list\n");
		goto err;
	}

	module->referenced_functions = rz_list_newf((RzListFree)free);
	if (!module->public_functions) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child module referenced function list\n");
		goto err;
	}

	// Pattern with mask
	// 4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E
	// 31C04885D2741F488D4417FF4839C77610EB1D0F1F4400004883E8014839C777
	tmp_tok = (char *)rz_list_pop_head(tokens);
	if (!flirt_pat_parse_pattern_mask(tmp_tok, child)) {
		RZ_LOG_ERROR("FLIRT: invalid pattern with mask (%s) at line %u\n", tmp_tok, line_num);
		goto err;
	}
	pat_dbg("pattern: %s\n", tmp_tok);

	// CRC16 length
	// [...] 07
	// [...] 13
	tmp_tok = (char *)rz_list_pop_head(tokens);
	if (tmp_tok && strlen(tmp_tok) == 2 && IS_HEXCHAR(tmp_tok[0]) && IS_HEXCHAR(tmp_tok[1])) {
		module->crc_length = parse_byte(tmp_tok[0], tmp_tok[1]);
	} else {
		RZ_LOG_ERROR("FLIRT: invalid crc16 length (%s) at line %u\n", tmp_tok, line_num);
		goto err;
	}
	pat_dbg("crc16 length: %s\n", tmp_tok);

	// CRC16 value
	// [...] FAEE
	// [...] 9867
	tmp_tok = (char *)rz_list_pop_head(tokens);
	if (tmp_tok && strlen(tmp_tok) == 4 &&
		IS_HEXCHAR(tmp_tok[0]) && IS_HEXCHAR(tmp_tok[1]) &&
		IS_HEXCHAR(tmp_tok[2]) && IS_HEXCHAR(tmp_tok[3])) {
		module->crc16 = parse_byte(tmp_tok[0], tmp_tok[1]) << 8;
		module->crc16 |= parse_byte(tmp_tok[2], tmp_tok[3]);
	} else {
		RZ_LOG_ERROR("FLIRT: invalid crc16 value (%s) at line %u\n", tmp_tok, line_num);
		goto err;
	}
	pat_dbg("crc16: %s\n", tmp_tok);

	// function size (min 2 bytes, but can be bigger)
	// [...] 003B
	// [...] 0033
	tmp_tok = (char *)rz_list_pop_head(tokens);
	if (!tmp_tok || strlen(tmp_tok) < 4 || !(module->length = strtol(tmp_tok, NULL, 16))) {
		RZ_LOG_ERROR("FLIRT: invalid function size (%s) at line %u\n", tmp_tok, line_num);
		goto err;
	}
	pat_dbg("function size: %s\n", tmp_tok);

	// symbols
	// :0000@ Curl_gethostname ^000E gethostname ^0027 strchr
	// :0000 Curl_memrchr
	while ((tmp_tok = (char *)rz_list_pop_head(tokens)) && RZ_STR_ISNOTEMPTY(tmp_tok)) {
		RzList *to_append = NULL;
		ut32 len_tok = strlen(tmp_tok);
		ut32 offset = 0;
		bool is_local = false;
		if (len_tok > 0 && !(len_tok & 1) && (IS_HEXCHAR(tmp_tok[0]) || tmp_tok[0] == '.')) {
			// it's trailer bytes
			break;
		}

		if (len_tok >= 6 && tmp_tok[0] == ':' && tmp_tok[len_tok - 1] == '@') {
			// :0000@ -> local function (handling it as public)
			tmp_tok[len_tok - 1] = 0;
			offset = strtol(tmp_tok + 1, NULL, 16);
			is_local = true;
			to_append = module->public_functions;
			tmp_tok[len_tok - 1] = '@';
		} else if (len_tok >= 5 && tmp_tok[0] == ':') {
			// :0000 -> public function
			offset = strtol(tmp_tok + 1, NULL, 16);
			to_append = module->public_functions;
		} else if (len_tok == 5 && tmp_tok[0] == '^') {
			// ^0000 -> reference function
			offset = strtol(tmp_tok + 1, NULL, 16);
			to_append = module->referenced_functions;
		} else {
			RZ_LOG_ERROR("FLIRT: invalid symbol offset (%.10s len %u) at line %u\n", tmp_tok, len_tok, line_num);
			goto err;
		}

		tmp_tok = (char *)rz_list_pop_head(tokens);
		if (RZ_STR_ISEMPTY(tmp_tok)) {
			RZ_LOG_ERROR("FLIRT: empty symbol name at line %u\n", line_num);
			goto err;
		}
		len_tok = strlen(tmp_tok);

		RzFlirtFunction *function = RZ_NEW0(RzFlirtFunction);
		if (!function || !rz_list_append(to_append, function)) {
			free(function);
			RZ_LOG_ERROR("FLIRT: cannot allocate or append RzFlirtFunction\n");
			goto err;
		}
		function->is_local = is_local;
		function->offset = offset;
		strncpy(function->name, tmp_tok, RZ_MIN(len_tok, RZ_FLIRT_NAME_MAX - 1));
		pat_dbg("%s function: %04x %s\n", to_append == module->referenced_functions ? "ref" : (function->is_local ? "loc" : "pub"), offset, tmp_tok);
	}

	if (tail_bytes && RZ_STR_ISNOTEMPTY(tmp_tok) && (IS_HEXCHAR(tmp_tok[0]) || tmp_tok[0] == '.')) {
		size_t len_tok = strlen(tmp_tok);

		module->tail_bytes = rz_list_newf((RzListFree)free);
		if (!module->public_functions) {
			RZ_LOG_ERROR("FLIRT: cannot allocate child module tail bytes list\n");
			goto err;
		}

		for (ut32 i = 0, o = 0; i < len_tok && rz_list_length(module->tail_bytes) < 0xFF; i += 2, o++) {
			if (tmp_tok[i] == '.' && tmp_tok[i + 1] == '.') {
				continue;
			} else if (!IS_HEXCHAR(tmp_tok[i]) || !IS_HEXCHAR(tmp_tok[i + 1])) {
				RZ_LOG_ERROR("FLIRT: expecting tail byte at line %u but got (%s)\n", line_num, tmp_tok + i);
				goto err;
			}
			ut8 byte = parse_byte(tmp_tok[i], tmp_tok[i + 1]);

			RzFlirtTailByte *tail = RZ_NEW0(RzFlirtTailByte);
			if (!tail || !rz_list_append(module->tail_bytes, tail)) {
				free(tail);
				RZ_LOG_ERROR("FLIRT: cannot allocate or append RzFlirtTailByte\n");
				goto err;
			}

			tail->offset = o;
			tail->value = byte;
		}
		pat_dbg("tail: %s\n", tmp_tok);
	}

	if (rz_list_length(module->public_functions) < 1) {
		RZ_LOG_ERROR("FLIRT: a node must have at least one public function\n");
		goto err;
	}

	if (!rz_list_append(root->child_list, child)) {
		RZ_LOG_ERROR("FLIRT: cannot append child to root\n");
		goto err;
	}

	rz_list_free(tokens);
	return true;

err:
	rz_sign_flirt_node_free(child);
	rz_list_free(tokens);
	return false;
}

/**
 * \brief Parses the RzBuffer containing a FLIRT signature in string format and returns an RzFlirtNode
 *
 * \param  flirt_buf     The buffer to read
 * \param  optimization  Optimization to apply after creation of the flatten nodes.
 * \param  info          Pointer to a RzFlirtInfo that can be used to get info about the pat file
 * \return               Parsed FLIRT node
 */
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_parse_string_pattern_from_buffer(RZ_NONNULL RzBuffer *flirt_buf, ut32 optimization, RZ_NULLABLE RzFlirtInfo *info) {
	rz_return_val_if_fail(flirt_buf, NULL);

	if (optimization > RZ_FLIRT_NODE_OPTIMIZE_MAX) {
		RZ_LOG_ERROR("FLIRT: optimization value is invalid (%u > RZ_FLIRT_NODE_OPTIMIZE_MAX).\n", optimization);
		return NULL;
	}

	char buffer[PAT_LINE_BUFFER_SIZE];
	const char *buffer_end = buffer + sizeof(buffer);
	ut32 line_num = 1;
	char *newline = NULL;
	st64 read = 0;
	RzFlirtNode *root = NULL;
	RzStrBuf *line = NULL;

	root = RZ_NEW0(RzFlirtNode);
	if (!root) {
		RZ_LOG_ERROR("FLIRT: cannot allocate root node\n");
		return NULL;
	}

	root->child_list = rz_list_newf((RzListFree)rz_sign_flirt_node_free);
	if (!root->child_list) {
		free(root);
		RZ_LOG_ERROR("FLIRT: cannot allocate root node child list\n");
		return NULL;
	}

	line = rz_strbuf_new("");
	if (!line) {
		rz_sign_flirt_node_free(root);
		RZ_LOG_ERROR("FLIRT: cannot allocate line buffer\n");
		return NULL;
	}

	bool tail_bytes = optimization != RZ_FLIRT_NODE_OPTIMIZE_MAX;
	do {
		if (newline && rz_strbuf_length(line) > 0) {
			char *p = newline + 1;
			pat_dbg("%05u: %s\n", line_num, rz_strbuf_get(line));
			bool parsed = flirt_pat_parse_line(root, line, line_num, tail_bytes);
			rz_strbuf_fini(line);
			rz_strbuf_init(line);
			if (!parsed) {
				break;
			}
			line_num++;
			if (p < buffer_end && *p) {
				if ((newline = strchr(p, '\n'))) {
					newline[0] = 0;
				}
				rz_strbuf_append(line, p);
			}
			continue;
		}
		memset(buffer, 0, sizeof(buffer));
		if ((read = rz_buf_read(flirt_buf, (ut8 *)buffer, sizeof(buffer) - 1)) < 1) {
			break;
		}
		if ((newline = strchr(buffer, '\n'))) {
			newline[0] = 0;
		}
		rz_strbuf_append(line, buffer);
	} while (true);

	if (rz_strbuf_length(line) > 0) {
		flirt_pat_parse_line(root, line, line_num, tail_bytes);
	}

	rz_strbuf_free(line);

	if (optimization == RZ_FLIRT_NODE_OPTIMIZE_NONE) {
		rz_list_sort(root->child_list, (RzListComparator)flirt_compare_node, NULL);
	} else if (!flirt_node_optimize(root)) {
		rz_sign_flirt_node_free(root);
		return NULL;
	}

	if (info) {
		info->type = RZ_FLIRT_FILE_TYPE_PAT;
		info->u.pat.n_modules = rz_sign_flirt_node_count_nodes(root);
	}

	return root;
}

static void flirt_pat_append_prelude(RzStrBuf *prelude, RZ_NONNULL const RzFlirtNode *child) {
	for (ut32 i = 0; i < child->length; i++) {
		if (child->pattern_mask[i]) {
			rz_strbuf_appendf(prelude, "%02X", child->pattern_bytes[i]);
		} else {
			rz_strbuf_append(prelude, "..");
		}
	}
}

static bool flirt_pat_write_line(RZ_NONNULL const RzFlirtNode *node, RZ_NONNULL RzBuffer *buffer, RzStrBuf *prelude) {
	flirt_pat_append_prelude(prelude, node);
	int prelude_len = rz_strbuf_length(prelude);

	if (rz_list_length(node->child_list) > 0) {
		RzListIter *it;
		RzFlirtNode *child;
		rz_list_foreach (node->child_list, it, child) {
			rz_strbuf_slice(prelude, 0, prelude_len);
			if (!flirt_pat_write_line(child, buffer, prelude)) {
				return false;
			}
		}
		return true;
	}

	if (prelude_len < (RZ_FLIRT_MAX_PRELUDE_SIZE << 1)) {
		char *pad = rz_str_pad('.', (RZ_FLIRT_MAX_PRELUDE_SIZE << 1) - prelude_len);
		rz_strbuf_append(prelude, pad);
		free(pad);
	}

	char tmp[32];
	ut32 offset = 0;
	RzListIter *it, *it2;
	const RzFlirtModule *module;
	const RzFlirtFunction *function;
	const RzFlirtTailByte *byte;
	rz_list_foreach (node->module_list, it, module) {
		// prelude pattern mask
		rz_buf_append_string(buffer, rz_strbuf_get(prelude));

		// crc16 length + crc16 value
		rz_strf(tmp, " %02X %04X ", module->crc_length, module->crc16);
		rz_buf_append_string(buffer, tmp);

		// function size
		rz_strf(tmp, "%04X ", module->length);
		rz_buf_append_string(buffer, tmp);
		// public functions
		rz_list_foreach (module->public_functions, it2, function) {
			rz_strf(tmp, ":%04X%s ", function->offset, function->is_local ? "@" : "");
			rz_buf_append_string(buffer, tmp);
			rz_buf_append_string(buffer, function->name);
			rz_buf_append_string(buffer, " ");
		}
		// referenced functions
		rz_list_foreach (module->referenced_functions, it2, function) {
			rz_strf(tmp, "^%04X ", function->offset);
			rz_buf_append_string(buffer, tmp);
			rz_buf_append_string(buffer, function->name);
			rz_buf_append_string(buffer, " ");
		}

		// tail bytes (if any)
		offset = 0;
		rz_list_foreach (module->tail_bytes, it2, byte) {
			while (offset < byte->offset) {
				rz_buf_append_string(buffer, "..");
				offset++;
			}
			rz_strf(tmp, "%02X", byte->value);
			rz_buf_append_string(buffer, tmp);
			offset++;
		}
		rz_buf_append_string(buffer, "\n");
	}
	return true;
}

/**
 * \brief Writes in the the RzBuffer the FLIRT signatures in string format
 *
 * \param  root   The FLIRT root node to use as input
 * \param  buffer The buffer to write to
 * \return               Parsed FLIRT node
 */
RZ_API bool rz_sign_flirt_write_string_pattern_to_buffer(RZ_NONNULL const RzFlirtNode *root, RZ_NONNULL RzBuffer *buffer) {
	rz_return_val_if_fail(root && buffer, false);
	// 4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E 07 FAEE 003B :0000@ Curl_gethostname ^000E gethostname ^0027 strchr ........4885C07403C600004489E05B5D415CC3
	RzStrBuf sb;

	RzListIter *it;
	RzFlirtNode *child;
	rz_list_foreach (root->child_list, it, child) {
		rz_strbuf_init(&sb);
		if (!flirt_pat_write_line(child, buffer, &sb)) {
			return false;
		}
		rz_strbuf_fini(&sb);
	}
	rz_buf_append_string(buffer, "---\n");
	return true;
}
