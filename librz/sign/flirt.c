// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
/* credits to IDA for the flirt tech */
/* original cpp code from Rheax <rheaxmascot@gmail.com> */
/* thanks LemonBoy for the improved research on rheax original work */
/* more information on flirt https://www.hex-rays.com/products/ida/tech/flirt/in_depth.shtml */

/*
   Flirt file format
   =================
   High level layout:
   After the v5 header, there might be two more header fields depending of the version.
   If version == 6 or version == 7, there is one more header field.
   If version == 8 or version == 9, there is two more header field.
   See idasig_v* structs for their description.
   Next there is the non null terminated library name of library_name_len length.
   Next see Parsing below.

   Endianness:
   All multi bytes values are stored in little endian form in the headers.
   For the rest of the file they are stored in big endian form.

   Parsing:
   - described headers
   - library name, not null terminated, length of library_name_len.

   parse_tree (cf. parse_tree):
   - read number of initial root nodes: 1 byte if strictly inferior to 127 otherwise 2 bytes,
   stored in big endian mode, and the most significant bit isn't used. cf. read_multiple_bytes().
   if 0, this is a leaf, goto leaf (cf. parse_leaf). else continue parsing (cf. parse_tree).

   - for number of root node do:
    - read node length, one unsigned byte (the pattern size in this node) (cf. read_node_length)
    - read node variant mask (bit array) (cf. read_node_variant_mask):
      if node length < 0x10 read up to two bytes. cf. read_max_2_bytes
      if node length < 0x20 read up to five bytes. cf. read_multiple_bytes
    - read non-variant bytes (cf. read_node_bytes)
    - goto parse_tree

   leaf (cf. parse_leaf):
   - read crc length, 1 byte
   - read crc value, 2 bytes
   module:
    - read total module length:
      if version >= 9 read up to five bytes, cf. read_multiple_bytes
      else read up to two bytes, cf. read_max_2_bytes
    - read module public functions (cf. read_module_public_functions):
    same crc:
      public function name:
	- read function offset:
	  if version >= 9 read up to five bytes, cf. read_multiple_bytes
	  else read up to two bytes, cf. read_max_2_bytes
	- if current byte < 0x20, read it : this is a function flag, see IDASIG_FUNCTION* defines
	- read function name until current byte < 0x20
	- read parsing flag, 1 byte
	- if flag & IDASIG_PARSE_MORE_PUBLIC_NAMES: goto public function name
	- if flag & IDASIG_PARSE_READ_TAIL_BYTES, read tail bytes, cf. read_module_tail_bytes:
	  - if version >= 8: read number of tail bytes, else suppose one
	  - for number of tail bytes do:
	    - read tail byte offset:
	      if version >= 9 read up to five bytes, cf. read_multiple_bytes
	      else read up to two bytes, cf. read_max_2_bytes
	    - read tail byte value, one byte

	- if flag & IDASIG_PARSE_READ_REFERENCED_FUNCTIONS, read referenced functions, cf. read_module_referenced_functions:
	  - if version >= 8: read number of referenced functions, else suppose one
	  - for number of referenced functions do:
	    - read referenced function offset:
	      if version >= 9 read up to five bytes, cf. read_multiple_bytes
	      else read up to two bytes, cf. read_max_2_bytes
	    - read referenced function name length, one byte:
	      - if name length == 0, read length up to five bytes, cf. read_multiple_bytes
	    - for name length, read name chars:
	      - if name is null terminated, it means the offset is negative

	- if flag & IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC, goto same crc, read function with same crc
	- if flag & IDASIG_PARSE_MORE_MODULES, goto module, to read another module


   More Information
   -----------------
   Function flags:
   - local functions ((l) with dumpsig) which are static ones.
   - collision functions ((!) with dumpsig) are the result of an unresolved collision.

   Tail bytes:
   When two modules have the same pattern, and same crc, flirt tries to identify
   a byte which is different in all the same modules.
   Their offset is from the first byte after the crc.
   They appear as "(XXXX: XX)" in dumpsig output

   Referenced functions:
   When two modules have the same pattern, and same crc, and are identical in
   non-variant bytes, they only differ by the functions they call. These functions are
   "referenced functions". They need to be identified first before the module can be
   identified.
   The offset is from the start of the function to the referenced function name.
   They appear as "(REF XXXX: NAME)" in dumpsig output
 */

#include <rz_lib.h>
#include <rz_flirt.h>
#define MAX_WBITS 15

#if 0
#define sig_dbg(...) eprintf(__VA_ARGS__)
static void sig_dbg_buffer(const char *name, const ut8 *buffer, ut32 b_size) {
	sig_dbg("%s ", name);
	for (ut32 i = 0; i < b_size; ++i) {
		sig_dbg(i == 0 ? "%02X" : ":%02X", buffer[i]);
	}
	sig_dbg("\n");
}
#else
#define sig_dbg(...)
#define sig_dbg_buffer(n, b, s)
#endif

#define rz_buf_append_le_bits(buffer, tmp, value, bits) \
	rz_write_le##bits(tmp, value); \
	rz_buf_append_bytes(buffer, tmp, sizeof(ut##bits))

#define rz_buf_append_be_bits(buffer, tmp, value, bits) \
	rz_write_be##bits(tmp, value); \
	rz_buf_append_bytes(buffer, tmp, sizeof(ut##bits))

/*feature flags*/
#define IDASIG_FEATURE_NONE          0x00
#define IDASIG_FEATURE_STARTUP       0x01
#define IDASIG_FEATURE_CTYPE_CRC     0x02
#define IDASIG_FEATURE_2BYTE_CTYPE   0x04
#define IDASIG_FEATURE_ALT_CTYPE_CRC 0x08
#define IDASIG_FEATURE_COMPRESSED    0x10

/*parsing flags*/
#define IDASIG_PARSE_MORE_PUBLIC_NAMES          0x01
#define IDASIG_PARSE_READ_TAIL_BYTES            0x02
#define IDASIG_PARSE_READ_REFERENCED_FUNCTIONS  0x04
#define IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC 0x08
#define IDASIG_PARSE_MORE_MODULES               0x10

/*functions flags*/
#define IDASIG_FUNCTION_LOCAL                0x02 // describes a static function
#define IDASIG_FUNCTION_UNRESOLVED_COLLISION 0x08 // describes a collision that wasn't resolved

typedef struct idasig_v5_t {
	/* newer header only add fields, that's why we'll always read a v5 header first */
	ut8 magic[6]; /* should be set to IDASGN */
	ut8 version; /*from 5 to 9*/
	ut8 arch;
	ut32 file_types;
	ut16 os_types;
	ut16 app_types;
	ut16 features;
	ut16 old_n_functions;
	ut16 crc16;
	ut8 ctype[12]; // XXX: how to use it
	ut8 library_name_len;
	ut16 ctypes_crc16;
} idasig_v5_t;

typedef struct idasig_v6_v7_t {
	ut32 n_functions;
} idasig_v6_v7_t;

typedef struct idasig_v8_v9_t {
	ut16 pattern_size;
} idasig_v8_v9_t;

typedef struct idasig_v10_t {
	ut16 unknown;
} idasig_v10_t;

typedef struct parse_status_t {
	RzBuffer *buffer;
	bool eof;
	bool error;
	ut8 version;
} ParseStatus;

#define is_status_err_or_eof(p) (p->eof || p->error)

/* newer header only add fields, that's why we'll always read a v5 header first */
/*
   arch             : target architecture
   file_types       : files where we expect to find the functions (exe, coff, ...)
   os_types         : os where we expect to find the functions
   app_types        : applications in which we expect to find the functions
   features         : signature file features
   old_n_functions  : number of functions
   crc16            : certainly crc16 of the tree
   ctype[12]        : unknown field
   library_name_len : length of the library name, which is right after the header
   ctypes_crc16     : unknown field
   n_functions      : number of functions
   pattern_size     : number of the leading pattern bytes
 */

// This is from flair tools flair/crc16.cpp
// CRC-HDLC & CRC-16/X-25 produces the same but in LE format.
#define POLY 0x8408
ut16 flirt_crc16(const ut8 *data_p, size_t length) {
	rz_return_val_if_fail(data_p, 0);

	ut8 i;
	ut32 data;
	ut32 crc = 0xFFFF;

	if (length == 0) {
		return 0;
	}
	do {
		data = *data_p++;
		for (i = 0; i < 8; i++) {
			if ((crc ^ data) & 1) {
				crc = (crc >> 1) ^ POLY;
			} else {
				crc >>= 1;
			}
			data >>= 1;
		}
	} while (--length > 0);

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | ((data >> 8) & 0xff);
	return (ut16)(crc);
}

static ut8 read_byte(ParseStatus *b) {
	ut8 r = 0;
	int length;

	if (b->eof || b->error) {
		return 0;
	}
	if ((length = rz_buf_read(b->buffer, &r, 1)) != 1) {
		if (length == -1) {
			b->error = true;
		}
		if (length == 0) {
			b->eof = true;
		}
		return 0;
	}
	return r;
}

static ut16 read_short(ParseStatus *b) {
	ut16 r = (read_byte(b) << 8);
	r += read_byte(b);
	return r;
}

static ut32 read_word(ParseStatus *b) {
	ut32 r = ((ut32)(read_short(b)) << 16);
	r += read_short(b);
	return r;
}

static ut16 read_max_2_bytes(ParseStatus *b) {
	ut16 r = read_byte(b);
	return (r & 0x80)
		? ((r & 0x7f) << 8) + read_byte(b)
		: r;
}

static ut32 read_multiple_bytes(ParseStatus *b) {
	ut32 r = read_byte(b);
	if ((r & 0x80) != 0x80) {
		return r;
	}
	if ((r & 0xc0) != 0xc0) {
		return ((r & 0x7f) << 8) + read_byte(b);
	}
	if ((r & 0xe0) != 0xe0) {
		r = ((r & 0x3f) << 24) + (read_byte(b) << 16);
		r += read_short(b);
		return r;
	}
	return read_word(b);
}

void module_free(RzFlirtModule *module) {
	if (!module) {
		return;
	}
	rz_list_free(module->public_functions);
	rz_list_free(module->tail_bytes);
	rz_list_free(module->referenced_functions);
	free(module);
}

/**
 * \brief Frees an RzFlirtNode struct
 *
 * \param RzFlirtNode  The RzFlirtNode to be freed
 */
RZ_API void rz_sign_flirt_node_free(RZ_NULLABLE RzFlirtNode *node) {
	if (!node) {
		return;
	}
	free(node->pattern_mask);
	free(node->pattern_bytes);
	rz_list_free(node->module_list);
	rz_list_free(node->child_list);
	free(node);
}

/**
 * \brief Frees an RzFlirtInfo struct elements without freeing the pointer
 *
 * \param RzFlirtInfo  The RzFlirtInfo elements to be freed
 */
RZ_API void rz_sign_flirt_info_fini(RZ_NULLABLE RzFlirtInfo *info) {
	if (!info) {
		return;
	}
	if (info->type == RZ_FLIRT_FILE_TYPE_SIG) {
		free(info->u.sig.name);
	}
	memset(info, 0, sizeof(RzFlirtInfo));
}

/**
 * \brief Checks if a pattern does match the buffer data
 *
 * \param p_size   The pattern size
 * \param pattern  The pattern to check agains
 * \param mask     The pattern mask
 * \param b        Buffer to check
 * \param b_size   Size of the buffer to check
 *
 * \return True if pattern does match, false otherwise.
 */
static bool is_pattern_matching(ut32 p_size, const ut8 *pattern, const ut8 *mask, const ut8 *b, ut32 b_size) {
	if (b_size < p_size) {
		return false;
	}
	for (ut32 i = 0; i < p_size; i++) {
		if (mask[i] == 0xFF && pattern[i] != b[i]) {
			return false;
		}
	}
	return true;
}

static bool check_crc16(const RzFlirtModule *module, ut8 *b, ut32 b_size) {
	if (!module->crc_length) {
		return true;
	} else if ((b_size - RZ_FLIRT_MAX_PRELUDE_SIZE) < module->crc_length) {
		return false;
	}
	return module->crc16 == flirt_crc16(b + RZ_FLIRT_MAX_PRELUDE_SIZE, module->crc_length);
}

static bool try_rename_function(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *name) {
	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		// do not rename if is a symbol but check if
		// another function has the same name
		return ht_sp_find(analysis->ht_name_fun, name, NULL) == NULL;
	}
	return rz_analysis_function_rename(fcn, name);
}

/**
 * \brief Checks if the module matches the buffer and renames the matched functions
 *
 * \param analysis  The RzAnalysis struct from where to fetch and modify the functions
 * \param module    The FLIRT module to match against the buffer
 * \param b         Buffer to check
 * \param address   Function address
 * \param buf_size  Size of the buffer to check
 *
 * \return True if pattern does match, false otherwise.
 */
static int module_match_buffer(RzAnalysis *analysis, const RzFlirtModule *module, ut8 *b, ut64 address, ut32 buf_size) {
	RzFlirtFunction *flirt_func = NULL;
	RzAnalysisFunction *next_module_function = NULL;
	RzListIter *it = NULL;
	RzFlirtTailByte *tail_byte = NULL;
	ut32 name_index = 0;

	if (!check_crc16(module, b, buf_size)) {
		return false;
	}
	if (module->tail_bytes) {
		size_t begin = RZ_FLIRT_MAX_PRELUDE_SIZE + module->crc_length;
		rz_list_foreach (module->tail_bytes, it, tail_byte) {
			if ((begin + tail_byte->offset) < buf_size &&
				b[begin + tail_byte->offset] != tail_byte->value) {
				return false;
			}
		}
	}

	rz_list_foreach (module->public_functions, it, flirt_func) {
		if (next_module_function && (address + flirt_func->offset) == next_module_function->addr) {
			// ensures that the next function is an actual function not pointing to the same offset
			break;
		}

		// Once the first module function is found, we need to go through the module->public_functions
		// list to identify the others. See flirt doc for more information
		next_module_function = rz_analysis_get_function_at(analysis, address + flirt_func->offset);
		if (next_module_function) {
			ut32 next_module_function_size;

			// get function size from flirt signature
			ut64 flirt_fcn_size = module->length - flirt_func->offset;
			RzFlirtFunction *next_flirt_func;
			RzListIter *next_it;
			rz_list_foreach_iter(rz_list_iter_get_next(it), next_it, next_flirt_func) {
				if (!next_flirt_func->is_local && !next_flirt_func->negative_offset) {
					flirt_fcn_size = next_flirt_func->offset - flirt_func->offset;
					break;
				}
			}
			// resize function if needed
			next_module_function_size = rz_analysis_function_linear_size(next_module_function);
			if (next_module_function_size < flirt_fcn_size) {
				RzListIter *iter;
				RzListIter *iter_tmp;
				RzAnalysisFunction *fcn;
				rz_list_foreach_safe (analysis->fcns, iter, iter_tmp, fcn) {
					if (fcn != next_module_function &&
						fcn->addr >= next_module_function->addr + next_module_function_size &&
						fcn->addr < next_module_function->addr + flirt_fcn_size) {
						void **iter_bb;
						RzAnalysisBlock *block;
						rz_pvector_foreach (fcn->bbs, iter_bb) {
							block = (RzAnalysisBlock *)*iter_bb;
							rz_analysis_function_add_block(next_module_function, block);
						}
						next_module_function->ninstr += fcn->ninstr;
						rz_analysis_function_delete(fcn);
					}
				}
				rz_analysis_function_resize(next_module_function, flirt_fcn_size);
				next_module_function_size = rz_analysis_function_linear_size(next_module_function);
				rz_analysis_trim_jmprefs((RzAnalysis *)analysis, next_module_function);
			}

			// filter name
			rz_name_filter(flirt_func->name, -1, true);

			// verify that the name is unique
			char *name = rz_str_newf("flirt.%s", flirt_func->name);
			if (!name) {
				RZ_LOG_ERROR("FLIRT: cannot allocate string buffer for name\n");
				return false;
			}

			while (!try_rename_function(analysis, next_module_function, name)) {
				free(name);
				name_index++;
				name = rz_str_newf("flirt.%s_%u", flirt_func->name, name_index);
				if (!name) {
					RZ_LOG_ERROR("FLIRT: cannot allocate string buffer for name\n");
					return false;
				}
			}

			// remove old flag
			RzFlagItem *fit = analysis->flb.get_at_by_spaces(analysis->flb.f, next_module_function->addr, "fcn.", "func.", NULL);
			if (fit) {
				analysis->flb.unset(analysis->flb.f, fit);
			}

			// set new flag
			analysis->flb.set(analysis->flb.f, name, next_module_function->addr, next_module_function_size);
			RZ_LOG_DEBUG("FLIRT: Found %s\n", next_module_function->name);
			free(name);
		}
	}
	return true;
}

static int node_match_buffer(RzAnalysis *analysis, const RzFlirtNode *node, ut8 *b, ut64 address, ut32 buf_size, ut32 buf_idx) {
	RzListIter *node_child_it, *module_it;
	RzFlirtNode *child;
	RzFlirtModule *module;

	if (is_pattern_matching(node->length, node->pattern_bytes, node->pattern_mask, b + buf_idx, buf_size - buf_idx)) {
		if (node->child_list) {
			rz_list_foreach (node->child_list, node_child_it, child) {
				if (node_match_buffer(analysis, child, b, address, buf_size, buf_idx + node->length)) {
					return true;
				}
			}
		} else if (node->module_list) {
			rz_list_foreach (node->module_list, module_it, module) {
				if (module_match_buffer(analysis, module, b, address, buf_size)) {
					return true;
				}
			}
		}
	}

	return false;
}

/**
 * \brief Tries to find matching functions between the signature infos in root_node and the analyzed functions in analysis
 *
 * \param analysis   The analysis
 * \param root_node  The root node
 *
 * \return False on error, otherwise true
 */
static bool node_match_functions(RzAnalysis *analysis, const RzFlirtNode *root_node) {
	bool ret = true;

	if (rz_list_length(analysis->fcns) == 0) {
		RZ_LOG_ERROR("FLIRT: There are no analyzed functions. Have you run 'aa'?\n");
		return ret;
	}

	analysis->flb.push_fs(analysis->flb.f, "flirt");
	RzListIter *it_func;
	RzAnalysisFunction *func;
	rz_list_foreach (analysis->fcns, it_func, func) {
		if (func->name && !strncmp(func->name, "flirt.", strlen("flirt."))) {
			continue;
		}

		ut64 func_size = rz_analysis_function_linear_size(func);
		ut64 malloc_size = RZ_MAX(func_size, RZ_FLIRT_MAX_PRELUDE_SIZE);
		ut8 *func_buf = calloc(1, malloc_size);
		if (!func_buf) {
			ret = false;
			break;
		}
		if (!analysis->iob.read_at(analysis->iob.io, func->addr, func_buf, (int)func_size)) {
			RZ_LOG_ERROR("FLIRT: Couldn't read function %s at 0x%" PFMT64x "\n", func->name, func->addr);
			RZ_FREE(func_buf);
			ret = false;
			break;
		}
		RzListIter *node_child_it;
		RzFlirtNode *child;
		rz_list_foreach (root_node->child_list, node_child_it, child) {
			if (node_match_buffer(analysis, child, func_buf, func->addr, malloc_size, 0)) {
				break;
			}
		}
		RZ_FREE(func_buf);
	}
	analysis->flb.pop_fs(analysis->flb.f);

	return ret;
}

static ut8 read_module_tail_bytes(RzFlirtModule *module, ParseStatus *b) {
	/* parses a module tail bytes */
	/* returns false on parsing error */
	int i;
	ut32 number_of_tail_bytes;
	RzFlirtTailByte *tail_byte = NULL;
	if (!(module->tail_bytes = rz_list_newf((RzListFree)free))) {
		RZ_LOG_ERROR("FLIRT: failed to allocate tail bytes list.\n");
		goto err_exit;
	}

	if (b->version == 8 || b->version == 9) {
		// this counter was introduced in version 8 and kept in version 9
		number_of_tail_bytes = read_max_2_bytes(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read referenced function count because EOF (version 8 or 9).\n");
			goto err_exit;
		}
	} else if (b->version > 9) {
		// this counter was changed from version 10
		number_of_tail_bytes = read_multiple_bytes(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read referenced function count because EOF (version > 9).\n");
			goto err_exit;
		}
	} else { // suppose there's only one
		number_of_tail_bytes = 1;
	}

	for (i = 0; i < number_of_tail_bytes; i++) {
		tail_byte = RZ_NEW0(RzFlirtTailByte);
		if (!tail_byte) {
			return false;
		}
		if (b->version >= 9) {
			/*/!\ XXX don't trust ./zipsig output because it will write a version 9 header, but keep the old version offsets*/
			tail_byte->offset = read_multiple_bytes(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read tail byte offset because EOF (version >= 9).\n");
				goto err_exit;
			}
		} else {
			tail_byte->offset = read_max_2_bytes(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read tail byte offset because EOF.\n");
				goto err_exit;
			}
		}
		tail_byte->value = read_byte(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read tail byte value because EOF.\n");
			goto err_exit;
		}
		rz_list_append(module->tail_bytes, tail_byte);
		sig_dbg("dbg: read tail byte: %04X: %02X\n", tail_byte->offset, tail_byte->value);
	}

	return true;

err_exit:
	free(tail_byte);
	rz_list_free(module->tail_bytes);
	return false;
}

static ut8 read_module_referenced_functions(RzFlirtModule *module, ParseStatus *b) {
	/* parses a module referenced functions */
	/* returns false on parsing error */
	ut32 i, j;
	ut32 number_of_referenced_functions;
	ut32 ref_function_name_length;
	RzFlirtFunction *ref_function = NULL;

	module->referenced_functions = rz_list_newf((RzListFree)free);

	if (b->version == 8 || b->version == 9) {
		// this counter was introduced in version 8 and kept in version 9
		number_of_referenced_functions = read_max_2_bytes(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read referenced function count because EOF (version 8 or 9).\n");
			goto err_exit;
		}
	} else if (b->version > 9) {
		// this counter was changed from version 10
		number_of_referenced_functions = read_multiple_bytes(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read referenced function count because EOF (version > 9).\n");
			goto err_exit;
		}
	} else { // suppose there's only one
		number_of_referenced_functions = 1;
	}
	sig_dbg("dbg: n refs: %02X\n", number_of_referenced_functions);

	for (i = 0; i < number_of_referenced_functions; i++) {
		ref_function = RZ_NEW0(RzFlirtFunction);
		if (!ref_function) {
			RZ_LOG_ERROR("FLIRT: failed to allocate RzFlirtFunction.\n");
			goto err_exit;
		}
		if (b->version >= 9) {
			ref_function->offset = read_multiple_bytes(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read referenced function offset because EOF (version >= 9).\n");
				goto err_exit;
			}
		} else {
			ref_function->offset = read_max_2_bytes(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read referenced function offset because EOF.\n");
				goto err_exit;
			}
		}
		ref_function_name_length = read_byte(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read referenced function name length because EOF.\n");
			goto err_exit;
		}
		if (!ref_function_name_length) {
			// not sure why it's not read_multiple_bytes() in the first place
			ref_function_name_length = read_multiple_bytes(b); // XXX might be read_max_2_bytes, need more data
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read referenced function name length because EOF (2).\n");
				goto err_exit;
			}
		}
		if (ref_function_name_length >= RZ_FLIRT_NAME_MAX) {
			RZ_LOG_ERROR("FLIRT: invalid referenced function name length (%u >= %u).\n", ref_function_name_length, RZ_FLIRT_NAME_MAX);
			goto err_exit;
		}
		sig_dbg("dbg: REF length %02X\n", ref_function_name_length);
		for (j = 0; j < ref_function_name_length; j++) {
			ref_function->name[j] = read_byte(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read referenced function name[%u] because EOF.\n", j);
				goto err_exit;
			}
		}
		if (!ref_function->name[ref_function_name_length]) {
			// if the last byte of the name is 0, it means the offset is negative
			ref_function->negative_offset = true;
		} else {
			ref_function->name[ref_function_name_length] = '\0';
		}
		rz_list_append(module->referenced_functions, ref_function);
		sig_dbg("dbg: (REF: %04X: %s)\n", ref_function->offset, ref_function->name);
	}

	return true;

err_exit:
	free(ref_function);
	return false;
}

static ut8 read_module_public_functions(RzFlirtModule *module, ParseStatus *b, ut8 *flags) {
	/* Reads and set the public functions names and offsets associated within a module */
	/* returns false on parsing error */
	int i;
	ut32 offset = 0;
	ut8 current_byte;
	RzFlirtFunction *function = NULL;

	module->public_functions = rz_list_newf((RzListFree)free);

	do {
		function = RZ_NEW0(RzFlirtFunction);
		if (b->version >= 9) { // seems like version 9 introduced some larger offsets
			offset += read_multiple_bytes(b); // offsets are dependent of the previous ones
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read public function offset because EOF (version >= 9).\n");
				goto err_exit;
			}
		} else {
			offset += read_max_2_bytes(b); // offsets are dependent of the previous ones
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read public function offset because EOF.\n");
				goto err_exit;
			}
		}
		function->offset = offset;

		current_byte = read_byte(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read public function flags because EOF.\n");
			goto err_exit;
		}
		if (current_byte < 0x20) {
			if (current_byte & IDASIG_FUNCTION_LOCAL) { // static function
				function->is_local = true;
			}
			if (current_byte & IDASIG_FUNCTION_UNRESOLVED_COLLISION) {
				// unresolved collision (happens in *.exc while creating .sig from .pat)
				function->is_collision = true;
			}
			current_byte = read_byte(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read public function current byte because EOF.\n");
				goto err_exit;
			}
		}

		for (i = 0; current_byte >= 0x20 && i < RZ_FLIRT_NAME_MAX; i++) {
			function->name[i] = current_byte;
			current_byte = read_byte(b);
			if (is_status_err_or_eof(b)) {
				RZ_LOG_ERROR("FLIRT: failed to read public function name[%u] because EOF.\n", i);
				goto err_exit;
			}
		}

		if (i == RZ_FLIRT_NAME_MAX) {
			RZ_LOG_WARN("FLIRT: public function name is too long\n");
			function->name[RZ_FLIRT_NAME_MAX - 1] = '\0';
		} else {
			function->name[i] = '\0';
		}

		sig_dbg("dbg: %04X: %s \n", function->offset, function->name);
		*flags = current_byte;
		rz_list_append(module->public_functions, function);
	} while (*flags & IDASIG_PARSE_MORE_PUBLIC_NAMES);

	return true;

err_exit:
	free(function);
	return false;
}

static ut8 parse_leaf(ParseStatus *b, RzFlirtNode *node) {
	/* parses a signature leaf: modules with same leading pattern */
	/* returns false on parsing error */
	ut8 flags, crc_length;
	ut16 crc16;
	RzFlirtModule *module = NULL;

	node->module_list = rz_list_newf((RzListFree)module_free);
	do { // loop for all modules having the same prefix

		crc_length = read_byte(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read crc16 length.\n");
			goto err_exit;
		}
		crc16 = read_short(b);
		if (is_status_err_or_eof(b)) {
			RZ_LOG_ERROR("FLIRT: failed to read crc16.\n");
			goto err_exit;
		}
		sig_dbg("dbg: crc_len: %02X crc16: %04X\n", crc_length, crc16);

		do { // loop for all modules having the same crc
			module = RZ_NEW0(RzFlirtModule);
			if (!module) {
				RZ_LOG_ERROR("FLIRT: failed to allocate RzFlirtModule.\n");
				goto err_exit;
			}

			module->crc_length = crc_length;
			module->crc16 = crc16;

			if (b->version >= 9) { // seems like version 9 introduced some larger length
				/*/!\ XXX don't trust ./zipsig output because it will write a version 9 header, but keep the old version offsets*/
				module->length = read_multiple_bytes(b); // should be < 0x8000
				if (is_status_err_or_eof(b)) {
					RZ_LOG_ERROR("FLIRT: failed to read module length because EOF (version >= 9).\n");
					goto err_exit;
				}
			} else {
				module->length = read_max_2_bytes(b); // should be < 0x8000
				if (is_status_err_or_eof(b)) {
					RZ_LOG_ERROR("FLIRT: failed to read module length because EOF.\n");
					goto err_exit;
				}
			}
			sig_dbg("dbg: module_length: %04X\n", module->length);

			if (!read_module_public_functions(module, b, &flags)) {
				goto err_exit;
			}

			if (flags & IDASIG_PARSE_READ_TAIL_BYTES) { // we need to read some tail bytes because in this leaf we have functions with same crc
				if (!read_module_tail_bytes(module, b)) {
					goto err_exit;
				}
			}
			if (flags & IDASIG_PARSE_READ_REFERENCED_FUNCTIONS) { // we need to read some referenced functions
				if (!read_module_referenced_functions(module, b)) {
					goto err_exit;
				}
			}

			rz_list_append(node->module_list, module);
		} while (flags & IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC);
	} while (flags & IDASIG_PARSE_MORE_MODULES); // same prefix but different crc

	return true;

err_exit:
	module_free(module);
	return false;
}

static bool read_node_length(RzFlirtNode *node, ParseStatus *b) {
	node->length = read_byte(b);
	if (is_status_err_or_eof(b)) {
		return false;
	}
	sig_dbg("dbg: node length: %02X\n", node->length);
	return true;
}

static bool read_node_variant_mask(RzFlirtNode *node, ParseStatus *b) {
	/* Reads and sets a node's variant bytes mask. This mask is then used to */
	/* read the non-variant bytes following. */
	/* returns false on parsing error */
	if (node->length < 0x10) {
		node->variant_mask = read_max_2_bytes(b);
		if (is_status_err_or_eof(b)) {
			return false;
		}
	} else if (node->length <= 0x20) {
		node->variant_mask = read_multiple_bytes(b);
		if (is_status_err_or_eof(b)) {
			return false;
		}
	} else if (node->length <= 0x40) { // it shouldn't be more than 64 bytes
		node->variant_mask = ((ut64)read_multiple_bytes(b) << 32) + read_multiple_bytes(b);
		if (is_status_err_or_eof(b)) {
			return false;
		}
	}

	sig_dbg("dbg: variant_mask %08llx\n", node->variant_mask);
	return true;
}

static bool read_node_bytes(RzFlirtNode *node, ParseStatus *b) {
	/* Reads the node bytes, and also sets the variant bytes in pattern_mask */
	/* returns false on parsing error */
	int i;
	ut64 current_mask_bit = 0;
	if ((int)node->length < 0) {
		return false;
	}
	current_mask_bit = 1ULL << (node->length - 1);
	if (!(node->pattern_bytes = malloc(node->length))) {
		return false;
	}
	if (!(node->pattern_mask = malloc(node->length))) {
		return false;
	}
	for (i = 0; i < node->length; i++, current_mask_bit >>= 1) {
		if (node->variant_mask & current_mask_bit) {
			node->pattern_bytes[i] = 0;
			node->pattern_mask[i] = 0;
		} else {
			node->pattern_bytes[i] = read_byte(b);
			node->pattern_mask[i] = 0xFF;
			if (is_status_err_or_eof(b)) {
				return false;
			}
		}
	}
	sig_dbg_buffer("bytes", node->pattern_bytes, node->length);
	sig_dbg_buffer("mask ", node->pattern_mask, node->length);
	return true;
}

static ut8 parse_tree(ParseStatus *b, RzFlirtNode *root_node) {
	/* parse a signature pattern tree or sub-tree */
	/* returns false on parsing error */
	RzFlirtNode *node = NULL;
	int i, tree_nodes = read_multiple_bytes(b); // confirmed it's not read_byte(), XXX could it be read_max_2_bytes() ???
	if (is_status_err_or_eof(b)) {
		RZ_LOG_ERROR("FLIRT: failed to read tree node number because EOF.\n");
		return false;
	}
	sig_dbg("dbg: tree_nodes %02x\n", tree_nodes);
	if (tree_nodes == 0) { // if there's no tree nodes remaining, that means we are on the leaf
		return parse_leaf(b, root_node);
	}
	root_node->child_list = rz_list_newf((RzListFree)rz_sign_flirt_node_free);

	for (i = 0; i < tree_nodes; i++) {
		if (!(node = RZ_NEW0(RzFlirtNode))) {
			RZ_LOG_ERROR("FLIRT: failed to allocate child tree node.\n");
			goto err_exit;
		}
		if (!read_node_length(node, b) || node->length > 0x40) {
			RZ_LOG_ERROR("FLIRT: failed to read pattern mask length (length %u).\n", node->length);
			goto err_exit;
		}
		if (!read_node_variant_mask(node, b)) {
			RZ_LOG_ERROR("FLIRT: failed to read variant mask.\n");
			goto err_exit;
		}
		if (!read_node_bytes(node, b)) {
			RZ_LOG_ERROR("FLIRT: failed to read pattern.\n");
			goto err_exit;
		}
		if (!parse_tree(b, node)) {
			goto err_exit; // parse child nodes
		}
		rz_list_append(root_node->child_list, node);
	}
	return true;
err_exit:
	rz_sign_flirt_node_free(node);
	return false;
}

static bool parse_v5_header(RzBuffer *buf, idasig_v5_t *header) {
	rz_buf_seek(buf, 0, RZ_BUF_SET);
	if (rz_buf_read(buf, header->magic, sizeof(header->magic)) != sizeof(header->magic)) {
		return false;
	}
	if (rz_buf_read(buf, &header->version, sizeof(header->version)) != sizeof(header->version)) {
		return false;
	}
	if (rz_buf_read(buf, &header->arch, sizeof(header->arch)) != sizeof(header->arch)) {
		return false;
	}
	if (!rz_buf_read_le32(buf, &header->file_types)) {
		return false;
	}
	if (!rz_buf_read_le16(buf, &header->os_types)) {
		return false;
	}
	if (!rz_buf_read_le16(buf, &header->app_types)) {
		return false;
	}
	if (!rz_buf_read_le16(buf, &header->features)) {
		return false;
	}
	if (!rz_buf_read_le16(buf, &header->old_n_functions)) {
		return false;
	}
	if (!rz_buf_read_le16(buf, &header->crc16)) {
		return false;
	}
	if (rz_buf_read(buf, header->ctype, sizeof(header->ctype)) != sizeof(header->ctype)) {
		return false;
	}
	if (rz_buf_read(buf, (unsigned char *)&header->library_name_len, sizeof(header->library_name_len)) != sizeof(header->library_name_len)) {
		return false;
	}
	if (!rz_buf_read_le16(buf, &header->ctypes_crc16)) {
		return false;
	}

	return true;
}

static int parse_v6_v7_header(RzBuffer *buf, idasig_v6_v7_t *header) {
	if (!rz_buf_read_le32(buf, &header->n_functions)) {
		RZ_LOG_ERROR("FLIRT: invalid sig file (EOF in v6/v7 header).\n");
		return false;
	}

	return true;
}

static int parse_v8_v9_header(RzBuffer *buf, idasig_v8_v9_t *header) {
	if (!rz_buf_read_le16(buf, &header->pattern_size)) {
		RZ_LOG_ERROR("FLIRT: invalid sig file (EOF in v8/v9 header).\n");
		return false;
	}

	return true;
}

static int parse_v10_header(RzBuffer *buf, idasig_v10_t *header) {
	if (!rz_buf_read_le16(buf, &header->unknown)) {
		RZ_LOG_ERROR("FLIRT: invalid sig file (EOF in v10 header).\n");
		return false;
	}

	return true;
}

/**
 * \brief Returns the FLIRT file version read from the RzBuffer
 * This function returns the FLIRT file version, when it fails returns 0
 *
 * \param  buffer The buffer to read
 * \return        Parsed FLIRT version
 */
static ut8 flirt_parse_version(RzBuffer *buffer) {
	ut8 ret = 0;

	idasig_v5_t *header = RZ_NEW0(idasig_v5_t);
	if (!header) {
		goto exit;
	}

	if (rz_buf_read(buffer, header->magic, sizeof(header->magic)) != sizeof(header->magic)) {
		RZ_LOG_ERROR("FLIRT: invalid sig file (EOF in v5 header magic).\n");
		goto exit;
	}

	if (memcmp((const char *)header->magic, "IDASGN", 6)) {
		RZ_LOG_ERROR("FLIRT: invalid sig magic.\n");
		goto exit;
	}

	if (rz_buf_read(buffer, &header->version, sizeof(header->version)) != sizeof(header->version)) {
		RZ_LOG_ERROR("FLIRT: invalid sig file (EOF in v5 header version).\n");
		goto exit;
	}

	ret = header->version;

exit:
	free(header);
	return ret;
}

/**
 * \brief Parses the RzBuffer containing a FLIRT structure and returns an RzFlirtInfo
 *
 * Parses the RzBuffer containing a FLIRT structure and returns an RzFlirtNode if expected_arch
 * matches the id or RZ_FLIRT_SIG_ARCH_ANY is set.
 *
 * \param  flirt_buf     The buffer to read
 * \param  expected_arch The expected arch to be used for the buffer
 * \param  info          Pointer to a RzFlirtInfo that can be used to get info about the sig file
 * \return               Parsed FLIRT node
 */
RZ_API RZ_OWN bool rz_sign_flirt_parse_header_compressed_pattern_from_buffer(RZ_NONNULL RzBuffer *flirt_buf, RZ_NONNULL RzFlirtInfo *info) {
	rz_return_val_if_fail(flirt_buf && info, false);

	bool res = false;
	ut8 *name = NULL;
	idasig_v5_t v5 = { 0 };
	idasig_v6_v7_t v6_v7 = { 0 };
	idasig_v8_v9_t v8_v9 = { 0 };
	idasig_v10_t v10 = { 0 };

	if (!parse_v5_header(flirt_buf, &v5)) {
		RZ_LOG_ERROR("FLIRT: invalid sig header.\n");
		goto exit;
	}

	if (memcmp((const char *)v5.magic, "IDASGN", 6)) {
		RZ_LOG_ERROR("FLIRT: invalid sig magic.\n");
		goto exit;
	}

	if (v5.version < 5 || v5.version > 10) {
		RZ_LOG_ERROR("FLIRT: Unsupported flirt signature version\n");
		goto exit;
	}

	if (v5.version >= 6 && !parse_v6_v7_header(flirt_buf, &v6_v7)) {
		goto exit;
	}

	if (v5.version >= 8 && !parse_v8_v9_header(flirt_buf, &v8_v9)) {
		goto exit;
	}

	if (v5.version >= 10 && !parse_v10_header(flirt_buf, &v10)) {
		goto exit;
	}

	name = malloc(v5.library_name_len + 1);
	if (!name) {
		RZ_LOG_ERROR("FLIRT: failed to allocate library name\n");
		goto exit;
	}

	if (rz_buf_read(flirt_buf, name, v5.library_name_len) != v5.library_name_len) {
		RZ_LOG_ERROR("FLIRT: failed to read library name\n");
		goto exit;
	}

	name[v5.library_name_len] = '\0';

	info->type = RZ_FLIRT_FILE_TYPE_SIG;
	info->u.sig.version = v5.version;
	info->u.sig.architecture = v5.arch;
	info->u.sig.n_modules = v5.version < 6 ? v5.old_n_functions : v6_v7.n_functions;
	info->u.sig.name = (char *)name;
	name = NULL;
	res = true;

exit:
	free(name);
	return res;
}

/**
 * \brief Parses the RzBuffer containing a FLIRT structure and returns an RzFlirtNode
 *
 * Parses the RzBuffer containing a FLIRT structure and returns an RzFlirtNode if expected_arch
 * matches the id or RZ_FLIRT_SIG_ARCH_ANY is set.
 *
 * \param  flirt_buf     The buffer to read
 * \param  expected_arch The expected arch to be used for the buffer
 * \param  info          Pointer to a RzFlirtInfo that can be used to get info about the sig file
 * \return               Parsed FLIRT node
 */
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_parse_compressed_pattern_from_buffer(RZ_NONNULL RzBuffer *flirt_buf, ut8 expected_arch, RZ_NULLABLE RzFlirtInfo *info) {
	rz_return_val_if_fail(flirt_buf && expected_arch <= RZ_FLIRT_SIG_ARCH_ANY, NULL);

	ut8 *name = NULL;
	ut8 *buf = NULL, *decompressed_buf = NULL;
	RzBuffer *rz_buf = NULL;
	int size, decompressed_size;
	RzFlirtNode *node = NULL;
	RzFlirtNode *ret = NULL;
	idasig_v5_t *header = NULL;
	idasig_v6_v7_t *v6_v7 = NULL;
	idasig_v8_v9_t *v8_v9 = NULL;
	idasig_v10_t *v10 = NULL;

	ParseStatus ps = { 0 };

	if (!(ps.version = flirt_parse_version(flirt_buf))) {
		goto exit;
	}

	if (ps.version < 5 || ps.version > 10) {
		RZ_LOG_ERROR("FLIRT: Unsupported flirt signature version\n");
		goto exit;
	}

	if (!(header = RZ_NEW0(idasig_v5_t))) {
		goto exit;
	}

	parse_v5_header(flirt_buf, header);

	if (expected_arch != RZ_FLIRT_SIG_ARCH_ANY && header->arch != expected_arch) {
		RZ_LOG_ERROR("FLIRT: the binary architecture did not match the .sig one.\n");
		goto exit;
	}

	if (ps.version >= 6) {
		if (!(v6_v7 = RZ_NEW0(idasig_v6_v7_t))) {
			goto exit;
		}
		if (!parse_v6_v7_header(flirt_buf, v6_v7)) {
			goto exit;
		}

		if (ps.version >= 8) {
			if (!(v8_v9 = RZ_NEW0(idasig_v8_v9_t))) {
				goto exit;
			}
			if (!parse_v8_v9_header(flirt_buf, v8_v9)) {
				goto exit;
			}

			if (ps.version >= 10) {
				if (!(v10 = RZ_NEW0(idasig_v10_t))) {
					goto exit;
				}
				if (!parse_v10_header(flirt_buf, v10)) {
					goto exit;
				}
			}
		}
	}

	name = malloc(header->library_name_len + 1);
	if (!name) {
		RZ_LOG_ERROR("FLIRT: failed to allocate library name\n");
		goto exit;
	}

	if (rz_buf_read(flirt_buf, name, header->library_name_len) != header->library_name_len) {
		RZ_LOG_ERROR("FLIRT: failed to read library name\n");
		goto exit;
	}

	name[header->library_name_len] = '\0';

	size = rz_buf_size(flirt_buf) - rz_buf_tell(flirt_buf);
	buf = malloc(size);
	if (!buf) {
		RZ_LOG_ERROR("FLIRT: failed to allocate buffer for signature body\n");
		goto exit;
	}

	if (rz_buf_read(flirt_buf, buf, size) != size) {
		RZ_LOG_ERROR("FLIRT: failed to read signature body\n");
		goto exit;
	}

	if (header->features & IDASIG_FEATURE_COMPRESSED) {
		if (ps.version >= 5 && ps.version < 7) {
			if (!(decompressed_buf = rz_inflate_ignore_header(buf, size, NULL, &decompressed_size))) {
				RZ_LOG_ERROR("FLIRT: Failed to decompress buffer.\n");
				goto exit;
			}
		} else if (ps.version >= 7) {
			if (!(decompressed_buf = rz_inflate(buf, size, NULL, &decompressed_size))) {
				RZ_LOG_ERROR("FLIRT: Failed to decompress buffer.\n");
				goto exit;
			}
		} else {
			RZ_LOG_ERROR("FLIRT: Sorry we do not support compressed signatures with version %d.\n", ps.version);
			goto exit;
		}

		RZ_FREE(buf);
		buf = decompressed_buf;
		size = decompressed_size;
	}
	rz_buf = rz_buf_new_with_pointers(buf, size, false);
	if (!rz_buf) {
		RZ_LOG_ERROR("FLIRT: failed to allocate new RzBuffer\n");
		goto exit;
	}
	ps.buffer = rz_buf;

	if (!(node = RZ_NEW0(RzFlirtNode))) {
		RZ_LOG_ERROR("FLIRT: failed to allocate root RzFlirtNode\n");
		goto exit;
	}

	if (parse_tree(&ps, node)) {
		ret = node;
	} else {
		free(node);
	}

	if (info && ret) {
		info->type = RZ_FLIRT_FILE_TYPE_SIG;
		info->u.sig.version = ps.version;
		info->u.sig.architecture = header->arch;
		info->u.sig.n_modules = rz_sign_flirt_node_count_nodes(ret);
		info->u.sig.name = (char *)name;
		name = NULL;
	}

exit:
	free(buf);
	rz_buf_free(rz_buf);
	free(header);
	free(v6_v7);
	free(v8_v9);
	free(v10);
	free(name);
	return ret;
}

/**
 * \brief Parses the FLIRT file and applies the signatures
 *
 * \param  analysis    The RzAnalysis structure
 * \param  flirt_file  The FLIRT file to parse
 * \return true if the signatures were sucessfully applied to the file
 */
RZ_API bool rz_sign_flirt_apply(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const char *flirt_file, ut8 expected_arch) {
	rz_return_val_if_fail(analysis && RZ_STR_ISNOTEMPTY(flirt_file), false);
	RzBuffer *flirt_buf = NULL;
	RzFlirtNode *node = NULL;

	if (expected_arch > RZ_FLIRT_SIG_ARCH_ANY) {
		RZ_LOG_ERROR("FLIRT: unknown architecture %u\n", expected_arch);
		return false;
	}

	const char *extension = rz_str_lchr(flirt_file, '.');
	if (RZ_STR_ISEMPTY(extension) || (strcmp(extension, ".sig") != 0 && strcmp(extension, ".pat") != 0)) {
		RZ_LOG_ERROR("FLIRT: unknown extension '%s'\n", extension);
		return false;
	}

	if (!(flirt_buf = rz_buf_new_slurp(flirt_file))) {
		RZ_LOG_ERROR("FLIRT: Can't open %s\n", flirt_file);
		return false;
	}

	if (!strcmp(extension, ".pat")) {
		node = rz_sign_flirt_parse_string_pattern_from_buffer(flirt_buf, RZ_FLIRT_NODE_OPTIMIZE_NONE, NULL);
	} else {
		node = rz_sign_flirt_parse_compressed_pattern_from_buffer(flirt_buf, expected_arch, NULL);
	}

	rz_buf_free(flirt_buf);
	if (node) {
		if (!node_match_functions(analysis, node)) {
			RZ_LOG_ERROR("FLIRT: Error while scanning the file %s\n", flirt_file);
		}
		rz_sign_flirt_node_free(node);
		return true;
	}
	RZ_LOG_ERROR("FLIRT: We encountered an error while parsing the file %s. Sorry.\n", flirt_file);
	return false;
}

/**
 * \brief Counts the number of FLIRT signatures in the node
 *
 * \param  flirt_file The FLIRT node to use to count
 * \return            Number of signatures
 */
RZ_API ut32 rz_sign_flirt_node_count_nodes(RZ_NONNULL const RzFlirtNode *node) {
	rz_return_val_if_fail(node, 0);
	ut32 count = 0;
	RzListIter *it;
	RzFlirtNode *child;
	rz_list_foreach (node->child_list, it, child) {
		count += rz_sign_flirt_node_count_nodes(child);
	}
	if (rz_list_length(node->module_list) > 0) {
		count += 1;
	}
	return count;
}

static inline bool rz_write_vle16(RzBuffer *buffer, ut16 val) {
	ut8 tmp[10];
	ut32 n_bytes = 0;
	if (val > 0x7FFF) {
		RZ_LOG_ERROR("FLIRT: the variable length value is too big\n");
		return false;
	} else if (val > 0x7F) {
		// 16 bit value with max value 0x1FFF
		n_bytes = 2;
		tmp[0] = 0x80 | (val >> 8);
		tmp[1] = val & 0xFF;
	} else {
		// 8 bit value with max value 0x1F
		n_bytes = 1;
		tmp[0] = val;
	}
	rz_buf_append_bytes(buffer, tmp, n_bytes);
	return true;
}

static inline bool rz_write_vle32(RzBuffer *buffer, ut32 val) {
	ut8 tmp[10];
	ut32 n_bytes = 0;

	if (val > 0x1FFFFFFF) {
		n_bytes = 5;
		tmp[0] = 0xFF; // includes the 0xE0 mask
		tmp[1] = (val >> 24) & 0xFF;
		tmp[2] = (val >> 16) & 0xFF;
		tmp[3] = (val >> 8) & 0xFF;
		tmp[4] = val & 0xFF;
	} else if (val > 0x3FFF) {
		n_bytes = 4;
		tmp[0] = 0xC0 | ((val >> 24) & 0x3F);
		tmp[1] = (val >> 16) & 0xFF;
		tmp[2] = (val >> 8) & 0xFF;
		tmp[3] = val & 0xFF;
	} else if (val > 0x7F) {
		n_bytes = 2;
		tmp[0] = 0x80 | ((val >> 8) & 0x3F);
		tmp[1] = val & 0xFF;
	} else {
		n_bytes = 1;
		tmp[0] = val;
	}

	rz_buf_append_bytes(buffer, tmp, n_bytes);
	return true;
}

static inline bool rz_write_vle64(RzBuffer *buffer, ut64 val) {
	return rz_write_vle32(buffer, (val >> 32) & UT32_MAX) && rz_write_vle32(buffer, val & UT32_MAX);
}

static bool flirt_has_references(RZ_NONNULL const RzFlirtModule *module) {
	return module->referenced_functions && rz_list_length(module->referenced_functions) > 0;
}

static bool rz_write_versioned_vle(RzBuffer *buffer, ut32 value, ut8 version) {
	if (version < 9) {
		return rz_write_vle16(buffer, value);
	}
	return rz_write_vle32(buffer, value);
}

static bool flirt_write_module(RZ_NONNULL const RzFlirtModule *module, RZ_NONNULL RzBuffer *buffer, ut8 flags, ut8 version, bool first) {
	ut8 tmp[4];
	size_t value = 0;
	ut32 base_offset = 0;
	RzListIter *it;
	RzFlirtFunction *func;
	RzFlirtTailByte *byte;
	bool has_ref = flirt_has_references(module);

	if (first) {
		rz_buf_append_le_bits(buffer, tmp, module->crc_length, 8);

		rz_buf_append_be_bits(buffer, tmp, module->crc16, 16);
	}
	rz_write_vle32(buffer, module->length);

	if (has_ref) {
		flags |= IDASIG_PARSE_READ_REFERENCED_FUNCTIONS;
	}
	if (rz_list_length(module->tail_bytes) > 0) {
		flags |= IDASIG_PARSE_READ_TAIL_BYTES;
	}

	rz_list_foreach (module->public_functions, it, func) {
		if (value > 0) {
			tmp[0] = IDASIG_PARSE_MORE_PUBLIC_NAMES;
			rz_buf_append_bytes(buffer, tmp, 1);
		}
		rz_write_vle32(buffer, func->offset - base_offset);
		base_offset = func->offset;
		tmp[0] = 0;
		if (func->is_local) {
			tmp[0] |= IDASIG_FUNCTION_LOCAL;
		}
		if (func->is_collision) {
			tmp[0] |= IDASIG_FUNCTION_UNRESOLVED_COLLISION;
		}
		if (tmp[0]) {
			rz_buf_append_bytes(buffer, tmp, 1);
		}
		rz_buf_append_string(buffer, func->name);
		value++;
	}

	if (value > 0) {
		rz_buf_append_bytes(buffer, &flags, 1);
	}

	value = rz_list_length(module->tail_bytes);
	if (value) {
		if (version >= 8) {
			// n of tail bytes.
			rz_write_versioned_vle(buffer, value, version);
		}
		value = 0;
		rz_list_foreach (module->tail_bytes, it, byte) {
			if (version < 8 && value > 1) {
				RZ_LOG_WARN("FLIRT: the number of tail bytes (%u) is > 1 when version %u does allow only 1\n", rz_list_length(module->tail_bytes), version);
				break;
			}
			value++;

			rz_write_versioned_vle(buffer, byte->offset, version);
			rz_buf_append_le_bits(buffer, tmp, byte->value, 8);
		}
	}

	if (has_ref) {
		// on sig files, it is not allowed to have multiple references.
		tmp[0] = 1;
		rz_buf_append_bytes(buffer, tmp, 1);

		value = 0;
		rz_list_foreach (module->referenced_functions, it, func) {
			if (value > 0) {
				break;
			}
			value++;

			rz_write_versioned_vle(buffer, func->offset, version);

			ut32 length = strlen(func->name);
			if (length > 0x7F) {
				tmp[0] = 0; // when name length is > 0x7F the length is preceeded by a 0x00
				rz_buf_append_bytes(buffer, tmp, 1);
			}
			rz_write_vle16(buffer, length);
			rz_buf_append_bytes(buffer, (ut8 *)func->name, length);
		}
	}

	return true;
}

static bool flirt_write_node(RZ_NONNULL const RzFlirtNode *node, RZ_NONNULL RzBuffer *buffer, ut8 version) {
	if (node->length > 64) {
		RZ_LOG_ERROR("FLIRT: pattern mask size is > 64.\n");
		return false;
	}

	RzListIter *it;
	RzFlirtNode *child;
	RzFlirtModule *module;

	ut32 n_childs = rz_list_length(node->child_list);
	rz_write_vle32(buffer, n_childs);

	if (n_childs < 1) {
		// leaf
		ut8 flags = 0;

		RzFlirtModule *last = rz_list_last(node->module_list);
		rz_list_foreach (node->module_list, it, module) {
			bool already_found = !(flags & IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC);
			if (last != module) {
				RzFlirtModule *next = rz_list_iter_get_next_data(it);
				if (next && next->crc16 == module->crc16) {
					flags = IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC;
				} else {
					flags = IDASIG_PARSE_MORE_MODULES;
				}
			} else {
				flags = 0;
			}
			if (!flirt_write_module(module, buffer, flags, version, already_found)) {
				return false;
			}
		}
		return true;
	}

	// tree
	rz_list_foreach (node->child_list, it, child) {
		// pattern mask size
		ut8 plen = child->length;
		rz_buf_append_bytes(buffer, &plen, 1);
		if (child->length < 0x10) {
			rz_write_vle16(buffer, child->variant_mask & UT16_MAX);
		} else if (child->length <= 0x20) {
			rz_write_vle32(buffer, child->variant_mask & UT32_MAX);
		} else if (child->length <= 0x40) {
			rz_write_vle64(buffer, child->variant_mask);
		} else {
			RZ_LOG_ERROR("FLIRT: pattern mask size cannot be > 64 bits\n");
			return false;
		}
		for (ut32 i = 0; i < child->length; i++) {
			if (child->pattern_mask[i] != 0xFF) {
				continue;
			}
			rz_buf_append_bytes(buffer, &child->pattern_bytes[i], 1);
		}
		if (!flirt_write_node(child, buffer, version)) {
			return false;
		}
	}

	return true;
}

/**
 * \brief Writes in the the RzBuffer the FLIRT signatures in compressed format
 *
 * \param  node   The FLIRT node to use as input
 * \param  buffer The buffer to write to
 * \return               Parsed FLIRT node
 */
RZ_API bool rz_sign_flirt_write_compressed_pattern_to_buffer(RZ_NONNULL const RzFlirtNode *node, RZ_NONNULL RzBuffer *buffer, RzFlirtCompressedOptions *options) {
	rz_return_val_if_fail(node && buffer && options, false);
	RzBuffer *body = buffer;

	if (options->version < 5 || options->version > 10) {
		RZ_LOG_ERROR("FLIRT: unsupported sig type version %u\n", options->version);
		return false;
	} else if (options->arch >= RZ_FLIRT_SIG_ARCH_ANY) {
		RZ_LOG_ERROR("FLIRT: unsupported architecture %u\n", options->arch);
		return false;
	} else if (RZ_STR_ISEMPTY(options->libname)) {
		RZ_LOG_ERROR("FLIRT: library name is empty\n");
		return false;
	}

	size_t library_name_len = strlen(options->libname);
	if (library_name_len > RZ_FLIRT_LIBRARY_NAME_MAX) {
		RZ_LOG_ERROR("FLIRT: library name is too big. max size is %u\n", RZ_FLIRT_LIBRARY_NAME_MAX);
		return false;
	}

	if (options->deflate) {
		if (options->version < 7) {
			RZ_LOG_ERROR("FLIRT: cannot deflate body due FLIRT version being < 7\n");
			return false;
		}

		body = rz_buf_new_empty(0);
		if (!body) {
			RZ_LOG_ERROR("FLIRT: cannot allocate body buffer\n");
			return false;
		}
	}

	ut8 tmp[32];
	ut32 n_functions = rz_sign_flirt_node_count_nodes(node);

	// magic
	rz_buf_append_string(buffer, "IDASGN");

	// version
	rz_buf_append_le_bits(buffer, tmp, options->version, 8);

	// arch
	rz_buf_append_le_bits(buffer, tmp, options->arch, 8);

	// file_types (little endian)
	rz_buf_append_le_bits(buffer, tmp, options->file, 32);

	// os_types (little endian)
	rz_buf_append_le_bits(buffer, tmp, options->os, 16);

	// app_types (little endian)
	rz_buf_append_le_bits(buffer, tmp, options->app, 16);

	// features (little endian)
	rz_buf_append_le_bits(buffer, tmp, options->deflate ? IDASIG_FEATURE_COMPRESSED : IDASIG_FEATURE_NONE, 16);

	// n_functions (little endian) - used only in v5.
	rz_buf_append_le_bits(buffer, tmp, options->version >= 6 ? 0 : n_functions, 16);

	// crc16 (little endian)
	rz_buf_append_le_bits(buffer, tmp, 0, 16);

	// ctype (little endian)
	memset(tmp, 0, 12);
	rz_buf_append_bytes(buffer, tmp, 12);

	// library_name_len (max 255)
	rz_buf_append_le_bits(buffer, tmp, library_name_len, 8);

	// crc16_ctypes (little endian)
	rz_buf_append_le_bits(buffer, tmp, IDASIG_FEATURE_NONE, 16);

	if (options->version >= 6) {
		// n_functions (little endian)
		rz_buf_append_le_bits(buffer, tmp, n_functions, 32);
	}

	if (options->version >= 8) {
		// pattern_size (little endian) - we always use 32 bytes prelude
		rz_buf_append_le_bits(buffer, tmp, RZ_FLIRT_MAX_PRELUDE_SIZE, 16);
	}

	if (options->version >= 10) {
		// unknown (little endian)
		rz_buf_append_le_bits(buffer, tmp, 0, 16);
	}

	// library name
	rz_buf_append_string(buffer, options->libname);

	if (!flirt_write_node(node, body, options->version)) {
		rz_buf_free(body);
		return false;
	}

	bool ret = true;
	if (options->deflate) {
		ut64 block_size = 1ull << 20; // 1 Mb
		if (!rz_deflatew_buf(body, buffer, block_size, NULL, 15)) {
			RZ_LOG_ERROR("FLIRT: cannot deflate body\n");
			ret = false;
		}
		rz_buf_free(body);
	}
	return ret;
}
