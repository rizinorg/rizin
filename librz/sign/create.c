// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file create.c
 * Generates RzFlirtNodes from data contained in RzAnalysis.
 */

#include <rz_flirt.h>
#include <rz_util.h>

#define starts_with_flag(b, c) (!strncmp(b, c, strlen(c)))

extern void module_free(RzFlirtModule *module);
extern ut16 flirt_crc16(const ut8 *data_p, size_t length);

static inline void flirt_function_sanitize_name(RzFlirtFunction *function) {
	for (ut32 i = 0; i < RZ_FLIRT_NAME_MAX; ++i) {
		char ch = function->name[i];
		if (ch > ' ' && ch <= '~') {
			continue;
		} else if (!ch) {
			break;
		}
		function->name[i] = '?';
	}
}

static RzFlirtFunction *flirt_function_new(const char *name, bool is_local, ut64 offset, ut64 address) {
	if (name) {
		if (starts_with_flag(name, "sym.")) {
			name += strlen("sym.");
		} else if (starts_with_flag(name, "flirt.")) {
			name += strlen("flirt.");
		}
	}

	ut32 namelen = name ? strlen(name) : 0;
	if (namelen >= RZ_FLIRT_NAME_MAX) {
		RZ_LOG_WARN("FLIRT: function at %08" PFMT64x " exceeds the max name length (%u >= %u)\n", offset, namelen, RZ_FLIRT_NAME_MAX);
		namelen = (RZ_FLIRT_NAME_MAX - 1);
	}

	RzFlirtFunction *function = RZ_NEW0(RzFlirtFunction);
	if (!function) {
		RZ_LOG_ERROR("FLIRT: cannot allocate function\n");
		return NULL;
	}

	if (namelen > 0) {
		strncpy(function->name, name, namelen);
		flirt_function_sanitize_name(function);
	} else {
		rz_strf(function->name, "fcn.%08" PFMT64x, offset);
	}

	function->offset = address - offset;
	function->negative_offset = offset < address;
	function->is_local = is_local;
	return function;
}

/**
 * The CRC used for the function can only be calculated with non-masked bytes
 * after the prelude.
 * The length of the buffer must be between 0 and 0xFF.
 * All the extra bytes not used by the CRC will be used in for the tail.
 */
static ut32 flirt_crc16_length(RZ_NONNULL const ut8 *mask, size_t size) {
	rz_return_val_if_fail(mask, 0);
	size = RZ_MIN(size, 0xFF);
	for (size_t i = 0; i < size; ++i) {
		if (mask[i] != 0xFF) {
			return i;
		}
	}
	return size;
}

static RzFlirtModule *flirt_module_new(RzAnalysis *analysis, RzAnalysisFunction *func, const ut8 *buffer, const ut8 *mask, ut64 b_size, bool tail_bytes) {
	RzFlirtModule *module = RZ_NEW0(RzFlirtModule);
	if (!module) {
		RZ_LOG_ERROR("FLIRT: cannot allocate module\n");
		return NULL;
	}

	module->tail_bytes = rz_list_newf((RzListFree)free);
	if (!module->tail_bytes) {
		RZ_LOG_ERROR("FLIRT: cannot allocate module tail list\n");
		goto fail;
	}

	module->public_functions = rz_list_newf((RzListFree)free);
	if (!module->public_functions) {
		RZ_LOG_ERROR("FLIRT: cannot allocate module public function list\n");
		goto fail;
	}

	module->referenced_functions = rz_list_newf((RzListFree)free);
	if (!module->referenced_functions) {
		RZ_LOG_ERROR("FLIRT: cannot allocate module referenced function list\n");
		goto fail;
	}

	if (b_size > 0 && buffer) {
		// the crc should be generated only for when the buffer is > RZ_FLIRT_MAX_PRELUDE_SIZE
		// also the size can be zero if after the prelude there is only masked bytes
		module->crc_length = flirt_crc16_length(mask, b_size);
		module->crc16 = flirt_crc16(buffer, module->crc_length);
	}

	module->length = rz_analysis_function_size_from_entry(func);

	if (tail_bytes) {
		for (ut32 i = module->crc_length, k = 0; i < b_size && k < 0xFF; ++i, ++k) {
			if (mask[i] != 0xff) {
				continue;
			}
			RzFlirtTailByte *tb = RZ_NEW0(RzFlirtTailByte);
			if (!tb || !rz_list_append(module->tail_bytes, tb)) {
				RZ_LOG_ERROR("FLIRT: cannot allocate or append tail byte to module list\n");
				free(tb);
				goto fail;
			}
			tb->offset = k;
			tb->value = buffer[i];
		}
	}

	RzFlirtFunction *function = flirt_function_new(func->name, false, func->addr, func->addr);
	if (!function || !rz_list_append(module->public_functions, function)) {
		RZ_LOG_ERROR("FLIRT: cannot append function to public list\n");
		free(function);
		goto fail;
	}

	return module;

fail:
	module_free(module);
	return NULL;
}

static RzFlirtNode *flirt_create_child(const ut8 *buffer, const ut8 *mask, ut32 b_size) {
	RzFlirtNode *child = RZ_NEW0(RzFlirtNode);
	if (!child) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child node.\n");
		goto fail;
	}

	child->child_list = rz_list_newf((RzListFree)rz_sign_flirt_node_free);
	if (!child->child_list) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child module list.\n");
		goto fail;
	}

	child->module_list = rz_list_newf((RzListFree)module_free);
	if (!child->module_list) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child module list.\n");
		goto fail;
	}

	child->pattern_bytes = malloc(RZ_MIN(b_size, RZ_FLIRT_MAX_PRELUDE_SIZE));
	child->pattern_mask = malloc(RZ_MIN(b_size, RZ_FLIRT_MAX_PRELUDE_SIZE));
	if (!child->pattern_bytes || !child->pattern_mask) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child pattern buffer.\n");
		goto fail;
	}

	if (b_size < RZ_FLIRT_MAX_PRELUDE_SIZE) {
		memcpy(child->pattern_bytes, buffer, b_size);
		memcpy(child->pattern_mask, mask, b_size);
		child->length = b_size;
	} else {
		memcpy(child->pattern_bytes, buffer, RZ_FLIRT_MAX_PRELUDE_SIZE);
		memcpy(child->pattern_mask, mask, RZ_FLIRT_MAX_PRELUDE_SIZE);
		child->length = RZ_FLIRT_MAX_PRELUDE_SIZE;
	}

	child->variant_mask = 0;
	for (ut32 i = 0; i < child->length; ++i) {
		child->variant_mask <<= 1;
		if (child->pattern_mask[i] != 0xff) {
			child->variant_mask |= 1;
		}
	}

	return child;

fail:
	rz_sign_flirt_node_free(child);
	return NULL;
}

static RzFlirtNode *flirt_create_child_from_analysis(RzAnalysis *analysis, RzAnalysisFunction *func, const ut8 *buffer, const ut8 *mask, ut32 b_size, bool tail_bytes) {
	RzFlirtNode *child = NULL;
	RzFlirtModule *module = NULL;

	child = flirt_create_child(buffer, mask, b_size);
	if (!child) {
		goto fail;
	}

	if (b_size <= RZ_FLIRT_MAX_PRELUDE_SIZE) {
		module = flirt_module_new(analysis, func, NULL, NULL, 0, false);
	} else {
		module = flirt_module_new(analysis, func, buffer + RZ_FLIRT_MAX_PRELUDE_SIZE, mask + RZ_FLIRT_MAX_PRELUDE_SIZE, b_size - RZ_FLIRT_MAX_PRELUDE_SIZE, tail_bytes);
	}

	if (!module) {
		goto fail;
	} else if (!rz_list_append(child->module_list, module)) {
		module_free(module);
		RZ_LOG_ERROR("FLIRT: cannot append module to child.\n");
		goto fail;
	}

	return child;

fail:
	rz_sign_flirt_node_free(child);
	return NULL;
}

static inline bool is_valid_mask_prelude(const ut8 *buffer, ut32 b_size) {
	for (ut32 i = 0; i < RZ_MIN(RZ_FLIRT_MAX_PRELUDE_SIZE, b_size); ++i) {
		if (buffer[i] == 0xff) {
			return true;
		}
	}
	return false;
}

static int flirt_compare_module(const RzFlirtModule *a, const RzFlirtModule *b) {
	if (a->length != b->length) {
		return a->length - b->length;
	} else if (a->crc_length != b->crc_length) {
		return a->crc_length - b->crc_length;
	}
	const RzFlirtFunction *af = rz_list_first(a->public_functions);
	const RzFlirtFunction *bf = rz_list_first(b->public_functions);
	return strcmp(af->name, bf->name);
}

int flirt_compare_node(const RzFlirtNode *a, const RzFlirtNode *b, void *user) {
	if (a->pattern_mask[0] == 0xFF && b->pattern_mask[0] == 0xFF) {
		return memcmp(a->pattern_bytes, b->pattern_bytes, RZ_MIN(a->length, b->length));
	}
	return a->pattern_mask[0] == 0xFF ? -1 : 1;
}

static void flirt_node_shorten_pattern(RzFlirtNode *node, ut32 from) {
	if (from < 1) {
		return;
	}
	node->length -= from;
	memmove(node->pattern_bytes, node->pattern_bytes + from, node->length);
	memmove(node->pattern_mask, node->pattern_mask + from, node->length);

	ut64 upper_mask = ~(UT64_MAX << node->length);
	node->variant_mask &= upper_mask;
}

static bool flirt_node_shorten_and_insert(const RzFlirtNode *root, RzFlirtNode *node) {
	RzListIter *it;
	RzFlirtNode *child;
	RzFlirtNode *middle_node;
	ut32 i;

	rz_list_foreach (root->child_list, it, child) {
		for (i = 0; i < child->length && i < node->length; ++i) {
			if (child->pattern_mask[i] != 0xFF && node->pattern_mask[i] != 0xFF) {
				continue;
			} else if (child->pattern_mask[i] != node->pattern_mask[i] ||
				child->pattern_bytes[i] != node->pattern_bytes[i]) {
				break;
			}
		}
		if (i == 0) {
			continue;
		} else if (child->length == i && node->length == child->length) {
			// same pattern just merge.
			rz_list_join(child->module_list, node->module_list);
			rz_sign_flirt_node_free(node);
			rz_list_sort(child->module_list, (RzListComparator)flirt_compare_module, NULL);
			return true;
		} else if (child->length == i) {
			// partial pattern match but matches the child
			flirt_node_shorten_pattern(node, i);
			if (!flirt_node_shorten_and_insert(child, node)) {
				return false;
			}
			rz_list_sort(child->child_list, (RzListComparator)flirt_compare_node, NULL);
		} else if (node->length == i) {
			// partial pattern match but matches the node
			rz_list_iter_set_data(it, node);
			flirt_node_shorten_pattern(child, i);
			if (!rz_list_append(node->child_list, child)) {
				RZ_LOG_ERROR("FLIRT: cannot append child to optimized list.\n");
				rz_sign_flirt_node_free(child);
				return false;
			}
		} else {
			// partial pattern match, requires to check the middle node
			middle_node = flirt_create_child(child->pattern_bytes, child->pattern_mask, i);
			if (!middle_node) {
				rz_sign_flirt_node_free(node);
				return false;
			}
			rz_list_iter_set_data(it, middle_node);
			if (!rz_list_append(middle_node->child_list, child)) {
				RZ_LOG_ERROR("FLIRT: cannot append child to optimized list.\n");
				rz_sign_flirt_node_free(node);
				rz_sign_flirt_node_free(child);
				return false;
			} else if (!rz_list_append(middle_node->child_list, node)) {
				RZ_LOG_ERROR("FLIRT: cannot append child to optimized list.\n");
				rz_sign_flirt_node_free(node);
				return false;
			}
			flirt_node_shorten_pattern(node, i);
			flirt_node_shorten_pattern(child, i);
			rz_list_sort(middle_node->child_list, (RzListComparator)flirt_compare_node, NULL);
		}
		return true;
	}

	if (!rz_list_append(root->child_list, node)) {
		RZ_LOG_ERROR("FLIRT: cannot shorten node or append child to optimized list.\n");
		rz_sign_flirt_node_free(node);
		return false;
	}
	return true;
}

bool flirt_node_optimize(RzFlirtNode *root) {
	if (rz_list_length(root->child_list) < 1) {
		return true;
	}

	RzList *childs = root->child_list;

	root->child_list = rz_list_newf((RzListFree)rz_sign_flirt_node_free);
	if (!root->child_list) {
		RZ_LOG_ERROR("FLIRT: cannot allocate child list.\n");
		goto fail;
	}

	rz_list_sort(childs, (RzListComparator)flirt_compare_node, NULL);

	RzListIter *it;
	RzFlirtNode *child;
	rz_list_foreach (childs, it, child) {
		rz_list_iter_set_data(it, NULL);
		if (!flirt_node_shorten_and_insert(root, child)) {
			goto fail;
		}
	}
	rz_list_free(childs);

	return true;

fail:
	rz_list_free(childs);
	return false;
}

static RzFlirtNode *flirt_create_child_from_function(RzAnalysis *analysis, RzAnalysisFunction *func, bool tail_bytes) {
	RzFlirtNode *child = NULL;
	ut64 func_size = rz_analysis_function_size_from_entry(func);
	if (func_size < 1) {
		return NULL;
	}

	if (func_size > ST32_MAX) {
		RZ_LOG_ERROR("FLIRT: this function exceeds the max size allowed by iob->read_at.\n");
		RZ_LOG_ERROR("FLIRT: this should never happen. please open a bug report.\n");
		return NULL;
	}

	ut8 *pattern = malloc(func_size);
	if (!pattern) {
		RZ_LOG_ERROR("FLIRT: cannot allocate function buffer.\n");
		return NULL;
	}

	if (!analysis->iob.read_at(analysis->iob.io, func->addr, pattern, (int)func_size)) {
		RZ_LOG_WARN("FLIRT: couldn't read function %s at 0x%" PFMT64x ".\n", func->name, func->addr);
		free(pattern);
		return NULL;
	}

	ut8 *mask = rz_analysis_mask(analysis, func_size, pattern, func->addr);
	if (!mask) {
		RZ_LOG_ERROR("FLIRT: cannot calculate pattern mask.\n");
		free(pattern);
		return NULL;
	} else if (!is_valid_mask_prelude(mask, func_size)) {
		RZ_LOG_ERROR("FLIRT: the function '%s' has a mask which remove all the bytes from the pattern.\n", func->name);
		goto fail;
	}

	for (ut32 i = func_size - 1; i > 1; --i) {
		if (mask[i] != 0xFF) {
			func_size--;
			continue;
		}
		break;
	}

	child = flirt_create_child_from_analysis(analysis, func, pattern, mask, func_size, tail_bytes);

fail:
	free(pattern);
	free(mask);
	return child;
}

/**
 * \brief      Creates a RzFlirtNode from a given function
 *
 * \param      analysis    The RzAnalysis structure to use
 * \param      func        The function to add in the flirt node
 * \param      tail_bytes  When false throws any tail bytes
 *
 * \return     Generated FLIRT node.
 */
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_node_from_function(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *func, bool tail_bytes) {
	rz_return_val_if_fail(analysis && analysis->coreb.core && func && func->name, NULL);

	RzFlirtNode *child = flirt_create_child_from_function(analysis, func, tail_bytes);
	if (!child) {
		return NULL;
	}

	RzFlirtNode *root = RZ_NEW0(RzFlirtNode);
	if (!root ||
		!(root->child_list = rz_list_newf((RzListFree)rz_sign_flirt_node_free))) {
		RZ_LOG_ERROR("FLIRT: cannot allocate root node.\n");
		goto fail;
	}

	if (!rz_list_append(root->child_list, child)) {
		RZ_LOG_ERROR("FLIRT: cannot append child to root list.\n");
		goto fail;
	}

	return root;

fail:
	rz_sign_flirt_node_free(child);
	rz_sign_flirt_node_free(root);
	return NULL;
}

/**
 * \brief Generates the FLIRT signatures and returns an RzFlirtNode
 *
 * \param  analysis        The RzAnalysis structure to derive the signatures.
 * \param  optimization    Optimization to apply after creation of the flatten nodes.
 * \param  ignore_unknown  When enabled adds also the `fcn.XXXXXXX` functions.
 * \return                 Generated FLIRT root node.
 */
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_node_new(RZ_NONNULL RzAnalysis *analysis, ut32 optimization, bool ignore_unknown) {
	rz_return_val_if_fail(analysis && analysis->coreb.core, NULL);
	if (optimization > RZ_FLIRT_NODE_OPTIMIZE_MAX) {
		RZ_LOG_ERROR("FLIRT: optimization value is invalid (%u > RZ_FLIRT_NODE_OPTIMIZE_MAX).\n", optimization);
		return NULL;
	}

	if (rz_pvector_len(analysis->fcns) < 1) {
		RZ_LOG_ERROR("FLIRT: There are no analyzed functions. Have you run 'aa'?\n");
		return NULL;
	}
	bool tail_bytes = optimization != RZ_FLIRT_NODE_OPTIMIZE_MAX;
	RzFlirtNode *root = RZ_NEW0(RzFlirtNode);
	if (!root) {
		RZ_LOG_ERROR("FLIRT: cannot allocate root node.\n");
		return NULL;
	}
	root->child_list = rz_list_newf((RzListFree)rz_sign_flirt_node_free);

	void **it;
	RzAnalysisFunction *func;
	rz_pvector_foreach (analysis->fcns, it) {
		func = *it;
		if (!func->name) {
			RZ_LOG_ERROR("FLIRT: function at 0x%" PFMT64x " has a null name. skipping function...\n", func->addr);
			continue;
		} else if (starts_with_flag(func->name, "imp.") ||
			starts_with_flag(func->name, "sym.imp.") ||
			(ignore_unknown && starts_with_flag(func->name, "fcn."))) {
			continue;
		}

		RzFlirtNode *child = flirt_create_child_from_function(analysis, func, tail_bytes);
		if (!child) {
			goto fail;
		} else if (!rz_list_append(root->child_list, child)) {
			RZ_LOG_ERROR("FLIRT: cannot append child to root list.\n");
			rz_sign_flirt_node_free(child);
			goto fail;
		}
	}

	if (rz_list_length(root->child_list) < 1) {
		RZ_LOG_ERROR("FLIRT: cannot create signature file when i do not have signatures.\n");
		goto fail;
	}

	if (optimization == RZ_FLIRT_NODE_OPTIMIZE_NONE) {
		rz_list_sort(root->child_list, (RzListComparator)flirt_compare_node, NULL);
	} else if (!flirt_node_optimize(root)) {
		goto fail;
	}

	return root;

fail:
	rz_sign_flirt_node_free(root);
	return NULL;
}
