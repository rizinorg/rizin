// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file prologues_generator.c
 * \brief Dynamic prologues generator plugin.
 *
 * TODO: short desc of algo, flow etc.
 */

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_util.h>
#include <rz_prologues.h>
#include "prologues_generator.inc"

#define rz_cmd_desc_argv_new_warn(rcmd, parent, cmd, cb, help) \
	rz_warn_if_fail(rz_cmd_desc_argv_new(rcmd, parent, cmd, cb, help))

#define rz_cmd_desc_argv_modes_new_warn(rcmd, root, cmd, flags, cb, help) \
	rz_warn_if_fail(rz_cmd_desc_argv_modes_new(rcmd, root, cmd, flags, cb, help))

RzCorePlugin rz_core_plugin_prologues_generator;

typedef struct core_prologues_generator_context_t {
	RzCmdDesc *cmd_desc;
	ut64 prologue_len; // cfg: prologue length used for generation
	double entropy_threshold; // cfg: threshold for node split entropy used for generalization
} CorePGContext;

/**
 * \brief
 */
typedef struct {
	ut64 hit_cnt; ///< number of hits of the bit in trie
	bool bit_val; ///< value of bit 0/1
} PGTrieNodeData;

typedef struct {
	RzStructuredData *arr;
	HtPU *ids;
	ut64 curr_id;
} TrieDFSContext;

typedef struct {
	RzVector /*<RzPrologue>*/ *prologues;
	ut8 *byte_buf;
	ut8 *mask_buf;
	size_t depth;
	ut64 prologue_len;
	double entropy_threshold;
	bool generalize;
} ProloguesDFSContext;

static void pg_prologue_free(void *e, RZ_UNUSED void *user) {
	RzPrologue *p = e;
	if (!p) {
		return;
	}
	RZ_FREE(p->bytes);
	RZ_FREE(p->mask);
}

static bool pg_match(const RzTrieNode *n, const void *key, size_t idx) {
	if (!n || !n->data || !key) {
		return false;
	}
	PGTrieNodeData *nd = n->data;
	const ut8 *seq = key;
	bool bit = (seq[idx / 8] & (1u << (7 - (idx % 8)))) != 0;
	return nd->bit_val == bit;
}

static void pg_node_init(RzTrieNode *n, const void *key, size_t idx) {
	if (!n || !key) {
		return;
	}
	PGTrieNodeData *nd = RZ_NEW0(PGTrieNodeData);
	if (!nd) {
		RZ_LOG_ERROR("calloc failed for new trie node data\n");
		return;
	}
	const ut8 *seq = key;
	nd->bit_val = (seq[idx / 8] & (1u << (7 - (idx % 8)))) != 0;
	nd->hit_cnt = 1;
	n->data = nd;
}

static void pg_node_free(RzTrieNode *n) {
	if (!n || !n->data) {
		return;
	}
	RZ_FREE(n->data);
}

static void pg_node_on_hit(RzTrieNode *n, RZ_UNUSED void *user) {
	if (!n || !n->data) {
		return;
	}
	PGTrieNodeData *nd = n->data;
	nd->hit_cnt++;
}

static bool config_prologue_len_getter(void *user, void *value) {
	CorePGContext *ctx = user;
	rz_return_val_if_fail(ctx && value, false);
	*(ut64 *)value = ctx->prologue_len;
	return true;
}

static bool config_prologue_len_setter(void *user, const void *value) {
	CorePGContext *ctx = user;
	rz_return_val_if_fail(ctx && value, false);
	const ut64 val = *(const ut64 *)value;
	if (val == 0) {
		RZ_LOG_ERROR("Prologue length must be a positive integer.\n");
		return false;
	}
	ctx->prologue_len = val;
	return true;
}

static bool config_entropy_threshold_getter(void *user, void *value) {
	CorePGContext *ctx = user;
	rz_return_val_if_fail(ctx && value, false);
	*(char **)value = rz_str_newf("%g", ctx->entropy_threshold);
	return true;
}

static bool config_entropy_threshold_setter(void *user, const void *value) {
	CorePGContext *ctx = user;
	rz_return_val_if_fail(ctx && value, false);
	const char *val_str = value;
	if (RZ_STR_ISEMPTY(val_str)) {
		return false;
	}
	char *end = NULL;
	double val = strtod(val_str, &end);
	if (!end || *end != '\0') {
		RZ_LOG_ERROR("Entropy threshold must be a valid double value\n");
		return false;
	}
	if (val < 0.0 || val > 1.0) {
		RZ_LOG_ERROR("Entropy threshold must be between 0.0 and 1.0\n");
		return false;
	}
	ctx->entropy_threshold = val;
	return true;
}

RZ_API RZ_OWN RzTrie *rz_prologues_trie_new(void) {
	RzTrie *t = rz_trie_new(pg_match, pg_node_init, pg_node_free);
	if (!t) {
		return NULL;
	}

	PGTrieNodeData *rd = RZ_NEW0(PGTrieNodeData);
	if (!rd) {
		RZ_LOG_ERROR("calloc failed for root trie node data\n");
		rz_trie_free(t);
		return NULL;
	}
	rd->hit_cnt = 0;
	t->root->data = rd;
	return t;
}

static bool isValidSymbol(RzBinSymbol *symbol) {
	if (symbol && symbol->type) {
		const char *type = symbol->type;
		return (symbol->paddr != UT64_MAX) && (!symbol->is_imported) &&
			(RZ_STR_EQ(type, RZ_BIN_TYPE_FUNC_STR) || RZ_STR_EQ(type, RZ_BIN_TYPE_METH_STR));
	}
	return false;
}

static bool build_prefix_tree_from_binfile(RzBinFile *binfile, RzTrie *t, ut64 prologue_len) {
	rz_return_val_if_fail(binfile && t, false);

	RzBinObject *o = binfile->o;
	if (!o) {
		RZ_LOG_ERROR("Failed to get bin object for file: %s\n", binfile->file);
		return false;
	}

	const RzPVector *symbols = rz_bin_object_get_symbols(o);
	if (!symbols) {
		RZ_LOG_ERROR("Failed to get symbols for bin object\n");
		return false;
	}

	RZ_LOG_INFO("Total %" PFMTSZu " symbols in symbol table\n", rz_pvector_len(symbols));

	void **it;
	size_t cnt = 0;

	ut8 *buf = RZ_NEWS0(ut8, prologue_len);
	if (!buf) {
		RZ_LOG_ERROR("calloc failed for prologue buffer\n");
		return false;
	}

	// some symbols have same address bcz of ICF, weak symbols, etc, so need to filter
	RzSetU *seen_addrs = rz_set_u_new();
	if (!seen_addrs) {
		RZ_FREE(buf);
		return false;
	}

	rz_pvector_foreach (symbols, it) {
		RzBinSymbol *sym = *it;
		if (isValidSymbol(sym)) {
			ut64 paddr = sym->paddr;
			if (rz_set_u_contains(seen_addrs, paddr)) {
				RZ_LOG_INFO("pg: Skipping symbol '%s' at address 0x%" PFMT64x ": duplicate address\n", sym->name, paddr);
				continue;
			}
			rz_set_u_add(seen_addrs, paddr);

			st64 n = rz_buf_read_at(binfile->buf, paddr, buf, prologue_len);
			if (n < 0 || (ut64)n != prologue_len) {
				RZ_LOG_ERROR("Failed to read prologue for symbol at address 0x%" PFMT64x "\n", paddr);
				continue;
			}

			PGTrieNodeData *nd = t->root->data;
			nd->hit_cnt++; // track total prologues inserted
			if (!rz_trie_insert(t, buf, prologue_len * 8, pg_node_on_hit, NULL)) {
				RZ_LOG_ERROR("Failed to insert prologue for symbol at address 0x%" PFMT64x " into prefix tree\n", paddr);
				RZ_FREE(buf);
				rz_set_u_free(seen_addrs);
				return false;
			}

			cnt++;
		}
	}

	RZ_LOG_INFO("Total %" PFMTSZu " symbols used out of %" PFMTSZu "\n", cnt, rz_pvector_len(symbols));

	RZ_FREE(buf);
	rz_set_u_free(seen_addrs);
	return true;
}

/**
 * \brief Free internal fields of an RzProloguesArchInfo struct and reset its values.
 *
 * \param arch_info Pointer to the RzProloguesArchInfo struct to finalize.
 */
RZ_API void rz_prologues_arch_info_fini(RZ_NULLABLE RzProloguesArchInfo *arch_info) {
	if (!arch_info) {
		return;
	}
	RZ_FREE(arch_info->arch);
	arch_info->bits = 0;
	arch_info->big_endian = false;
}

/**
 * \brief Check if a binary's arch matches the target arch, or adopt it if uninitialized.
 * If \p target_arch is NULL = accept any arch
 * If \p target_arch->arch is NULL = adopts and sets the arch and endianness from \p info
 * (or fallback arguments if not specified in \p info).
 * If \p target_arch->bits <= 0, it adopts and sets the bitness from \p info.
 * If \p target_arch fields are already set, it checks that \p info matches them.
 *
 * \param[in]		info                Binary info to check or adopt.
 * \param[in,out] 	target_arch         Arch container to match against or populate.
 * \param[in] 		fallback_arch       Optional fallback arch if info->arch is empty.
 * \param[in] 		fallback_bits       Optional fallback bitness if info->bits <= 0.
 * \param[in] 		fallback_big_endian Optional fallback endianness if info->arch is empty.
 *
 * \return true if the binary matches or was successfully adopted, false on arch/bitness/endianness mismatch.
 */
RZ_API bool rz_prologues_arch_check(RZ_NONNULL const RzBinInfo *info,
	RZ_NULLABLE RzProloguesArchInfo *target_arch,
	RZ_NULLABLE const char *fallback_arch, int fallback_bits, bool fallback_big_endian) {
	rz_return_val_if_fail(info, false);

	if (!target_arch) {
		return true;
	}

	const char *file_arch = RZ_STR_ISNOTEMPTY(info->arch) ? info->arch : fallback_arch;
	int file_bits = info->bits > 0 ? info->bits : fallback_bits;
	bool file_be = RZ_STR_ISNOTEMPTY(info->arch) ? info->big_endian : fallback_big_endian;

	if (target_arch->arch) {
		if (!file_arch || !RZ_STR_EQ(file_arch, target_arch->arch)) {
			return false;
		}
		if (file_be != target_arch->big_endian) {
			return false;
		}
	}

	if (target_arch->bits > 0 && file_bits != target_arch->bits) {
		return false;
	}

	// if arch/bits not specified set it from the bin (skip if unknown)
	if (!target_arch->arch && RZ_STR_ISNOTEMPTY(file_arch)) {
		target_arch->arch = rz_str_dup(file_arch);
		target_arch->big_endian = file_be;
	}
	if (target_arch->bits <= 0 && file_bits > 0) {
		target_arch->bits = file_bits;
	}

	return true;
}

/**
 * \brief Feed function prologues from a loaded binfile's symbol table into a trie.
 *
 * Reads \p prologue_len bytes from each FUNC/METH symbol's physical address
 * and inserts them into \p pg_trie. Skips imported symbols and deduplicates
 * by address (handles ICF / weak symbol aliasing).
 *
 * \param pg_trie     	proglogues trie to feed into.
 * \param binfile     	already open/loaded RzBinFile with symbols available.
 * \param prologue_len 	number of bytes to read per function entry point (must be > 0).
 *
 * \return true on success, false on error.
 */
RZ_API bool rz_prologues_trie_feed_binfile(RZ_NONNULL RzTrie *pg_trie, RZ_NONNULL RzBinFile *binfile, ut64 prologue_len) {
	rz_return_val_if_fail(pg_trie && binfile && prologue_len > 0, false);
	return build_prefix_tree_from_binfile(binfile, pg_trie, prologue_len);
}

static bool print_sd(RzStructuredData *sd, RzOutputMode mode) {
	rz_return_val_if_fail(sd, false);

	char *output = NULL;
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON:
		output = rz_structured_data_to_json(sd);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		output = rz_structured_data_to_yaml(sd);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	if (!output) {
		return false;
	}
	rz_cons_printf("%s\n", output);
	RZ_FREE(output);
	return true;
}

RZ_IPI RzCmdStatus rz_cmd_prologues_gen_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	CorePGContext *ctx = rz_core_plugin_context_get(core, &rz_core_plugin_prologues_generator);
	rz_return_val_if_fail(ctx, RZ_CMD_STATUS_ERROR);

	RzBin *bin = rz_core_get_bin(core);
	if (!bin) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 fd = rz_core_file_cur_fd(core);
	if (fd == UT32_MAX) {
		RZ_LOG_ERROR("Failed to get current file descriptor\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzBinFile *binfile = rz_bin_file_find_by_fd(bin, fd);
	if (!binfile) {
		RZ_LOG_ERROR("Failed to find bin file for fd: %" PFMT32u "\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}

	const RzBinInfo *info = rz_bin_object_get_info(binfile->o);
	if (!info) {
		RZ_LOG_ERROR("No binary info available for file: %s\n", binfile->file);
		return RZ_CMD_STATUS_ERROR;
	}

	RzTrie *pg_trie = rz_prologues_trie_new();
	if (!pg_trie) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (!build_prefix_tree_from_binfile(binfile, pg_trie, ctx->prologue_len)) {
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	RzProloguesArchInfo arch_info = { 0 };
	rz_prologues_arch_check(info, &arch_info, NULL, 0, false);

	RzVector *prologues = rz_prologues_generalize_and_extract(pg_trie, ctx->prologue_len, ctx->entropy_threshold);
	if (!prologues) {
		RZ_LOG_ERROR("Failed to generalize prologues from trie\n");
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	RzStructuredData *root = rz_prologues_to_structured_data(prologues, ctx->prologue_len, &arch_info);
	if (!root) {
		rz_vector_free(prologues);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!print_sd(root, mode)) {
		rz_structured_data_free(root);
		rz_vector_free(prologues);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_structured_data_free(root);
	rz_vector_free(prologues);
	rz_prologues_arch_info_fini(&arch_info);
	rz_trie_free(pg_trie);

	return RZ_CMD_STATUS_OK;
}

RZ_API st64 rz_prologues_trie_feed_all_binfiles(RZ_NONNULL RzTrie *pg_trie, RZ_NONNULL RzBin *bin, ut64 prologue_len,
	RZ_NULLABLE RzProloguesArchInfo *arch_info, RZ_NULLABLE RzSetS *processed_files) {
	rz_return_val_if_fail(pg_trie && bin && prologue_len > 0, -1);

	RzList *binfiles = bin ? bin->binfiles : NULL;
	if (!binfiles) {
		RZ_LOG_ERROR("No binfiles available in the current bin session\n");
		return -1;
	}

	RzListIter *it;
	RzBinFile *curr_file;
	st64 fcnt = 0;
	rz_list_foreach (binfiles, it, curr_file) {
		if (!curr_file) {
			RZ_LOG_WARN("Skipping, null file found in list\n");
			continue;
		}
		const RzBinInfo *info = rz_bin_object_get_info(curr_file->o);
		if (!info) {
			RZ_LOG_WARN("Skipping file '%s': missing binobject/bininfo\n",
				curr_file ? curr_file->file : "unknown");
			continue;
		}

		if (processed_files && rz_set_s_contains(processed_files, curr_file->file)) {
			RZ_LOG_WARN("Skipping file '%s', already processed.\n", curr_file->file);
			continue;
		}

		if (!rz_prologues_arch_check(info, arch_info, NULL, 0, false)) {
			const char *file_arch = RZ_STR_ISNOTEMPTY(info->arch) ? info->arch : "unknown";
			RZ_LOG_WARN("Skipping file '%s': arch mismatch.\n"
				    "  Trie: (%s, %d-bit, %cE)\n"
				    "  File: (%s, %d-bit, %cE)\n",
				curr_file->file,
				arch_info ? arch_info->arch : "unknown",
				arch_info ? arch_info->bits : 0,
				(arch_info && arch_info->big_endian) ? 'B' : 'L',
				file_arch, info->bits, info->big_endian ? 'B' : 'L');
			continue;
		}

		if (!build_prefix_tree_from_binfile(curr_file, pg_trie, prologue_len)) {
			RZ_LOG_WARN("Failed to build prefix tree for file: %s\n", curr_file->file);
			continue;
		}
		if (processed_files) {
			rz_set_s_add(processed_files, curr_file->file);
		}
		fcnt++;
	}
	return fcnt;
}

RZ_IPI RzCmdStatus rz_cmd_prologues_gen_all_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	CorePGContext *ctx = rz_core_plugin_context_get(core, &rz_core_plugin_prologues_generator);
	rz_return_val_if_fail(ctx, RZ_CMD_STATUS_ERROR);
	RzBin *bin = rz_core_get_bin(core);

	RzTrie *pg_trie = rz_prologues_trie_new();
	if (!pg_trie) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzSetS *processed_files = rz_set_s_new(HT_STR_DUP);
	RzProloguesArchInfo arch_info = { 0 };

	st64 fcnt = rz_prologues_trie_feed_all_binfiles(pg_trie, bin, ctx->prologue_len, &arch_info, processed_files);
	if (fcnt == -1) {
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}
	RZ_LOG_INFO("Processed %" PFMTSZu " files out of %" PFMT32u "\n", fcnt, rz_list_length(bin->binfiles));

	RzVector *prologues = rz_prologues_generalize_and_extract(pg_trie, ctx->prologue_len, ctx->entropy_threshold);
	if (!prologues) {
		RZ_LOG_ERROR("Failed to generalize prologues from trie\n");
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	RzStructuredData *root = rz_prologues_to_structured_data(prologues, ctx->prologue_len, &arch_info);
	if (!root) {
		rz_vector_free(prologues);
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!print_sd(root, mode)) {
		rz_structured_data_free(root);
		rz_vector_free(prologues);
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_structured_data_free(root);
	rz_vector_free(prologues);
	rz_set_s_free(processed_files);
	rz_prologues_arch_info_fini(&arch_info);
	rz_trie_free(pg_trie);

	return RZ_CMD_STATUS_OK;
}

RZ_API st64 rz_prologues_trie_feed_directory(RZ_NONNULL RzTrie *pg_trie, RZ_NONNULL RzBin *bin, RZ_NONNULL const char *dir_path,
	ut64 prologue_len, RZ_NULLABLE RzProloguesArchInfo *arch_info, RZ_NULLABLE RzSetS *processed_files) {
	rz_return_val_if_fail(pg_trie && bin && dir_path && prologue_len > 0, -1);

	if (!rz_file_is_directory(dir_path)) {
		RZ_LOG_ERROR("%s is not a directory or does not exist.\n", dir_path);
		return -1;
	}
	RzList *files = rz_sys_dir(dir_path);
	if (!files) {
		return -1;
	}

	RzListIter *it;
	char *file;
	st64 fcnt = 0;
	// nested dir not supported
	rz_list_foreach (files, it, file) {
		char *file_path = rz_file_path_join(dir_path, file);
		if (!rz_file_is_regular(file_path)) {
			RZ_FREE(file_path);
			continue;
		}
		// using rz_buf... + rz_bin_open_buf instead of rz_bin_open to avoid RzIO
		// bcz for RzIO we need to close fd seperately after rz_bin_file_delete
		RzBuffer *buf = rz_buf_new_file(file_path, O_RDONLY, 0);
		if (!buf) {
			RZ_LOG_WARN("Failed to open buffer for file: %s\n", file_path);
			RZ_FREE(file_path);
			continue;
		}

		RzBinOptions opt;
		rz_bin_options_init(&opt, -1, 0, 0, false);
		opt.filename = file_path;
		RzBinFile *bf = rz_bin_open_buf(bin, buf, &opt);
		rz_buf_free(buf);
		if (!bf) {
			RZ_LOG_WARN("Failed to parse binary for file: %s\n", file_path);
			RZ_FREE(file_path);
			continue;
		}

		const RzBinInfo *info = rz_bin_object_get_info(bf->o);
		if (!info) {
			RZ_LOG_WARN("Skipping file '%s': missing binobject/bininfo\n", file);
			rz_bin_file_delete(bin, bf);
			RZ_FREE(file_path);
			continue;
		}

		if (processed_files && rz_set_s_contains(processed_files, file)) {
			RZ_LOG_WARN("Skipping file '%s', already processed.\n", file);
			rz_bin_file_delete(bin, bf);
			RZ_FREE(file_path);
			continue;
		}

		if (!rz_prologues_arch_check(info, arch_info, NULL, 0, false)) {
			const char *file_arch = RZ_STR_ISNOTEMPTY(info->arch) ? info->arch : "unknown";
			RZ_LOG_WARN("Skipping file '%s': arch mismatch.\n"
				    "  Trie: (%s, %d-bit, %cE)\n"
				    "  File: (%s, %d-bit, %cE)\n",
				file,
				arch_info ? arch_info->arch : "unknown",
				arch_info ? arch_info->bits : 0,
				(arch_info && arch_info->big_endian) ? 'B' : 'L',
				file_arch, info->bits, info->big_endian ? 'B' : 'L');

			rz_bin_file_delete(bin, bf);
			RZ_FREE(file_path);
			continue;
		}

		if (!build_prefix_tree_from_binfile(bf, pg_trie, prologue_len)) {
			RZ_LOG_WARN("Failed to build prefix tree for file: %s\n", file);
			rz_bin_file_delete(bin, bf);
			RZ_FREE(file_path);
			continue;
		}

		if (processed_files) {
			rz_set_s_add(processed_files, file);
		}
		fcnt++;
		rz_bin_file_delete(bin, bf);
		RZ_FREE(file_path);
	}

	RZ_LOG_INFO("Processed %" PFMTSZu " files out of %" PFMT32u "\n", fcnt, rz_list_length(files));
	rz_list_free(files);
	return fcnt;
}

RZ_IPI RzCmdStatus rz_cmd_prologues_gen_dir_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	CorePGContext *ctx = rz_core_plugin_context_get(core, &rz_core_plugin_prologues_generator);
	rz_return_val_if_fail(ctx, RZ_CMD_STATUS_ERROR);

	const char *dir_path = argv[1];
	RzBin *bin = rz_core_get_bin(core);

	RzTrie *pg_trie = rz_prologues_trie_new();
	if (!pg_trie) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzSetS *processed_files = rz_set_s_new(HT_STR_DUP);
	RzProloguesArchInfo arch_info = { 0 };

	st64 fcnt = rz_prologues_trie_feed_directory(pg_trie, bin, dir_path, ctx->prologue_len, &arch_info, processed_files);
	if (fcnt == -1) {
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	RzVector *prologues = rz_prologues_generalize_and_extract(pg_trie, ctx->prologue_len, ctx->entropy_threshold);
	if (!prologues) {
		RZ_LOG_ERROR("Failed to generalize prologues from trie\n");
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	RzStructuredData *root = rz_prologues_to_structured_data(prologues, ctx->prologue_len, &arch_info);
	if (!root) {
		rz_vector_free(prologues);
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!print_sd(root, mode)) {
		rz_structured_data_free(root);
		rz_vector_free(prologues);
		rz_set_s_free(processed_files);
		rz_prologues_arch_info_fini(&arch_info);
		rz_trie_free(pg_trie);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_structured_data_free(root);
	rz_vector_free(prologues);
	rz_set_s_free(processed_files);
	rz_prologues_arch_info_fini(&arch_info);
	rz_trie_free(pg_trie);

	return RZ_CMD_STATUS_OK;
}

static double shanon_entropy_of_split(const RzTrieNode *p) {
	rz_return_val_if_fail(p && !rz_pvector_empty(&p->children) && p->data, 0.0);
	double H = 0.0;
	PGTrieNodeData *pd = p->data;
	void **it;
	rz_pvector_foreach (&p->children, it) {
		RzTrieNode *n = *it;
		PGTrieNodeData *nd = n->data;
		double p_i = (double)nd->hit_cnt / (double)pd->hit_cnt; // probability of child node
		H += -(p_i * log2(p_i));
	}
	return H;
}

// merge source tree to destination tree, and free source tree
static void merge_subtrees(RzTrieNode *src, RzTrieNode *dst) {
	rz_return_if_fail(src && dst && src->data && dst->data);
	PGTrieNodeData *src_nd = src->data;
	PGTrieNodeData *dst_nd = dst->data;
	dst_nd->hit_cnt += src_nd->hit_cnt;

	void **src_it;
	rz_pvector_foreach (&src->children, src_it) {
		RzTrieNode *src_child = *src_it;
		PGTrieNodeData *src_child_nd = src_child->data;

		// merge if matching child in dst else append child
		bool found = false;
		void **dst_it;
		rz_pvector_foreach (&dst->children, dst_it) {
			RzTrieNode *dst_child = *dst_it;
			PGTrieNodeData *dst_child_nd = dst_child->data;
			if (dst_child_nd->bit_val == src_child_nd->bit_val) {
				merge_subtrees(src_child, dst_child);
				found = true;
				break;
			}
		}

		if (!found) {
			rz_pvector_push(&dst->children, src_child);
		}
	}
	rz_pvector_fini(&src->children);
	RZ_FREE(src->data);
	RZ_FREE(src);
}

static void pre_visit_prologues(RzTrieNode *n, void *user) {
	rz_return_if_fail(n && n->data && user);

	ProloguesDFSContext *pgctx = user;
	PGTrieNodeData *nd = n->data;
	// skip root, hence 1 based idx
	if (pgctx->depth > 0) {
		size_t bit_idx = pgctx->depth - 1;
		size_t byte_idx = bit_idx / 8;
		size_t bit_pos = 7 - (bit_idx % 8);
		if (nd->bit_val) {
			pgctx->byte_buf[byte_idx] |= (1u << bit_pos);
		} else {
			pgctx->byte_buf[byte_idx] &= ~(1u << bit_pos);
		}
	}

	// check split entropy and merge subtrees based on it (skip if not generalizing)
	if (pgctx->generalize && rz_pvector_len(&n->children) == 2) {
		double entropy = shanon_entropy_of_split(n);
		if (entropy > pgctx->entropy_threshold) {
			// set next depth bit to 0 in mask
			size_t child_byte_idx = pgctx->depth / 8;
			size_t child_bit_pos = 7 - (pgctx->depth % 8);
			// len(pvec)==2 check already prevents oob for leaf ndoe below
			pgctx->mask_buf[child_byte_idx] &= ~(1u << child_bit_pos);
			merge_subtrees(rz_pvector_at(&n->children, 1), rz_pvector_at(&n->children, 0));
			rz_pvector_pop(&n->children);
		}
	}

	if (n->is_end) {
		size_t byte_len = pgctx->depth / 8;
		ut8 *byte_buf = rz_mem_dup(pgctx->byte_buf, byte_len);
		ut8 *mask_buf = rz_mem_dup(pgctx->mask_buf, byte_len);
		if (!byte_buf || !mask_buf) {
			RZ_FREE(byte_buf);
			RZ_FREE(mask_buf);
			return;
		}

		RzPrologue p = { .bytes = byte_buf, .mask = mask_buf };
		rz_vector_push(pgctx->prologues, &p);
	}
	pgctx->depth++;
}

static void post_visit_prologues(RzTrieNode *n, void *user) {
	rz_return_if_fail(n && n->data && user);
	ProloguesDFSContext *pgctx = user;
	// reset child's mask bit to 1
	size_t child_byte_idx = (pgctx->depth - 1) / 8;
	size_t child_bit_pos = 7 - ((pgctx->depth - 1) % 8);
	if (child_byte_idx < pgctx->prologue_len) { // bcz its oob for leaf node
		pgctx->mask_buf[child_byte_idx] |= (1u << child_bit_pos);
	}
	pgctx->depth--;
}

RZ_API RZ_OWN RzVector /*<RzPrologue>*/ *rz_prologues_generalize_and_extract(RzTrie *pg_trie, ut64 prologue_len, double entropy_threshold) {
	rz_return_val_if_fail(pg_trie && prologue_len > 0, NULL);
	rz_return_val_if_fail(entropy_threshold >= 0.0 && entropy_threshold <= 1.0, NULL);

	PGTrieNodeData *rd = pg_trie->root->data;
	if (rd->hit_cnt == 0) {
		RZ_LOG_ERROR("Prologues trie is empty. Cannot generalize and extract prologues.\n");
		return NULL;
	}

	ut8 *byte_buf = RZ_NEWS0(ut8, prologue_len);
	ut8 *mask_buf = RZ_NEWS0(ut8, prologue_len);
	if (!byte_buf || !mask_buf) {
		RZ_FREE(byte_buf);
		RZ_FREE(mask_buf);
		return NULL;
	}
	memset(mask_buf, 0xFF, prologue_len);

	RzVector *prologues = rz_vector_new(sizeof(RzPrologue), pg_prologue_free, NULL);
	ProloguesDFSContext pgctx = {
		.prologues = prologues,
		.byte_buf = byte_buf,
		.mask_buf = mask_buf,
		.depth = 0,
		.prologue_len = prologue_len,
		.entropy_threshold = entropy_threshold,
		.generalize = true
	};

	rz_trie_dfs(pg_trie->root, pre_visit_prologues, NULL, post_visit_prologues, &pgctx);

	RZ_LOG_INFO("Generated %" PFMTSZu " prologues from trie\n", rz_vector_len(prologues));
	RZ_FREE(byte_buf);
	RZ_FREE(mask_buf);
	return prologues;
}

RZ_API RZ_OWN RzVector /*<RzPrologue>*/ *rz_prologues_extract_raw_from_trie(RzTrie *pg_trie, ut64 prologue_len) {
	rz_return_val_if_fail(pg_trie && prologue_len > 0, NULL);

	PGTrieNodeData *rd = pg_trie->root->data;
	if (rd->hit_cnt == 0) {
		RZ_LOG_ERROR("Prologues trie is empty. Build it first with pg, pga, or pgd.\n");
		return NULL;
	}

	ut8 *byte_buf = RZ_NEWS0(ut8, prologue_len);
	ut8 *mask_buf = RZ_NEWS0(ut8, prologue_len);
	if (!byte_buf || !mask_buf) {
		RZ_FREE(byte_buf);
		RZ_FREE(mask_buf);
		return NULL;
	}
	memset(mask_buf, 0xFF, prologue_len);

	RzVector *prologues = rz_vector_new(sizeof(RzPrologue), pg_prologue_free, NULL);
	ProloguesDFSContext pgctx = {
		.prologues = prologues,
		.byte_buf = byte_buf,
		.mask_buf = mask_buf,
		.depth = 0,
		.entropy_threshold = 0.0,
		.generalize = false
	};

	rz_trie_dfs(pg_trie->root, pre_visit_prologues, NULL, post_visit_prologues, &pgctx);

	RZ_LOG_INFO("Generated %" PFMTSZu " prologues from trie\n", rz_vector_len(prologues));
	RZ_FREE(byte_buf);
	RZ_FREE(mask_buf);
	return prologues;
}

static void edge_visit_sd(RzTrieNode *parent, RzTrieNode *child, void *user) {
	rz_return_if_fail(parent && parent->data && child && child->data && user);

	TrieDFSContext *sdctx = user;

	if (!ht_pu_insert(sdctx->ids, child, ++sdctx->curr_id)) {
		RZ_LOG_ERROR("Failed to insert node ID\n");
		return;
	}

	RzStructuredData *entry = rz_structured_data_array_add_map(sdctx->arr);
	if (!entry) {
		RZ_LOG_ERROR("Failed to add entry to structured data array\n");
		return;
	}
	ut64 p_id = ht_pu_find(sdctx->ids, parent, NULL);
	PGTrieNodeData *nd = child->data;
	if (!nd) {
		RZ_LOG_ERROR("Trie node missing data\n");
		return;
	}
	rz_structured_data_map_add_unsigned(entry, "node_id", sdctx->curr_id, false);
	rz_structured_data_map_add_unsigned(entry, "parent_id", p_id, false);
	rz_structured_data_map_add_unsigned(entry, "bit_val", nd->bit_val ? 1 : 0, false);
	rz_structured_data_map_add_unsigned(entry, "hit_cnt", nd->hit_cnt, false);
}

static void add_session_metadata_to_sd(RzStructuredData *root, const RzProloguesArchInfo *arch_info) {
	rz_return_if_fail(root);
	const char *arch = arch_info && arch_info->arch ? arch_info->arch : "unknown";
	int bits = arch_info ? arch_info->bits : 0;
	bool big_endian = arch_info ? arch_info->big_endian : false;
	rz_structured_data_map_add_string(root, "arch", arch);
	rz_structured_data_map_add_signed(root, "bits", bits);
	rz_structured_data_map_add_string(root, "endian", big_endian ? "big" : "little");
}

RZ_API RZ_OWN RzStructuredData *rz_prologues_trie_to_structured_data(RZ_NONNULL const RzTrie *pg_trie,
	ut64 prologue_len, RZ_NULLABLE const RzProloguesArchInfo *arch_info, RZ_NULLABLE const RzSetS *files) {
	rz_return_val_if_fail(pg_trie && prologue_len > 0, NULL);

	HtPUOptions opt = { 0 };
	HtPU *node_ids = ht_pu_new_opt(&opt);
	if (!node_ids) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		ht_pu_free(node_ids);
		return NULL;
	}

	add_session_metadata_to_sd(root, arch_info);
	rz_structured_data_map_add_unsigned(root, "prologue_length", prologue_len, false);

	PGTrieNodeData *rd = pg_trie->root->data;
	rz_structured_data_map_add_unsigned(root, "total_prologues_analyzed", rd->hit_cnt, false);

	if (files) {
		RzStructuredData *files_arr = rz_structured_data_map_add_array(root, "files");
		RzIterator *it = rz_set_s_as_iter(files);
		const char **file;
		rz_iterator_foreach(it, file) {
			rz_structured_data_array_add_string(files_arr, *file);
		}
		rz_iterator_free(it);
	}

	RzStructuredData *arr = rz_structured_data_map_add_array(root, "prefix_tree");

	TrieDFSContext sdctx = {
		.arr = arr,
		.ids = node_ids,
		.curr_id = 0
	};

	if (!ht_pu_insert(sdctx.ids, pg_trie->root, 0)) {
		RZ_LOG_ERROR("Failed to insert root node ID\n");
		ht_pu_free(node_ids);
		rz_structured_data_free(root);
		return NULL;
	}

	rz_trie_dfs(pg_trie->root, NULL, edge_visit_sd, NULL, &sdctx);
	ht_pu_free(node_ids);
	return root;
}

RZ_API RZ_OWN RzStructuredData *rz_prologues_to_structured_data(RZ_NONNULL const RzVector /*<RzPrologue>*/ *prologues,
	ut64 prologue_len, RZ_NULLABLE const RzProloguesArchInfo *arch_info) {
	rz_return_val_if_fail(prologues && prologue_len > 0, NULL);

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	add_session_metadata_to_sd(root, arch_info);
	rz_structured_data_map_add_unsigned(root, "prologue_length", prologue_len, false);
	rz_structured_data_map_add_unsigned(root, "count", rz_vector_len(prologues), false);

	RzStructuredData *arr = rz_structured_data_map_add_array(root, "prologues");
	RzPrologue *p;
	rz_vector_foreach (prologues, p) {
		RzStructuredData *prologue_sd = rz_structured_data_array_add_map(arr);
		rz_structured_data_map_add_bytes(prologue_sd, "bytes", p->bytes, prologue_len, RZ_STRUCTURED_DATA_FORMAT_DEFAULT);
		rz_structured_data_map_add_bytes(prologue_sd, "mask", p->mask, prologue_len, RZ_STRUCTURED_DATA_FORMAT_DEFAULT);
	}
	return root;
}

static bool rz_cmd_prologues_gen_init(RzCore *core, RZ_OUT void **user) {
	CorePGContext *ctx = RZ_NEW0(CorePGContext);
	if (!ctx) {
		return false;
	}
	RzConfig *cfg = NULL;

	ctx->prologue_len = RZ_PROLOGUE_DEFAULT_LEN;
	ctx->entropy_threshold = RZ_PROLOGUE_DEFAULT_ENTROPY_THRESHOLD;

	// cmds
	RzCmd *rcmd = core->rcmd;
	if (!rcmd) {
		goto error;
	}
	RzCmdDesc *root_cd = rz_cmd_get_root(core->rcmd);
	if (!root_cd) {
		goto error;
	}

	RzCmdDesc *pg = rz_cmd_desc_group_modes_new(rcmd, root_cd, "pg", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON,
		rz_cmd_prologues_gen_handler, &cmd_prologues_gen_help, &prologues_gen_help);

	if (!pg) {
		goto error;
	}
	ctx->cmd_desc = pg;

	rz_cmd_desc_argv_modes_new_warn(rcmd, pg, "pga", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON,
		rz_cmd_prologues_gen_all_handler, &cmd_prologues_gen_all_help);
	rz_cmd_desc_argv_modes_new_warn(rcmd, pg, "pgd", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON,
		rz_cmd_prologues_gen_dir_handler, &cmd_prologues_gen_dir_help);

	// configs
	cfg = rz_config_new(NULL);
	if (!cfg) {
		goto error;
	}
	rz_config_add_integer_bind(cfg, "plugins.prologues_generator.prologue_len",
		"Number of bytes (>0) to extract from start of function for prologue generation",
		config_prologue_len_getter, config_prologue_len_setter, NULL, ctx);

	rz_config_add_string_bind(cfg, "plugins.prologues_generator.entropy_threshold",
		"Threshold for shanon entropy of node split to consider 0.0 to 1.0",
		config_entropy_threshold_getter, config_entropy_threshold_setter, NULL, ctx);

	ht_sp_insert(core->plugin_configs, "prologues_generator", cfg);

	*user = ctx;
	return true;

error:
	rz_warn_if_reached();
	rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
	rz_config_free(cfg);
	RZ_FREE(ctx);
	return false;
}

static bool rz_cmd_prologues_gen_fini(RzCore *core, RZ_NULLABLE void *user) {
	CorePGContext *ctx = user;
	rz_return_val_if_fail(ctx, false);
	if (!rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc)) {
		return false;
	}
	RZ_FREE(ctx);
	return true;
}

RzCorePlugin rz_core_plugin_prologues_generator = {
	.name = "prologues_generator",
	.desc = "Suite of commands for prologue generation from binary's symbol table, type `pg` for more info",
	.license = "LGPL-3.0-only",
	.author = "MrQuantum1915",
	.version = "1.0",
	.init = rz_cmd_prologues_gen_init,
	.fini = rz_cmd_prologues_gen_fini,
	.analysis = NULL, // TODO
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_prologues_generator,
	.version = RZ_VERSION,
};
#endif
