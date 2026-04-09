// SPDX-FileCopyrightText: 2021 Pulak Malhotra <pulakmalhotra2000@gmail.com>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_windows_heap.h>

#if __WINDOWS__
bool is_windows_live_debug(RzCore *core) {
	return core->dbg && core->dbg->cur && !rz_debug_is_dead(core->dbg);
}
#endif

void init_heap_config(RzCore *core, RzWindowsHeapConfig *config) {
	ut8 ptr_size = 8;
	int build = RZ_W10_BUILD_21H1;

	if (core->analysis && core->analysis->bits) {
		ptr_size = (core->analysis->bits == 32) ? 4 : 8;
	}

	const char *version_cfg = rz_config_get(core->config, "dbg.windows.version");
	if (version_cfg && RZ_STR_NE(version_cfg, "auto")) {
		if (RZ_STR_EQ(version_cfg, "21H1") || RZ_STR_EQ(version_cfg, "21H2") ||
			RZ_STR_EQ(version_cfg, "22H2")) {
			build = RZ_W10_BUILD_21H1;
		} else if (RZ_STR_EQ(version_cfg, "1607") || RZ_STR_EQ(version_cfg, "1703") ||
			RZ_STR_EQ(version_cfg, "1709") || RZ_STR_EQ(version_cfg, "1803") ||
			RZ_STR_EQ(version_cfg, "1809") || RZ_STR_EQ(version_cfg, "1903") ||
			RZ_STR_EQ(version_cfg, "1909") || RZ_STR_EQ(version_cfg, "2004") ||
			RZ_STR_EQ(version_cfg, "20H2")) {
			build = RZ_W10_BUILD_1607;
		} else { // default case
			build = RZ_W10_BUILD_1511;
		}
	}

	rz_w32_heap_config_init(config, ptr_size, build);
}

ut64 get_heap_base(RzIO *io, const RzWindowsHeapConfig *config) {
	ut8 buf[8];
	if (!rz_io_read_at_mapped(io, config->segment.base_address, buf, config->ptr_size)) {
		return 0;
	}
	if (config->ptr_size == 8) {
		return rz_read_le64(buf);
	}
	return (ut64)rz_read_le32(buf);
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heaps_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
#if __WINDOWS__
	if (is_windows_live_debug(core)) {
		rz_heap_list_w32(core, state->mode);
		return RZ_CMD_STATUS_OK;
	}
#endif

	RzWindowsHeapConfig config;
	init_heap_config(core, &config);

	ut64 heap_base = get_heap_base(core->io, &config);
	RzWindowsHeapInfo *info = rz_w32_heap_info_parse(core->io, heap_base, &config);
	if (!info) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzList *blocks = rz_w32_heap_blocks_list(core->io, info, &config);
	ut64 block_count = blocks ? rz_list_length(blocks) : 0;

	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		PJ *pj = state->d.pj;
		pj_a(pj);
		pj_o(pj);
		pj_kN(pj, "address", info->base_address);
		pj_kN(pj, "count", block_count);
		pj_kN(pj, "flags", info->flags);
		pj_kN(pj, "signature", info->heap_signature);
		pj_end(pj);
		pj_end(pj);
	} else {
		RzTable *tbl = state->d.t;
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Address");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Blocks");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Pages");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_STRING, "FrontEnd");
		const char *fe_type = "None";
		if (info->front_end_heap_type == 2) {
			fe_type = "LFH";
		} else if (info->front_end_heap_type == 1) {
			fe_type = "Lookaside";
		}
		rz_table_add_rowf(tbl, "xnns", info->base_address, block_count,
			(ut64)info->number_of_pages, fe_type);
	}

	rz_list_free(blocks);
	RZ_FREE(info);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_process_heap_block_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
#if __WINDOWS__
	if (is_windows_live_debug(core)) {
		if (argc == 2) {
			rz_heap_debug_block_win(core, argv[1], state->mode, false);
		} else {
			rz_heap_debug_block_win(core, NULL, state->mode, false);
		}
		return RZ_CMD_STATUS_OK;
	}
#endif

	RzWindowsHeapConfig config;
	init_heap_config(core, &config);

	ut64 heap_base = get_heap_base(core->io, &config);
	RzWindowsHeapInfo *info = rz_w32_heap_info_parse(core->io, heap_base, &config);
	if (!info) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzList *blocks = rz_w32_heap_blocks_list(core->io, info, &config);
	if (!blocks) {
		RZ_FREE(info);
		return RZ_CMD_STATUS_ERROR;
	}

	// an address argument is given, find and display just that block
	if (argc == 2) {
		ut64 target = rz_num_math(core->num, argv[1]);
		RzListIter *iter;
		RzWindowsHeapEntry *block;
		bool found = false;

		rz_list_foreach (blocks, iter, block) {
			if (block->user_address == target ||
				block->header_address == target ||
				(target >= block->header_address && target < block->header_address + block->size)) {
				found = true;

				const char *block_state = block->is_busy ? "BUSY" : "FREE";
				if (state->mode == RZ_OUTPUT_MODE_JSON) {
					PJ *pj = state->d.pj;
					pj_o(pj);
					pj_kN(pj, "header_address", block->header_address);
					pj_kN(pj, "user_address", block->user_address);
					pj_kN(pj, "size", block->size);
					pj_kN(pj, "unused", block->unused_bytes);
					pj_ks(pj, "type", block_state);
					pj_end(pj);
				} else {
					RzTable *tbl = state->d.t;
					rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "HeaderAddress");
					rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "UserAddress");
					rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Size");
					rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Unused");
					rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_STRING, "Type");
					rz_table_add_rowf(tbl, "xxnns", block->header_address,
						block->user_address, block->size,
						(ut64)block->unused_bytes, block_state);
				}
				break;
			}
		}
		if (!found) {
			RZ_LOG_ERROR("core: Heap block not found at 0x%" PFMT64x "\n", target);
		}

		rz_list_free(blocks);
		RZ_FREE(info);
		return found ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	}

	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		PJ *pj = state->d.pj;
		pj_o(pj);
		pj_kN(pj, "heap", info->base_address);
		pj_k(pj, "blocks");
		pj_a(pj);

		RzListIter *iter;
		RzWindowsHeapEntry *block;
		rz_list_foreach (blocks, iter, block) {
			const char *block_state = block->is_busy ? "BUSY" : "FREE";
			pj_o(pj);
			pj_kN(pj, "header_address", block->header_address);
			pj_kN(pj, "user_address", block->user_address);
			pj_kN(pj, "size", block->size);
			pj_kN(pj, "unused", block->unused_bytes);
			pj_ks(pj, "type", block_state);
			pj_end(pj);
		}

		pj_end(pj);
		pj_end(pj);
		pj_end(pj);
	} else {
		RzTable *tbl = state->d.t;
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "HeaderAddress");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "UserAddress");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Size");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_NUMBER, "Unused");
		rz_table_add_column(tbl, RZ_TABLE_COLUMN_TYPE_STRING, "Type");

		RzListIter *iter;
		RzWindowsHeapEntry *block;
		rz_list_foreach (blocks, iter, block) {
			const char *block_state = block->is_busy ? "BUSY" : "FREE";
			rz_table_add_rowf(tbl, "xxnns", block->header_address,
				block->user_address, block->size,
				(ut64)block->unused_bytes, block_state);
		}
	}

	rz_list_free(blocks);
	RZ_FREE(info);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_heap_block_flag_handler(RzCore *core, int argc, const char **argv) {
#if __WINDOWS__
	if (is_windows_live_debug(core)) {
		rz_heap_debug_block_win(core, NULL, RZ_OUTPUT_MODE_STANDARD, true);
		return RZ_CMD_STATUS_OK;
	}
#endif
	RzWindowsHeapConfig config;
	init_heap_config(core, &config);

	ut64 heap_base = get_heap_base(core->io, &config);
	RzWindowsHeapInfo *info = rz_w32_heap_info_parse(core->io, heap_base, &config);
	if (!info) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzList *blocks = rz_w32_heap_blocks_list(core->io, info, &config);
	if (!blocks) {
		RZ_FREE(info);
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *iter;
	RzWindowsHeapEntry *block;
	rz_list_foreach (blocks, iter, block) {
		char *name = rz_str_newf("alloc.%" PFMT64x, block->header_address);
		if (name) {
			rz_flag_set(core->flags, name, block->header_address, block->size);
			free(name);
		}
	}

	rz_list_free(blocks);
	RZ_FREE(info);
	return RZ_CMD_STATUS_OK;
}
