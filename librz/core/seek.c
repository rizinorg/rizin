// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API void rz_core_seek_item_free(RzCoreSeekItem *item) {
	free(item);
}

static void get_current_seek_state(RzCore *core, RzCoreSeekItem *elem) {
	elem->offset = core->offset;
	elem->cursor = core->print->cur_enabled ? rz_print_get_cursor(core->print) : 0;
	elem->is_current = false;
}

static void set_current_seek_state(RzCore *core, RzCoreSeekItem *elem) {
	rz_core_seek(core, elem->offset, true);
	core->print->cur = elem->cursor;
}

static void add_seek_history(RzCore *core) {
	RzVector *vundo = &core->seek_history.undos;
	RzVector *vredo = &core->seek_history.redos;
	RzCoreSeekItem *item = &core->seek_history.saved_item;
	ut64 histsize = rz_config_get_i(core->config, "cfg.seek.histsize");
	if (!rz_vector_empty(vundo)) {
		RzCoreSeekItem *last = rz_vector_index_ptr(vundo, rz_vector_len(vundo) - 1);
		if (item->offset == last->offset && item->cursor == last->cursor) {
			return;
		}
	}
	if (histsize != 0 && rz_vector_len(vundo) >= histsize) {
		rz_vector_remove_at(vundo, 0, NULL);
	}
	rz_vector_push(vundo, item);
	rz_vector_clear(vredo);
}

static bool seek_check_save(RzCore *core, ut64 addr, bool rb, bool save) {
	if (save) {
		return rz_core_seek_and_save(core, addr, rb);
	} else {
		return rz_core_seek(core, addr, rb);
	}
}

/**
 * \brief Mark current state (offset+cursor) as the next state to save in history
 *
 * The saving can be disabled if eval var cfg.seek.silent is set to true. The
 * state saved here is actually saved in history once \p rz_core_seek_and_save
 * is called (or other functions with the \p save argument set to true).
 *
 * \param core RzCore reference
 */
RZ_API bool rz_core_seek_mark(RzCore *core) {
	if (!rz_config_get_i(core->config, "cfg.seek.silent")) {
		get_current_seek_state(core, &core->seek_history.saved_item);
		core->seek_history.saved_set = true;
		return true;
	}
	core->seek_history.saved_set = false;
	return false;
}

static bool need_add2history(RzCore *core, ut64 addr) {
	RzCoreSeekHistory *hist = &core->seek_history;
	return hist->saved_set && (addr != hist->saved_item.offset || hist->saved_item.cursor != 0);
}

static bool seek_save(RzCore *core, ut64 addr) {
	if (need_add2history(core, addr)) {
		add_seek_history(core);
		core->seek_history.saved_set = false;
		return true;
	}
	core->seek_history.saved_set = false;
	return false;
}

/**
 * \brief Save last marked position, if any, in the seek history.
 *
 * \param core RzCore reference
 */
RZ_API bool rz_core_seek_save(RzCore *core) {
	return seek_save(core, core->offset);
}

/**
 * \brief Save currently marked state in seek history and seek to \p addr .
 *
 * If \p rz_core_seek_mark is used to mark a position, that position will be
 * saved in the history, otherwise the current state is used.
 *
 * \param core RzCore reference
 * \param addr Address where to move to
 * \param rb If true read the block
 */
RZ_API bool rz_core_seek_and_save(RzCore *core, ut64 addr, bool rb) {
	if (!core->seek_history.saved_set) {
		rz_core_seek_mark(core);
	}
	seek_save(core, addr);
	return rz_core_seek(core, addr, rb);
}

/**
 * \brief Seek to \p addr.
 *
 * \param core RzCore reference
 * \param addr Address where to move to
 * \param rb If true read the block
 */
RZ_API bool rz_core_seek(RzCore *core, ut64 addr, bool rb) {
	core->offset = rz_io_seek(core->io, addr, RZ_IO_SEEK_SET);
	if (rb) {
		rz_core_block_read(core);
	}
	if (core->binat) {
		RzBinFile *bf = rz_bin_file_at(core->bin, core->offset);
		if (bf) {
			core->bin->cur = bf;
			rz_bin_select_bfid(core->bin, bf->id);
		} else {
			core->bin->cur = NULL;
		}
	}
	return core->offset == addr;
}

/**
 * \brief Seek to \p addr and optionally save the current offset in seek history.
 *
 * \param core RzCore reference
 * \param addr Address where to move to
 * \param rb If true read the block
 * \param save If true save the current state in seek history before seeking
 */
RZ_API bool rz_core_seek_opt(RzCore *core, ut64 addr, bool rb, bool save) {
	return seek_check_save(core, addr, rb, save);
}

/**
 * \brief Seek relative to current offset and optionally save the current offset in seek history.
 *
 * \param core RzCore reference
 * \param delta Delta address added to the current offset
 * \param save If true save the current state in seek history before seeking
 */
RZ_API bool rz_core_seek_delta(RzCore *core, st64 delta, bool save) {
	ut64 newaddr;
	if (delta > 0 && UT64_ADD_OVFCHK(core->offset, (ut64)(delta))) {
		newaddr = UT64_MAX;
	} else if (delta < 0 && core->offset < (ut64)RZ_ABS(delta)) {
		newaddr = 0;
	} else {
		newaddr = core->offset + delta;
	}
	return seek_check_save(core, newaddr, true, save);
}

/**
 * \brief Seek to a new address composed of current offset with last hex digits replaced with those of \p hex
 *
 * \param core RzCore reference
 * \param hex New final part of the address (in hex)
 * \param save If true save the current state in seek history before seeking
 */
RZ_API int rz_core_seek_base(RzCore *core, const char *hex, bool save) {
	ut64 addr = rz_num_tail(core->num, core->offset, hex);
	return seek_check_save(core, addr, true, save);
}

struct seek_flag_offset_t {
	ut64 offset;
	ut64 *next;
	bool is_next;
};

static bool seek_flag_offset(RzFlagItem *fi, void *user) {
	struct seek_flag_offset_t *u = (struct seek_flag_offset_t *)user;
	ut64 fi_off = rz_flag_item_get_offset(fi);
	if (u->is_next) {
		if (fi_off < *u->next && fi_off > u->offset) {
			*u->next = fi_off;
		}
	} else {
		if (fi_off > *u->next && fi_off < u->offset) {
			*u->next = fi_off;
		}
	}
	return true;
}

/**
 * \brief Seek to the next \p type of item from current offset
 *
 * \param core RzCore reference
 * \param type Type of next "item" to seek to (could be "opc", "fun", "hit", "flag")
 * \param save If true save the current state in seek history before seeking
 */
RZ_API bool rz_core_seek_next(RzCore *core, const char *type, bool save) {
	RzListIter *iter;
	ut64 next = UT64_MAX;
	if (strstr(type, "opc")) {
		RzAnalysisOp aop = { 0 };
		rz_analysis_op_init(&aop);
		if (rz_analysis_op(core->analysis, &aop, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC) > 0) {
			next = core->offset + aop.size;
		} else {
			RZ_LOG_ERROR("core: invalid opcode\n");
		}
		rz_analysis_op_fini(&aop);
	} else if (strstr(type, "fun")) {
		RzAnalysisFunction *fcni;
		rz_list_foreach (core->analysis->fcns, iter, fcni) {
			if (fcni->addr < next && fcni->addr > core->offset) {
				next = fcni->addr;
			}
		}
	} else if (strstr(type, "hit")) {
		const char *pfx = rz_config_get(core->config, "search.prefix");
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = true };
		rz_flag_foreach_prefix(core->flags, pfx, -1, seek_flag_offset, &u);
	} else { // flags
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = true };
		rz_flag_foreach(core->flags, seek_flag_offset, &u);
	}
	if (next == UT64_MAX) {
		return false;
	}
	return seek_check_save(core, next, true, save);
}

/**
 * \brief Seek to the previous \p type of item from current offset
 *
 * \param core RzCore reference
 * \param type Type of previous "item" to seek to (could be "opc", "fun", "hit", "flag")
 * \param save If true save the current state in seek history before seeking
 */
RZ_API bool rz_core_seek_prev(RzCore *core, const char *type, bool save) {
	RzListIter *iter;
	ut64 next = 0;
	if (strstr(type, "opc")) {
		RZ_LOG_WARN("core: TODO: rz_core_seek_prev (opc)\n");
	} else if (strstr(type, "fun")) {
		RzAnalysisFunction *fcni;
		rz_list_foreach (core->analysis->fcns, iter, fcni) {
			if (fcni->addr > next && fcni->addr < core->offset) {
				next = fcni->addr;
			}
		}
	} else if (strstr(type, "hit")) {
		const char *pfx = rz_config_get(core->config, "search.prefix");
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = false };
		rz_flag_foreach_prefix(core->flags, pfx, -1, seek_flag_offset, &u);
	} else { // flags
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = false };
		rz_flag_foreach(core->flags, seek_flag_offset, &u);
	}
	if (next == 0) {
		return false;
	}
	return seek_check_save(core, next, true, save);
}

/**
 * \brief Seek to current offset aligned to \p align
 *
 * \param core RzCore reference
 * \param align Value to align the current offset
 * \param save If true save the current state in seek history before seeking
 */
RZ_API bool rz_core_seek_align(RzCore *core, ut64 align, bool save) {
	if (!align) {
		return false;
	}
	int diff = core->offset % align;
	return seek_check_save(core, core->offset - diff, true, save);
}

/**
 * \brief Seek to basic block that contains address \p addr
 *
 * \param core RzCore reference
 * \param addr Address that needs to be in the basicblock
 * \param save If true save the current state in seek history before seeking
 */
RZ_API bool rz_core_seek_analysis_bb(RzCore *core, ut64 addr, bool save) {
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
	if (block) {
		seek_check_save(core, block->addr, false, save);
		return true;
	}
	return false;
}

/**
 * Undo the last entry in the seek history
 */
RZ_API bool rz_core_seek_undo(RzCore *core) {
	if (rz_vector_empty(&core->seek_history.undos)) {
		return false;
	}
	RzCoreSeekItem elem;
	get_current_seek_state(core, &elem);
	rz_vector_push(&core->seek_history.redos, &elem);
	rz_vector_pop(&core->seek_history.undos, &elem);
	set_current_seek_state(core, &elem);
	return true;
}

/**
 * Redo the last undone entry in the seek history
 */
RZ_API bool rz_core_seek_redo(RzCore *core) {
	if (rz_vector_empty(&core->seek_history.redos)) {
		return false;
	}
	RzCoreSeekItem elem;
	get_current_seek_state(core, &elem);
	rz_vector_push(&core->seek_history.undos, &elem);
	rz_vector_pop(&core->seek_history.redos, &elem);
	set_current_seek_state(core, &elem);
	return true;
}

static RzCoreSeekItem *get_current_item(RzCore *core) {
	RzCoreSeekItem *res = RZ_NEW0(RzCoreSeekItem);
	if (!res) {
		return NULL;
	}
	get_current_seek_state(core, res);
	res->is_current = true;
	res->idx = 0;
	return res;
}

static RzCoreSeekItem *dup_seek_history_item(RzCoreSeekItem *item, int i) {
	RzCoreSeekItem *res = RZ_NEW0(RzCoreSeekItem);
	if (!res) {
		return NULL;
	}
	res->offset = item->offset;
	res->cursor = item->cursor;
	res->is_current = item->is_current;
	res->idx = i;
	return res;
}

/**
 * \brief Return a element in the undo/redo list.
 *
 * The element is not removed from the list nor it is restored as the current
 * state. Useful if you want to inspect the undo history. The object shall be
 * freed by the caller.
 *
 * \param core Reference to RzCore
 * \param idx Index of the element. 0 references the current seek, <0 are undos, >0 redos
 */
RZ_API RzCoreSeekItem *rz_core_seek_peek(RzCore *core, int idx) {
	if (idx == 0) {
		return get_current_item(core);
	} else if (idx < 0) {
		RzVector *vundo = &core->seek_history.undos;
		size_t i = RZ_ABS(idx) - 1;
		size_t len = rz_vector_len(vundo);
		if (i >= len) {
			return NULL;
		}
		RzCoreSeekItem *vel = (RzCoreSeekItem *)rz_vector_index_ptr(vundo, len - i - 1);
		return dup_seek_history_item(vel, idx);
	} else {
		RzVector *vredo = &core->seek_history.redos;
		size_t i = RZ_ABS(idx) - 1;
		size_t len = rz_vector_len(vredo);
		if (i >= len) {
			return NULL;
		}
		RzCoreSeekItem *vel = (RzCoreSeekItem *)rz_vector_index_ptr(vredo, len - i - 1);
		return dup_seek_history_item(vel, idx);
	}
}

/**
 * Remove all seek history entries
 */
RZ_API void rz_core_seek_reset(RzCore *core) {
	rz_vector_fini(&core->seek_history.undos);
	rz_vector_fini(&core->seek_history.redos);
	rz_vector_init(&core->seek_history.undos, sizeof(RzCoreSeekItem), NULL, NULL);
	rz_vector_init(&core->seek_history.redos, sizeof(RzCoreSeekItem), NULL, NULL);
}

/**
 * Free seek history data
 */
RZ_API void rz_core_seek_free(RzCore *core) {
	rz_vector_fini(&core->seek_history.undos);
	rz_vector_fini(&core->seek_history.redos);
}

/**
 * \brief Return the seek history.
 *
 * The list is composed of some items with negative idx which are Undos items
 * (potentially none), then there is an item with is_current=true that is the
 * current state, followed by some items with positive idx which are Redos
 * items.
 */
RZ_API RzList /*<RzCoreSeekItem *>*/ *rz_core_seek_list(RzCore *core) {
	RzList *res = rz_list_newf((RzListFree)rz_core_seek_item_free);
	if (!res) {
		return NULL;
	}

	RzCoreSeekItem *it;
	int i = -rz_vector_len(&core->seek_history.undos);
	rz_vector_foreach (&core->seek_history.undos, it) {
		RzCoreSeekItem *dup = dup_seek_history_item(it, i++);
		if (!dup) {
			goto err;
		}
		rz_list_append(res, dup);
	}

	RzCoreSeekItem *cur = get_current_item(core);
	if (!cur) {
		goto err;
	}
	rz_list_append(res, cur);

	i = 1;
	rz_vector_foreach_prev (&core->seek_history.redos, it) {
		RzCoreSeekItem *dup = dup_seek_history_item(it, i++);
		if (!dup) {
			goto err;
		}
		rz_list_append(res, dup);
	}
	return res;

err:
	rz_list_free(res);
	return NULL;
}

/* \brief Seek to the \p index instruction in the current basic block
 *
 * Allows \p index to be negative, in this case it will count
 * the instructions from the end of the block
 * */
RZ_IPI bool rz_core_seek_bb_instruction(RzCore *core, int index) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!bb) {
		RZ_LOG_ERROR("Can't find a basic block for 0x%08" PFMT64x "\n", core->offset);
		return false;
	}
	// handle negative indices
	if (index < 0) {
		index = bb->ninstr + index;
	}
	if (!(index >= 0 && index < bb->ninstr)) {
		RZ_LOG_ERROR("The current basic block has %d instructions\n", bb->ninstr);
		return false;
	}
	ut64 inst_addr = rz_analysis_block_get_op_addr(bb, index);
	return rz_core_seek(core, inst_addr, true);
}
