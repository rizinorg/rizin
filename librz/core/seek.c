// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

static void get_current_seek_state(RzCore *core, RzCoreSeekItem *elem) {
	elem->offset = core->offset;
	elem->cursor = core->print->cur_enabled ? rz_print_get_cursor (core->print) : 0;
	elem->is_current = false;
}

static void set_current_seek_state(RzCore *core, RzCoreSeekItem *elem) {
	rz_core_seek (core, elem->offset, true);
	core->print->cur = elem->cursor;
}

static void add_seek_history(RzCore *core) {
	RzVector *vundo = &core->seek_history.undos;
	RzVector *vredo = &core->seek_history.redos;
	RzCoreSeekItem item;
	get_current_seek_state (core, &item);
	// TODO: check double entries
	rz_vector_push (vundo, &item);
	rz_vector_clear (vredo);
}

static bool seek_check_save(RzCore *core, ut64 addr, bool rb, bool save) {
	if (save) {
		return rz_core_seek_and_save (core, addr, rb);
	} else {
		return rz_core_seek (core, addr, rb);
	}
}

/**
 *
 */
RZ_API bool rz_core_seek_save(RzCore *core) {
	if (!rz_config_get_i (core->config, "cfg.seek.silent")) {
		add_seek_history (core);
		return true;
	}
	return false;
}

/**
 *
 */
RZ_API bool rz_core_seek_and_save(RzCore *core, ut64 addr, bool rb) {
	if (addr != core->offset) {
		rz_core_seek_save (core);
	}
	return rz_core_seek (core, addr, rb);
}

/**
 *
 */
RZ_API bool rz_core_seek(RzCore *core, ut64 addr, bool rb) {
	core->offset = rz_io_seek (core->io, addr, RZ_IO_SEEK_SET);
	if (rb) {
		rz_core_block_read (core);
	}
	if (core->binat) {
		RzBinFile *bf = rz_bin_file_at (core->bin, core->offset);
		if (bf) {
			core->bin->cur = bf;
			rz_bin_select_bfid (core->bin, bf->id);
		} else {
			core->bin->cur = NULL;
		}
	}
	return core->offset == addr;
}

/**
 * 
 */
RZ_API bool rz_core_seek_opt(RzCore *core, ut64 addr, bool rb, bool save) {
	return seek_check_save (core, addr, rb, save);
}

/**
 *
 */
RZ_API int rz_core_seek_delta(RzCore *core, st64 delta, bool save) {
	ut64 newaddr;
	if (delta > 0 && UT64_ADD_OVFCHK (core->offset, (ut64) (delta))) {
		newaddr = UT64_MAX;
	} else if (delta < 0 && core->offset < (ut64)RZ_ABS (delta)) {
		newaddr = 0;
	} else {
		newaddr = core->offset + delta;
	}
	return seek_check_save (core, newaddr, true, save);
}

/**
 *
 */
RZ_API int rz_core_seek_base(RzCore *core, const char *hex, bool save) {
	ut64 addr = rz_num_tail (core->num, core->offset, hex);
	return seek_check_save (core, addr, true, save);
}

struct seek_flag_offset_t {
	ut64 offset;
	ut64 *next;
	bool is_next;
};

static bool seek_flag_offset(RzFlagItem *fi, void *user) {
	struct seek_flag_offset_t *u = (struct seek_flag_offset_t *)user;
	if (u->is_next) {
		if (fi->offset < *u->next && fi->offset > u->offset) {
			*u->next = fi->offset;
		}
	} else {
		if (fi->offset > *u->next && fi->offset < u->offset) {
			*u->next = fi->offset;
		}
	}
	return true;
}

/**
 *
 */
RZ_API void rz_core_seek_next(RzCore *core, const char *type, bool save) {
	RzListIter *iter;
	ut64 next = UT64_MAX;
	if (strstr (type, "opc")) {
		RzAnalysisOp aop;
		if (rz_analysis_op (core->analysis, &aop, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC)) {
			next = core->offset + aop.size;
		} else {
			eprintf ("Invalid opcode\n");
		}
	} else if (strstr (type, "fun")) {
		RzAnalysisFunction *fcni;
		rz_list_foreach (core->analysis->fcns, iter, fcni) {
			if (fcni->addr < next && fcni->addr > core->offset) {
				next = fcni->addr;
			}
		}
	} else if (strstr (type, "hit")) {
		const char *pfx = rz_config_get (core->config, "search.prefix");
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = true };
		rz_flag_foreach_prefix (core->flags, pfx, -1, seek_flag_offset, &u);
	} else { // flags
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = true };
		rz_flag_foreach (core->flags, seek_flag_offset, &u);
	}
	if (next != UT64_MAX) {
		seek_check_save (core, next, true, save);
	}
}

/**
 *
 */
RZ_API void rz_core_seek_prev(RzCore *core, const char *type, bool save) {
	RzListIter *iter;
	ut64 next = 0;
	if (strstr (type, "opc")) {
		eprintf ("TODO: rz_core_seek_prev (opc)\n");
	} else if (strstr (type, "fun")) {
		RzAnalysisFunction *fcni;
		rz_list_foreach (core->analysis->fcns, iter, fcni) {
			if (fcni->addr > next && fcni->addr < core->offset) {
				next = fcni->addr;
			}
		}
	} else if (strstr (type, "hit")) {
		const char *pfx = rz_config_get (core->config, "search.prefix");
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = false };
		rz_flag_foreach_prefix (core->flags, pfx, -1, seek_flag_offset, &u);
	} else { // flags
		struct seek_flag_offset_t u = { .offset = core->offset, .next = &next, .is_next = false };
		rz_flag_foreach (core->flags, seek_flag_offset, &u);
	}
	if (next != 0) {
		seek_check_save (core, next, true, save);
	}
}

/**
 *
 */
RZ_API int rz_core_seek_align(RzCore *core, ut64 align, bool save) {
	if (!align) {
		return false;
	}
	int diff = core->offset % align;
	return seek_check_save (core, core->offset - diff, true, save);
}

/**
 * Seek basic block that contains address addr or do nothing if there is no
 * block.
 */
RZ_API bool rz_core_seek_analysis_bb(RzCore *core, ut64 addr, bool save) {
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in (core->analysis, addr);
	if (block) {
		seek_check_save (core, block->addr, false, save);
		return true;
	}
	return false;
}

RZ_API bool rz_core_seek_undo(RzCore *core) {
	if (rz_vector_empty (&core->seek_history.undos)) {
		return false;
	}
	RzCoreSeekItem elem;
	get_current_seek_state (core, &elem);
	rz_vector_push (&core->seek_history.redos, &elem);
	rz_vector_pop (&core->seek_history.undos, &elem);
	set_current_seek_state (core, &elem);
	return true;
}

RZ_API bool rz_core_seek_redo(RzCore *core) {
	if (rz_vector_empty (&core->seek_history.redos)) {
		return false;
	}
	RzCoreSeekItem elem;
	get_current_seek_state (core, &elem);
	rz_vector_push (&core->seek_history.undos, &elem);
	rz_vector_pop (&core->seek_history.redos, &elem);
	set_current_seek_state (core, &elem);
	return true;
}

RZ_API void rz_core_seek_reset(RzCore *core) {
	rz_vector_fini (&core->seek_history.undos);
	rz_vector_fini (&core->seek_history.redos);
	return;
}

static RzCoreSeekItem *dup_seek_history_item(RzCoreSeekItem *item, int i) {
	RzCoreSeekItem *res = RZ_NEW0 (RzCoreSeekItem);
	if (!res) {
		return NULL;
	}
	res->offset = item->offset;
	res->cursor = item->cursor;
	res->is_current = item->is_current;
	res->idx = i;
	return res;
}

RZ_API RzList *rz_core_seek_list(RzCore *core) {
	RzList *res = rz_list_newf ((RzListFree)free);
	RzCoreSeekItem *it;
	int i = -rz_vector_len (&core->seek_history.undos);
	rz_vector_foreach (&core->seek_history.undos, it) {
		RzCoreSeekItem *dup = dup_seek_history_item (it, ++i);
		if (!dup) {
			goto err;
		}
		rz_list_append (res, dup);
	}

	RzCoreSeekItem *cur = RZ_NEW0 (RzCoreSeekItem);
	if (!cur) {
	    goto err;
	}
	cur->offset = core->offset;
	cur->cursor = core->print->cur_enabled? rz_print_get_cursor (core->print): 0;
	cur->is_current = true;
	cur->idx = 0;
	rz_list_append (res, cur);

	i = 0;
	rz_vector_foreach_prev (&core->seek_history.redos, it) {
		RzCoreSeekItem *dup = dup_seek_history_item (it, i++);
		if (!dup) {
			goto err;
		}
		rz_list_append (res, dup);
	}
	return res;

err:
	rz_list_free (res);
	return NULL;
}
