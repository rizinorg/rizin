// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 Oleg Bushin
// SPDX-License-Identifier: MIT

/**
 * \file Calculates a list of possible base addresses candidates using the strings position
 * Original code from 2013 Michael Coppola
 * https://github.com/mncoppola/ws30/blob/master/basefind.py
 */

#include <rz_basefind.h>
#include <rz_th.h>

typedef struct basefind_addresses_t {
	ut64 *ptr;
	ut32 size;
} BaseFindArray;

typedef struct basefind_data_t {
	ut32 score;
	ut64 start;
	ut64 end;
	BaseFindArray *array;
	RzAtomicBool *loop;
} BaseFindData;

typedef struct basefind_thread_data_t {
	ut32 id;
	ut64 current;
	ut64 base_start;
	ut64 base_end;
	ut64 alignment;
	ut64 io_size;
	ut32 score_min;
	RzThreadLock *lock;
	RzList /*<RzBaseFindScore *>*/ *scores;
	HtUU *pointers;
	BaseFindArray *array;
	RzAtomicBool *loop;
} BaseFindThreadData;

typedef struct basefind_ui_info_t {
	RzAtomicBool *loop;
	RzThreadPool *pool;
	void *user;
	RzBaseFindThreadInfoCb callback;
} BaseFindUIInfo;

static void basefind_stop_all_search_threads(RzThreadPool *pool) {
	size_t pool_size = rz_th_pool_size(pool);
	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_pool_get_thread(pool, i);
		if (!th) {
			continue;
		}
		BaseFindThreadData *bftd = rz_th_get_user(th);
		rz_atomic_bool_set(bftd->loop, false);
	}
}

static RzBinFile *basefind_new_bin_file(RzCore *core) {
	// Copied from cbin.c -> rz_core_bin_whole_strings_print
	// TODO: manually creating an RzBinFile like this is a hack and abuse of RzBin API
	// If we don't want to use an RzBinFile for searching strings, the raw strings search
	// should be refactored out of bin.
	RzIODesc *desc = rz_io_desc_get(core->io, core->file->fd);
	if (!desc) {
		RZ_LOG_ERROR("basefind: cannot get RzIODesc from core.\n");
		return NULL;
	}

	RzBinFile *bf = RZ_NEW0(RzBinFile);
	if (!bf) {
		RZ_LOG_ERROR("basefind: cannot allocate RzBinFile structure.\n");
		return NULL;
	}

	bf->file = strdup(desc->name);
	bf->size = rz_io_desc_size(desc);
	if (bf->size == UT64_MAX) {
		RZ_LOG_ERROR("basefind: filesize exeeds memory size (UT64_MAX).\n");
		free(bf->file);
		free(bf);
		return NULL;
	}

	bf->buf = rz_buf_new_with_io_fd(&core->bin->iob, core->file->fd);
	bf->rbin = core->bin;
	return bf;
}

static void basefind_array_free(BaseFindArray *array) {
	if (!array) {
		return;
	}
	free(array->ptr);
	free(array);
}

static bool basefind_array_has(const BaseFindArray *array, ut64 value) {
	// half-interval search should be better here.
	for (ut32 i = 0; i < array->size; ++i) {
		if (array->ptr[i] == value) {
			return true;
		}
	}
	return false;
}

static BaseFindArray *basefind_create_array_of_addresses(RzCore *core, RzBinStringSearchOpt *opt) {
	RzPVector *strings = NULL;
	BaseFindArray *array = NULL;
	RzBinFile *alloc = NULL;
	RzBinFile *current = rz_bin_cur(core->bin);
	if (!current) {
		current = alloc = basefind_new_bin_file(core);
		if (!current) {
			return NULL;
		}
	}

	// if this list is sorted we can improve speed via half-interval search
	strings = rz_bin_file_strings(current, opt);
	if (!strings || rz_pvector_empty(strings)) {
		RZ_LOG_ERROR("basefind: cannot find strings in binary with a minimum size of %" PFMTSZu ".\n", opt->min_length);
		rz_pvector_free(strings);
		return NULL;
	}

	array = RZ_NEW0(BaseFindArray);
	if (!array) {
		RZ_LOG_ERROR("basefind: cannot allocate BaseFindArray.\n");
		goto error;
	}

	array->size = rz_pvector_len(strings);
	array->ptr = RZ_NEWS0(ut64, array->size);
	if (!array->ptr) {
		RZ_LOG_ERROR("basefind: cannot allocate array of addresses.\n");
		basefind_array_free(array);
		array = NULL;
		goto error;
	}

	ut32 idx;
	void **iter;
	RzBinString *string;
	rz_pvector_enumerate (strings, iter, idx) {
		string = *iter;
		RZ_LOG_VERBOSE("basefind: 0x%016" PFMT64x " '%s'\n", string->paddr, string->string);
		array->ptr[idx] = string->paddr;
	}
	RZ_LOG_INFO("basefind: located %u strings\n", array->size);

error:
	rz_pvector_free(strings);
	if (alloc) {
		rz_buf_free(alloc->buf);
		free(alloc->file);
		free(alloc);
	}
	return array;
}

static HtUU *basefind_create_pointer_map(RzCore *core, ut32 pointer_size) {
	rz_return_val_if_fail(pointer_size == sizeof(ut32) || pointer_size == sizeof(ut64), NULL);

	HtUU *map = ht_uu_new();
	if (!map) {
		RZ_LOG_ERROR("basefind: cannot allocate hashmap for pointer.\n");
		return NULL;
	}

	ut8 buffer[sizeof(ut64)];
	ut64 io_size = rz_io_size(core->io);
	ut64 address = 0;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");

	for (ut64 pos = 0; pos < io_size; pos += pointer_size) {
		rz_io_pread_at(core->io, pos, buffer, pointer_size);
		address = pointer_size == sizeof(ut64) ? rz_read_ble64(buffer, big_endian) : rz_read_ble32(buffer, big_endian);
		ut64 value = ht_uu_find(map, address, NULL) + 1;
		ht_uu_insert(map, address, value);
	}
	RZ_LOG_INFO("basefind: located %u pointers\n", map->count);

	return map;
}

static bool basefind_pointer_map_iter(BaseFindData *bfd, const ut64 address, const ut64 hits) {
	if (!rz_atomic_bool_get(bfd->loop)) {
		return false;
	}
	if (address < bfd->start || address >= bfd->end) {
		return true;
	}
	ut64 offset = address - bfd->start;
	if (basefind_array_has(bfd->array, offset)) {
		bfd->score += hits;
	}
	return true;
}

static int basefind_score_compare(const RzBaseFindScore *a, const RzBaseFindScore *b, void *user) {
	if (b->score == a->score) {
		if (b->candidate == a->candidate) {
			return 0;
		} else if (b->candidate < a->candidate) {
			return -1;
		}
		return 1;
	} else if (b->score < a->score) {
		return -1;
	}
	return 1;
}

static void *basefind_thread_runner(BaseFindThreadData *bftd) {
	RzAtomicBool *loop = bftd->loop;
	RzBaseFindScore *pair = NULL;
	BaseFindData bfd;
	ut64 base;

	bfd.array = bftd->array;
	bfd.loop = loop;
	for (base = bftd->base_start; base < bftd->base_end; base += bftd->alignment) {
		if (!rz_atomic_bool_get(loop)) {
			break;
		}
		bftd->current = base;
		bfd.score = 0;
		bfd.start = base;
		bfd.end = base + bftd->io_size;
		ht_uu_foreach(bftd->pointers, (HtUUForeachCallback)basefind_pointer_map_iter, &bfd);

		if (bfd.score < bftd->score_min) {
			// ignore any score below than score_min
			continue;
		}

		pair = RZ_NEW0(RzBaseFindScore);
		if (!pair) {
			RZ_LOG_ERROR("basefind: cannot allocate RzBaseFindScore.\n");
			break;
		}
		pair->score = bfd.score;
		pair->candidate = base;

		rz_th_lock_enter(bftd->lock);
		if (!rz_list_append(bftd->scores, pair)) {
			rz_th_lock_leave(bftd->lock);
			free(pair);
			RZ_LOG_ERROR("basefind: cannot append new score to the scores list.\n");
			break;
		}
		RZ_LOG_DEBUG("basefind: possible candidate at 0x%016" PFMT64x " with score of %u\n", base, bfd.score);
		rz_th_lock_leave(bftd->lock);
	}
	bftd->current = base;

	return NULL;
}

static void basefind_set_thread_info(BaseFindThreadData *bftd, RzBaseFindThreadInfo *th_info, ut32 thread_idx) {
	ut32 percentage = ((bftd->current - bftd->base_start) * 100) / (bftd->base_end - bftd->base_start);
	if (percentage > 100) {
		percentage = 100;
	}

	th_info->thread_idx = thread_idx;
	th_info->begin_address = bftd->base_start;
	th_info->current_address = bftd->current;
	th_info->end_address = bftd->base_end;
	th_info->percentage = percentage;
}

// this thread does not care about thread-safety since it only prints
// data that will always be available during its lifetime.
static void *basefind_thread_ui(BaseFindUIInfo *ui_info) {
	RzThreadPool *pool = ui_info->pool;
	RzAtomicBool *loop = ui_info->loop;
	ut32 pool_size = rz_th_pool_size(pool);
	RzBaseFindThreadInfoCb callback = ui_info->callback;
	void *user = ui_info->user;
	RzBaseFindThreadInfo th_info;
	th_info.n_threads = pool_size;

	do {
		for (ut32 i = 0; i < pool_size; ++i) {
			RzThread *th = rz_th_pool_get_thread(pool, i);
			if (!th) {
				continue;
			}
			BaseFindThreadData *bftd = rz_th_get_user(th);
			basefind_set_thread_info(bftd, &th_info, i);
			if (!callback(&th_info, user)) {
				basefind_stop_all_search_threads(pool);
				goto end;
			}
		}
		rz_sys_usleep(100000);
	} while (rz_atomic_bool_get(loop));
end:
	return NULL;
}

static inline bool create_thread_interval(RzThreadPool *pool, BaseFindThreadData *bfd) {
	RzThread *thread = rz_th_new((RzThreadFunction)basefind_thread_runner, bfd);
	if (!thread) {
		RZ_LOG_ERROR("basefind: cannot allocate RzThread\n");
		return false;
	} else if (!rz_th_pool_add_thread(pool, thread)) {
		RZ_LOG_ERROR("basefind: cannot add thread to pool\n");
		rz_th_free(thread);
		return false;
	}
	return true;
}

/**
 * \brief Calculates a list of possible base addresses candidates using the strings position
 *
 * The code finds all the strings in memory with a minimum acceptable size (via opt.min_string_len)
 * and calculates all possible words 32 or 64 bit large sizes (endianness via cfg.bigendian) in the
 * given binary.
 * These addresses are then compared with the strings and a variable base address which is increased
 * over time by opt.alignment.
 *
 * The scores are added to the result list with the associated base address if their score are higher
 * than opt.min_score, otherwise they are ignored.
 *
 * It is possible via opt.callback to set a callback function that can stop the search (when returning
 * false) or display the thread statuses (the callback will be called N-times for N spawned threads.
 *
 * \param  core     RzCore struct to use.
 * \param  options  Pointer to the RzBaseFindOpt structure.
 */
RZ_API RZ_OWN RzList /*<RzBaseFindScore *>*/ *rz_basefind(RZ_NONNULL RzCore *core, RZ_NONNULL RzBaseFindOpt *options) {
	rz_return_val_if_fail(core && options, NULL);
	RzList *scores = NULL;
	BaseFindArray *array = NULL;
	HtUU *pointers = NULL;
	size_t pool_size = 1;
	RzThreadPool *pool = NULL;
	RzThreadLock *lock = NULL;
	RzThread *user_thread = NULL;
	BaseFindUIInfo ui_info = { 0 };

	ut64 base_start = options->start_address;
	ut64 base_end = options->end_address;
	ut64 alignment = options->alignment;

	if (options->pointer_size != 32 && options->pointer_size != 64) {
		RZ_LOG_ERROR("basefind: supported pointer sizes are 32 and 64 bits.\n");
		return NULL;
	} else if (!core->file) {
		RZ_LOG_ERROR("basefind: the file was not opened via RzCore.\n");
		return NULL;
	} else if (base_start >= base_end) {
		RZ_LOG_ERROR("basefind: start address is greater or equal to end address.\n");
		return NULL;
	} else if (alignment < 1) {
		RZ_LOG_ERROR("basefind: the alignment is set to zero bytes.\n");
		return NULL;
	} else if (options->min_score < 1) {
		RZ_LOG_ERROR("basefind: the minimum score is set to zero.\n");
		return NULL;
	} else if (options->min_string_len < 1) {
		RZ_LOG_ERROR("basefind: the minimum string length is set to zero.\n");
		return NULL;
	}

	if (alignment < RZ_BASEFIND_BASE_ALIGNMENT) {
		RZ_LOG_WARN("basefind: the alignment is less than 0x%x bytes, "
			    "which may result in a very slow search.\n",
			RZ_BASEFIND_BASE_ALIGNMENT);
	}

	// Copy RzBin string search configuration.
	RzBinStringSearchOpt opt = core->bin->str_search_cfg;

	// Enforce raw binary mode, thread count & min string length.
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;
	opt.max_threads = options->max_threads;
	opt.min_length = options->min_string_len;

	array = basefind_create_array_of_addresses(core, &opt);
	if (!array) {
		goto rz_basefind_end;
	}

	pointers = basefind_create_pointer_map(core, options->pointer_size / 8);
	if (!pointers) {
		goto rz_basefind_end;
	}

	scores = rz_list_newf((RzListFree)free);
	if (!scores) {
		RZ_LOG_ERROR("basefind: cannot allocate new scores list.\n");
		goto rz_basefind_end;
	}

	pool = rz_th_pool_new(options->max_threads);
	if (!pool) {
		RZ_LOG_ERROR("basefind: cannot allocate thread pool.\n");
		goto rz_basefind_end;
	}
	pool_size = rz_th_pool_size(pool);

	lock = rz_th_lock_new(false);
	if (!lock) {
		RZ_LOG_ERROR("basefind: cannot allocate thread lock.\n");
		goto rz_basefind_end;
	}

	RZ_LOG_VERBOSE("basefind: using %u threads\n", (ut32)pool_size);

	ut64 io_size = rz_io_size(core->io);
	ut64 sector_size = (((base_end - base_start) + pool_size - 1) / pool_size);
	for (size_t i = 0; i < pool_size; ++i) {
		BaseFindThreadData *bftd = RZ_NEW(BaseFindThreadData);
		if (!bftd) {
			RZ_LOG_ERROR("basefind: cannot allocate BaseFindThreadData.\n");
			basefind_stop_all_search_threads(pool);
			goto rz_basefind_end;
		}
		bftd->alignment = alignment;
		bftd->base_start = base_start + (sector_size * i);
		bftd->current = bftd->base_start;
		bftd->base_end = bftd->base_start + sector_size;
		bftd->score_min = options->min_score;
		bftd->io_size = io_size;
		bftd->lock = lock;
		bftd->scores = scores;
		bftd->pointers = pointers;
		bftd->array = array;
		bftd->loop = rz_atomic_bool_new(true);
		if (!create_thread_interval(pool, bftd)) {
			free(bftd);
			basefind_stop_all_search_threads(pool);
			goto rz_basefind_end;
		}
	}

	if (options->callback) {
		ui_info.pool = pool;
		ui_info.user = options->user;
		ui_info.callback = options->callback;
		ui_info.loop = rz_atomic_bool_new(true);
		user_thread = rz_th_new((RzThreadFunction)basefind_thread_ui, &ui_info);
		if (!user_thread) {
			basefind_stop_all_search_threads(pool);
			goto rz_basefind_end;
		}
	}

	// wait the pool to finish
	rz_th_pool_wait(pool);

	if (options->callback) {
		rz_atomic_bool_set(ui_info.loop, false);
		rz_th_wait(user_thread);
		rz_th_free(user_thread);
		rz_atomic_bool_free(ui_info.loop);

		RzBaseFindThreadInfo th_info;
		th_info.n_threads = pool_size;
		for (ut32 i = 0; i < pool_size; ++i) {
			RzThread *th = rz_th_pool_get_thread(pool, i);
			if (!th) {
				continue;
			}
			BaseFindThreadData *bftd = rz_th_get_user(th);
			basefind_set_thread_info(bftd, &th_info, i);
			options->callback(&th_info, options->user);
		}
	}

	rz_list_sort(scores, (RzListComparator)basefind_score_compare, NULL);

rz_basefind_end:
	if (pool) {
		for (ut32 i = 0; i < pool_size; ++i) {
			RzThread *th = rz_th_pool_get_thread(pool, i);
			if (!th) {
				continue;
			}
			BaseFindThreadData *bftd = rz_th_get_user(th);
			rz_atomic_bool_free(bftd->loop);
			free(bftd);
		}
		rz_th_pool_free(pool);
	}
	rz_th_lock_free(lock);
	basefind_array_free(array);
	ht_uu_free(pointers);
	return scores;
}
