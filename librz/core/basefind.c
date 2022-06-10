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
} BaseFindData;

typedef struct basefind_thread_data_t {
	ut32 id;
	ut64 current;
	ut64 base_start;
	ut64 base_end;
	ut64 base_inc;
	ut64 io_size;
	ut32 score_min;
	RzThreadLock *lock;
	RzList *scores;
	HtUU *pointers;
	BaseFindArray *array;
} BaseFindThreadData;

typedef struct basefind_thread_cons_t {
	bool progress;
	RzThreadPool *pool;
} BaseFindThreadCons;

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

static BaseFindArray *basefind_create_array_of_addresses(RzCore *core) {
	RzList *strings = NULL;
	BaseFindArray *array = NULL;
	RzBinFile *alloc = NULL;
	RzBinFile *current = rz_bin_cur(core->bin);
	if (!current) {
		current = alloc = basefind_new_bin_file(core);
		if (!current) {
			return NULL;
		}
	}

	ut32 string_min_size = rz_config_get_i(core->config, "basefind.string.min");
	if (string_min_size < 1) {
		RZ_LOG_ERROR("basefind: cannot find strings when 'basefind.string.min' is zero.\n");
		rz_goto_if_reached(error);
	}

	// if this list is sorted we can improve speed via half-interval search
	strings = rz_bin_file_strings(current, string_min_size, true);
	if (!strings || rz_list_empty(strings)) {
		RZ_LOG_ERROR("basefind: cannot find strings in binary with a minimum size of %u.\n", string_min_size);
		rz_list_free(strings);
		return NULL;
	}

	array = RZ_NEW0(BaseFindArray);
	if (!array) {
		RZ_LOG_ERROR("basefind: cannot allocate BaseFindArray.\n");
		goto error;
	}

	array->size = rz_list_length(strings);
	array->ptr = RZ_NEWS0(ut64, array->size);
	if (!array->ptr) {
		RZ_LOG_ERROR("basefind: cannot allocate array of addresses.\n");
		basefind_array_free(array);
		array = NULL;
		goto error;
	}

	ut32 i = 0;
	RzListIter *iter;
	RzBinString *string;
	rz_list_foreach (strings, iter, string) {
		RZ_LOG_VERBOSE("basefind: 0x%016" PFMT64x " '%s'\n", string->paddr, string->string);
		array->ptr[i] = string->paddr;
		i++;
	}
	RZ_LOG_INFO("basefind: located %u strings\n", array->size);

error:
	rz_list_free(strings);
	if (alloc) {
		rz_buf_free(alloc->buf);
		free(alloc->file);
		free(alloc);
	}
	return array;
}

static HtUU *basefind_create_pointer_map(RzCore *core, ut32 pointer_size) {
	rz_return_val_if_fail(pointer_size == sizeof(ut32) || pointer_size == sizeof(ut64), NULL);

	HtUU *map = ht_uu_new0();
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
	if (rz_cons_is_breaked()) {
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

static int basefind_score_compare(const RzBaseFindScore *a, const RzBaseFindScore *b) {
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
	RzBaseFindScore *pair = NULL;
	BaseFindData bfd;
	ut64 base;

	bfd.array = bftd->array;
	for (base = bftd->base_start; base < bftd->base_end; base += bftd->base_inc) {
		if (rz_cons_is_breaked()) {
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

// this thread does not care about thread-safety since it only prints
// data that will always be available during its lifetime.
static void *basefind_thread_cons(BaseFindThreadCons *th_cons) {
	bool progress = th_cons->progress;
	RzThreadPool *pool = th_cons->pool;
	size_t pool_size = rz_th_pool_size(pool);
	rz_cons_flush();
	int begin_line = rz_cons_get_cur_line();
	do {
		if (progress) {
			rz_cons_gotoxy(1, begin_line);
			for (ut32 i = 0; i < pool_size; ++i) {
				RzThread *th = rz_th_pool_get_thread(pool, i);
				if (!th) {
					continue;
				}
				BaseFindThreadData *bftd = rz_th_get_user(th);
				ut32 perc = ((bftd->current - bftd->base_start) * 100) / (bftd->base_end - bftd->base_start);
				if (perc > 100) {
					perc = 100;
				}
				rz_cons_printf("basefind: thread %u: 0x%08" PFMT64x " / 0x%08" PFMT64x " %u%%\n", i, bftd->current, bftd->base_end, perc);
			}
			rz_cons_flush();
			begin_line = rz_cons_get_cur_line() - pool_size;
		}
		rz_sys_usleep(100000);
		if (rz_cons_is_breaked()) {
			rz_th_pool_kill(pool);
			break;
		}
	} while (1);
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
 * The code finds all the strings in memory with a minimum acceptable size (via basefind.string.min)
 * and calculates all possible words 32 or 64 bit large sizes (endianness via cfg.bigendian) in the
 * given binary.
 * These addresses are then compared with the strings and a variable base address (see basefind.base.start
 * and basefind.base.end) which is increased over time (see basefind.base.increase).
 * The scores are ignored if below basefind.score.min otherwise they are added to the list with the
 * associated base address.
 *
 * \param  core         RzCore struct to use.
 * \param  pointer_size Pointer size in bits.
 * \return RzList       Sorted list of pairs (score, address) from highest score to lowest.
 */
RZ_API RZ_OWN RzList *rz_basefind(RZ_NONNULL RzCore *core, ut32 pointer_size) {
	rz_return_val_if_fail(core, NULL);
	RzList *scores = NULL;
	BaseFindArray *array = NULL;
	HtUU *pointers = NULL;
	ut64 base_start = 0, base_end = 0, base_inc = 0;
	ut32 score_min = 0;
	size_t max_threads = 0, pool_size = 1;
	RzThreadPool *pool = NULL;
	RzThreadLock *lock = NULL;
	bool progress = false;

	if (pointer_size != 32 && pointer_size != 64) {
		RZ_LOG_ERROR("basefind: supported pointer sizes are 32 and 64 bits.\n");
		return NULL;
	}
	pointer_size /= 8;

	if (!core->file) {
		RZ_LOG_ERROR("basefind: not file was opened via RzCore.\n");
		return NULL;
	}

	base_start = rz_config_get_i(core->config, "basefind.base.start");
	base_end = rz_config_get_i(core->config, "basefind.base.end");
	base_inc = rz_config_get_i(core->config, "basefind.base.increase");
	score_min = rz_config_get_i(core->config, "basefind.score.min");
	max_threads = rz_config_get_i(core->config, "basefind.threads.max");
	progress = rz_config_get_b(core->config, "basefind.progress");

	if (base_start >= base_end) {
		RZ_LOG_ERROR("basefind: option 'basefind.base.start' is greater or equal to 'basefind.base.end'.\n");
		return NULL;
	} else if (base_inc < 1) {
		RZ_LOG_ERROR("basefind: option 'basefind.base.increase' is zero.\n");
		return NULL;
	} else if (base_inc < RZ_BASEFIND_BASE_INCREASE) {
		RZ_LOG_WARN("basefind: option 'basefind.base.increase' is less than 0x%x, which may result in a very slow search.\n", RZ_BASEFIND_BASE_INCREASE);
	}

	if (score_min < 1) {
		RZ_LOG_WARN("basefind: option 'basefind.score.min' zero, which may result in a long list of results.\n");
	}

	array = basefind_create_array_of_addresses(core);
	if (!array) {
		goto rz_basefind_end;
	}

	pointers = basefind_create_pointer_map(core, pointer_size);
	if (!pointers) {
		goto rz_basefind_end;
	}

	scores = rz_list_newf((RzListFree)free);
	if (!scores) {
		RZ_LOG_ERROR("basefind: cannot allocate new scores list.\n");
		goto rz_basefind_end;
	}

	pool = rz_th_pool_new(max_threads);
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
			rz_th_pool_kill(pool);
			goto rz_basefind_end;
		}
		bftd->base_inc = base_inc;
		bftd->base_start = base_start + (sector_size * i);
		bftd->current = bftd->base_start;
		bftd->base_end = bftd->base_start + sector_size;
		bftd->score_min = score_min;
		bftd->io_size = io_size;
		bftd->lock = lock;
		bftd->scores = scores;
		bftd->pointers = pointers;
		bftd->array = array;
		if (!create_thread_interval(pool, bftd)) {
			free(bftd);
			rz_th_pool_kill(pool);
			goto rz_basefind_end;
		}
	}

	BaseFindThreadCons th_cons;
	th_cons.progress = progress;
	th_cons.pool = pool;

	RzThread *cons_thread = rz_th_new((RzThreadFunction)basefind_thread_cons, &th_cons);
	if (!cons_thread) {
		rz_th_pool_kill(pool);
		goto rz_basefind_end;
	}
	rz_th_pool_wait(pool);
	if (progress) {
		// ensure to print the 100%
		rz_sys_usleep(100000);
	}
	rz_th_kill(cons_thread);
	rz_th_free(cons_thread);

	rz_list_sort(scores, (RzListComparator)basefind_score_compare);

rz_basefind_end:
	if (pool) {
		for (ut32 i = 0; i < pool_size; ++i) {
			RzThread *th = rz_th_pool_get_thread(pool, i);
			if (!th) {
				continue;
			}
			free(rz_th_get_user(th));
		}
		rz_th_pool_free(pool);
	}
	rz_th_lock_free(lock);
	basefind_array_free(array);
	ht_uu_free(pointers);
	return scores;
}
