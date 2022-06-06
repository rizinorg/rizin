// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_str_search.h>

#define UTIL_STR_SCAN_OPT_BUFFER_SIZE 2048

typedef struct search_interval_t {
	ut64 paddr;
	ut64 psize;
} SearchInterval;

typedef struct search_thread_data_t {
	RzThreadLock *lock;
	RzThreadQueue *intervals;
	RzBinFile *bf;
	HtUP *strings_db;
	RzList *results;
	size_t min_length;
	RzStrEnc encoding;
} SearchThreadData;

static bool is_data_section(RzBinFile *a, RzBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	} else if (!s->name) {
		return false;
	}
	// Rust
	return strstr(s->name, "_const") != NULL;
}

static RzBinString *to_bin_string(RzDetectedString *src) {
	RzBinString *dst = RZ_NEW0(RzBinString);
	if (!dst) {
		rz_detected_string_free(src);
		RZ_LOG_ERROR("bin_file_strings: cannot allocate RzBinString.\n");
		return NULL;
	}

	dst->string = src->string;
	dst->size = src->size;
	dst->length = src->length;
	dst->type = src->type;
	dst->paddr = src->addr;
	dst->vaddr = src->addr;

	// variables has been transfered to RzBinString
	free(src);
	return dst;
}

static RzList *string_scan_range(SearchThreadData *std, const ut64 paddr, const ut64 size) {
	RzList *found = rz_list_newf((RzListFree)free);
	if (!found) {
		return NULL;
	}

	RzUtilStrScanOptions scan_opt = {
		.buf_size = UTIL_STR_SCAN_OPT_BUFFER_SIZE,
		.max_uni_blocks = 4,
		.min_str_length = std->min_length,
		.prefer_big_endian = false,
		.check_ascii_freq = std->bf->rbin->strseach_check_ascii_freq,
	};

	ut8 *buf = calloc(size, 1);
	if (!buf) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate string seac buffer.\n");
		return NULL;
	}

	// beg critical section
	rz_th_lock_enter(std->lock);
	rz_buf_read_at(std->bf->buf, paddr, buf, size);
	rz_th_lock_leave(std->lock);
	// end critical section

	ut64 end = paddr + size;
	int count = rz_scan_strings_raw(buf, found, &scan_opt, paddr, end, std->encoding);
	free(buf);

	if (count <= 0) {
		RZ_FREE_CUSTOM(found, rz_list_free);
	}
	return found;
}

static void *search_string_thread_runner(SearchThreadData *std) {
	SearchInterval *itv = NULL;
	RzDetectedString *detected = NULL;
	ut64 paddr = 0, psize = 0;
	bool loop = true;
	RzBinFile *bf = std->bf;

	do {
		itv = rz_th_queue_pop(std->intervals, false);
		if (!itv) {
			break;
		}
		paddr = itv->paddr;
		psize = itv->psize;
		free(itv);
		RZ_LOG_DEBUG("[%p] searching between [0x%08" PFMT64x " : 0x%08" PFMT64x "]\n", std, paddr, paddr + psize);

		RzList *list = string_scan_range(std, paddr, psize);
		while (list) {
			detected = rz_list_pop_head(list);
			if (!detected) {
				break;
			}

			RzBinString *bstr = to_bin_string(detected);
			if (!bstr || !rz_list_append(std->results, bstr)) {
				rz_bin_string_free(bstr);
				loop = false;
				break;
			} else if (!bf->o) {
				continue;
			}

			// find virt address.
			bstr->paddr += bf->o->boffset;
			bstr->vaddr = rz_bin_object_p2v(bf->o, bstr->paddr);

			// beg critical section
			rz_th_lock_enter(std->lock);
			ht_up_insert(std->strings_db, bstr->vaddr, bstr);
			rz_th_lock_leave(std->lock);
			// end critical section
		}

		rz_list_free(list);
	} while (loop);

	RZ_LOG_DEBUG("[%p] died\n", std);
	return NULL;
}

static void bin_file_string_search_free(SearchThreadData *std) {
	if (!std) {
		return;
	}
	rz_list_free(std->results);
	free(std);
}

static bool create_string_search_thread(RzThreadPool *pool, RzThreadLock *lock, RzBinFile *bf, size_t min_length, RzThreadQueue *intervals, HtUP *strings_db) {
	RzStrEnc encoding = RZ_STRING_ENC_GUESS;
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);

	if (!min_length) {
		min_length = plugin && plugin->minstrlen > 0 ? plugin->minstrlen : 4;
	}

	if (bf->rbin) {
		encoding = rz_str_enc_string_as_type(bf->rbin->strenc);
	}

	SearchThreadData *std = RZ_NEW0(SearchThreadData);
	if (!std) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate SearchThreadData.\n");
		return false;
	}

	std->results = rz_list_newf(rz_bin_string_free);
	if (!std->results) {
		bin_file_string_search_free(std);
		return false;
	}
	std->strings_db = strings_db;
	std->bf = bf;
	std->min_length = min_length;
	std->lock = lock;
	std->intervals = intervals;
	std->encoding = encoding;

	RzThread *thread = rz_th_new((RzThreadFunction)search_string_thread_runner, std);
	if (!thread) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate RzThread\n");
		bin_file_string_search_free(std);
		return false;
	} else if (!rz_th_pool_add_thread(pool, thread)) {
		RZ_LOG_ERROR("bin_file_strings: cannot add thread to pool\n");
		bin_file_string_search_free(std);
		rz_th_free(thread);
		return false;
	}
	return true;
}

static int string_compare_sort(const RzBinString *a, const RzBinString *b) {
	if (b->paddr == a->paddr) {
		if (b->vaddr == a->vaddr) {
			return 0;
		} else if (b->vaddr > a->vaddr) {
			return -1;
		}
		return 1;
	} else if (b->paddr > a->paddr) {
		return -1;
	}
	return 1;
}

static void string_scan_range_cfstring(RzBinFile *bf, HtUP *strings_db, RzList *results, const RzBinSection *section) {
	// load objc/swift strings from cfstring table section

	RzBinObject *o = bf->o;
	const int bits = o->info ? o->info->bits : 32;
	const int cfstr_size = (bits == 64) ? 32 : 16;
	const int cfstr_offs = (bits == 64) ? 16 : 8;

	ut8 *sbuf = calloc(section->size, 1);
	if (!sbuf) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate RzBinString.\n");
		return;
	}

	rz_buf_read_at(bf->buf, section->paddr + cfstr_offs, sbuf, section->size);
	for (ut64 i = 0; i < section->size; i += cfstr_size) {
		ut8 *buf = sbuf;
		ut8 *p = buf + i;
		if ((i + ((bits == 64) ? 8 : 4)) >= section->size) {
			break;
		}

		ut64 cfstr_vaddr = section->vaddr + i;
		ut64 cstr_vaddr = (bits == 64) ? rz_read_le64(p) : rz_read_le32(p);
		if (!cstr_vaddr || cstr_vaddr == UT64_MAX) {
			continue;
		}

		RzBinString *s = ht_up_find(strings_db, cstr_vaddr, NULL);
		if (!s) {
			continue;
		}

		RzBinString *bs = RZ_NEW0(RzBinString);
		if (!bs) {
			RZ_LOG_ERROR("bin_file_strings: cannot allocate RzBinString\n");
			break;
		}

		bs->type = s->type;
		bs->length = s->length;
		bs->size = s->size;
		bs->ordinal = s->ordinal;
		bs->vaddr = cfstr_vaddr;
		bs->paddr = rz_bin_object_v2p(o, bs->vaddr);
		bs->string = rz_str_newf("cstr.%s", s->string);
		rz_list_append(results, bs);
		ht_up_insert(strings_db, bs->vaddr, bs);
	}
	free(sbuf);
}

static void scan_cfstring_table(RzBinFile *bf, HtUP *strings_db, RzList *results, ut64 max_interval) {
	RzListIter *iter = NULL;
	RzBinSection *section = NULL;
	RzBinObject *o = bf->o;
	if (!o) {
		return;
	}
	rz_list_foreach (o->sections, iter, section) {
		if (!section->name || section->paddr >= bf->size) {
			continue;
		} else if (max_interval && section->size > max_interval) {
			RZ_LOG_WARN("bin_file_strings: search interval size (0x%" PFMT64x ") exeeds bin.maxstrbuf (0x%" PFMT64x "), skipping it.\n", section->size, max_interval);
			continue;
		}

		if (strstr(section->name, "__cfstring")) {
			string_scan_range_cfstring(bf, strings_db, results, section);
		}
	}
}

/**
 * \brief  Generates a RzList struct containing RzBinString from a given RzBinFile
 *
 * \param  bf           The RzBinFile to use for searching for strings
 * \param  min_length   The string minimum length
 * \param  raw_strings  When set to false, it will search for strings only in the data section
 *
 * \return On success returns RzList pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList *rz_bin_file_strings(RZ_NONNULL RzBinFile *bf, size_t min_length, bool raw_strings) {
	rz_return_val_if_fail(bf, NULL);

	HtUP *strings_db = NULL;
	RzList *results = NULL;
	RzThreadQueue *intervals = NULL;
	RzThreadPool *pool = NULL;
	RzThreadLock *lock = NULL;
	ut64 max_interval = 0;
	size_t pool_size = 1;

	if (bf->rbin) {
		max_interval = bf->rbin->maxstrbuf;
	}

	pool = rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES);
	if (!pool) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate thread pool.\n");
		goto fail;
	}
	pool_size = rz_th_pool_size(pool);

	lock = rz_th_lock_new(false);
	if (!lock) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate thread lock.\n");
		goto fail;
	}

	intervals = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)free);
	if (!intervals) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate intervals queue.\n");
		goto fail;
	}

	strings_db = ht_up_new0();
	if (!strings_db) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate string map.\n");
		goto fail;
	}

	if (raw_strings) {
		// returns all the strings found on the RzBinFile
		ut64 section_size = bf->size / pool_size;
		if (section_size & (0x10000 - 1)) {
			section_size += 0x10000;
			section_size &= ~(0x10000 - 1);
		}
		if (!section_size) {
			section_size += 0x10000;
		}

		if (max_interval && section_size > max_interval) {
			RZ_LOG_WARN("bin_file_strings: search interval size (0x%" PFMT64x ") exeeds bin.maxstrbuf (0x%" PFMT64x "), skipping it.\n", section_size, max_interval);
			goto fail;
		}

		for (ut64 from = 0; from < bf->size; from += section_size) {
			SearchInterval *itv = RZ_NEW0(SearchInterval);
			if (!itv) {
				RZ_LOG_ERROR("bin_file_strings: cannot allocate SearchInterval.\n");
				goto fail;
			}

			itv->paddr = from;
			itv->psize = section_size;
			if ((itv->paddr + itv->psize) > bf->size) {
				itv->psize = bf->size - itv->paddr;
			}

			if (!rz_th_queue_push(intervals, itv, true)) {
				free(itv);
				RZ_LOG_ERROR("bin_file_strings: cannot append SearchInterval to list.\n");
				goto fail;
			}
		}
	} else if (bf->o && !rz_list_empty(bf->o->sections)) {
		// returns only the strings found on the RzBinFile but within the data section
		RzListIter *iter = NULL;
		RzBinSection *section = NULL;
		RzBinObject *o = bf->o;
		rz_list_foreach (o->sections, iter, section) {
			if (section->paddr >= bf->size) {
				continue;
			} else if (max_interval && section->size > max_interval) {
				RZ_LOG_WARN("bin_file_strings: search interval size (0x%" PFMT64x ") exeeds bin.maxstrbuf (0x%" PFMT64x "), skipping it.\n", section->size, max_interval);
				continue;
			}

			if (is_data_section(bf, section)) {
				SearchInterval *itv = RZ_NEW0(SearchInterval);
				if (!itv) {
					RZ_LOG_ERROR("bin_file_strings: cannot allocate SearchInterval.\n");
					goto fail;
				}

				itv->paddr = section->paddr;
				itv->psize = section->size;
				if ((itv->paddr + itv->psize) > bf->size) {
					itv->psize = bf->size - itv->paddr;
				}

				if (!rz_th_queue_push(intervals, itv, true)) {
					free(itv);
					RZ_LOG_ERROR("bin_file_strings: cannot append SearchInterval to list.\n");
					goto fail;
				}
			}
		}
	}

	RZ_LOG_VERBOSE("bin_file_strings: using %u threads\n", (ut32)pool_size);
	for (size_t i = 0; i < pool_size; ++i) {
		if (!create_string_search_thread(pool, lock, bf, min_length, intervals, strings_db)) {
			rz_th_pool_kill(pool);
			goto fail;
		}
	}

	rz_th_pool_wait(pool);

	results = rz_list_newf(rz_bin_string_free);
	if (!results) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate results list.\n");
		goto fail;
	}

	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_pool_get_thread(pool, i);
		if (!th) {
			continue;
		}
		SearchThreadData *std = (SearchThreadData *)rz_th_get_user(th);
		if (std) {
			rz_list_join(results, std->results);
		}
	}

	if (!raw_strings) {
		scan_cfstring_table(bf, strings_db, results, max_interval);
	}
	rz_list_sort(results, (RzListComparator)string_compare_sort);

	{
		RzListIter *it;
		RzBinString *bstr;
		ut32 ordinal = 0;
		rz_list_foreach (results, it, bstr) {
			bstr->ordinal = ordinal;
			ordinal++;
		}
	}

fail:
	if (pool) {
		for (ut32 i = 0; i < pool_size; ++i) {
			RzThread *th = rz_th_pool_get_thread(pool, i);
			if (!th) {
				continue;
			}
			SearchThreadData *std = (SearchThreadData *)rz_th_get_user(th);
			bin_file_string_search_free(std);
		}
		rz_th_pool_free(pool);
	}
	ht_up_free(strings_db);
	rz_th_lock_free(lock);
	rz_th_queue_free(intervals);
	return results;
}
