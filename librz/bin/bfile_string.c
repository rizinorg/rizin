// SPDX-FileCopyrightText: 2022-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_list.h>
#include <rz_search.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_vector.h>

typedef struct search_interval_t {
	ut64 paddr;
	ut64 psize;
} SearchInterval;

typedef struct shared_data_t {
	RzThreadLock *lock;
	RzBinFile *bf;
	HtUP *strings_db;
	RzStrEnc string_encoding;
	size_t max_uni_blocks;
	size_t buffer_size;
	size_t min_str_length;
	bool check_ascii_freq;
	bool prefer_big_endian;
} SharedData;

typedef struct search_thread_data_t {
	RzThreadQueue *intervals;
	RzPVector /*<RzBinString *>*/ *results;
	SharedData *shared;
	RzAtomicBool *loop;
} SearchThreadData;

static st64 shared_data_read_at(SharedData *sd, ut64 addr, ut8 *buf, ut64 size) {
	rz_th_lock_enter(sd->lock);
	st64 ret = rz_buf_read_at(sd->bf->buf, addr, buf, size);
	rz_th_lock_leave(sd->lock);
	return ret;
}

static bool shared_ht_up_insert(SharedData *sd, const ut64 key, void *value) {
	rz_th_lock_enter(sd->lock);
	bool ret = ht_up_insert(sd->strings_db, key, value);
	rz_th_lock_leave(sd->lock);
	return ret;
}

static bool is_data_section(RzBinFile *a, RzBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	} else if (!s->name) {
		return false;
	}
	// Rust binaries contains the _const section which is a data section.
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
	dst->type = src->encoding;
	dst->paddr = src->addr;
	dst->vaddr = src->addr;

	// variables has been transfered to RzBinString
	free(src->byte_mem_map);
	free(src);
	return dst;
}

static RzPVector /*<RzBinString *>*/ *string_wildcard_search(
	RzBinFile *bf,
	const RzList /*<RzInterval *>*/ *intervals,
	const RzBinStringSearchOpt *opt) {
	// If the string encoding doesn't need scanning,
	// we can create a wildcard pattern and search it.
	// This speeds up the string search a lot.
	RzSearchOpt *search_opts = rz_search_opt_new();
	if (!search_opts) {
		RZ_LOG_ERROR("bin_file_strings: search_opts NULL check failed!\n");
		return NULL;
	}
	size_t n_threads = opt->max_threads ? opt->max_threads : rz_th_max_threads(0);
	// We only search with one thread, because this function
	// was already dispatched into its own thread.
	rz_search_opt_set_max_threads(search_opts, n_threads);
	rz_search_opt_set_show_progress_from_str(search_opts, "no");
	if (opt->max_region_size) {
		rz_search_opt_set_chunk_size(search_opts, opt->max_region_size);
	}

	// The find options allow to configure string specific settings.
	RzSearchFindOpt *find_opts = rz_search_find_opt_new();
	if (!find_opts) {
		rz_search_opt_free(search_opts);
		RZ_LOG_ERROR("bin_file_strings: find_opts NULL check failed!\n");
		return NULL;
	}

	size_t match_alignment = rz_string_enc_code_point_width(opt->string_encoding);
	if (!match_alignment) {
		rz_warn_if_reached();
		match_alignment = 1;
	}

	rz_search_find_opt_set_alignment(find_opts, match_alignment);
	rz_search_find_opt_set_overlap_match(find_opts, false);
	if (!rz_search_opt_set_find_options(search_opts, find_opts)) {
		rz_search_opt_free(search_opts);
		RZ_LOG_ERROR("bin_file_strings: Setting find options failed!\n");
		return NULL;
	}
	rz_search_find_opt_set_alignment(find_opts, match_alignment);
	rz_search_find_opt_set_overlap_match(find_opts, false);

	RzSearchCollection *collection = rz_search_collection_strings(NULL, n_threads);
	if (!collection) {
		rz_search_opt_free(search_opts);
		RZ_LOG_ERROR("bin_file_strings: Collection NULL check failed!\n");
		return NULL;
	}

	char *wildcard = rz_regex_create_wildcard_pattern(opt->min_length, 0);
	if (!wildcard) {
		RZ_LOG_ERROR("bin_file_strings: Failed to create wildcard pattern!\n");
		rz_search_collection_free(collection);
		rz_search_opt_free(search_opts);
		return NULL;
	}
	if (!rz_search_collection_string_add(collection, wildcard, RZ_REGEX_EXTENDED, match_alignment, opt->string_encoding)) {
		RZ_LOG_ERROR("bin_file_strings: Failed to add wildcard pattern!\n");
		free(wildcard);
		rz_search_collection_free(collection);
		rz_search_opt_free(search_opts);
		return NULL;
	}
	free(wildcard);

	RzList *hits = rz_search_on_buffer(search_opts, collection, bf->buf, intervals);
	rz_search_collection_free(collection);
	rz_search_opt_free(search_opts);

	if (!hits) {
		RZ_LOG_ERROR("bin_file_strings: rz_search_on_buffer() failed!\n");
		return NULL;
	}
	RzPVector *bin_strings = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!bin_strings) {
		rz_list_free(hits);
		return NULL;
	}
	RzListIter *it;
	RzSearchHit *hit;
	rz_list_foreach (hits, it, hit) {
		RzBinString *bfs = RZ_NEW0(RzBinString);
		if (!bfs) {
			goto convert_error;
		}
		bfs->string = RZ_NEWS0(char, hit->size + 1);
		if (!bfs->string) {
			rz_bin_string_free(bfs);
			goto convert_error;
		}
		if (rz_buf_read_at(bf->buf, hit->address, (ut8 *)bfs->string, hit->size) == 0) {
			RZ_LOG_WARN("bin_file_strings: Failed read RzBinString data at paddr: 0x%" PFMT64x "\n", hit->address);
			rz_bin_string_free(bfs);
			continue;
		}
		ut8 *utf8_str = NULL;
		if (!(opt->string_encoding == RZ_STRING_ENC_8BIT || opt->string_encoding == RZ_STRING_ENC_UTF8)) {
			// Convert to UTF-8.
			switch (opt->string_encoding) {
			default:
				rz_warn_if_reached();
				break;
			case RZ_STRING_ENC_UTF16LE:
			case RZ_STRING_ENC_UTF16BE:
				utf8_str = rz_str_utf16_to_utf8((ut8 *)bfs->string, hit->size, opt->string_encoding == RZ_STRING_ENC_UTF16BE);
				break;
			case RZ_STRING_ENC_UTF32LE:
			case RZ_STRING_ENC_UTF32BE:
				utf8_str = rz_str_utf32_to_utf8((ut8 *)bfs->string, hit->size, opt->string_encoding == RZ_STRING_ENC_UTF32BE);
				break;
			}
		}
		if (utf8_str) {
			free(bfs->string);
			bfs->string = (char *)utf8_str;
		}
		ut64 length;
		rz_search_hit_detail_get_unsigned(hit->detail, &length);
		bfs->length = length;
		bfs->size = hit->size;
		bfs->paddr = hit->address;
		if (bf->o) {
			// only available when rzbin is used.
			bfs->paddr += bf->o->boffset;
			bfs->vaddr = rz_bin_object_p2v(bf->o, bfs->paddr);
		}
		bfs->type = opt->string_encoding;
		rz_pvector_push(bin_strings, bfs);
	}
	rz_list_free(hits);
	return bin_strings;

convert_error:
	rz_pvector_free(bin_strings);
	rz_list_free(hits);
	RZ_LOG_ERROR("bin_file_strings: Critical convert error.\n");
	return NULL;
}

static RzList /*<RzDetectedString *>*/ *string_scan_range(SharedData *shared, const ut64 paddr, const ut64 interval_size) {
	RzList *found = rz_list_newf((RzListFree)free);
	if (!found) {
		return NULL;
	}

	// ensure the scan buffer size is less or equal to the the actual interval size.
	size_t buffer_size = RZ_MIN(shared->buffer_size, interval_size);

	RzUtilStrScanOptions scan_opt = {
		.max_str_length = buffer_size,
		.min_str_length = shared->min_str_length,
		.prefer_big_endian = shared->prefer_big_endian,
		.check_ascii_freq = shared->check_ascii_freq,
	};

	ut8 *buf = calloc(interval_size, 1);
	if (!buf) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate string seac buffer.\n");
		rz_list_free(found);
		return NULL;
	}

	shared_data_read_at(shared, paddr, buf, interval_size);

	ut64 end = paddr + interval_size;
	int count = rz_scan_strings_raw(buf, found, &scan_opt, paddr, end, shared->string_encoding);
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
	SharedData *shared = std->shared;
	const RzBinFile *bf = shared->bf; // this data is always RO

	do {
		void *data = NULL;
		if (!rz_th_queue_pop(std->intervals, false, &data) || !data) {
			break;
		}
		itv = (SearchInterval *)data;
		paddr = itv->paddr;
		psize = itv->psize;
		free(itv);
		RZ_LOG_DEBUG("[%p] searching between [0x%08" PFMT64x " : 0x%08" PFMT64x "]\n", std, paddr, paddr + psize);

		RzList *list = string_scan_range(shared, paddr, psize);
		while (list && rz_atomic_bool_get(std->loop)) {
			detected = rz_list_pop_head(list);
			if (!detected) {
				break;
			}

			RzBinString *bstr = to_bin_string(detected);
			if (!bstr || !rz_pvector_push(std->results, bstr)) {
				rz_bin_string_free(bstr);
				loop = false;
				break;
			} else if (!bf->o) {
				continue;
			}

			// find virt address.
			bstr->paddr += bf->o->boffset;
			bstr->vaddr = rz_bin_object_p2v(bf->o, bstr->paddr);

			shared_ht_up_insert(shared, bstr->vaddr, bstr);
		}

		rz_list_free(list);
	} while (loop && rz_atomic_bool_get(std->loop));

	RZ_LOG_DEBUG("[%p] died\n", std);
	return NULL;
}

static void bin_file_string_search_free(SearchThreadData *std) {
	if (!std) {
		return;
	}
	rz_pvector_free(std->results);
	rz_atomic_bool_free(std->loop);
	free(std);
}

static void interrupt_thread(RzThread *thread) {
	if (!thread) {
		return;
	}
	SearchThreadData *std = (SearchThreadData *)rz_th_get_user(thread);
	rz_atomic_bool_set(std->loop, false);
	rz_th_wait(thread);
}

static void interrupt_pool(RzThreadPool *pool) {
	size_t pool_size = rz_th_pool_size(pool);
	for (size_t i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_pool_get_thread(pool, i);
		interrupt_thread(th);
	}
}

static bool create_string_search_thread(RzThreadPool *pool, RzThreadQueue *intervals, SharedData *shared) {
	SearchThreadData *std = RZ_NEW0(SearchThreadData);
	if (!std) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate SearchThreadData.\n");
		return false;
	}

	std->results = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!std->results) {
		bin_file_string_search_free(std);
		return false;
	}
	std->shared = shared;
	std->intervals = intervals;
	std->loop = rz_atomic_bool_new(true);

	RzThread *thread = rz_th_new((RzThreadFunction)search_string_thread_runner, std);
	if (!thread) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate RzThread\n");
		bin_file_string_search_free(std);
		return false;
	} else if (!rz_th_pool_add_thread(pool, thread)) {
		RZ_LOG_ERROR("bin_file_strings: cannot add thread to pool\n");
		interrupt_thread(thread);
		bin_file_string_search_free(std);
		rz_th_free(thread);
		return false;
	}
	return true;
}

static void string_scan_range_cfstring(RzBinFile *bf, HtUP *strings_db, RzPVector /*<RzBinString *>*/ *results, const RzBinSection *section) {
	// load objc/swift strings from CFstring table section

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
		bs->vaddr = cfstr_vaddr;
		bs->paddr = rz_bin_object_v2p(o, bs->vaddr);
		bs->string = rz_str_newf("cstr.%s", s->string);
		rz_pvector_push(results, bs);
		ht_up_insert(strings_db, bs->vaddr, bs);
	}
	free(sbuf);
}

static int string_compare_sort(const RzBinString *a, const RzBinString *b, void *user) {
	if (b->paddr > a->paddr) {
		return -1;
	} else if (b->paddr < a->paddr) {
		return 1;
	} else if (b->vaddr > a->vaddr) {
		return -1;
	} else if (b->vaddr < a->vaddr) {
		return 1;
	}
	return 0;
}

static void scan_cfstring_table(RzBinFile *bf, HtUP *strings_db, RzPVector /*<RzBinString *>*/ *results, ut64 max_region_size) {
	void **iter = NULL;
	RzBinSection *section = NULL;
	RzBinObject *o = bf->o;
	if (!o) {
		return;
	}
	rz_pvector_foreach (o->sections, iter) {
		section = *iter;
		if (!section->name || section->paddr >= bf->size) {
			continue;
		} else if (max_region_size && section->size > max_region_size) {
			RZ_LOG_WARN("bin_file_strings: search interval size (0x%" PFMT64x
				    ") exceeds max region size (0x%" PFMT64x "), skipping it.\n",
				section->size, max_region_size);
			continue;
		}

		if (strstr(section->name, "__cfstring")) {
			string_scan_range_cfstring(bf, strings_db, results, section);
		}
	}
}

/**
 * \brief  Sets the RzBinStringSearchOpt struct to its default options.
 *
 * \param  opt   The RzBinStringSearchOpt struct to initialize.
 */
RZ_API void rz_bin_string_search_opt_init(RZ_NONNULL RzBinStringSearchOpt *opt) {
	rz_return_if_fail(opt);
	opt->max_threads = RZ_THREAD_N_CORES_ALL_AVAILABLE;
	opt->min_length = RZ_BIN_STRING_SEARCH_MIN_STRING;
	opt->max_length = RZ_BIN_STRING_SEARCH_BUFFER_SIZE;
	opt->max_region_size = RZ_BIN_STRING_SEARCH_MAX_REGION_SIZE;
	opt->raw_alignment = RZ_BIN_STRING_SEARCH_RAW_FILE_ALIGNMENT;
	opt->string_encoding = RZ_STRING_ENC_GUESS;
	opt->check_ascii_freq = RZ_BIN_STRING_SEARCH_CHECK_ASCII_FREQ;
	opt->mode = RZ_BIN_STRING_SEARCH_MODE_AUTO;
}

static RzList /*<RzInterval *>*/ *gen_intervals(RzBinFile *bf, const RzBinStringSearchOpt *opt, size_t pool_size, bool list_doesnt_own) {
	bool has_sections = bf->o && !rz_pvector_empty(bf->o->sections);
	const size_t raw_alignment = opt->raw_alignment;
	RzBinStringSearchMode mode = opt->mode;
	RzList *intervals = list_doesnt_own ? rz_list_new() : rz_list_newf((RzListFree)rz_itv_free);
	if (!intervals) {
		goto fail;
	}

	if (mode == RZ_BIN_STRING_SEARCH_MODE_AUTO && !has_sections) {
		mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;
	}

	if (mode == RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY) {
		// returns all the strings found on the RzBinFile
		ut64 section_size = bf->size / pool_size;
		if (section_size & (raw_alignment - 1)) {
			section_size += raw_alignment;
			section_size &= ~(raw_alignment - 1);
		}
		if (!section_size) {
			section_size += raw_alignment;
		}

		if (opt->max_region_size && section_size > opt->max_region_size) {
			RZ_LOG_ERROR("bin_file_strings: search interval size (0x%" PFMT64x
				     ") exceeds max region size (0x%" PFMTSZx ").\n",
				section_size, opt->max_region_size);
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
			if (!rz_list_push(intervals, itv)) {
				RZ_LOG_ERROR("bin_file_strings: failed to push SearchInterval.\n");
				goto fail;
			}
		}
	} else if (has_sections) {
		// returns only the strings found on the RzBinFile but within the data section
		void **iter = NULL;
		RzBinSection *section = NULL;
		RzBinObject *o = bf->o;
		rz_pvector_foreach (o->sections, iter) {
			section = *iter;
			if (section->paddr >= bf->size) {
				continue;
			} else if (opt->max_region_size && section->size > opt->max_region_size) {
				RZ_LOG_WARN("bin_file_strings: search interval size (0x%" PFMT64x
					    ") exceeds max region size (0x%" PFMTSZx "), skipping it.\n",
					section->size, opt->max_region_size);
				continue;
			}

			if (!is_data_section(bf, section)) {
				continue;
			}

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
			if (!rz_list_push(intervals, itv)) {
				RZ_LOG_ERROR("bin_file_strings: failed to push SearchInterval.\n");
				goto fail;
			}
		}
	} else {
		RZ_LOG_WARN("The binary loader searches strings only in the read only sections,"
			    "but the binary has no sections.\n Please search strings manually with /z.\n");
	}
	return intervals;

fail:
	rz_list_free(intervals);
	return NULL;
}

/**
 * \brief  Generates a RzList struct containing RzBinString from a given RzBinFile.
 * The search is performed multi-threaded.
 *
 * \param  bf   The RzBinFile to use for searching for strings
 * \param  opt  The options regarding the string search.
 *
 * \return On success returns RzList pointer, otherwise NULL
 */
RZ_API RZ_OWN RzPVector /*<RzBinString *>*/ *rz_bin_file_strings(RZ_NONNULL RzBinFile *bf, RZ_NONNULL const RzBinStringSearchOpt *opt) {
	rz_return_val_if_fail(bf && opt, NULL);

	HtUP *strings_db = NULL;
	RzPVector *results = NULL;
	RzThreadQueue *intervals = NULL;
	RzThreadPool *pool = NULL;
	RzThreadLock *lock = NULL;
	size_t pool_size = 1;
	bool prefer_big_endian = false;
	RzList *itv_list = NULL;

	pool = rz_th_pool_new(opt->max_threads);
	if (!pool) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate thread pool.\n");
		goto fail;
	}
	pool_size = rz_th_pool_size(pool);
	bool scan_for_strings = rz_search_str_enc_needs_scanning(opt->string_encoding);
	itv_list = gen_intervals(bf, opt, pool_size, scan_for_strings);

	if (!itv_list) {
		RZ_LOG_ERROR("bin_file_strings: Failed to generate interval list.\n");
		goto fail;
	}

	if (!scan_for_strings) {
		// If scanning is not needed for the string search we
		// can instead just default to our normal string search
		// with a wildcard pattern.
		// It is much faster than scanning.
		RzPVector *res = string_wildcard_search(bf, itv_list, opt);
		rz_th_pool_free(pool);
		rz_list_free(itv_list);
		return res;
	}

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

	strings_db = ht_up_new(NULL, NULL);
	if (!strings_db) {
		RZ_LOG_ERROR("bin_file_strings: cannot allocate string map.\n");
		goto fail;
	}

	RzListIter *it;
	RzInterval *itv;
	rz_list_foreach (itv_list, it, itv) {
		if (!rz_th_queue_push(intervals, itv, true)) {
			free(itv);
			RZ_LOG_ERROR("bin_file_strings: cannot append SearchInterval to list.\n");
			goto fail;
		}
	}
	rz_list_free(itv_list);
	itv_list = NULL;

	if (rz_th_queue_is_empty(intervals)) {
		// we just fail directly and return an empty vector, since there are no search intervals.
		goto fail;
	}

	if (bf->o) {
		const RzBinInfo *binfo = rz_bin_object_get_info(bf->o);
		prefer_big_endian = binfo ? binfo->big_endian : false;
	}

	SharedData shared = {
		.lock = lock,
		.bf = bf,
		.strings_db = strings_db,
		.buffer_size = opt->max_length,
		.string_encoding = opt->string_encoding,
		.min_str_length = opt->min_length,
		.check_ascii_freq = opt->check_ascii_freq,
		.prefer_big_endian = prefer_big_endian,
	};

	if (shared.min_str_length < 1) {
		// always ensure string min length is at least 1
		shared.min_str_length = RZ_BIN_STRING_SEARCH_MIN_STRING;
	}

	RZ_LOG_VERBOSE("bin_file_strings: using %u threads\n", (ut32)pool_size);
	for (size_t i = 0; i < pool_size; ++i) {
		if (!create_string_search_thread(pool, intervals, &shared)) {
			interrupt_pool(pool);
			goto fail;
		}
	}

	rz_th_queue_close_when_empty(intervals);
	rz_th_pool_wait(pool);

	results = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
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
			rz_pvector_join(results, std->results);
		}
	}

	if (opt->mode != RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY) {
		scan_cfstring_table(bf, strings_db, results, opt->max_region_size);
	}
	rz_pvector_sort(results, (RzPVectorComparator)string_compare_sort, NULL);

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
	rz_list_free(itv_list);
	ht_up_free(strings_db);
	rz_th_lock_free(lock);
	rz_th_queue_free(intervals);
	return results;
}
