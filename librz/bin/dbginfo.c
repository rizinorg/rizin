// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin_source_line.h>
#include <ctype.h>

RZ_API void rz_bin_source_line_info_builder_init(RzBinSourceLineInfoBuilder *builder) {
	rz_vector_init(&builder->samples, sizeof(RzBinSourceLineSample), NULL, NULL);
	rz_str_constpool_init(&builder->filename_pool);
}

RZ_API void rz_bin_source_line_info_builder_fini(RzBinSourceLineInfoBuilder *builder) {
	rz_vector_fini(&builder->samples);
	rz_str_constpool_fini(&builder->filename_pool);
}

/**
 * \brief Push a new sample into the builder
 *
 * This function is used to continuously fill the builder with concrete samples of line info for a specific address,
 * usually during parsing of debug info from a file.
 * The samples may be pushed in any order and the builder will later take care of generating a valid RzBinSourceLineInfo from it.
 *
 * \param line may be 0 or a positive line number, where 0 means that this entry closes the one before it. see also RzBinSourceLine.
 */
RZ_API void rz_bin_source_line_info_builder_push_sample(RzBinSourceLineInfoBuilder *builder, ut64 address, ut32 line, ut32 column, const char *file) {
	RzBinSourceLineSample *sample = rz_vector_push(&builder->samples, NULL);
	if (!sample) {
		return;
	}
	sample->address = address;
	sample->line = line;
	sample->column = column;
	sample->file = file ? rz_str_constpool_get(&builder->filename_pool, file) : NULL;
}

static int line_sample_cmp(const void *a, const void *b, void *user) {
	const RzBinSourceLineSample *sa = a;
	const RzBinSourceLineSample *sb = b;
	// first, sort by addr
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	// closing samples are always equal (rest of their fields are ignored anyway)
	if (rz_bin_source_line_sample_is_closing(sa) && rz_bin_source_line_sample_is_closing(sb)) {
		return 0;
	}
	// push closing samples to the back, which is necessary to skip them during packing
	if (rz_bin_source_line_sample_is_closing(sa)) {
		return 1;
	}
	if (rz_bin_source_line_sample_is_closing(sb)) {
		return -1;
	}
	// then sort by line
	if (sa->line < sb->line) {
		return -1;
	}
	if (sa->line > sb->line) {
		return 1;
	}
	// then by column
	if (sa->column < sb->column) {
		return -1;
	}
	if (sa->column > sb->column) {
		return 1;
	}
	// and eventually by file because this is the most exponsive operation
	if (!sa->file && !sb->file) {
		return 0;
	}
	if (!sa->file) {
		return -1;
	}
	if (!sb->file) {
		return 1;
	}
	return strcmp(sa->file, sb->file);
}

RZ_API RzBinSourceLineInfo *rz_bin_source_line_info_builder_build_and_fini(RzBinSourceLineInfoBuilder *builder) {
	RzBinSourceLineInfo *r = RZ_NEW0(RzBinSourceLineInfo);
	if (!r) {
		goto err;
	}
	size_t initial_samples_count = rz_vector_len(&builder->samples); // final count may be less after removing unnecessary closing samples
	if (initial_samples_count) {
		r->samples = RZ_NEWS0(RzBinSourceLineSample, initial_samples_count);
		if (!r->samples) {
			goto err_r;
		}

		// samples should be built in flat RzVector to avoid excessive small mallocs,
		// for sorting we use a pvector with references into our flat vectors (after flushing them).

		RzPVector sorter;
		rz_pvector_init(&sorter, NULL);
		RzBinSourceLineSample *initial_samples = rz_vector_flush(&builder->samples);
		rz_pvector_reserve(&sorter, initial_samples_count);
		for (size_t i = 0; i < initial_samples_count; i++) {
			rz_pvector_push(&sorter, &initial_samples[i]);
		}
		rz_pvector_sort(&sorter, line_sample_cmp, NULL);

		r->samples_count = 0;
		for (size_t i = 0; i < initial_samples_count; i++) {
			RzBinSourceLineSample *new_sample = rz_pvector_at(&sorter, i);
			if (r->samples_count) {
				RzBinSourceLineSample *prev = &r->samples[r->samples_count - 1];
				if (prev->address == new_sample->address && rz_bin_source_line_sample_is_closing(new_sample)) {
					// closing sample but there are others that are not closing so this is dropped
					continue;
				}
			}
			r->samples[r->samples_count++] = *new_sample;
		}
		free(initial_samples); // all inner strings are moved already
		rz_pvector_fini(&sorter);
	}
	r->filename_pool = builder->filename_pool;
	// don't call regular fini on the builder because we moved its string pool!
	rz_vector_fini(&builder->samples);
	return r;
err_r:
	free(r);
err:
	rz_bin_source_line_info_builder_fini(builder);
	return NULL;
}

RZ_API void rz_bin_source_line_info_free(RzBinSourceLineInfo *sli) {
	if (!sli) {
		return;
	}
	free(sli->samples);
	rz_str_constpool_fini(&sli->filename_pool);
	free(sli);
}

/**
 * \brief Merge two RzBinSourceLineInfo, save to \p dst
 * \param dst the RzBinSourceLineInfo destination
 * \param src the RzBinSourceLineInfo source
 * \return true if success else false
 */
RZ_API bool rz_bin_source_line_info_merge(RZ_BORROW RZ_NONNULL RzBinSourceLineInfo *dst, RZ_BORROW RZ_NONNULL RzBinSourceLineInfo *src) {
	rz_return_val_if_fail(dst && src, false);
	size_t new_samples_count = dst->samples_count + src->samples_count;
	if (!new_samples_count) {
		return true;
	}
	RzBinSourceLineSample *tmp = realloc(dst->samples, sizeof(RzBinSourceLineSample) * new_samples_count);
	if (!tmp) {
		return false;
	}
	dst->samples = tmp;
	for (int i = 0; i < src->samples_count; ++i) {
		RzBinSourceLineSample *sample_src = src->samples + i;
		RzBinSourceLineSample *sample_dst = dst->samples + dst->samples_count + i;
		if (!rz_mem_copy(sample_dst, sizeof(RzBinSourceLineSample), sample_src, sizeof(RzBinSourceLineSample))) {
			return false;
		}
		sample_dst->file = sample_src->file ? rz_str_constpool_get(&dst->filename_pool, sample_src->file) : NULL;
	}
	dst->samples_count += src->samples_count;
	return true;
}

/**
 * \brief Find the first sample that affects the given address.
 * i.e. find the first sample with the highest address less or equal to addr.
 * There may be more which can be retrieved by repeatedly calling rz_bin_source_line_info_get_next() until it returns NULL.
 */
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_first_at(const RzBinSourceLineInfo *sli, ut64 addr) {
	if (!sli->samples_count) {
		return NULL;
	}
	size_t l;
#define CMP(x, y) (x > y.address ? 1 : (x < y.address ? -1 : 0))
	rz_array_upper_bound(sli->samples, sli->samples_count, addr, l, CMP);
#undef CMP
	if (!l) {
		return NULL;
	}
	l--;
	RzBinSourceLineSample *r = &sli->samples[l];
	if (r->address > addr || rz_bin_source_line_sample_is_closing(r)) {
		return NULL;
	}
	// walk back to the very first entry with this addr
	while (r > sli->samples) {
		if ((r - 1)->address == r->address) {
			r--;
		} else {
			break;
		}
	}
	return r;
}

/**
 * \param cur MUST be a pointer returned by either rz_bin_source_line_info_get_first_at() or rz_bin_source_line_info_get_next().
 * \return The next sample at the same address as cur or NULL if there is none.
 */
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_next(const RzBinSourceLineInfo *sli, RZ_NONNULL const RzBinSourceLineSample *cur) {
	rz_return_val_if_fail(sli && cur && cur >= sli->samples && cur < sli->samples + sli->samples_count, NULL);
	if (cur == sli->samples + sli->samples_count - 1) {
		return NULL;
	}
	const RzBinSourceLineSample *next = cur + 1;
	if (next->address != cur->address) {
		return NULL;
	}
	return next;
}

RZ_API bool rz_bin_source_line_addr2line(
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinSourceLineInfo *sl,
	ut64 addr,
	RZ_BORROW RZ_OUT RZ_NULLABLE char *file,
	int len,
	RZ_BORROW RZ_OUT RZ_NULLABLE int *line) {
	rz_return_val_if_fail(sl, false);
	const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(sl, addr);
	if (!s || s->address != addr) {
		// consider only exact matches, not inside of samples
		return false;
	}
	if (line) {
		*line = s->line;
	}
	if (file && len) {
		if (s->file) {
			rz_str_ncpy(file, s->file, len);
		} else {
			*file = 0;
		}
	}
	return true;
}

static char *str_trim_left_right(char *l, char *r) {
	l = (char *)rz_str_trim_head_ro(l);
	for (; r > l && isspace(*r); --r) {
		*r = '\0';
	}
	return l;
}

static void cache_lines(RzBinSourceLineCacheItem *x) {
	if (!x->file_content) {
		return;
	}

	char *p = x->file_content;
	char *q = NULL;
	do {
		q = strchr(p, '\n');
		if (!q) {
			break;
		}
		*q = '\0';
		p = str_trim_left_right(p, q);
		rz_pvector_push(x->line_by_ln, p);
		p = q + 1;
	} while ((p && p - x->file_content < x->file_size));
}

static const char *read_line(const char *file, int line, RzBinSourceLineCache *cache) {
	rz_return_val_if_fail(file && line >= 1, NULL);
	if (!(cache && cache->items)) {
		return rz_file_slurp_line(file, line, 0);
	}
	bool found = false;
	char *content = NULL;
	size_t sz = 0;
	RzBinSourceLineCacheItem *item = ht_sp_find(cache->items, file, &found);
	if (found) {
		if (!(item && item->file_content)) {
			return NULL;
		} else {
			return rz_pvector_at(item->line_by_ln, line - 1);
		}
	} else {
		content = rz_file_slurp(file, &sz);
		if (!content) {
			ht_sp_insert(cache->items, file, NULL);
			return NULL;
		}
		item = RZ_NEW0(RzBinSourceLineCacheItem);
		if (!item) {
			goto err;
		}
		item->file_content = content;
		item->file_size = sz;
		item->line_by_ln = rz_pvector_new(NULL);
		if (!item->line_by_ln) {
			goto err;
		}
		ht_sp_update(cache->items, file, item);

		rz_pvector_reserve(item->line_by_ln, line);
		cache_lines(item);
		return rz_pvector_at(item->line_by_ln, line - 1);
	}
err:
	if (item) {
		rz_pvector_free(item->line_by_ln);
	}
	free(content);
	free(item);
	return NULL;
}

RZ_API RZ_OWN char *rz_bin_source_line_addr2text(
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinSourceLineInfo *sl, ut64 addr, RzDebugInfoOption opt) {
	rz_return_val_if_fail(sl, NULL);
	const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(sl, addr);
	if (!(s && s->address == addr)) {
		// consider only exact matches, not inside of samples
		return NULL;
	}
	while (s && !s->file) {
		s = rz_bin_source_line_info_get_next(sl, s);
	}
	if (!s) {
		return NULL;
	}
	const char *filepath = opt.abspath ? s->file : rz_file_basename(s->file);
	if (!s->line) {
		return strdup(filepath);
	}

	RzStrBuf sb = { 0 };
	rz_strbuf_initf(&sb, "%s:%" PFMT32u, filepath, s->line);
	if (!opt.file) {
		return rz_strbuf_drain_nofree(&sb);
	}

	const char *out = read_line(s->file, s->line, &opt.cache);
	if (!out) {
		return rz_strbuf_drain_nofree(&sb);
	}

	rz_strbuf_appendf(&sb, " %s", out);
	return rz_strbuf_drain_nofree(&sb);
}
