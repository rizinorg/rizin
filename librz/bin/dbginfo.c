// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin.h>

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

static int line_sample_cmp(const void *a, const void *b) {
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
		rz_pvector_sort(&sorter, line_sample_cmp);

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
 * \brief Find the first sample that affects the given address.
 * i.e. find the first sample with the highest address less or equal to addr.
 * There may be more which can be retrieved by repeatedly calling rz_bin_source_line_info_get_next() until it returns NULL.
 */
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_first_at(const RzBinSourceLineInfo *sli, ut64 addr) {
	if (!sli->samples_count) {
		return NULL;
	}
	// binary search
	size_t l = 0;
	size_t h = sli->samples_count;
	while (l < h - 1) {
		size_t m = l + ((h - l) >> 1);
		if (addr < sli->samples[m].address) {
			h = m;
		} else {
			l = m;
		}
	}
	if (l >= sli->samples_count) {
		return NULL;
	}
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

RZ_API bool rz_bin_addr2line(RzBin *bin, ut64 addr, char *file, int len, int *line) {
	rz_return_val_if_fail(bin, false);
	if (!bin->cur || !bin->cur->o || !bin->cur->o->lines) {
		return NULL;
	}
	const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(bin->cur->o->lines, addr);
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
	return false;
}

RZ_API char *rz_bin_addr2text(RzBin *bin, ut64 addr, int origin) {
	rz_return_val_if_fail(bin, NULL);
	if (!bin->cur || !bin->cur->o || !bin->cur->o->lines) {
		return NULL;
	}
	const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(bin->cur->o->lines, addr);
	if (s && s->address != addr) {
		// consider only exact matches, not inside of samples
		return NULL;
	}
	while (s && !s->file) {
		s = rz_bin_source_line_info_get_next(bin->cur->o->lines, s);
	}
	if (!s) {
		return NULL;
	}
	const char *file_nopath;
	if (origin > 1) {
		file_nopath = s->file;
	} else {
		file_nopath = strrchr(s->file, '/');
		if (file_nopath) {
			file_nopath++;
		} else {
			file_nopath = s->file;
		}
	}
	if (!s->line) {
		return strdup(file_nopath);
	}
	char *out = rz_file_slurp_line(s->file, s->line, 0);
	if (out) {
		rz_str_trim(out);
		if (origin) {
			char *res = rz_str_newf("%s:%d %s",
				file_nopath, s->line,
				out ? out : "");
			free(out);
			out = res;
		}
		return out;
	}
	return rz_str_newf("%s:%" PFMT32u, file_nopath, s->line);
}
