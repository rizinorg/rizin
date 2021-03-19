// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin.h>

RZ_API void rz_bin_source_row_free(RzBinSourceRow *row) {
	if (!row) {
		return;
	}
	free(row->file);
	free(row);
}

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
	RzBinFile *binfile = rz_bin_cur(bin);
	RzBinObject *o = rz_bin_cur_object(bin);
	RzBinPlugin *cp = rz_bin_file_cur_plugin(binfile);
	ut64 baddr = rz_bin_get_baddr(bin);
	if (cp && cp->dbginfo) {
		if (o && addr >= baddr && addr < baddr + bin->cur->o->size) {
			if (cp->dbginfo->get_line) {
				return cp->dbginfo->get_line(
					bin->cur, addr, file, len, line);
			}
		}
	}
	return false;
}

RZ_API char *rz_bin_addr2text(RzBin *bin, ut64 addr, int origin) {
	rz_return_val_if_fail(bin, NULL);
	char file[4096];
	int line;
	char *out = NULL, *out2 = NULL;
	char *file_nopath = NULL;
	if (!bin->cur) {
		return NULL;
	}
	char *key = rz_str_newf("0x%" PFMT64x, addr);
	char *file_line = sdb_get(bin->cur->sdb_addrinfo, key, 0);
	if (file_line) {
		char *token = strchr(file_line, '|');
		if (token) {
			*token++ = 0;
			line = atoi(token);
			out = rz_file_slurp_line(file_line, line, 0);
			*token++ = ':';
		} else {
			return file_line;
		}
	}
	free(key);
	if (out) {
		if (origin > 1) {
			file_nopath = file_line;
		} else {
			file_nopath = strrchr(file_line, '/');
			if (file_nopath) {
				file_nopath++;
			} else {
				file_nopath = file_line;
			}
		}
		if (origin) {
			char *res = rz_str_newf("%s:%d%s%s",
				file_nopath ? file_nopath : "",
				line, file_nopath ? " " : "",
				out ? out : "");
			free(out);
			out = res;
		}
		free(file_line);
		return out;
	}
	RZ_FREE(file_line);

	file[0] = 0;
	if (rz_bin_addr2line(bin, addr, file, sizeof(file), &line)) {
		if (bin->srcdir && *bin->srcdir) {
			char *slash = strrchr(file, '/');
			char *nf = rz_str_newf("%s/%s", bin->srcdir, slash ? slash + 1 : file);
			strncpy(file, nf, sizeof(file) - 1);
			free(nf);
		}
		// TODO: this is slow. must use a cached pool of mapped files and line:off entries
		out = rz_file_slurp_line(file, line, 0);
		if (!out) {
			if (origin > 1) {
				file_nopath = file;
			} else {
				file_nopath = strrchr(file, '/');
				if (file_nopath) {
					file_nopath++;
				} else {
					file_nopath = file;
				}
			}
			return rz_str_newf("%s:%d", file_nopath ? file_nopath : "", line);
		}
		out2 = malloc((strlen(file) + 64 + strlen(out)) * sizeof(char));
		if (origin > 1) {
			file_nopath = NULL;
		} else {
			file_nopath = strrchr(file, '/');
		}
		if (origin) {
			snprintf(out2, strlen(file) + 63 + strlen(out), "%s:%d%s%s",
				file_nopath ? file_nopath + 1 : file, line, *out ? " " : "", out);
		} else {
			snprintf(out2, 64, "%s", out);
		}
		free(out);
	}
	return out2;
}

RZ_API char *rz_bin_addr2fileline(RzBin *bin, ut64 addr) {
	rz_return_val_if_fail(bin, NULL);
	char file[1024];
	int line = 0;

	if (rz_bin_addr2line(bin, addr, file, sizeof(file) - 1, &line)) {
		char *file_nopath = strrchr(file, '/');
		return rz_str_newf("%s:%d", file_nopath ? file_nopath + 1 : file, line);
	}
	return NULL;
}
