// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_RZ_BIN_SOURCE_LINE_H
#define RIZIN_RZ_BIN_SOURCE_LINE_H

#include <rz_vector.h>
#include <rz_util.h>

typedef struct rz_bin_source_line_info_t RzBinSourceLineInfo;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief A single sample of source line info for a specific address
 *
 * If at least one of the line, column and file members is not 0/NULL, such a sample specifies the line info
 * for all addresses greater or equal to address until the next address that has another sample.
 *
 * If all the members line, column and file are 0/NULL, then this is a closing sample, indicating that the
 * previous entry stops here. The address is the first address **not contained** by the previous record.
 * Such a case corresponds for example to what DW_LNE_end_sequence emits in Dwarf.
 * Use rz_bin_source_line_sample_is_closing() for checking if a sample is closing.
 */
typedef struct rz_bin_source_line_sample_t {
	/**
	 * The first address that is covered by the given line and column,
	 * or, if all other members are 0/NULL, this is the first.
	 */
	ut64 address;

	/**
	 * If > 0, then indicates the line for the given address and the following.
	 * If == 0, then indicates that no line information is known.
	 *
	 * 32bit for this value is an intentional decision to lower memory consumption.
	 */
	ut32 line;

	/**
	 * If > 0, then indicates the column.
	 * If == 0, then no column information is known.
	 *
	 * 32bit for this value is an intentional decision to lower memory consumption.
	 */
	ut32 column;

	/**
	 * Filename, which must come out of the const pool of the owning
	 * RzBinSourceLineInfo or RzBinSourceLineInfoBuilder.
	 */
	const char *file;
} RzBinSourceLineSample;

/*
 * see documentation of RzBinSourceLineSample about what closing exactly means.
 */
static inline bool rz_bin_source_line_sample_is_closing(const RzBinSourceLineSample *s) {
	return !s->line && !s->column && !s->file;
}

struct rz_bin_source_line_info_t {
	/**
	 * \brief All source line references for given adresses
	 *
	 * These elements must be sorted by address and addresses must be unique, so binary search can be applied.
	 * Source file information is not contained within this array because source file changes
	 * are generally much sparser than line changes.
	 */
	RzBinSourceLineSample *samples;
	size_t samples_count;
	RzStrConstPool filename_pool;
}; // RzBinSourceLineInfo

/**
 * Temporary data structure for building an RzBinSourceLineInfo.
 */
typedef struct rz_bin_source_line_info_builder_t {
	RzVector /*<RzBinSourceLineSample>*/ samples; //< may be unsorted and will be sorted in the finalization step
	RzStrConstPool filename_pool;
} RzBinSourceLineInfoBuilder;

typedef struct {
	char *file_content;
	ut64 file_size;
	RzPVector /*<const char *>*/ *line_by_ln;
} RzBinSourceLineCacheItem;

typedef struct {
	HtSP /*<const char*, RzBinSourceLineCacheItem *>*/ *items;
} RzBinSourceLineCache;

typedef struct {
	RzBinSourceLineCache cache;
	bool enable : 1;
	bool file : 1;
	bool abspath : 1;
	bool lines : 1;
} RzDebugInfoOption;

RZ_API void rz_bin_source_line_info_builder_init(RzBinSourceLineInfoBuilder *builder);
RZ_API void rz_bin_source_line_info_builder_fini(RzBinSourceLineInfoBuilder *builder);
RZ_API void rz_bin_source_line_info_builder_push_sample(RzBinSourceLineInfoBuilder *builder, ut64 address, ut32 line, ut32 column, const char *file);
RZ_API RzBinSourceLineInfo *rz_bin_source_line_info_builder_build_and_fini(RzBinSourceLineInfoBuilder *builder);

RZ_API bool rz_bin_source_line_info_merge(RZ_BORROW RZ_NONNULL RzBinSourceLineInfo *dst, RZ_BORROW RZ_NONNULL RzBinSourceLineInfo *src);
RZ_API void rz_bin_source_line_info_free(RzBinSourceLineInfo *sli);
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_first_at(const RzBinSourceLineInfo *sli, ut64 addr);
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_next(const RzBinSourceLineInfo *sli, RZ_NONNULL const RzBinSourceLineSample *cur);

RZ_API bool rz_bin_source_line_addr2line(
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinSourceLineInfo *sl,
	ut64 addr,
	RZ_BORROW RZ_OUT RZ_NULLABLE char *file,
	int len,
	RZ_BORROW RZ_OUT RZ_NULLABLE int *line);
RZ_API RZ_OWN char *rz_bin_source_line_addr2text(
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinSourceLineInfo *sl, ut64 addr, RzDebugInfoOption opt);

#ifdef __cplusplus
}
#endif
#endif // RIZIN_RZ_BIN_SOURCE_LINE_H
