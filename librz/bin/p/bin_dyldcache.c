// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 keegan
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_io.h>
#include <ht_pu.h>
// #include "../format/mach0/mach0_defines.h"
#define RZ_BIN_MACH064 1
#include "../format/mach0/mach0.h"
#include "objc/mach0_classes.h"

#define RZ_IS_PTR_AUTHENTICATED(x) B_IS_SET(x, 63)

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
} RDyldRebaseInfo;

typedef struct {
	ut64 start;
	ut64 end;
	RDyldRebaseInfo *info;
} RDyldRebaseInfosEntry;

typedef struct {
	RDyldRebaseInfosEntry *entries;
	size_t length;
} RDyldRebaseInfos;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut64 delta_mask;
	ut32 delta_shift;
	ut64 auth_value_add;
} RDyldRebaseInfo3;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut16 *page_extras;
	ut32 page_extras_count;
	ut64 delta_mask;
	ut64 value_mask;
	ut32 delta_shift;
	ut64 value_add;
} RDyldRebaseInfo2;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *toc;
	ut32 toc_count;
	ut8 *entries;
	ut32 entries_size;
} RDyldRebaseInfo1;

typedef struct {
	char *strings;
	ut64 strings_size;
	struct MACH0_(nlist) * nlists;
	ut64 nlists_count;
	cache_locsym_entry_t *entries;
	ut64 entries_count;
} RDyldLocSym;

typedef struct _r_dyldcache {
	ut8 magic[8];
	RzList *bins;
	RzBuffer *buf;
	int (*original_io_read)(RzIO *io, RzIODesc *fd, ut8 *buf, int count);
	RDyldRebaseInfos *rebase_infos;
	cache_hdr_t *hdr;
	cache_map_t *maps;
	cache_accel_t *accel;
	RDyldLocSym *locsym;
} RDyldCache;

typedef struct _r_bin_image {
	char *file;
	ut64 header_at;
} RDyldBinImage;

static RzList *pending_bin_files = NULL;

static ut64 va2pa(uint64_t addr, cache_hdr_t *hdr, cache_map_t *maps, RzBuffer *cache_buf, ut64 slide, ut32 *offset, ut32 *left);

static void free_bin(RDyldBinImage *bin) {
	if (!bin) {
		return;
	}

	RZ_FREE(bin->file);
	RZ_FREE(bin);
}

static void rebase_info3_free(RDyldRebaseInfo3 *rebase_info) {
	if (!rebase_info) {
		return;
	}

	RZ_FREE(rebase_info->page_starts);
	RZ_FREE(rebase_info);
}

static void rebase_info2_free(RDyldRebaseInfo2 *rebase_info) {
	if (!rebase_info) {
		return;
	}

	RZ_FREE(rebase_info->page_starts);
	RZ_FREE(rebase_info->page_extras);
	RZ_FREE(rebase_info);
}

static void rebase_info1_free(RDyldRebaseInfo1 *rebase_info) {
	if (!rebase_info) {
		return;
	}

	RZ_FREE(rebase_info->toc);
	RZ_FREE(rebase_info->entries);
	RZ_FREE(rebase_info);
}

static void rebase_info_free(RDyldRebaseInfo *rebase_info) {
	if (!rebase_info) {
		return;
	}

	RZ_FREE(rebase_info->one_page_buf);

	ut8 version = rebase_info->version;

	if (version == 1) {
		rebase_info1_free((RDyldRebaseInfo1 *)rebase_info);
	} else if (version == 2 || version == 4) {
		rebase_info2_free((RDyldRebaseInfo2 *)rebase_info);
	} else if (version == 3) {
		rebase_info3_free((RDyldRebaseInfo3 *)rebase_info);
	} else {
		RZ_FREE(rebase_info);
	}
}

static RDyldLocSym *rz_dyld_locsym_new(RzBuffer *cache_buf, cache_hdr_t *hdr) {
	if (!cache_buf || !hdr || !hdr->localSymbolsSize || !hdr->localSymbolsOffset) {
		return NULL;
	}

	cache_locsym_info_t *info = NULL;
	char *strings = NULL;
	cache_locsym_entry_t *entries = NULL;
	struct MACH0_(nlist) *nlists = NULL;

	ut64 info_size = sizeof(cache_locsym_info_t);
	info = RZ_NEW0(cache_locsym_info_t);
	if (!info) {
		goto beach;
	}
	if (rz_buf_fread_at(cache_buf, hdr->localSymbolsOffset, (ut8 *)info, "6i", 1) != info_size) {
		goto beach;
	}

	ut64 nlists_size = sizeof(struct MACH0_(nlist)) * info->nlistCount;
	nlists = RZ_NEWS0(struct MACH0_(nlist), info->nlistCount);
	if (!nlists) {
		goto beach;
	}
	if (rz_buf_fread_at(cache_buf, hdr->localSymbolsOffset + info->nlistOffset, (ut8 *)nlists, "iccsl",
		    info->nlistCount) != nlists_size) {
		goto beach;
	}

	strings = malloc(info->stringsSize);
	if (!strings) {
		goto beach;
	}
	if (rz_buf_read_at(cache_buf, hdr->localSymbolsOffset + info->stringsOffset, (ut8 *)strings,
		    info->stringsSize) != info->stringsSize) {
		goto beach;
	}

	ut64 entries_size = sizeof(cache_locsym_entry_t) * info->entriesCount;
	entries = RZ_NEWS0(cache_locsym_entry_t, info->entriesCount);
	if (!entries) {
		goto beach;
	}
	if (rz_buf_fread_at(cache_buf, hdr->localSymbolsOffset + info->entriesOffset, (ut8 *)entries, "3i",
		    info->entriesCount) != entries_size) {
		goto beach;
	}

	RDyldLocSym *locsym = RZ_NEW0(RDyldLocSym);
	if (!locsym) {
		goto beach;
	}

	locsym->nlists = nlists;
	locsym->nlists_count = info->nlistCount;
	locsym->strings = strings;
	locsym->strings_size = info->stringsSize;
	locsym->entries = entries;
	locsym->entries_count = info->entriesCount;

	free(info);

	return locsym;

beach:
	free(info);
	free(strings);
	free(entries);
	free(nlists);

	eprintf("dyldcache: malformed local symbols metadata\n");
	return NULL;
}

static void rz_dyld_locsym_free(RDyldLocSym *locsym) {
	if (!locsym) {
		return;
	}
	RZ_FREE(locsym->strings);
	RZ_FREE(locsym->entries);
	RZ_FREE(locsym->nlists);
	free(locsym);
}

static ut64 rebase_infos_get_slide(RDyldCache *cache) {
	if (!cache->rebase_infos || !cache->rebase_infos->length) {
		return 0;
	}

	size_t i;
	for (i = 0; i < cache->rebase_infos->length; i++) {
		if (cache->rebase_infos->entries[i].info) {
			return cache->rebase_infos->entries[i].info->slide;
		}
	}

	return 0;
}

static void rz_dyld_locsym_entries_by_offset(RDyldCache *cache, RzList *symbols, SetU *hash, ut64 bin_header_offset) {
	RDyldLocSym *locsym = cache->locsym;
	if (!locsym || !locsym->entries) {
		return;
	}

	ut64 i;
	for (i = 0; i != locsym->entries_count; i++) {
		cache_locsym_entry_t *entry = &locsym->entries[i];
		if (entry->dylibOffset != bin_header_offset) {
			continue;
		}

		if (entry->nlistStartIndex >= locsym->nlists_count ||
			entry->nlistStartIndex + entry->nlistCount > locsym->nlists_count) {
			eprintf("dyldcache: malformed local symbol entry\n");
			break;
		}

		ut32 j;
		for (j = 0; j != entry->nlistCount; j++) {
			struct MACH0_(nlist) *nlist = &locsym->nlists[j + entry->nlistStartIndex];
			if (set_u_contains(hash, (ut64)nlist->n_value)) {
				continue;
			}
			set_u_add(hash, (ut64)nlist->n_value);
			if (nlist->n_strx >= locsym->strings_size) {
				continue;
			}
			char *symstr = &locsym->strings[nlist->n_strx];
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			if (!sym) {
				return;
			}
			sym->type = "LOCAL";
			sym->vaddr = nlist->n_value;
			ut64 slide = rebase_infos_get_slide(cache);
			sym->paddr = va2pa(nlist->n_value, cache->hdr, cache->maps, cache->buf, slide, NULL, NULL);

			int len = locsym->strings_size - nlist->n_strx;
			ut32 k;
			for (k = 0; k < len; k++) {
				if (((ut8)symstr[k] & 0xff) == 0xff || !symstr[k]) {
					len = k;
					break;
				}
			}
			if (len > 0) {
				sym->name = rz_str_ndup(symstr, len);
			} else {
				sym->name = rz_str_newf("unk_local%d", k);
			}

			rz_list_append(symbols, sym);
		}
		break;
	}
}

static void rz_dyldcache_free(RDyldCache *cache) {
	if (!cache) {
		return;
	}

	rz_list_free(cache->bins);
	cache->bins = NULL;
	rz_buf_free(cache->buf);
	cache->buf = NULL;
	if (cache->rebase_infos) {
		int i;
		for (i = 0; i < cache->rebase_infos->length; i++) {
			rebase_info_free(cache->rebase_infos->entries[i].info);
			cache->rebase_infos->entries[i].info = NULL;
		}
		RZ_FREE(cache->rebase_infos->entries);
		RZ_FREE(cache->rebase_infos);
	}
	RZ_FREE(cache->hdr);
	RZ_FREE(cache->maps);
	RZ_FREE(cache->accel);
	rz_dyld_locsym_free(cache->locsym);
	RZ_FREE(cache);
}

static ut64 va2pa(uint64_t addr, cache_hdr_t *hdr, cache_map_t *maps, RzBuffer *cache_buf, ut64 slide, ut32 *offset, ut32 *left) {
	ut64 res = UT64_MAX;
	uint32_t i;

	addr -= slide;

	for (i = 0; i < hdr->mappingCount; i++) {
		if (addr >= maps[i].address && addr < maps[i].address + maps[i].size) {
			res = maps[i].fileOffset + addr - maps[i].address;
			if (offset) {
				*offset = addr - maps[i].address;
			}
			if (left) {
				*left = maps[i].size - (addr - maps[i].address);
			}
			break;
		}
	}

	return res;
}

static ut64 bin_obj_va2pa(ut64 p, ut32 *offset, ut32 *left, RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return 0;
	}

	RDyldCache *cache = (RDyldCache *)((struct MACH0_(obj_t) *)bf->o->bin_obj)->user;
	if (!cache) {
		return 0;
	}

	ut64 slide = rebase_infos_get_slide(cache);
	ut64 res = va2pa(p, cache->hdr, cache->maps, cache->buf, slide, offset, left);
	if (res == UT64_MAX) {
		res = 0;
	}
	return res;
}

static struct MACH0_(obj_t) * bin_to_mach0(RzBinFile *bf, RDyldBinImage *bin) {
	if (!bin || !bf) {
		return NULL;
	}

	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default)
	(&opts, bf);
	opts.header_at = bin->header_at;
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(cache->buf, &opts);
	mach0->user = cache;
	mach0->va2pa = &bin_obj_va2pa;
	return mach0;
}

static int prot2perm(int x) {
	int r = 0;
	if (x & 1) {
		r |= 4;
	}
	if (x & 2) {
		r |= 2;
	}
	if (x & 4) {
		r |= 1;
	}
	return r;
}

static ut32 dumb_ctzll(ut64 x) {
	ut64 result = 0;
	int i, j;
	for (i = 0; i < 64; i += 8) {
		ut8 byte = (x >> i) & 0xff;
		if (!byte) {
			result += 8;
		} else {
			for (j = 0; j < 8; j++) {
				if (!((byte >> j) & 1)) {
					result++;
				} else {
					break;
				}
			}
			break;
		}
	}
	return result;
}

static ut64 estimate_slide(RzBinFile *bf, RDyldCache *cache, ut64 value_mask, ut64 value_add) {
	ut64 slide = 0;
	ut64 *classlist = malloc(64);
	if (!classlist) {
		goto beach;
	}

	RzListIter *iter;
	RDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		bool found_sample = false;

		struct MACH0_(opts_t) opts;
		opts.verbose = bf->rbin->verbose;
		opts.header_at = bin->header_at;

		struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(cache->buf, &opts);
		if (!mach0) {
			goto beach;
		}

		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections)(mach0))) {
			MACH0_(mach0_free)
			(mach0);
			goto beach;
		}

		int i;
		int incomplete = 2;
		int classlist_idx = 0, data_idx = 0;
		for (i = 0; !sections[i].last && incomplete; i++) {
			if (sections[i].size == 0) {
				continue;
			}
			if (strstr(sections[i].name, "__objc_classlist")) {
				incomplete--;
				classlist_idx = i;
				continue;
			}
			if (strstr(sections[i].name, "__objc_data")) {
				incomplete--;
				data_idx = i;
				continue;
			}
		}

		if (incomplete) {
			goto next_bin;
		}

		int classlist_sample_size = RZ_MIN(64, sections[classlist_idx].size);
		int n_classes = classlist_sample_size / 8;

		if (rz_buf_fread_at(cache->buf, sections[classlist_idx].offset, (ut8 *)classlist, "l", n_classes) < classlist_sample_size) {
			goto next_bin;
		}

		ut64 data_addr = sections[data_idx].addr;
		ut64 data_tail = data_addr & 0xfff;
		ut64 data_tail_end = (data_addr + sections[data_idx].size) & 0xfff;
		for (i = 0; i < n_classes; i++) {
			ut64 cl_addr = (classlist[i] & value_mask) + value_add;
			ut64 cl_tail = cl_addr & 0xfff;
			if (cl_tail >= data_tail && cl_tail < data_tail_end) {
				ut64 off = cl_tail - data_tail;
				slide = ((cl_addr - off) & value_mask) - (data_addr & value_mask);
				found_sample = true;
				break;
			}
		}

	next_bin:
		MACH0_(mach0_free)
		(mach0);
		RZ_FREE(sections);

		if (found_sample) {
			break;
		}
	}

beach:
	RZ_FREE(classlist);
	return slide;
}

static RDyldRebaseInfo *get_rebase_info(RzBinFile *bf, RDyldCache *cache, ut64 slideInfoOffset, ut64 slideInfoSize, ut64 start_of_data, ut64 slide) {
	ut8 *tmp_buf_1 = NULL;
	ut8 *tmp_buf_2 = NULL;
	ut8 *one_page_buf = NULL;
	RzBuffer *cache_buf = cache->buf;

	ut64 offset = slideInfoOffset;
	ut32 slide_info_version = 0;
	if (rz_buf_read_at(cache_buf, offset, (ut8 *)&slide_info_version, 4) != 4) {
		return NULL;
	}

	if (slide_info_version == 3) {
		cache_slide3_t slide_info;
		ut64 size = sizeof(cache_slide3_t);
		if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&slide_info, "4i1l", 1) < 20) {
			return NULL;
		}

		ut64 page_starts_offset = offset + size;
		ut64 page_starts_size = slide_info.page_starts_count * 2;

		if (page_starts_size + size > slideInfoSize) {
			return NULL;
		}

		if (page_starts_size > 0) {
			tmp_buf_1 = malloc(page_starts_size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, page_starts_offset, tmp_buf_1, "s", slide_info.page_starts_count) != page_starts_size) {
				goto beach;
			}
		}

		if (slide_info.page_size > 0) {
			one_page_buf = malloc(slide_info.page_size);
			if (!one_page_buf) {
				goto beach;
			}
		}

		RDyldRebaseInfo3 *rebase_info = RZ_NEW0(RDyldRebaseInfo3);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 3;
		rebase_info->delta_mask = 0x3ff8000000000000ULL;
		rebase_info->delta_shift = 51;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16 *)tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->auth_value_add = slide_info.auth_value_add;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide(bf, cache, 0x7ffffffffffffULL, 0);
			if (rebase_info->slide) {
				eprintf("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RDyldRebaseInfo *)rebase_info;
	} else if (slide_info_version == 2 || slide_info_version == 4) {
		cache_slide2_t slide_info;
		ut64 size = sizeof(cache_slide2_t);
		if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&slide_info, "6i2l", 1) != size) {
			return NULL;
		}

		if (slide_info.page_starts_offset == 0 ||
			slide_info.page_starts_offset > slideInfoSize ||
			slide_info.page_starts_offset + slide_info.page_starts_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.page_extras_offset == 0 ||
			slide_info.page_extras_offset > slideInfoSize ||
			slide_info.page_extras_offset + slide_info.page_extras_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.page_starts_count > 0) {
			ut64 size = slide_info.page_starts_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_starts_offset;
			tmp_buf_1 = malloc(size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, at, tmp_buf_1, "s", slide_info.page_starts_count) != size) {
				goto beach;
			}
		}

		if (slide_info.page_extras_count > 0) {
			ut64 size = slide_info.page_extras_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_extras_offset;
			tmp_buf_2 = malloc(size);
			if (!tmp_buf_2) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, at, tmp_buf_2, "s", slide_info.page_extras_count) != size) {
				goto beach;
			}
		}

		if (slide_info.page_size > 0) {
			one_page_buf = malloc(slide_info.page_size);
			if (!one_page_buf) {
				goto beach;
			}
		}

		RDyldRebaseInfo2 *rebase_info = RZ_NEW0(RDyldRebaseInfo2);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = slide_info_version;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16 *)tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->page_extras = (ut16 *)tmp_buf_2;
		rebase_info->page_extras_count = slide_info.page_extras_count;
		rebase_info->value_add = slide_info.value_add;
		rebase_info->delta_mask = slide_info.delta_mask;
		rebase_info->value_mask = ~rebase_info->delta_mask;
		rebase_info->delta_shift = dumb_ctzll(rebase_info->delta_mask) - 2;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide(bf, cache, rebase_info->value_mask, rebase_info->value_add);
			if (rebase_info->slide) {
				eprintf("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RDyldRebaseInfo *)rebase_info;
	} else if (slide_info_version == 1) {
		cache_slide1_t slide_info;
		ut64 size = sizeof(cache_slide1_t);
		if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&slide_info, "6i", 1) != size) {
			return NULL;
		}

		if (slide_info.toc_offset == 0 ||
			slide_info.toc_offset > slideInfoSize ||
			slide_info.toc_offset + slide_info.toc_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.entries_offset == 0 ||
			slide_info.entries_offset > slideInfoSize ||
			slide_info.entries_offset + slide_info.entries_count * slide_info.entries_size > slideInfoSize) {
			return NULL;
		}

		if (slide_info.toc_count > 0) {
			ut64 size = slide_info.toc_count * 2;
			ut64 at = slideInfoOffset + slide_info.toc_offset;
			tmp_buf_1 = malloc(size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, at, tmp_buf_1, "s", slide_info.toc_count) != size) {
				goto beach;
			}
		}

		if (slide_info.entries_count > 0) {
			ut64 size = (ut64)slide_info.entries_count * (ut64)slide_info.entries_size;
			ut64 at = slideInfoOffset + slide_info.entries_offset;
			tmp_buf_2 = malloc(size);
			if (!tmp_buf_2) {
				goto beach;
			}
			if (rz_buf_read_at(cache_buf, at, tmp_buf_2, size) != size) {
				goto beach;
			}
		}

		one_page_buf = malloc(4096);
		if (!one_page_buf) {
			goto beach;
		}

		RDyldRebaseInfo1 *rebase_info = RZ_NEW0(RDyldRebaseInfo1);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 1;
		rebase_info->start_of_data = start_of_data;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->page_size = 4096;
		rebase_info->toc = (ut16 *)tmp_buf_1;
		rebase_info->toc_count = slide_info.toc_count;
		rebase_info->entries = tmp_buf_2;
		rebase_info->entries_size = slide_info.entries_size;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide(bf, cache, UT64_MAX, 0);
			if (rebase_info->slide) {
				eprintf("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RDyldRebaseInfo *)rebase_info;
	} else {
		eprintf("unsupported slide info version %d\n", slide_info_version);
		return NULL;
	}

beach:
	RZ_FREE(tmp_buf_1);
	RZ_FREE(tmp_buf_2);
	RZ_FREE(one_page_buf);
	return NULL;
}

static RDyldRebaseInfos *get_rebase_infos(RzBinFile *bf, RDyldCache *cache) {
	RzBuffer *cache_buf = cache->buf;

	RDyldRebaseInfos *result = RZ_NEW0(RDyldRebaseInfos);
	if (!result) {
		return NULL;
	}

	if (!cache->hdr->slideInfoOffset || !cache->hdr->slideInfoSize) {
		ut64 slide_infos_offset;
		size_t n_slide_infos;
		if ((slide_infos_offset = rz_buf_read_le32_at(cache_buf, 0x138)) == UT32_MAX) {
			goto beach;
		}
		if ((n_slide_infos = rz_buf_read_le32_at(cache_buf, 0x13c)) == UT32_MAX) {
			goto beach;
		}

		RDyldRebaseInfosEntry *infos = RZ_NEWS0(RDyldRebaseInfosEntry, n_slide_infos);
		if (!infos) {
			goto beach;
		}

		size_t i, j;
		RDyldRebaseInfo *prev_info = NULL;
		for (i = 0, j = 0; i < n_slide_infos; i++) {
			ut64 offset = slide_infos_offset + i * sizeof(cache_mapping_slide);
			cache_mapping_slide entry;
			if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&entry, "6lii", 1) != sizeof(cache_mapping_slide)) {
				free(infos);
				goto beach;
			}

			if (entry.slideInfoOffset && entry.slideInfoSize) {
				infos[j].start = entry.fileOffset;
				infos[j].end = entry.fileOffset + entry.size;
				ut64 slide = prev_info ? prev_info->slide : UT64_MAX;
				infos[j].info = get_rebase_info(bf, cache, entry.slideInfoOffset, entry.slideInfoSize, entry.fileOffset, slide);
				prev_info = infos[j].info;
				j++;
			}
		}

		if (!j) {
			free(infos);
			goto beach;
		}

		if (j != n_slide_infos) {
			RDyldRebaseInfosEntry *pruned_infos = RZ_NEWS0(RDyldRebaseInfosEntry, j);
			if (!pruned_infos) {
				free(infos);
				goto beach;
			}

			memcpy(pruned_infos, infos, sizeof(RDyldRebaseInfosEntry) * j);
			free(infos);
			infos = pruned_infos;
		}

		result->entries = infos;
		result->length = j;
		return result;
	}

	if (cache->hdr->mappingCount > 1) {
		RDyldRebaseInfosEntry *infos = RZ_NEWS0(RDyldRebaseInfosEntry, 1);
		if (!infos) {
			goto beach;
		}

		infos[0].start = cache->maps[1].fileOffset;
		infos[0].end = infos[0].start + cache->maps[1].size;
		infos[0].info = get_rebase_info(bf, cache, cache->hdr->slideInfoOffset, cache->hdr->slideInfoSize, infos[0].start, UT64_MAX);

		result->entries = infos;
		result->length = 1;
		return result;
	}

beach:
	free(result);
	return NULL;
}

static bool check_buffer(RzBuffer *buf) {
	if (rz_buf_size(buf) < 32) {
		return false;
	}

	char hdr[17] = { 0 };
	int rzhdr = rz_buf_read_at(buf, 0, (ut8 *)&hdr, sizeof(hdr) - 1);
	if (rzhdr != sizeof(hdr) - 1) {
		return false;
	}

	return !strcmp(hdr, "dyld_v1   arm64") || !strcmp(hdr, "dyld_v1  arm64e") || !strcmp(hdr, "dyld_v1  x86_64") || !strcmp(hdr, "dyld_v1 x86_64h");
}

static cache_img_t *read_cache_images(RzBuffer *cache_buf, cache_hdr_t *hdr) {
	if (!cache_buf || !hdr || !hdr->imagesCount || !hdr->imagesOffset) {
		return NULL;
	}

	ut64 size = sizeof(cache_img_t) * hdr->imagesCount;
	cache_img_t *images = RZ_NEWS0(cache_img_t, hdr->imagesCount);
	if (!images) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, hdr->imagesOffset, (ut8 *)images, "3l2i", hdr->imagesCount) != size) {
		RZ_FREE(images);
		return NULL;
	}

	return images;
}

static cache_imgxtr_t *read_cache_imgextra(RzBuffer *cache_buf, cache_hdr_t *hdr, cache_accel_t *accel) {
	if (!cache_buf || !hdr || !hdr->imagesCount || !accel || !accel->imageExtrasCount || !accel->imagesExtrasOffset) {
		return NULL;
	}

	ut64 size = sizeof(cache_imgxtr_t) * accel->imageExtrasCount;
	cache_imgxtr_t *images = RZ_NEWS0(cache_imgxtr_t, accel->imageExtrasCount);
	if (!images) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, accel->imagesExtrasOffset, (ut8 *)images, "ll4i", accel->imageExtrasCount) != size) {
		RZ_FREE(images);
		return NULL;
	}

	return images;
}

static char *get_lib_name(RzBuffer *cache_buf, cache_img_t *img) {
	char file[256];
	char *lib_name = file;
	if (rz_buf_read_at(cache_buf, img->pathFileOffset, (ut8 *)&file, sizeof(file)) == sizeof(file)) {
		file[255] = 0;
		/*char * last_slash = strrchr (file, '/');
		if (last_slash && *last_slash) {
			lib_name = last_slash + 1;
		}*/
		return strdup(lib_name);
	}
	return strdup("FAIL");
}

static int string_contains(const void *a, const void *b) {
	return !strstr((const char *)a, (const char *)b);
}

static HtPU *create_path_to_index(RzBuffer *cache_buf, cache_img_t *img, cache_hdr_t *hdr) {
	HtPU *path_to_idx = ht_pu_new0();
	if (!path_to_idx) {
		return NULL;
	}
	for (size_t i = 0; i != hdr->imagesCount; i++) {
		char file[256];
		if (rz_buf_read_at(cache_buf, img[i].pathFileOffset, (ut8 *)&file, sizeof(file)) != sizeof(file)) {
			continue;
		}
		file[255] = 0;
		ht_pu_insert(path_to_idx, file, (ut64)i);
	}

	return path_to_idx;
}

static void carve_deps_at_address(RzBuffer *cache_buf, cache_img_t *img, cache_hdr_t *hdr, cache_map_t *maps, HtPU *path_to_idx, ut64 address, int *deps) {
	ut64 pa = va2pa(address, hdr, maps, cache_buf, 0, NULL, NULL);
	if (pa == UT64_MAX) {
		return;
	}
	struct MACH0_(mach_header) mh;
	if (rz_buf_fread_at(cache_buf, pa, (ut8 *)&mh, "8i", 1) != sizeof(struct MACH0_(mach_header))) {
		return;
	}
	if (mh.magic != MH_MAGIC_64 || mh.sizeofcmds == 0) {
		return;
	}
	ut64 cmds_at = pa + sizeof(struct MACH0_(mach_header));
	ut8 *cmds = malloc(mh.sizeofcmds + 1);
	if (!cmds || rz_buf_read_at(cache_buf, cmds_at, cmds, mh.sizeofcmds) != mh.sizeofcmds) {
		goto beach;
	}
	cmds[mh.sizeofcmds] = 0;
	ut8 *cursor = cmds;
	ut8 *end = cmds + mh.sizeofcmds;
	while (cursor < end) {
		ut32 cmd = rz_read_le32(cursor);
		ut32 cmdsize = rz_read_le32(cursor + sizeof(ut32));
		if (cmd == LC_LOAD_DYLIB ||
			cmd == LC_LOAD_WEAK_DYLIB ||
			cmd == LC_REEXPORT_DYLIB ||
			cmd == LC_LOAD_UPWARD_DYLIB) {
			bool found;
			if (cursor + 24 >= end) {
				break;
			}
			const char *key = (const char *)cursor + 24;
			size_t dep_index = (size_t)ht_pu_find(path_to_idx, key, &found);
			if (!found || dep_index >= hdr->imagesCount) {
				eprintf("WARNING: alien dep '%s'\n", key);
				continue;
			}
			deps[dep_index]++;
			eprintf("-> %s\n", key);
		}
		cursor += cmdsize;
	}

beach:
	free(cmds);
}

static RzList *create_cache_bins(RzBinFile *bf, RzBuffer *cache_buf, cache_hdr_t *hdr, cache_map_t *maps, cache_accel_t *accel) {
	RzList *bins = rz_list_newf((RzListFree)free_bin);
	if (!bins) {
		return NULL;
	}

	cache_img_t *img = read_cache_images(cache_buf, hdr);
	if (!img) {
		rz_list_free(bins);
		return NULL;
	}

	int i;
	int *deps = NULL;
	char *target_libs = NULL;
	target_libs = rz_sys_getenv("RZ_DYLDCACHE_FILTER");
	RzList *target_lib_names = NULL;
	ut16 *depArray = NULL;
	cache_imgxtr_t *extras = NULL;
	if (target_libs) {
		target_lib_names = rz_str_split_list(target_libs, ":", 0);
		if (!target_lib_names) {
			goto error;
		}

		deps = RZ_NEWS0(int, hdr->imagesCount);
		if (!deps) {
			goto error;
		}

		HtPU *path_to_idx = NULL;
		if (accel) {
			depArray = RZ_NEWS0(ut16, accel->depListCount);
			if (!depArray) {
				goto error;
			}

			if (rz_buf_fread_at(cache_buf, accel->depListOffset, (ut8 *)depArray, "s", accel->depListCount) != accel->depListCount * 2) {
				goto error;
			}

			extras = read_cache_imgextra(cache_buf, hdr, accel);
			if (!extras) {
				goto error;
			}
		} else {
			path_to_idx = create_path_to_index(cache_buf, img, hdr);
		}

		for (i = 0; i < hdr->imagesCount; i++) {
			char *lib_name = get_lib_name(cache_buf, &img[i]);
			if (!lib_name) {
				break;
			}
			if (strstr(lib_name, "libobjc.A.dylib")) {
				deps[i]++;
			}
			if (!rz_list_find(target_lib_names, lib_name, string_contains)) {
				RZ_FREE(lib_name);
				continue;
			}
			eprintf("FILTER: %s\n", lib_name);
			RZ_FREE(lib_name);
			deps[i]++;

			if (extras && depArray) {
				ut32 j;
				for (j = extras[i].dependentsStartArrayIndex; depArray[j] != 0xffff; j++) {
					ut16 dep_index = depArray[j] & 0x7fff;
					deps[dep_index]++;

					char *dep_name = get_lib_name(cache_buf, &img[dep_index]);
					if (!dep_name) {
						break;
					}
					eprintf("-> %s\n", dep_name);
					free(dep_name);
				}
			} else if (path_to_idx) {
				carve_deps_at_address(cache_buf, img, hdr, maps, path_to_idx, img[i].address, deps);
			}
		}

		ht_pu_free(path_to_idx);
		RZ_FREE(depArray);
		RZ_FREE(extras);
		RZ_FREE(target_libs);
		rz_list_free(target_lib_names);
		target_lib_names = NULL;
	}

	for (i = 0; i < hdr->imagesCount; i++) {
		if (deps && !deps[i]) {
			continue;
		}
		ut64 pa = va2pa(img[i].address, hdr, maps, cache_buf, 0, NULL, NULL);
		if (pa == UT64_MAX) {
			continue;
		}
		ut8 magicbytes[4];
		rz_buf_read_at(cache_buf, pa, magicbytes, 4);
		int magic = rz_read_le32(magicbytes);
		switch (magic) {
		case MH_MAGIC:
			// parse_mach0 (ret, *ptr, bf);
			break;
		case MH_MAGIC_64: {
			char file[256];
			RDyldBinImage *bin = RZ_NEW0(RDyldBinImage);
			if (!bin) {
				goto error;
			}
			bin->header_at = pa;
			if (rz_buf_read_at(cache_buf, img[i].pathFileOffset, (ut8 *)&file, sizeof(file)) == sizeof(file)) {
				file[255] = 0;
				char *last_slash = strrchr(file, '/');
				if (last_slash && *last_slash) {
					if (last_slash > file) {
						char *scan = last_slash - 1;
						while (scan > file && *scan != '/') {
							scan--;
						}
						if (*scan == '/') {
							bin->file = strdup(scan + 1);
						} else {
							bin->file = strdup(last_slash + 1);
						}
					} else {
						bin->file = strdup(last_slash + 1);
					}
				} else {
					bin->file = strdup(file);
				}
			}
			rz_list_append(bins, bin);
			break;
		}
		default:
			eprintf("Unknown sub-bin\n");
			break;
		}
	}

	goto beach;
error:
	if (bins) {
		rz_list_free(bins);
	}
	bins = NULL;
beach:
	RZ_FREE(depArray);
	RZ_FREE(extras);
	RZ_FREE(target_libs);
	if (target_lib_names) {
		rz_list_free(target_lib_names);
	}
	RZ_FREE(deps);
	RZ_FREE(img);
	return bins;
}

static void rebase_bytes_v1(RDyldRebaseInfo1 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;
		ut64 entry_index = page_offset / 32;
		ut64 offset_in_entry = (page_offset % 32) / 4;

		if (entry_index >= rebase_info->entries_size) {
			in_buf += to_next_page;
			offset += to_next_page;
			continue;
		}

		if (page_index >= rebase_info->toc_count) {
			break;
		}

		ut8 *entry = &rebase_info->entries[rebase_info->toc[page_index] * rebase_info->entries_size];
		ut8 b = entry[entry_index];

		if (b & (1 << offset_in_entry)) {
			ut64 value = rz_read_le64(buf + in_buf);
			value += rebase_info->slide;
			rz_write_le64(buf + in_buf, value);
			in_buf += 8;
			offset += 8;
		} else {
			in_buf += 4;
			offset += 4;
		}
	}
}

static void rebase_bytes_v2(RDyldRebaseInfo2 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut16 page_flag = rebase_info->page_starts[page_index];

		if (page_flag == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		if (!(page_flag & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)) {
			ut64 first_rebase_off = rebase_info->page_starts[page_index] * 4;
			if (first_rebase_off >= page_offset && first_rebase_off < page_offset + count) {
				ut32 delta = 1;
				while (delta) {
					ut64 position = in_buf + first_rebase_off - page_offset;
					if (position >= count) {
						break;
					}
					ut64 raw_value = rz_read_le64(buf + position);
					delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift);
					if (position >= start_of_write) {
						ut64 new_value = raw_value & rebase_info->value_mask;
						if (new_value != 0) {
							new_value += rebase_info->value_add;
							new_value += rebase_info->slide;
						}
						rz_write_le64(buf + position, new_value);
					}
					first_rebase_off += delta;
				}
			}
		}
	next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static void rebase_bytes_v3(RDyldRebaseInfo3 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut64 delta = rebase_info->page_starts[page_index];

		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		ut64 first_rebase_off = delta;
		if (first_rebase_off >= page_offset && first_rebase_off < page_offset + count) {
			do {
				ut64 position = in_buf + first_rebase_off - page_offset;
				if (position >= count) {
					break;
				}
				ut64 raw_value = rz_read_le64(buf + position);
				delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
				if (position >= start_of_write) {
					ut64 new_value = 0;
					if (RZ_IS_PTR_AUTHENTICATED(raw_value)) {
						new_value = (raw_value & 0xFFFFFFFFULL) + rebase_info->auth_value_add;
						// TODO: don't throw auth info away
					} else {
						new_value = ((raw_value << 13) & 0xFF00000000000000ULL) | (raw_value & 0x7ffffffffffULL);
						new_value &= 0x00FFFFFFFFFFFFFFULL;
					}
					if (new_value != 0) {
						new_value += rebase_info->slide;
					}
					rz_write_le64(buf + position, new_value);
				}
				first_rebase_off += delta;
			} while (delta);
		}
	next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static RDyldRebaseInfo *rebase_info_by_range(RDyldRebaseInfos *infos, ut64 offset, int count) {
	int imid;
	int imin = 0;
	int imax = infos->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RDyldRebaseInfosEntry *entry = &infos->entries[imid];
		if ((entry->end) <= offset) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RDyldRebaseInfosEntry *minEntry = &infos->entries[imin];
	if ((imax == imin) && (minEntry->start <= offset + count) && (minEntry->end >= offset)) {
		return minEntry->info;
	}
	return NULL;
}

static void rebase_bytes(RDyldRebaseInfo *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	if (!rebase_info || !buf) {
		return;
	}

	if (rebase_info->version == 3) {
		rebase_bytes_v3((RDyldRebaseInfo3 *)rebase_info, buf, offset, count, start_of_write);
	} else if (rebase_info->version == 2 || rebase_info->version == 4) {
		rebase_bytes_v2((RDyldRebaseInfo2 *)rebase_info, buf, offset, count, start_of_write);
	} else if (rebase_info->version == 1) {
		rebase_bytes_v1((RDyldRebaseInfo1 *)rebase_info, buf, offset, count, start_of_write);
	}
}

static int dyldcache_io_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	rz_return_val_if_fail(io, -1);
	RzCore *core = (RzCore *)io->corebind.core;

	if (!core || !core->bin || !core->bin->binfiles) {
		return -1;
	}

	RDyldCache *cache = NULL;
	RzListIter *iter;
	RzBinFile *bf;
	rz_list_foreach (core->bin->binfiles, iter, bf) {
		if (bf->fd == fd->fd) {
			if (!strncmp((char *)bf->o->bin_obj, "dyldcac", 7)) {
				cache = bf->o->bin_obj;
			} else {
				cache = ((struct MACH0_(obj_t) *)bf->o->bin_obj)->user;
			}
			if (pending_bin_files) {
				RzListIter *to_remove = rz_list_contains(pending_bin_files, bf);
				if (to_remove) {
					rz_list_delete(pending_bin_files, to_remove);
					if (rz_list_empty(pending_bin_files)) {
						rz_list_free(pending_bin_files);
						pending_bin_files = NULL;
					}
				}
			}
			break;
		}
	}
	if (!cache) {
		rz_list_foreach (pending_bin_files, iter, bf) {
			if (bf->fd == fd->fd && bf->o) {
				if (!strncmp((char *)bf->o->bin_obj, "dyldcac", 7)) {
					cache = bf->o->bin_obj;
				} else {
					cache = ((struct MACH0_(obj_t) *)bf->o->bin_obj)->user;
				}
				break;
			}
		}
	}
	if (!cache || !cache->original_io_read) {
		if (fd->plugin->read == &dyldcache_io_read) {
			return -1;
		}
		return fd->plugin->read(io, fd, buf, count);
	}

	RDyldRebaseInfo *rebase_info = rebase_info_by_range(cache->rebase_infos, io->off, count);

	int result = 0;

	if (rebase_info && count > 0) {
		ut64 offset_in_data = io->off - rebase_info->start_of_data;
		ut64 page_offset = offset_in_data % rebase_info->page_size;

		ut64 internal_offset = io->off & ~(rebase_info->page_size - 1);
		ut64 internal_end = io->off + count;
		int rounded_count = internal_end - internal_offset;

		ut8 *internal_buf = rebase_info->one_page_buf;
		if (rounded_count > rebase_info->page_size) {
			internal_buf = malloc(rounded_count);
			if (!internal_buf) {
				eprintf("Cannot allocate memory for 'internal_buf'\n");
				return -1;
			}
		}

		ut64 original_off = io->off;
		io->off = internal_offset;

		int internal_result = cache->original_io_read(io, fd, internal_buf, rounded_count);

		io->off = original_off;

		if (internal_result >= page_offset + count) {
			rebase_bytes(rebase_info, internal_buf, internal_offset, internal_result, page_offset);
			result = RZ_MIN(count, internal_result);
			memcpy(buf, internal_buf + page_offset, result);
		} else {
			eprintf("ERROR rebasing\n");
			result = cache->original_io_read(io, fd, buf, count);
		}

		if (internal_buf != rebase_info->one_page_buf) {
			RZ_FREE(internal_buf);
		}
	} else {
		result = cache->original_io_read(io, fd, buf, count);
	}

	return result;
}

static void swizzle_io_read(RDyldCache *cache, RzIO *io) {
	if (!io || !io->desc || !io->desc->plugin) {
		return;
	}

	RzIOPlugin *plugin = io->desc->plugin;
	cache->original_io_read = plugin->read;
	plugin->read = &dyldcache_io_read;
}

static cache_hdr_t *read_cache_header(RzBuffer *cache_buf) {
	if (!cache_buf) {
		return NULL;
	}

	cache_hdr_t *hdr = RZ_NEW0(cache_hdr_t);
	if (!hdr) {
		return NULL;
	}

	ut64 size = sizeof(cache_hdr_t);
	if (rz_buf_fread_at(cache_buf, 0, (ut8 *)hdr, "16c4i7l16clii4l", 1) != size) {
		RZ_FREE(hdr);
		return NULL;
	}

	return hdr;
}

static cache_map_t *read_cache_maps(RzBuffer *cache_buf, cache_hdr_t *hdr) {
	if (!cache_buf || !hdr || !hdr->mappingCount || !hdr->mappingOffset) {
		return NULL;
	}

	ut64 size = sizeof(cache_map_t) * hdr->mappingCount;
	cache_map_t *maps = RZ_NEWS0(cache_map_t, hdr->mappingCount);
	if (!maps) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, hdr->mappingOffset, (ut8 *)maps, "3l2i", hdr->mappingCount) != size) {
		RZ_FREE(maps);
		return NULL;
	}

	return maps;
}

static cache_accel_t *read_cache_accel(RzBuffer *cache_buf, cache_hdr_t *hdr, cache_map_t *maps) {
	if (!cache_buf || !hdr || !hdr->accelerateInfoSize || !hdr->accelerateInfoAddr) {
		return NULL;
	}

	ut64 offset = va2pa(hdr->accelerateInfoAddr, hdr, maps, cache_buf, 0, NULL, NULL);
	if (!offset) {
		return NULL;
	}

	ut64 size = sizeof(cache_accel_t);
	cache_accel_t *accel = RZ_NEW0(cache_accel_t);
	if (!accel) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, offset, (ut8 *)accel, "16il", 1) != size) {
		RZ_FREE(accel);
		return NULL;
	}

	accel->imagesExtrasOffset += offset;
	accel->bottomUpListOffset += offset;
	accel->dylibTrieOffset += offset;
	accel->initializersOffset += offset;
	accel->dofSectionsOffset += offset;
	accel->reExportListOffset += offset;
	accel->depListOffset += offset;
	accel->rangeTableOffset += offset;

	return accel;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	RDyldCache *cache = RZ_NEW0(RDyldCache);
	memcpy(cache->magic, "dyldcac", 7);
	cache->buf = rz_buf_ref(buf);
	cache->hdr = read_cache_header(cache->buf);
	if (!cache->hdr) {
		rz_dyldcache_free(cache);
		return false;
	}
	cache->maps = read_cache_maps(cache->buf, cache->hdr);
	if (!cache->maps) {
		rz_dyldcache_free(cache);
		return false;
	}
	cache->accel = read_cache_accel(cache->buf, cache->hdr, cache->maps);
	cache->locsym = rz_dyld_locsym_new(cache->buf, cache->hdr);
	cache->bins = create_cache_bins(bf, cache->buf, cache->hdr, cache->maps, cache->accel);
	if (!cache->bins) {
		rz_dyldcache_free(cache);
		return false;
	}
	cache->rebase_infos = get_rebase_infos(bf, cache);
	if (cache->rebase_infos) {
		if (!rebase_infos_get_slide(cache)) {
			if (!pending_bin_files) {
				pending_bin_files = rz_list_new();
				if (!pending_bin_files) {
					rz_dyldcache_free(cache);
					return false;
				}
			}
			rz_list_push(pending_bin_files, bf);
			swizzle_io_read(cache, bf->rbin->iob.io);
		}
	}
	*bin_obj = cache;
	return true;
}

static RzList *entries(RzBinFile *bf) {
	RzBinAddr *ptr = NULL;
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;

	if (!bf || !bf->o) {
		return NULL;
	}

	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	bool big_endian = 0;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->bclass = strdup("dyldcache");
	ret->os = strdup("Darwin"); // TODO: actual OS info is available. See the platform member of struct dyld_cache_header in dyld source.
	if (strstr(cache->hdr->magic, "x86_64")) {
		ret->arch = strdup("x86");
		ret->bits = 64;
	} else {
		ret->arch = strdup("arm");
		ret->bits = strstr(cache->hdr->magic, "arm64") ? 64 : 32;
	}
	ret->machine = strdup(ret->arch);
	ret->subsystem = strdup("xnu");
	ret->type = strdup("library-cache");
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

#if 0
static void parse_mach0 (RzList *ret, ut64 paddr, RzBinFile *bf) {
	// TODO
}
#endif

static ut64 baddr(RzBinFile *bf) {
	// XXX hardcoded
	return 0x180000000;
}

void symbols_from_bin(RzList *ret, RzBinFile *bf, RDyldBinImage *bin, SetU *hash) {
	struct MACH0_(obj_t) *mach0 = bin_to_mach0(bf, bin);
	if (!mach0) {
		return;
	}

	// const RzList*symbols = MACH0_(get_symbols_list) (mach0);
	const struct symbol_t *symbols = MACH0_(get_symbols)(mach0);
	if (!symbols) {
		return;
	}
	int i;
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		if (strstr(symbols[i].name, "<redacted>")) {
			continue;
		}
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = strdup(symbols[i].name);
		sym->vaddr = symbols[i].addr;
		sym->forwarder = "NONE";
		sym->bind = (symbols[i].type == RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL) ? RZ_BIN_BIND_LOCAL_STR : RZ_BIN_BIND_GLOBAL_STR;
		sym->type = RZ_BIN_TYPE_FUNC_STR;
		sym->paddr = symbols[i].offset + bf->o->boffset;
		sym->size = symbols[i].size;
		sym->ordinal = i;

		set_u_add(hash, sym->vaddr);
		rz_list_append(ret, sym);
	}
	MACH0_(mach0_free)
	(mach0);
}

static bool __is_data_section(const char *name) {
	if (strstr(name, "_cstring")) {
		return true;
	}
	if (strstr(name, "_os_log")) {
		return true;
	}
	if (strstr(name, "_objc_methname")) {
		return true;
	}
	if (strstr(name, "_objc_classname")) {
		return true;
	}
	if (strstr(name, "_objc_methtype")) {
		return true;
	}
	return false;
}

static void sections_from_bin(RzList *ret, RzBinFile *bf, RDyldBinImage *bin) {
	struct MACH0_(obj_t) *mach0 = bin_to_mach0(bf, bin);
	if (!mach0) {
		return;
	}

	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return;
	}

	int i;
	for (i = 0; !sections[i].last; i++) {
		RzBinSection *ptr = RZ_NEW0(RzBinSection);
		if (!ptr) {
			break;
		}
		if (bin->file) {
			ptr->name = rz_str_newf("%s.%s", bin->file, (char *)sections[i].name);
		} else {
			ptr->name = rz_str_newf("%s", (char *)sections[i].name);
		}
		if (strstr(ptr->name, "la_symbol_ptr")) {
			int len = sections[i].size / 8;
			ptr->format = rz_str_newf("Cd %d[%d]", 8, len);
		}
		ptr->is_data = __is_data_section(ptr->name);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].offset + bf->o->boffset;
		ptr->vaddr = sections[i].addr;
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = sections[i].perm;
		rz_list_append(ret, ptr);
	}
	free(sections);
	MACH0_(mach0_free)
	(mach0);
}

static RzList *maps(RzBinFile *bf) {
	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	ut64 slide = rebase_infos_get_slide(cache);
	for (ut32 i = 0; i < cache->hdr->mappingCount; i++) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			rz_list_free(ret);
			return NULL;
		}
		map->name = rz_str_newf("cache_map.%d", i);
		map->paddr = cache->maps[i].fileOffset;
		map->psize = cache->maps[i].size;
		map->vsize = map->psize;
		map->vaddr = cache->maps[i].address + slide;
		map->perm = prot2perm(cache->maps[i].initProt);
		rz_list_append(ret, map);
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	RzListIter *iter;
	RDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		sections_from_bin(ret, bf, bin);
	}
	ut64 slide = rebase_infos_get_slide(cache);
	if (slide) {
		RzBinSection *section;
		rz_list_foreach (ret, iter, section) {
			section->vaddr += slide;
		}
	}
	return ret;
}

static RzList *symbols(RzBinFile *bf) {
	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzListIter *iter;
	RDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		SetU *hash = set_u_new();
		if (!hash) {
			rz_list_free(ret);
			return NULL;
		}
		symbols_from_bin(ret, bf, bin, hash);
		rz_dyld_locsym_entries_by_offset(cache, ret, hash, bin->header_at);
		set_u_free(hash);
	}

	ut64 slide = rebase_infos_get_slide(cache);
	if (slide) {
		RzBinSymbol *sym;
		rz_list_foreach (ret, iter, sym) {
			sym->vaddr += slide;
		}
	}

	return ret;
}

/* static void unswizzle_io_read(RDyldCache *cache, RzIO *io) {
	if (!io || !io->desc || !io->desc->plugin || !cache->original_io_read) {
		return;
	}

	RzIOPlugin *plugin = io->desc->plugin;
	plugin->read = cache->original_io_read;
	cache->original_io_read = NULL;
} */

static void destroy(RzBinFile *bf) {
	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	// unswizzle_io_read (cache, bf->rbin->iob.io); // XXX io may be dead here
	rz_dyldcache_free(cache);
}

static RzList *classes(RzBinFile *bf) {
	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}

	RzListIter *iter;
	RDyldBinImage *bin;

	RzBuffer *orig_buf = bf->buf;
	ut32 num_of_unnamed_class = 0;
	rz_list_foreach (cache->bins, iter, bin) {
		struct MACH0_(obj_t) *mach0 = bin_to_mach0(bf, bin);
		if (!mach0) {
			goto beach;
		}

		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections)(mach0))) {
			MACH0_(mach0_free)
			(mach0);
			goto beach;
		}

		int i;
		for (i = 0; !sections[i].last; i++) {
			if (sections[i].size == 0) {
				continue;
			}

			bool is_classlist = strstr(sections[i].name, "__objc_classlist");
			bool is_catlist = strstr(sections[i].name, "__objc_catlist");

			if (!is_classlist && !is_catlist) {
				continue;
			}

			ut8 *pointers = malloc(sections[i].size);
			if (rz_buf_read_at(cache->buf, sections[i].offset, pointers, sections[i].size) < sections[i].size) {
				RZ_FREE(pointers);
				continue;
			}
			ut8 *cursor = pointers;
			ut8 *pointers_end = pointers + sections[i].size;

			for (; cursor < pointers_end; cursor += 8) {
				ut64 pointer_to_class = rz_read_le64(cursor);

				RzBinClass *klass;
				if (!(klass = RZ_NEW0(RzBinClass)) ||
					!(klass->methods = rz_list_new()) ||
					!(klass->fields = rz_list_new())) {
					RZ_FREE(klass);
					RZ_FREE(pointers);
					RZ_FREE(sections);
					MACH0_(mach0_free)
					(mach0);
					goto beach;
				}

				bf->o->bin_obj = mach0;
				bf->buf = cache->buf;
				if (is_classlist) {
					MACH0_(get_class_t)
					((ut64)pointer_to_class, bf, klass, false, NULL);
				} else {
					MACH0_(get_category_t)
					((ut64)pointer_to_class, bf, klass, NULL);
				}
				bf->o->bin_obj = cache;
				bf->buf = orig_buf;

				if (!klass->name) {
					klass->name = rz_str_newf("UnnamedClass%u", num_of_unnamed_class);
					if (!klass->name) {
						RZ_FREE(klass);
						RZ_FREE(pointers);
						RZ_FREE(sections);
						MACH0_(mach0_free)
						(mach0);
						goto beach;
					}
					num_of_unnamed_class++;
				}
				rz_list_append(ret, klass);
			}

			RZ_FREE(pointers);
		}

		RZ_FREE(sections);
		MACH0_(mach0_free)
		(mach0);
	}

	return ret;

beach:
	rz_list_free(ret);
	return NULL;
}

static void header(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}

	RDyldCache *cache = (RDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return;
	}

	RzBin *bin = bf->rbin;
	ut64 slide = rebase_infos_get_slide(cache);
	PrintfCallback p = bin->cb_printf;

	PJ *pj = pj_new();
	if (!pj) {
		return;
	}

	pj_o(pj);
	pj_k(pj, "header");
	pj_o(pj);
	pj_ks(pj, "magic", cache->hdr->magic);
	pj_kn(pj, "mappingOffset", cache->hdr->mappingOffset);
	pj_kn(pj, "mappingCount", cache->hdr->mappingCount);
	pj_kn(pj, "imagesOffset", cache->hdr->imagesOffset);
	pj_kn(pj, "imagesCount", cache->hdr->imagesCount);
	pj_kn(pj, "dyldBaseAddress", cache->hdr->dyldBaseAddress);
	pj_kn(pj, "codeSignatureOffset", cache->hdr->codeSignatureOffset);
	pj_kn(pj, "codeSignatureSize", cache->hdr->codeSignatureSize);
	pj_kn(pj, "slideInfoOffset", cache->hdr->slideInfoOffset);
	pj_kn(pj, "slideInfoSize", cache->hdr->slideInfoSize);
	pj_kn(pj, "localSymbolsOffset", cache->hdr->localSymbolsOffset);
	pj_kn(pj, "localSymbolsSize", cache->hdr->localSymbolsSize);
	char uuidstr[128];
	rz_hex_bin2str((ut8 *)cache->hdr->uuid, 16, uuidstr);
	pj_ks(pj, "uuid", uuidstr);
	pj_ks(pj, "cacheType", (cache->hdr->cacheType == 0) ? "development" : "production");
	pj_kn(pj, "branchPoolsOffset", cache->hdr->branchPoolsOffset);
	pj_kn(pj, "branchPoolsCount", cache->hdr->branchPoolsCount);
	pj_kn(pj, "accelerateInfoAddr", cache->hdr->accelerateInfoAddr + slide);
	pj_kn(pj, "accelerateInfoSize", cache->hdr->accelerateInfoSize);
	pj_kn(pj, "imagesTextOffset", cache->hdr->imagesTextOffset);
	pj_kn(pj, "imagesTextCount", cache->hdr->imagesTextCount);
	pj_end(pj);

	if (cache->accel) {
		pj_k(pj, "accelerator");
		pj_o(pj);
		pj_kn(pj, "version", cache->accel->version);
		pj_kn(pj, "imageExtrasCount", cache->accel->imageExtrasCount);
		pj_kn(pj, "imagesExtrasOffset", cache->accel->imagesExtrasOffset);
		pj_kn(pj, "bottomUpListOffset", cache->accel->bottomUpListOffset);
		pj_kn(pj, "dylibTrieOffset", cache->accel->dylibTrieOffset);
		pj_kn(pj, "dylibTrieSize", cache->accel->dylibTrieSize);
		pj_kn(pj, "initializersOffset", cache->accel->initializersOffset);
		pj_kn(pj, "initializersCount", cache->accel->initializersCount);
		pj_kn(pj, "dofSectionsOffset", cache->accel->dofSectionsOffset);
		pj_kn(pj, "dofSectionsCount", cache->accel->dofSectionsCount);
		pj_kn(pj, "reExportListOffset", cache->accel->reExportListOffset);
		pj_kn(pj, "reExportCount", cache->accel->reExportCount);
		pj_kn(pj, "depListOffset", cache->accel->depListOffset);
		pj_kn(pj, "depListCount", cache->accel->depListCount);
		pj_kn(pj, "rangeTableOffset", cache->accel->rangeTableOffset);
		pj_kn(pj, "rangeTableCount", cache->accel->rangeTableCount);
		pj_kn(pj, "dyldSectionAddr", cache->accel->dyldSectionAddr + slide);
		pj_end(pj);
	}

	if (cache->rebase_infos) {
		size_t i;
		pj_k(pj, "slideInfo");
		pj_a(pj);
		for (i = 0; i < cache->rebase_infos->length; i++) {
			RDyldRebaseInfo *rebase_info = cache->rebase_infos->entries[i].info;
			pj_o(pj);
			pj_kn(pj, "start", cache->rebase_infos->entries[i].start);
			pj_kn(pj, "end", cache->rebase_infos->entries[i].end);
			if (rebase_info) {
				ut8 version = rebase_info->version;
				pj_kn(pj, "version", version);
				pj_kn(pj, "slide", slide);
				if (version == 3) {
					RDyldRebaseInfo3 *info3 = (RDyldRebaseInfo3 *)rebase_info;
					pj_kn(pj, "page_starts_count", info3->page_starts_count);
					pj_kn(pj, "page_size", info3->page_size);
					pj_kn(pj, "auth_value_add", info3->auth_value_add);
				} else if (version == 2 || version == 4) {
					RDyldRebaseInfo2 *info2 = (RDyldRebaseInfo2 *)rebase_info;
					pj_kn(pj, "page_starts_count", info2->page_starts_count);
					pj_kn(pj, "page_extras_count", info2->page_extras_count);
					pj_kn(pj, "delta_mask", info2->delta_mask);
					pj_kn(pj, "value_mask", info2->value_mask);
					pj_kn(pj, "value_add", info2->value_add);
					pj_kn(pj, "delta_shift", info2->delta_shift);
					pj_kn(pj, "page_size", info2->page_size);
				} else if (version == 1) {
					RDyldRebaseInfo1 *info1 = (RDyldRebaseInfo1 *)rebase_info;
					pj_kn(pj, "toc_count", info1->toc_count);
					pj_kn(pj, "entries_size", info1->entries_size);
					pj_kn(pj, "page_size", 4096);
				}
			}
			pj_end(pj);
		}
		pj_end(pj);
	}

	if (cache->hdr->imagesTextCount) {
		pj_k(pj, "images");
		pj_a(pj);
		ut64 total_size = cache->hdr->imagesTextCount * sizeof(cache_text_info_t);
		cache_text_info_t *text_infos = malloc(total_size);
		if (!text_infos) {
			goto beach;
		}
		if (rz_buf_fread_at(cache->buf, cache->hdr->imagesTextOffset, (ut8 *)text_infos, "16clii", cache->hdr->imagesTextCount) != total_size) {
			free(text_infos);
			goto beach;
		}
		size_t i;
		for (i = 0; i != cache->hdr->imagesTextCount; i++) {
			cache_text_info_t *text_info = &text_infos[i];
			rz_hex_bin2str((ut8 *)text_info->uuid, 16, uuidstr);
			pj_o(pj);
			pj_ks(pj, "uuid", uuidstr);
			pj_kn(pj, "address", text_info->loadAddress + slide);
			pj_kn(pj, "textSegmentSize", text_info->textSegmentSize);
			char file[256];
			if (rz_buf_read_at(cache->buf, text_info->pathOffset, (ut8 *)&file, sizeof(file)) == sizeof(file)) {
				file[255] = 0;
				pj_ks(pj, "path", file);
				char *last_slash = strrchr(file, '/');
				if (last_slash && *last_slash) {
					pj_ks(pj, "name", last_slash + 1);
				} else {
					pj_ks(pj, "name", file);
				}
			}
			pj_end(pj);
		}
		pj_end(pj);
		free(text_infos);
	}

	pj_end(pj);
	p("%s\n", pj_string(pj));

beach:
	pj_free(pj);
}

RzBinPlugin rz_bin_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyldcache bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.entries = &entries,
	.baddr = &baddr,
	.symbols = &symbols,
	.maps = &maps,
	.sections = &sections,
	.check_buffer = &check_buffer,
	.destroy = &destroy,
	.classes = &classes,
	.header = &header,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dyldcache,
	.version = RZ_VERSION
};
#endif
