// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 keegan
// SPDX-FileCopyrightText: 2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dyldcache.h"

#include <ht_pu.h>

static RzDyldLocSym *rz_dyld_locsym_new(RzBuffer *cache_buf, cache_hdr_t *hdr);

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

static void free_bin(RzDyldBinImage *bin) {
	if (!bin) {
		return;
	}
	free(bin->file);
	free(bin);
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
		free(hdr);
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

static RzList *create_cache_bins(RzBuffer *cache_buf, cache_hdr_t *hdr, cache_map_t *maps, cache_accel_t *accel) {
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
			// 32bit not supported (yet)
			break;
		case MH_MAGIC_64: {
			char file[256];
			RzDyldBinImage *bin = RZ_NEW0(RzDyldBinImage);
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

static ut64 estimate_slide(RzDyldCache *cache, ut64 value_mask, ut64 value_add) {
	ut64 slide = 0;
	ut64 *classlist = malloc(64);
	if (!classlist) {
		goto beach;
	}

	RzListIter *iter;
	RzDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		bool found_sample = false;

		struct MACH0_(opts_t) opts = { 0 };
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
		free(sections);

		if (found_sample) {
			break;
		}
	}

beach:
	free(classlist);
	return slide;
}

static RzDyldRebaseInfo *get_rebase_info(RzDyldCache *cache, ut64 slideInfoOffset, ut64 slideInfoSize, ut64 start_of_data, ut64 slide) {
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

		RzDyldRebaseInfo3 *rebase_info = RZ_NEW0(RzDyldRebaseInfo3);
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
			rebase_info->slide = estimate_slide(cache, 0x7ffffffffffffULL, 0);
			if (rebase_info->slide) {
				eprintf("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RzDyldRebaseInfo *)rebase_info;
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

		RzDyldRebaseInfo2 *rebase_info = RZ_NEW0(RzDyldRebaseInfo2);
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
			rebase_info->slide = estimate_slide(cache, rebase_info->value_mask, rebase_info->value_add);
			if (rebase_info->slide) {
				eprintf("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RzDyldRebaseInfo *)rebase_info;
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

		RzDyldRebaseInfo1 *rebase_info = RZ_NEW0(RzDyldRebaseInfo1);
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
			rebase_info->slide = estimate_slide(cache, UT64_MAX, 0);
			if (rebase_info->slide) {
				eprintf("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RzDyldRebaseInfo *)rebase_info;
	} else {
		eprintf("unsupported slide info version %d\n", slide_info_version);
		return NULL;
	}

beach:
	free(tmp_buf_1);
	free(tmp_buf_2);
	free(one_page_buf);
	return NULL;
}

static RzDyldRebaseInfos *get_rebase_infos(RzDyldCache *cache) {
	RzBuffer *cache_buf = cache->buf;

	RzDyldRebaseInfos *result = RZ_NEW0(RzDyldRebaseInfos);
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

		RzDyldRebaseInfosEntry *infos = RZ_NEWS0(RzDyldRebaseInfosEntry, n_slide_infos);
		if (!infos) {
			goto beach;
		}

		size_t i, j;
		RzDyldRebaseInfo *prev_info = NULL;
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
				infos[j].info = get_rebase_info(cache, entry.slideInfoOffset, entry.slideInfoSize, entry.fileOffset, slide);
				prev_info = infos[j].info;
				j++;
			}
		}

		if (!j) {
			free(infos);
			goto beach;
		}

		if (j != n_slide_infos) {
			RzDyldRebaseInfosEntry *pruned_infos = RZ_NEWS0(RzDyldRebaseInfosEntry, j);
			if (!pruned_infos) {
				free(infos);
				goto beach;
			}

			memcpy(pruned_infos, infos, sizeof(RzDyldRebaseInfosEntry) * j);
			free(infos);
			infos = pruned_infos;
		}

		result->entries = infos;
		result->length = j;
		return result;
	}

	if (cache->hdr->mappingCount > 1) {
		RzDyldRebaseInfosEntry *infos = RZ_NEWS0(RzDyldRebaseInfosEntry, 1);
		if (!infos) {
			goto beach;
		}

		infos[0].start = cache->maps[1].fileOffset;
		infos[0].end = infos[0].start + cache->maps[1].size;
		infos[0].info = get_rebase_info(cache, cache->hdr->slideInfoOffset, cache->hdr->slideInfoSize, infos[0].start, UT64_MAX);

		result->entries = infos;
		result->length = 1;
		return result;
	}

beach:
	free(result);
	return NULL;
}

RZ_API ut64 rz_dyldcache_get_slide(RzDyldCache *cache) {
	rz_return_val_if_fail(cache, 0);
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

RZ_API RzDyldCache *rz_dyldcache_new_buf(RzBuffer *buf) {
	RzDyldCache *cache = RZ_NEW0(RzDyldCache);
	if (!cache) {
		return NULL;
	}
	memcpy(cache->magic, "dyldcac", 7);
	cache->buf = rz_buf_ref(buf);
	cache->hdr = read_cache_header(cache->buf);
	if (!cache->hdr) {
		goto cupertino;
	}
	cache->maps = read_cache_maps(cache->buf, cache->hdr);
	if (!cache->maps) {
		goto cupertino;
	}
	cache->accel = read_cache_accel(cache->buf, cache->hdr, cache->maps);
	cache->locsym = rz_dyld_locsym_new(cache->buf, cache->hdr);
	cache->bins = create_cache_bins(cache->buf, cache->hdr, cache->maps, cache->accel);
	if (!cache->bins) {
		goto cupertino;
	}
	cache->rebase_infos = get_rebase_infos(cache);
	return cache;
cupertino:
	rz_dyldcache_free(cache);
	return NULL;
}

static void rebase_info3_free(RzDyldRebaseInfo3 *rebase_info) {
	if (!rebase_info) {
		return;
	}
	free(rebase_info->page_starts);
	free(rebase_info);
}

static void rebase_info2_free(RzDyldRebaseInfo2 *rebase_info) {
	if (!rebase_info) {
		return;
	}
	free(rebase_info->page_starts);
	free(rebase_info->page_extras);
	free(rebase_info);
}

static void rebase_info1_free(RzDyldRebaseInfo1 *rebase_info) {
	if (!rebase_info) {
		return;
	}
	free(rebase_info->toc);
	free(rebase_info->entries);
	free(rebase_info);
}

static void rebase_info_free(RzDyldRebaseInfo *rebase_info) {
	if (!rebase_info) {
		return;
	}

	RZ_FREE(rebase_info->one_page_buf);

	ut8 version = rebase_info->version;

	if (version == 1) {
		rebase_info1_free((RzDyldRebaseInfo1 *)rebase_info);
	} else if (version == 2 || version == 4) {
		rebase_info2_free((RzDyldRebaseInfo2 *)rebase_info);
	} else if (version == 3) {
		rebase_info3_free((RzDyldRebaseInfo3 *)rebase_info);
	} else {
		free(rebase_info);
	}
}

static RzDyldLocSym *rz_dyld_locsym_new(RzBuffer *cache_buf, cache_hdr_t *hdr) {
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

	RzDyldLocSym *locsym = RZ_NEW0(RzDyldLocSym);
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

static void rz_dyld_locsym_free(RzDyldLocSym *locsym) {
	if (!locsym) {
		return;
	}
	free(locsym->strings);
	free(locsym->entries);
	free(locsym->nlists);
	free(locsym);
}

RZ_API void rz_dyldcache_free(RzDyldCache *cache) {
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
	free(cache->hdr);
	free(cache->maps);
	free(cache->accel);
	rz_dyld_locsym_free(cache->locsym);
	free(cache);
}

RZ_API ut64 rz_dyldcache_va2pa(RzDyldCache *cache, uint64_t vaddr, ut32 *offset, ut32 *left) {
	rz_return_val_if_fail(cache, UT64_MAX);
	ut64 slide = rz_dyldcache_get_slide(cache);
	ut64 res = va2pa(vaddr, cache->hdr, cache->maps, cache->buf, slide, offset, left);
	if (res == UT64_MAX) {
		res = 0;
	}
	return res;
}

RZ_API void rz_dyldcache_locsym_entries_by_offset(RzDyldCache *cache, RzList *symbols, SetU *hash, ut64 bin_header_offset) {
	RzDyldLocSym *locsym = cache->locsym;
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
			ut64 slide = rz_dyldcache_get_slide(cache);
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
