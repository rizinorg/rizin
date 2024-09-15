// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 mrmacete <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_syscall.h>

#include "../format/mach0/kernelcache.h"
#include "../format/xnu/mig_index.h"

#define VFILE_NAME_PATCHED "patched"

typedef struct _RPrelinkRange {
	RzXNUKernelCacheFileRange range;
	ut64 pa2va_exec;
	ut64 pa2va_data;
} RPrelinkRange;

typedef struct _RStubsInfo {
	RzXNUKernelCacheFileRange got;
	RzXNUKernelCacheFileRange stubs;
	ut64 got_addr;
} RStubsInfo;

typedef struct _RKext {
	RzXNUKernelCacheFileRange range;
	RzXNUKernelCacheFileRange text_range;
	char *name;
	ut64 mod_info;
	ut64 vaddr;
	struct MACH0_(obj_t) * mach0;
	bool own_name;
	ut64 pa2va_exec;
	ut64 pa2va_data;
} RKext;

typedef struct _RKextIndex {
	ut64 length;
	RKext **entries;
} RKextIndex;

typedef struct _RzParsedPointer {
	ut64 address;
} RzParsedPointer;

typedef struct _RKmodInfo {
	char name[0x41];
	ut64 start;
} RKmodInfo;

#define KEXT_SHORT_NAME_FROM_SECTION(io_section) ({ \
	char *result = NULL; \
	char *clone = rz_str_dup(io_section->name); \
	char *cursor = strstr(clone, "__"); \
	if (cursor) { \
		cursor--; \
		*cursor = 0; \
		cursor--; \
		cursor = strrchr(cursor, '.'); \
		if (cursor) { \
			*cursor = 0; \
			cursor = strrchr(cursor, '.'); \
			if (cursor) { \
				result = rz_str_dup(cursor + 1); \
				RZ_FREE(clone); \
			} \
		} \
	} \
	result ? result : clone; \
})

#define KEXT_INFER_VSIZE(index, i) \
	((i + 1 < index->length) ? index->entries[i + 1]->vaddr - index->entries[i]->vaddr : UT64_MAX)

#define KEXT_INFER_PSIZE(index, i) \
	((i + 1 < index->length) ? index->entries[i + 1]->range.offset - index->entries[i]->range.offset : UT64_MAX)

#define RZ_K_CONSTRUCTOR_TO_ENTRY  0
#define RZ_K_CONSTRUCTOR_TO_SYMBOL 1

#define K_PPTR(p)   p_ptr(p, obj)
#define K_RPTR(buf) rz_ptr(buf, obj)

#define IS_PTR_AUTH(x) ((x & (1ULL << 63)) != 0)
#define IS_PTR_BIND(x) ((x & (1ULL << 62)) != 0)

static ut64 p_ptr(ut64 decorated_addr, RzXNUKernelCacheObj *obj);
static ut64 rz_ptr(ut8 *buf, RzXNUKernelCacheObj *obj);

static RzXNUKernelCacheRebaseInfo *rz_rebase_info_new_from_mach0(RzBuffer *cache_buf, struct MACH0_(obj_t) * mach0);
static void rz_rebase_info_free(RzXNUKernelCacheRebaseInfo *info);

static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) * mach0);
static RzList /*<RKext *>*/ *filter_kexts(RzXNUKernelCacheObj *obj);
static RzList /*<RKext *>*/ *carve_kexts(RzXNUKernelCacheObj *obj);
static RzList /*<RKext *>*/ *kexts_from_load_commands(RzXNUKernelCacheObj *obj);

static void sections_from_mach0(RzPVector /*<RzBinSection *>*/ *ret, struct MACH0_(obj_t) * mach0, RzBinFile *bf, ut64 paddr, char *prefix, RzXNUKernelCacheObj *obj);
static void handle_data_sections(RzBinSection *sect);
static void symbols_from_mach0(RzPVector /*<RzBinSymbol *>*/ *ret, struct MACH0_(obj_t) * mach0, RzBinFile *bf, ut64 paddr, int ordinal);
static RzList /*<RzBinSymbol *>*/ *resolve_syscalls(RzXNUKernelCacheObj *obj, ut64 enosys_addr);
static RzList /*<RzBinSymbol *>*/ *resolve_mig_subsystem(RzXNUKernelCacheObj *obj);
static void symbols_from_stubs(RzPVector /*<RzBinSymbol *>*/ *ret, HtUP /*<ut64, char *>*/ *kernel_syms_by_addr, RzXNUKernelCacheObj *obj, RzBinFile *bf, RKext *kext, int ordinal);
static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) * mach0, ut64 paddr, RzXNUKernelCacheObj *obj);
static int prot2perm(int x);

static void rz_kext_free(RKext *kext);
static void rz_kext_fill_text_range(RKext *kext);
static int kexts_sort_vaddr_func(const void *a, const void *b, void *user);
static struct MACH0_(obj_t) * create_kext_mach0(RzXNUKernelCacheObj *obj, RKext *kext);
static struct MACH0_(obj_t) * create_kext_shared_mach0(RzXNUKernelCacheObj *obj, RKext *kext);

#define rz_kext_index_foreach(index, i, item) \
	if (index) \
		for (i = 0; i < index->length && (item = index->entries[i], 1); i++)

static RKextIndex *rz_kext_index_new(RzList /*<RKext *>*/ *kexts);
static void rz_kext_index_free(RKextIndex *index);
static RKext *rz_kext_index_vget(RKextIndex *index, ut64 vaddr);

static void process_kmod_init_term(RzXNUKernelCacheObj *obj, RKext *kext, RzPVector /*<RzBinSymbol *>*/ *ret, ut64 **inits, ut64 **terms);
static void create_initterm_syms(RKext *kext, RzPVector /*<RzBinSymbol *>*/ *ret, int type, ut64 *pointers);
static void process_constructors(RzXNUKernelCacheObj *obj, struct MACH0_(obj_t) * mach0, RzPVector /*<void *>*/ *ret, ut64 paddr, bool is_first, int mode, const char *prefix);
static RzBinAddr *newEntry(ut64 haddr, ut64 vaddr, int type);
static void ensure_kexts_initialized(RzXNUKernelCacheObj *obj);

static void rz_kernel_cache_free(RzXNUKernelCacheObj *obj);

static bool load_buffer(RzBinFile *bf, RzBinObject *o, RzBuffer *buf, Sdb *sdb) {
	RzBuffer *fbuf = rz_buf_ref(buf);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default)
	(&opts, bf);
	struct MACH0_(obj_t) *main_mach0 = MACH0_(new_buf)(fbuf, &opts);
	if (!main_mach0) {
		return false;
	}

	RzXNUKernelCacheRebaseInfo *rebase_info = rz_rebase_info_new_from_mach0(fbuf, main_mach0);
	RzXNUKernelCacheObj *obj = NULL;

	RPrelinkRange *prelink_range = get_prelink_info_range_from_mach0(main_mach0);
	if (!prelink_range) {
		goto beach;
	}

	obj = RZ_NEW0(RzXNUKernelCacheObj);
	if (!obj) {
		RZ_FREE(prelink_range);
		goto beach;
	}

	RzCFValueDict *prelink_info = NULL;
	if (main_mach0->hdr.filetype != MH_FILESET && prelink_range->range.size) {
		prelink_info = rz_cf_value_dict_parse(fbuf, prelink_range->range.offset,
			prelink_range->range.size, RZ_CF_OPTION_SKIP_NSDATA | RZ_CF_OPTION_SUPPORT_IDREF);
		if (!prelink_info) {
			RZ_FREE(prelink_range);
			RZ_FREE(obj);
			goto beach;
		}
	}

	obj->mach0 = main_mach0;
	obj->rebase_info = rebase_info;
	obj->prelink_info = prelink_info;
	obj->cache_buf = fbuf;
	obj->pa2va_exec = prelink_range->pa2va_exec;
	obj->pa2va_data = prelink_range->pa2va_data;

	o->bin_obj = obj;

	if (rz_xnu_kernelcache_needs_rebasing(obj)) {
		obj->patched_buf = rz_xnu_kernelcache_new_patched_buf(obj);
	}

	return true;

beach:
	rz_buf_free(fbuf);
	MACH0_(mach0_free)
	(main_mach0);
	return false;
}

static void ensure_kexts_initialized(RzXNUKernelCacheObj *obj) {
	if (obj->kexts_initialized) {
		return;
	}
	obj->kexts_initialized = true;

	RzList *kexts = NULL;

	if (obj->prelink_info) {
		kexts = filter_kexts(obj);
	}

	if (kexts && !rz_list_length(kexts)) {
		rz_list_free(kexts);
		kexts = NULL;
	}

	if (!kexts) {
		kexts = kexts_from_load_commands(obj);
	}

	if (kexts && !rz_list_length(kexts)) {
		rz_list_free(kexts);
		kexts = NULL;
	}

	if (!kexts) {
		kexts = carve_kexts(obj);
	}

	obj->kexts = rz_kext_index_new(kexts);
}

static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) * mach0) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return NULL;
	}

	RPrelinkRange *prelink_range = RZ_NEW0(RPrelinkRange);
	if (!prelink_range) {
		RZ_FREE(sections);
		return NULL;
	}

	int incomplete = 3;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__PRELINK_INFO.__info")) {
			prelink_range->range.offset = sections[i].offset;
			prelink_range->range.size = sections[i].size;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr(sections[i].name, "__PRELINK_TEXT.__text")) {
			prelink_range->pa2va_exec = sections[i].addr - sections[i].offset;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr(sections[i].name, "__PRELINK_DATA.__data")) {
			prelink_range->pa2va_data = sections[i].addr - sections[i].offset;
			if (!--incomplete) {
				break;
			}
		}
	}

	RZ_FREE(sections);

	if (incomplete == 1 && !prelink_range->pa2va_data) {
		struct MACH0_(segment_command) * seg;
		int nsegs = RZ_MIN(mach0->nsegs, 128);
		size_t i;
		for (i = 0; i < nsegs; i++) {
			seg = &mach0->segs[i];
			if (!strcmp(seg->segname, "__DATA")) {
				prelink_range->pa2va_data = seg->vmaddr - seg->fileoff;
				incomplete--;
				break;
			}
		}
	}

	if (incomplete) {
		RZ_FREE(prelink_range);
	}

	return prelink_range;
}

static RzList /*<RKext *>*/ *filter_kexts(RzXNUKernelCacheObj *obj) {
	RzCFValueArray *kext_array = NULL;
	RzListIter *iter;
	RzCFKeyValue *item;
	rz_list_foreach (obj->prelink_info->pairs, iter, item) {
		if (!strcmp(item->key, "_PrelinkInfoDictionary")) {
			kext_array = (RzCFValueArray *)item->value;
			break;
		}
	}

	if (!kext_array) {
		return NULL;
	}

	RzList *kexts = rz_list_newf((RzListFree)&rz_kext_free);
	if (!kexts) {
		return NULL;
	}

	bool is_sorted = true;
	RKext *prev_kext = NULL;
	RzCFValueDict *kext_item;
	rz_list_foreach (kext_array->values, iter, kext_item) {
		RKext *kext = RZ_NEW0(RKext);
		if (!kext) {
			RZ_FREE(kexts);
			return NULL;
		}

		int kext_incomplete = 5;
		RzListIter *internal_iter;
		rz_list_foreach (kext_item->pairs, internal_iter, item) {
			if (!strcmp(item->key, "CFBundlePackageType")) {
				if (item->value->type != RZ_CF_STRING) {
					break;
				}
				RzCFValueString *type = (RzCFValueString *)item->value;
				if (strcmp(type->value, "KEXT")) {
					break;
				}
				kext_incomplete--;
			}

			if (!strcmp(item->key, "_PrelinkExecutableLoadAddr")) {
				if (item->value->type == RZ_CF_INTEGER) {
					kext_incomplete--;
					kext->vaddr = ((RzCFValueInteger *)item->value)->value;
					kext->range.offset = kext->vaddr - obj->pa2va_exec;
				}
			}

			if (!strcmp(item->key, "_PrelinkExecutableSize")) {
				kext_incomplete--;
				if (item->value->type == RZ_CF_INTEGER) {
					kext->range.size = ((RzCFValueInteger *)item->value)->value;
				} else {
					kext->range.size = 0;
				}
			}

			if (!strcmp(item->key, "_PrelinkKmodInfo")) {
				if (item->value->type == RZ_CF_INTEGER) {
					kext_incomplete--;
					kext->mod_info = ((RzCFValueInteger *)item->value)->value;
					kext->mod_info -= obj->pa2va_data;
				}
			}

			if (!strcmp(item->key, "CFBundleIdentifier")) {
				if (item->value->type == RZ_CF_STRING) {
					kext_incomplete--;
					kext->name = ((RzCFValueString *)item->value)->value;
				}
			}
		}

		if (kext_incomplete) {
			rz_kext_free(kext);
			continue;
		}

		if (prev_kext && kext->vaddr < prev_kext->vaddr) {
			is_sorted = false;
		}
		prev_kext = kext;

		kext->mach0 = create_kext_mach0(obj, kext);
		if (!kext->mach0) {
			rz_kext_free(kext);
			continue;
		}

		rz_kext_fill_text_range(kext);

		rz_list_push(kexts, kext);
	}

	if (!is_sorted) {
		eprintf("SORTING KEXTs...\n");
		rz_list_sort(kexts, kexts_sort_vaddr_func, NULL);
	}
	return kexts;
}

static ut64 p_ptr(ut64 decorated_addr, RzXNUKernelCacheObj *obj) {
	RzXNUKernelCacheParsedPointer ptr;
	rz_xnu_kernelcache_parse_pointer(&ptr, decorated_addr, obj);
	return ptr.address;
}

static ut64 rz_ptr(ut8 *buf, RzXNUKernelCacheObj *obj) {
	ut64 decorated_addr = rz_read_le64(buf);
	return K_PPTR(decorated_addr);
}

static RzList /*<RKext *>*/ *carve_kexts(RzXNUKernelCacheObj *obj) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(obj->mach0))) {
		return NULL;
	}

	ut64 pa2va_exec = 0;
	ut64 pa2va_data = 0;
	ut64 kmod_start = 0, kmod_end = 0;
	ut64 kmod_info = 0, kmod_info_end = 0;
	int incomplete = 4;
	RKmodInfo *all_infos = NULL;

	int i = 0;
	for (; !sections[i].last && incomplete > 0; i++) {
		if (strstr(sections[i].name, "__TEXT_EXEC.__text")) {
			pa2va_exec = sections[i].addr - sections[i].offset;
			incomplete--;
		}
		if (strstr(sections[i].name, "__DATA.__data")) {
			pa2va_data = sections[i].addr - sections[i].offset;
			incomplete--;
		}
		if (strstr(sections[i].name, "__PRELINK_INFO.__kmod_start")) {
			kmod_start = sections[i].offset;
			kmod_end = kmod_start + sections[i].size;
			incomplete--;
		}
		if (strstr(sections[i].name, "__PRELINK_INFO.__kmod_info")) {
			kmod_info = sections[i].offset;
			kmod_info_end = kmod_info + sections[i].size;
			incomplete--;
		}
	}

	RZ_FREE(sections);

	if (incomplete) {
		return NULL;
	}

	RzList *kexts = rz_list_newf((RzListFree)&rz_kext_free);
	if (!kexts) {
		return NULL;
	}

	int n_kmod_info = (kmod_info_end - kmod_info) / 8;
	if (n_kmod_info == 0) {
		goto beach;
	}

	all_infos = RZ_NEWS0(RKmodInfo, n_kmod_info);
	if (!all_infos) {
		goto beach;
	}

	ut8 bytes[8];
	int j = 0;
	for (; j < n_kmod_info; j++) {
		ut64 entry_offset = j * 8 + kmod_info;

		if (rz_buf_read_at(obj->cache_buf, entry_offset, bytes, 8) < 8) {
			goto beach;
		}

		ut64 kmod_info_paddr = K_RPTR(bytes) - pa2va_data;

		ut64 field_name = kmod_info_paddr + 0x10;
		ut64 field_start = kmod_info_paddr + 0xb4;

		if (rz_buf_read_at(obj->cache_buf, field_start, bytes, 8) < 8) {
			goto beach;
		}

		all_infos[j].start = K_RPTR(bytes);

		if (rz_buf_read_at(obj->cache_buf, field_name, (ut8 *)all_infos[j].name, 0x40) < 0x40) {
			goto beach;
		}

		all_infos[j].name[0x40] = 0;
	}

	ut64 cursor = kmod_start;
	for (; cursor < kmod_end; cursor += 8) {
		ut8 bytes[8];
		if (rz_buf_read_at(obj->cache_buf, cursor, bytes, 8) < 8) {
			goto beach;
		}

		RKext *kext = RZ_NEW0(RKext);
		if (!kext) {
			goto beach;
		}

		kext->vaddr = K_RPTR(bytes);
		kext->range.offset = kext->vaddr - pa2va_exec;

		kext->mach0 = create_kext_mach0(obj, kext);
		if (!kext->mach0) {
			rz_kext_free(kext);
			continue;
		}

		rz_kext_fill_text_range(kext);
		kext->vaddr = K_PPTR(kext->vaddr);
		kext->pa2va_exec = pa2va_exec;
		kext->pa2va_data = pa2va_data;

		ut64 text_start = kext->vaddr;
		ut64 text_end = text_start + kext->text_range.size;

		if (text_start == text_end) {
			rz_kext_free(kext);
			continue;
		}

		for (j = 0; j < n_kmod_info; j++) {
			if (text_start > all_infos[j].start || all_infos[j].start >= text_end) {
				continue;
			}

			kext->name = rz_str_dup(all_infos[j].name);
			kext->own_name = true;
			break;
		}

		if (!kext->name) {
			rz_kext_free(kext);
			continue;
		}

		rz_list_push(kexts, kext);
	}

	RZ_FREE(all_infos);
	return kexts;

beach:
	rz_list_free(kexts);
	RZ_FREE(all_infos);
	return NULL;
}

static RzList /*<RKext *>*/ *kexts_from_load_commands(RzXNUKernelCacheObj *obj) {
	RzList *kexts = rz_list_newf((RzListFree)&rz_kext_free);
	if (!kexts) {
		return NULL;
	}

	ut32 i;
	ut32 ncmds;
	if (!rz_buf_read_le32_at(obj->cache_buf, 16, &ncmds)) {
		rz_list_free(kexts);
		return NULL;
	}

	ut64 length = rz_buf_size(obj->cache_buf);

	ut32 cursor = sizeof(struct MACH0_(mach_header));
	for (i = 0; i < ncmds && cursor < length; i++) {
		ut32 cmdtype;
		if (!rz_buf_read_le32_at(obj->cache_buf, cursor, &cmdtype)) {
			rz_list_free(kexts);
			return NULL;
		}

		ut32 cmdsize;
		if (!rz_buf_read_le32_at(obj->cache_buf, cursor + 4, &cmdsize)) {
			rz_list_free(kexts);
			return NULL;
		}

		if (cmdtype != LC_KEXT) {
			cursor += cmdsize;
			continue;
		}

		ut64 vaddr;
		if (!rz_buf_read_le64_at(obj->cache_buf, cursor + 8, &vaddr)) {
			rz_list_free(kexts);
			return NULL;
		}

		ut64 paddr;
		if (!rz_buf_read_le64_at(obj->cache_buf, cursor + 16, &paddr)) {
			rz_list_free(kexts);
			return NULL;
		}

		st32 padded_name_length = (st32)cmdsize - 32;
		if (padded_name_length <= 0) {
			cursor += cmdsize;
			continue;
		}

		char *padded_name = calloc(1, padded_name_length);
		if (!padded_name) {
			goto beach;
		}
		if (rz_buf_read_at(obj->cache_buf, cursor + 32, (ut8 *)padded_name, padded_name_length) != padded_name_length) {
			free(padded_name);
			goto early;
		}

		RKext *kext = RZ_NEW0(RKext);
		if (!kext) {
			free(padded_name);
			goto beach;
		}

		kext->vaddr = vaddr;
		kext->range.offset = paddr;

		kext->mach0 = create_kext_shared_mach0(obj, kext);
		if (!kext->mach0) {
			free(padded_name);
			rz_kext_free(kext);
			cursor += cmdsize;
			continue;
		}

		rz_kext_fill_text_range(kext);
		kext->vaddr = K_PPTR(kext->vaddr);
		kext->pa2va_exec = obj->pa2va_exec;
		kext->pa2va_data = obj->pa2va_data;
		kext->name = rz_str_dup(padded_name);
		kext->own_name = true;
		free(padded_name);
		rz_list_push(kexts, kext);

		cursor += cmdsize;
	}
early:
	return kexts;
beach:
	rz_list_free(kexts);
	return NULL;
}

static void rz_kext_free(RKext *kext) {
	if (!kext) {
		return;
	}

	if (kext->mach0) {
		MACH0_(mach0_free)
		(kext->mach0);
		kext->mach0 = NULL;
	}

	if (kext->own_name && kext->name) {
		RZ_FREE(kext->name);
		kext->name = NULL;
	}

	RZ_FREE(kext);
}

static void rz_kext_fill_text_range(RKext *kext) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(kext->mach0))) {
		return;
	}

	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__TEXT_EXEC.__text")) {
			kext->text_range.offset = sections[i].offset;
			kext->text_range.size = sections[i].size;
			kext->vaddr = sections[i].addr;
			break;
		}
	}

	RZ_FREE(sections);
}

static int kexts_sort_vaddr_func(const void *a, const void *b, void *user) {
	RKext *A = (RKext *)a;
	RKext *B = (RKext *)b;
	int vaddr_compare = A->vaddr - B->vaddr;
	if (vaddr_compare == 0) {
		return A->text_range.size - B->text_range.size;
	}
	return vaddr_compare;
}

static RKextIndex *rz_kext_index_new(RzList /*<RKext *>*/ *kexts) {
	if (!kexts) {
		return NULL;
	}

	int length = rz_list_length(kexts);
	if (!length) {
		return NULL;
	}

	RKextIndex *index = RZ_NEW0(RKextIndex);
	if (!index) {
		return NULL;
	}

	index->entries = malloc(length * sizeof(RKext *));
	if (!index->entries) {
		RZ_FREE(index);
		return NULL;
	}

	RzListIter *iter;
	RKext *kext;
	int i = 0;
	rz_list_foreach (kexts, iter, kext) {
		index->entries[i++] = kext;
	}
	index->length = i;

	return index;
}

static void rz_kext_index_free(RKextIndex *index) {
	if (!index) {
		return;
	}

	int i = 0;
	RKext *kext;
	rz_kext_index_foreach(index, i, kext) {
		rz_kext_free(kext);
		index->entries[i] = NULL;
	}

	index->length = 0;
	RZ_FREE(index);
}

static RKext *rz_kext_index_vget(RKextIndex *index, ut64 vaddr) {
	int imid;
	int imin = 0;
	int imax = index->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RKext *entry = index->entries[imid];
		if ((entry->vaddr + entry->text_range.size) <= vaddr || (entry->vaddr == vaddr && entry->text_range.size == 0)) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RKext *minEntry = index->entries[imin];
	if ((imax == imin) && (minEntry->vaddr <= vaddr) && ((minEntry->vaddr + minEntry->text_range.size) > vaddr)) {
		return minEntry;
	}
	return NULL;
}

static struct MACH0_(obj_t) * create_kext_mach0(RzXNUKernelCacheObj *obj, RKext *kext) {
	RzBuffer *buf = rz_buf_new_slice(obj->cache_buf, kext->range.offset, rz_buf_size(obj->cache_buf) - kext->range.offset);
	struct MACH0_(opts_t) opts = { 0 };
	opts.verbose = true;
	opts.header_at = 0;
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(buf, &opts);
	rz_buf_free(buf);
	return mach0;
}

static struct MACH0_(obj_t) * create_kext_shared_mach0(RzXNUKernelCacheObj *obj, RKext *kext) {
	RzBuffer *buf = rz_buf_ref(obj->cache_buf);
	struct MACH0_(opts_t) opts = { 0 };
	opts.verbose = false;
	opts.header_at = kext->range.offset;
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(buf, &opts);
	rz_buf_free(buf);
	return mach0;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinObject *obj = bf ? bf->o : NULL;

	if (!obj || !obj->bin_obj || !(ret = rz_pvector_new(free))) {
		return NULL;
	}

	RzXNUKernelCacheObj *kobj = (RzXNUKernelCacheObj *)obj->bin_obj;
	ut64 entry_vaddr = kobj->mach0->entry;
	if (kobj->pa2va_exec <= entry_vaddr) {
		ut64 entry_paddr = entry_vaddr - kobj->pa2va_exec;
		RzBinAddr *ba = newEntry(entry_paddr, entry_vaddr, 0);
		if (ba) {
			rz_pvector_push(ret, ba);
		}
	}

	process_constructors(kobj, kobj->mach0, ret, 0, true, RZ_K_CONSTRUCTOR_TO_ENTRY, NULL);

	return ret;
}

static void process_kmod_init_term(RzXNUKernelCacheObj *obj, RKext *kext, RzPVector /*<RzBinSymbol *>*/ *ret, ut64 **inits, ut64 **terms) {
	if (!*inits || !*terms) {
		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections)(obj->mach0))) {
			return;
		}

		int i = 0;
		for (; !sections[i].last; i++) {
			if (sections[i].size == 0) {
				continue;
			}

			ut64 start_paddr = 0;
			ut64 *target = NULL;
			int n_ptrs = 0;

			if (!*inits && strstr(sections[i].name, "__kmod_init")) {
				int n_inits = sections[i].size / 8;
				if (n_inits <= 0) {
					continue;
				}
				*inits = RZ_NEWS0(ut64, n_inits + 1);
				target = *inits;
				n_ptrs = n_inits;
			}
			if (!*terms && strstr(sections[i].name, "__kmod_term")) {
				int n_terms = sections[i].size / 8;
				if (n_terms <= 0) {
					continue;
				}
				*terms = RZ_NEWS0(ut64, n_terms + 1);
				target = *terms;
				n_ptrs = n_terms;
			}
			if (!target || !n_ptrs) {
				continue;
			}
			start_paddr = sections[i].offset;
			int j = 0;
			ut8 bytes[8];
			for (; j < n_ptrs; j++) {
				if (rz_buf_read_at(obj->cache_buf, start_paddr + j * 8, bytes, 8) < 8) {
					break;
				}
				target[j] = K_RPTR(bytes);
			}
			target[j] = 0;
		}

		RZ_FREE(sections);
	}

	if (*inits) {
		create_initterm_syms(kext, ret, RZ_BIN_ENTRY_TYPE_INIT, *inits);
	}
	if (*terms) {
		create_initterm_syms(kext, ret, RZ_BIN_ENTRY_TYPE_FINI, *terms);
	}
}

/*
 * com.apple.driver.AppleMesaSEPDriver.3.__TEXT_EXEC.__text
 *                       |
 *                       |
 * AppleMesaSEPDriver <--+
 */
static const char *kext_short_name(RKext *kext) {
	const char *sn = strrchr(kext->name, '.');
	return sn ? sn + 1 : kext->name;
}

static void create_initterm_syms(RKext *kext, RzPVector /*<RzBinSymbol *>*/ *ret, int type, ut64 *pointers) {
	int i = 0;
	int count = 0;
	for (; pointers[i]; i++) {
		ut64 func_vaddr = pointers[i];
		ut64 text_start = kext->vaddr;
		ut64 text_end = text_start + kext->text_range.size;

		if (text_start == text_end) {
			continue;
		}

		if (text_start > func_vaddr || func_vaddr >= text_end) {
			continue;
		}

		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}

		sym->name = rz_str_newf("%s.%s.%d", kext_short_name(kext), (type == RZ_BIN_ENTRY_TYPE_INIT) ? "init" : "fini", count++);
		sym->vaddr = func_vaddr;
		sym->paddr = func_vaddr - kext->pa2va_exec;
		sym->size = 0;
		sym->forwarder = "NONE";
		sym->bind = "GLOBAL";
		sym->type = "FUNC";

		rz_pvector_push(ret, sym);
	}
}

static void process_constructors(RzXNUKernelCacheObj *obj, struct MACH0_(obj_t) * mach0, RzPVector /*<void *>*/ *ret, ut64 paddr, bool is_first, int mode, const char *prefix) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return;
	}
	int i, type;
	for (i = 0; !sections[i].last; i++) {
		if (sections[i].size == 0) {
			continue;
		}

		if (strstr(sections[i].name, "_mod_fini_func") || strstr(sections[i].name, "_mod_term_func")) {
			type = RZ_BIN_ENTRY_TYPE_FINI;
		} else if (strstr(sections[i].name, "_mod_init_func")) {
			type = is_first ? 0 : RZ_BIN_ENTRY_TYPE_INIT;
			is_first = false;
		} else {
			continue;
		}

		ut8 *buf = calloc(sections[i].size, 1);
		if (!buf) {
			break;
		}
		if (rz_buf_read_at(obj->cache_buf, sections[i].offset + paddr, buf, sections[i].size) < sections[i].size) {
			free(buf);
			break;
		}
		int j;
		int count = 0;
		for (j = 0; j < sections[i].size; j += 8) {
			ut64 addr64 = K_RPTR(buf + j);
			ut64 paddr64 = sections[i].offset + paddr + j;
			if (mode == RZ_K_CONSTRUCTOR_TO_ENTRY) {
				RzBinAddr *ba = newEntry(paddr64, addr64, type);
				rz_pvector_push(ret, ba);
			} else if (mode == RZ_K_CONSTRUCTOR_TO_SYMBOL) {
				RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
				if (!sym) {
					break;
				}

				sym->name = rz_str_newf("%s.%s.%d", prefix, (type == RZ_BIN_ENTRY_TYPE_INIT) ? "init" : "fini", count++);
				sym->vaddr = addr64;
				sym->paddr = paddr64;
				sym->size = 0;
				sym->forwarder = "NONE";
				sym->bind = "GLOBAL";
				sym->type = "FUNC";

				rz_pvector_push(ret, sym);
			}
		}
		free(buf);
	}
	free(sections);
}

static RzBinAddr *newEntry(ut64 haddr, ut64 vaddr, int type) {
	RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
	if (!ptr) {
		return NULL;
	}
	ptr->paddr = haddr;
	ptr->vaddr = vaddr;
	ptr->hpaddr = haddr;
	ptr->bits = 64;
	ptr->type = type;
	return ptr;
}

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 4) {
		ut8 buf[4];
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		if (!memcmp(buf, "\xcf\xfa\xed\xfe", 4)) {
			return rz_xnu_kernelcache_buf_is_kernelcache(b);
		}
	}
	return false;
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!ret) {
		return NULL;
	}
	RzXNUKernelCacheObj *kobj = bf->o->bin_obj;
	if (kobj->patched_buf) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return ret;
		}
		vf->buf = kobj->patched_buf;
		vf->buf_owned = false;
		vf->name = rz_str_dup(VFILE_NAME_PATCHED);
		rz_pvector_push(ret, vf);
	}
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzBinObject *obj = bf ? bf->o : NULL;
	if (!obj || !obj->bin_obj) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzXNUKernelCacheObj *kobj = (RzXNUKernelCacheObj *)obj->bin_obj;
	ensure_kexts_initialized(kobj);

	int nsegs = RZ_MIN(kobj->mach0->nsegs, 128);
	int i;
	for (i = 0; i < nsegs; i++) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			break;
		}
		char segname[17];
		struct MACH0_(segment_command) *seg = &kobj->mach0->segs[i];
		rz_str_ncpy(segname, seg->segname, 17);
		rz_str_filter(segname);
		map->name = rz_str_newf("%d.%s", i, segname);
		map->paddr = seg->fileoff + bf->o->boffset;
		map->psize = seg->vmsize;
		map->vsize = seg->vmsize;
		map->vaddr = seg->vmaddr;
		if (!map->vaddr) {
			map->vaddr = map->paddr;
		}
		map->perm = prot2perm(seg->initprot);
		map->vfile_name = kobj->patched_buf ? rz_str_dup(VFILE_NAME_PATCHED) : NULL;
		rz_pvector_push(ret, map);
	}

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinObject *obj = bf ? bf->o : NULL;

	if (!obj || !obj->bin_obj || !(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}

	RzXNUKernelCacheObj *kobj = (RzXNUKernelCacheObj *)obj->bin_obj;
	ensure_kexts_initialized(kobj);

	int iter;
	RKext *kext;
	rz_kext_index_foreach(kobj->kexts, iter, kext) {
		ut8 magicbytes[4];

		rz_buf_read_at(kobj->cache_buf, kext->range.offset, magicbytes, 4);
		int magic = rz_read_le32(magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			sections_from_mach0(ret, kext->mach0, bf, kext->range.offset, kext->name, kobj);
			break;
		default:
			eprintf("Unknown sub-bin\n");
			break;
		}
	}

	sections_from_mach0(ret, kobj->mach0, bf, 0, NULL, kobj);

	struct MACH0_(segment_command) * seg;
	int nsegs = RZ_MIN(kobj->mach0->nsegs, 128);
	int i;
	for (i = 0; i < nsegs; i++) {
		RzBinSection *ptr;
		char segname[17];

		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}

		seg = &kobj->mach0->segs[i];
		rz_str_ncpy(segname, seg->segname, 17);
		rz_str_filter(segname);
		ptr->name = rz_str_newf("%d.%s", i, segname);
		ptr->size = seg->vmsize;
		ptr->vsize = seg->vmsize;
		ptr->paddr = seg->fileoff + bf->o->boffset;
		ptr->vaddr = seg->vmaddr;
		ptr->is_segment = true;
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = prot2perm(seg->initprot);
		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static int prot2perm(int x) {
	int r = 0;
	if (x & 1)
		r |= 4;
	if (x & 2)
		r |= 2;
	if (x & 4)
		r |= 1;
	return r;
}

static void sections_from_mach0(RzPVector /*<RzBinSection *>*/ *ret, struct MACH0_(obj_t) * mach0, RzBinFile *bf, ut64 paddr, char *prefix, RzXNUKernelCacheObj *obj) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return;
	}
	int i;
	for (i = 0; !sections[i].last; i++) {
		RzBinSection *ptr;
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		if (prefix) {
			ptr->name = rz_str_newf("%s.%s", prefix, (char *)sections[i].name);
		} else {
			ptr->name = rz_str_newf("%s", (char *)sections[i].name);
		}
		if (strstr(ptr->name, "la_symbol_ptr")) {
			int len = sections[i].size / 8;
			ptr->format = rz_str_newf("Cd %d %d", 8, len);
		}
		handle_data_sections(ptr);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].offset + bf->o->boffset + paddr;
		ptr->vaddr = K_PPTR(sections[i].addr);
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = sections[i].perm;
		if (!ptr->perm && strstr(sections[i].name, "__TEXT_EXEC.__text")) {
			ptr->perm = 1 | 4;
		}
		rz_pvector_push(ret, ptr);
	}
	free(sections);
}

static void handle_data_sections(RzBinSection *sect) {
	if (strstr(sect->name, "_cstring")) {
		sect->is_data = true;
	} else if (strstr(sect->name, "_os_log")) {
		sect->is_data = true;
	} else if (strstr(sect->name, "_objc_methname")) {
		sect->is_data = true;
	} else if (strstr(sect->name, "_objc_classname")) {
		sect->is_data = true;
	} else if (strstr(sect->name, "_objc_methtype")) {
		sect->is_data = true;
	}
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzXNUKernelCacheObj *obj = (RzXNUKernelCacheObj *)bf->o->bin_obj;

	symbols_from_mach0(ret, obj->mach0, bf, 0, 0);

	HtUP *kernel_syms_by_addr = ht_up_new((HtUPDupValue)rz_str_dup, free);
	if (!kernel_syms_by_addr) {
		rz_pvector_free(ret);
		return NULL;
	}

	RzListIter *iter;
	void **it;
	RzBinSymbol *sym;
	ut64 enosys_addr = 0;
	rz_pvector_foreach (ret, it) {
		sym = *it;
		ht_up_insert(kernel_syms_by_addr, sym->vaddr, sym->dname ? sym->dname : sym->name);
		if (!enosys_addr && strstr(sym->name, "enosys")) {
			enosys_addr = sym->vaddr;
		}
	}

	RzList *syscalls = resolve_syscalls(obj, enosys_addr);
	if (syscalls) {
		rz_list_foreach (syscalls, iter, sym) {
			ht_up_insert(kernel_syms_by_addr, sym->vaddr, sym->name);
			rz_pvector_push(ret, sym);
		}
		syscalls->free = NULL;
		rz_list_free(syscalls);
	}

	RzList *subsystem = resolve_mig_subsystem(obj);
	if (subsystem) {
		rz_list_foreach (subsystem, iter, sym) {
			ht_up_insert(kernel_syms_by_addr, sym->vaddr, sym->name);
			rz_pvector_push(ret, sym);
		}
		subsystem->free = NULL;
		rz_list_free(subsystem);
	}

	ensure_kexts_initialized(obj);

	RKext *kext;
	int kiter;
	ut64 *inits = NULL;
	ut64 *terms = NULL;
	rz_kext_index_foreach(obj->kexts, kiter, kext) {
		ut8 magicbytes[4];
		rz_buf_read_at(obj->cache_buf, kext->range.offset, magicbytes, 4);
		int magic = rz_read_le32(magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			symbols_from_mach0(ret, kext->mach0, bf, kext->range.offset, rz_pvector_len(ret));
			symbols_from_stubs(ret, kernel_syms_by_addr, obj, bf, kext, rz_pvector_len(ret));
			process_constructors(obj, kext->mach0, ret, kext->range.offset, false, RZ_K_CONSTRUCTOR_TO_SYMBOL, kext_short_name(kext));
			process_kmod_init_term(obj, kext, ret, &inits, &terms);

			break;
		default:
			eprintf("Unknown sub-bin\n");
			break;
		}
	}

	free(inits);
	free(terms);
	ht_up_free(kernel_syms_by_addr);

	return ret;
}

static void symbols_from_mach0(RzPVector /*<RzBinSymbol *>*/ *ret, struct MACH0_(obj_t) * mach0, RzBinFile *bf, ut64 paddr, int ordinal) {
	const struct symbol_t *symbols = MACH0_(get_symbols)(mach0);
	if (!symbols) {
		return;
	}
	int i;
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = rz_str_dup(symbols[i].name);
		sym->vaddr = symbols[i].addr;
		sym->forwarder = "NONE";
		sym->bind = (symbols[i].type == RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL) ? "LOCAL" : "GLOBAL";
		sym->type = "FUNC";
		sym->paddr = symbols[i].offset + bf->o->boffset + paddr;
		sym->size = symbols[i].size;
		sym->ordinal = ordinal + i;
		rz_pvector_push(ret, sym);
	}
}

#define IS_KERNEL_ADDR(x) ((x & 0xfffffff000000000L) == 0xfffffff000000000L)

typedef struct _r_sysent {
	ut64 sy_call;
	ut64 sy_arg_munge32;
	st32 sy_return_type;
	st16 sy_narg;
	ut16 sy_arg_bytes;
} RSysEnt;

/**
 * Search for the struct sysent sysent[] array of xnu and assign names to all syscall
 * handlers referenced by it.
 */
static RzList /*<RzBinSymbol *>*/ *resolve_syscalls(RzXNUKernelCacheObj *obj, ut64 enosys_addr) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(obj->mach0))) {
		return NULL;
	}

	RzList *syscalls = NULL;
	RzSyscall *syscall = NULL;
	ut8 *data_const = NULL;
	ut64 data_const_offset = 0, data_const_size = 0, data_const_vaddr = 0;
	for (int i = 0; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__DATA_CONST.__const")) {
			data_const_offset = sections[i].offset;
			data_const_size = sections[i].size;
			data_const_vaddr = K_PPTR(sections[i].addr);
			break;
		}
	}

	if (!data_const_offset || !data_const_size || !data_const_vaddr) {
		goto beach;
	}

	data_const = malloc(data_const_size);
	if (!data_const) {
		goto beach;
	}
	if (rz_buf_read_at(obj->cache_buf, data_const_offset, data_const, data_const_size) < data_const_size) {
		goto beach;
	}

	ut8 *cursor = data_const;
	ut8 *end = data_const + data_const_size;
	while (cursor + sizeof(ut64) <= end) {
		ut64 test = rz_read_le64(cursor);
		if (test == enosys_addr) {
			break;
		}
		cursor += 8;
	}

	if (cursor >= end) {
		goto beach;
	}

	cursor -= 24;
	while (cursor >= data_const) {
		ut64 addr = rz_read_le64(cursor);
		ut64 x = rz_read_le64(cursor + 8);
		ut64 y = rz_read_le64(cursor + 16);

		// rewind by sizeof(struct sysent) until finding something that is definitely not a struct sysent
		if (IS_KERNEL_ADDR(addr) &&
			(x == 0 || IS_KERNEL_ADDR(x)) &&
			(y != 0 && !IS_KERNEL_ADDR(y))) {
			cursor -= 24;
			continue;
		}

		cursor += 24;
		break;
	}

	if (cursor < data_const) {
		goto beach;
	}

	syscalls = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!syscalls) {
		goto beach;
	}

	syscall = rz_syscall_new();
	if (!syscall) {
		goto beach;
	}
	rz_syscall_setup(syscall, "arm", 64, NULL, "ios");
	if (!syscall->db) {
		goto beach;
	}

	ut64 sysent_vaddr = cursor - data_const + data_const_vaddr;

	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		goto beach;
	}

	sym->name = rz_str_newf("sysent");
	sym->vaddr = sysent_vaddr;
	sym->paddr = cursor - data_const + data_const_offset;
	sym->size = 0;
	sym->forwarder = "NONE";
	sym->bind = "GLOBAL";
	sym->type = "OBJECT";
	rz_list_append(syscalls, sym);

	int i = 1;
	cursor += 24;
	int num_syscalls = sdb_count(syscall->db);
	while (cursor < end && i < num_syscalls) {
		ut64 addr = rz_read_le64(cursor);
		RzSyscallItem *item = rz_syscall_get(syscall, i, 0x80);
		if (item && item->name) {
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			if (!sym) {
				rz_syscall_item_free(item);
				goto beach;
			}

			sym->name = rz_str_newf("syscall.%d.%s", i, item->name);
			sym->vaddr = addr;
			sym->paddr = addr;
			sym->size = 0;
			sym->forwarder = "NONE";
			sym->bind = "GLOBAL";
			sym->type = "FUNC";
			rz_list_append(syscalls, sym);
		}

		rz_syscall_item_free(item);
		cursor += 24;
		i++;
	}

	rz_syscall_free(syscall);
	RZ_FREE(data_const);
	RZ_FREE(sections);
	return syscalls;

beach:
	rz_syscall_free(syscall);
	rz_list_free(syscalls);
	free(data_const);
	free(sections);
	return NULL;
}

#define K_MIG_SUBSYSTEM_SIZE (4 * 8)
#define K_MIG_ROUTINE_SIZE   (5 * 8)
#define K_MIG_MAX_ROUTINES   100

static HtUP /*<ut64, const char *>*/ *mig_hash_new(void) {
	HtUP *hash = ht_up_new(NULL, NULL);
	if (!hash) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_MIG_INDEX_LEN; i += 2) {
		ut64 num = strtoull(mig_index[i], NULL, 10);
		const char *name = mig_index[i + 1];
		ht_up_insert(hash, num, (void *)name);
	}

	return hash;
}

static RzList /*<RzBinSymbol *>*/ *resolve_mig_subsystem(RzXNUKernelCacheObj *obj) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(obj->mach0))) {
		return NULL;
	}

	HtUP *mig_hash = NULL;
	RzList *subsystem = NULL;
	ut8 *data_const = NULL;
	ut64 data_const_offset = 0, data_const_size = 0, data_const_vaddr = 0;
	ut64 text_exec_offset = 0, text_exec_size = 0, text_exec_vaddr = 0;
	int incomplete = 2;
	int i = 0;
	for (; !sections[i].last && incomplete > 0; i++) {
		if (strstr(sections[i].name, "__DATA_CONST.__const")) {
			data_const_offset = sections[i].offset;
			data_const_size = sections[i].size;
			data_const_vaddr = K_PPTR(sections[i].addr);
			incomplete--;
		}
		if (strstr(sections[i].name, "__TEXT_EXEC.__text")) {
			text_exec_offset = sections[i].offset;
			text_exec_size = sections[i].size;
			text_exec_vaddr = K_PPTR(sections[i].addr);
			incomplete--;
		}
	}

	if (!data_const_offset || !data_const_size || !data_const_vaddr ||
		!text_exec_offset || !text_exec_size || !text_exec_vaddr) {
		goto beach;
	}

	data_const = malloc(data_const_size);
	if (!data_const) {
		goto beach;
	}
	if (rz_buf_read_at(obj->cache_buf, data_const_offset, data_const, data_const_size) < data_const_size) {
		goto beach;
	}

	subsystem = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!subsystem) {
		goto beach;
	}

	mig_hash = mig_hash_new();
	if (!mig_hash) {
		goto beach;
	}

	ut8 *cursor = data_const;
	ut8 *end = data_const + data_const_size;
	while (cursor + sizeof(ut64) * 2 <= end) {
		ut64 subs_p = K_PPTR(rz_read_le64(cursor));
		if (subs_p < text_exec_vaddr || subs_p >= text_exec_vaddr + text_exec_size) {
			cursor += 8;
			continue;
		}
		ut32 subs_min_idx = rz_read_le32(cursor + 8);
		ut32 subs_max_idx = rz_read_le32(cursor + 12);
		ut32 n_routines = (subs_max_idx - subs_min_idx);
		if (subs_min_idx >= subs_max_idx || (subs_max_idx - subs_min_idx) > K_MIG_MAX_ROUTINES) {
			cursor += 16;
			continue;
		}

		ut8 *array_cursor = cursor + K_MIG_SUBSYSTEM_SIZE;
		ut8 *end_array = array_cursor + n_routines * K_MIG_ROUTINE_SIZE;
		if (end_array > end) {
			cursor += 16;
			continue;
		}
		ut64 *routines = (ut64 *)malloc(n_routines * sizeof(ut64));
		if (!routines) {
			goto beach;
		}
		bool is_consistent = true;
		int idx = 0;
		while (array_cursor < end_array) {
			ut64 should_be_null = rz_read_le64(array_cursor);
			if (should_be_null != 0) {
				is_consistent = false;
				break;
			}

			ut64 routine_p = K_PPTR(rz_read_le64(array_cursor + 8));
			if (routine_p != 0 && (routine_p < text_exec_vaddr || routine_p >= text_exec_vaddr + text_exec_size)) {
				is_consistent = false;
				break;
			}

			routines[idx++] = routine_p;
			array_cursor += K_MIG_ROUTINE_SIZE;
		}

		if (is_consistent) {
			for (idx = 0; idx < n_routines; idx++) {
				ut64 routine_p = routines[idx];
				if (!routine_p) {
					continue;
				}

				RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
				if (!sym) {
					RZ_FREE(routines);
					goto beach;
				}

				int num = idx + subs_min_idx;
				const char *name = ht_up_find(mig_hash, (ut64)num, NULL);
				if (RZ_STR_ISNOTEMPTY(name)) {
					sym->name = rz_str_newf("mig.%d.%s", num, name);
				} else {
					sym->name = rz_str_newf("mig.%d", num);
				}

				sym->vaddr = routine_p;
				sym->paddr = sym->vaddr - text_exec_vaddr + text_exec_offset;
				sym->size = 0;
				sym->forwarder = "NONE";
				sym->bind = "GLOBAL";
				sym->type = "OBJECT";
				rz_list_append(subsystem, sym);
			}

			cursor += K_MIG_SUBSYSTEM_SIZE + n_routines * K_MIG_ROUTINE_SIZE;
		} else {
			cursor += 8;
		}

		RZ_FREE(routines);
	}

	ht_up_free(mig_hash);
	free(data_const);
	free(sections);
	return subsystem;

beach:
	rz_list_free(subsystem);
	ht_up_free(mig_hash);
	free(data_const);
	free(sections);
	return NULL;
}

static ut64 extract_addr_from_code(ut8 *arm64_code, ut64 vaddr) {
	ut64 addr = vaddr & ~0xfff;

	ut64 adrp = rz_read_le32(arm64_code);
	ut64 adrp_offset = ((adrp & 0x60000000) >> 29) | ((adrp & 0xffffe0) >> 3);
	addr += adrp_offset << 12;

	ut64 ldr = rz_read_le32(arm64_code + 4);
	addr += ((ldr & 0x3ffc00) >> 10) << ((ldr & 0xc0000000) >> 30);

	return addr;
}

static void symbols_from_stubs(RzPVector /*<RzBinSymbol *>*/ *ret, HtUP /*<ut64, char *>*/ *kernel_syms_by_addr, RzXNUKernelCacheObj *obj, RzBinFile *bf, RKext *kext, int ordinal) {
	RStubsInfo *stubs_info = get_stubs_info(kext->mach0, kext->range.offset, obj);
	if (!stubs_info) {
		return;
	}
	ut64 stubs_cursor = stubs_info->stubs.offset;
	ut64 stubs_end = stubs_cursor + stubs_info->stubs.size;

	for (; stubs_cursor < stubs_end; stubs_cursor += 12) {
		ut8 arm64_code[8];
		if (rz_buf_read_at(obj->cache_buf, stubs_cursor, arm64_code, 8) < 8) {
			break;
		}

		ut64 vaddr = stubs_cursor + obj->pa2va_exec;
		ut64 addr_in_got = extract_addr_from_code(arm64_code, vaddr);

		bool found = false;
		int level = 3;

		ut64 target_addr = UT64_MAX;

		while (!found && level-- > 0) {
			if (addr_in_got < obj->pa2va_exec) {
				// invalid addr
				break;
			}
			ut64 offset_in_got = addr_in_got - obj->pa2va_exec;
			ut64 addr;
			if (rz_buf_read_at(obj->cache_buf, offset_in_got, (ut8 *)&addr, 8) < 8) {
				break;
			}

			if (level == 2) {
				target_addr = addr;
			}

			const char *name = ht_up_find(kernel_syms_by_addr, addr, &found);

			if (found) {
				RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
				if (!sym) {
					break;
				}
				sym->name = rz_str_newf("stub.%s", name);
				sym->vaddr = vaddr;
				sym->paddr = stubs_cursor;
				sym->size = 12;
				sym->forwarder = "NONE";
				sym->bind = "LOCAL";
				sym->type = "FUNC";
				sym->ordinal = ordinal++;
				rz_pvector_push(ret, sym);
				break;
			}

			addr_in_got = addr;
		}

		if (found || target_addr == UT64_MAX) {
			continue;
		}

		ensure_kexts_initialized(obj);
		RKext *remote_kext = rz_kext_index_vget(obj->kexts, target_addr);
		if (!remote_kext) {
			continue;
		}

		RzBinSymbol *remote_sym = RZ_NEW0(RzBinSymbol);
		if (!remote_sym) {
			break;
		}

		remote_sym->name = rz_str_newf("exp.%s.0x%" PFMT64x, kext_short_name(remote_kext), target_addr);
		remote_sym->vaddr = target_addr;
		remote_sym->paddr = target_addr - obj->pa2va_exec;
		remote_sym->size = 0;
		remote_sym->forwarder = "NONE";
		remote_sym->bind = "GLOBAL";
		remote_sym->type = "FUNC";
		remote_sym->ordinal = ordinal++;
		rz_pvector_push(ret, remote_sym);

		RzBinSymbol *local_sym = RZ_NEW0(RzBinSymbol);
		if (!local_sym) {
			break;
		}

		local_sym->name = rz_str_newf("stub.%s.0x%" PFMT64x, kext_short_name(remote_kext), target_addr);
		local_sym->vaddr = vaddr;
		local_sym->paddr = stubs_cursor;
		local_sym->size = 12;
		local_sym->forwarder = "NONE";
		local_sym->bind = "GLOBAL";
		local_sym->type = "FUNC";
		local_sym->ordinal = ordinal++;
		rz_pvector_push(ret, local_sym);
	}

	RZ_FREE(stubs_info);
}

static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) * mach0, ut64 paddr, RzXNUKernelCacheObj *obj) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return NULL;
	}

	RStubsInfo *stubs_info = RZ_NEW0(RStubsInfo);
	if (!stubs_info) {
		return NULL;
	}

	int incomplete = 2;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__DATA_CONST.__got")) {
			stubs_info->got.offset = sections[i].offset + paddr;
			stubs_info->got.size = sections[i].size;
			stubs_info->got_addr = K_PPTR(sections[i].addr);
			if (!--incomplete) {
				break;
			}
		}

		if (strstr(sections[i].name, "__TEXT_EXEC.__stubs")) {
			stubs_info->stubs.offset = sections[i].offset + paddr;
			stubs_info->stubs.size = sections[i].size;
			if (!--incomplete) {
				break;
			}
		}
	}

	RZ_FREE(sections);

	if (incomplete) {
		RZ_FREE(stubs_info);
	}

	return stubs_info;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	bool big_endian = 0;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("kernelcache");
	ret->rclass = rz_str_dup("ios");
	ret->os = rz_str_dup("iOS");
	ret->arch = rz_str_dup("arm"); // XXX
	ret->machine = rz_str_dup(ret->arch);
	ret->subsystem = rz_str_dup("xnu");
	ret->type = rz_str_dup("kernel-cache");
	ret->bits = 64;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 baddr(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return 8LL;
	}

	RzXNUKernelCacheObj *obj = (RzXNUKernelCacheObj *)bf->o->bin_obj;
	return MACH0_(get_baddr)(obj->mach0);
}

static void destroy(RzBinFile *bf) {
	rz_kernel_cache_free((RzXNUKernelCacheObj *)bf->o->bin_obj);
}

static void rz_kernel_cache_free(RzXNUKernelCacheObj *obj) {
	if (!obj) {
		return;
	}

	if (obj->mach0) {
		MACH0_(mach0_free)
		(obj->mach0);
		obj->mach0 = NULL;
		obj->cache_buf = NULL;
	}

	if (obj->cache_buf) {
		rz_buf_free(obj->cache_buf);
		obj->cache_buf = NULL;
	}

	if (obj->prelink_info) {
		rz_cf_value_dict_free(obj->prelink_info);
		obj->prelink_info = NULL;
	}

	if (obj->kexts) {
		rz_kext_index_free(obj->kexts);
		obj->kexts = NULL;
	}

	if (obj->rebase_info) {
		rz_rebase_info_free(obj->rebase_info);
		obj->rebase_info = NULL;
	}

	RZ_FREE(obj);
}

static RzXNUKernelCacheRebaseInfo *rz_rebase_info_new_from_mach0(RzBuffer *cache_buf, struct MACH0_(obj_t) * mach0) {
	RzXNUKernelCacheFileRange *rebase_ranges = NULL;
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return NULL;
	}

	ut64 starts_offset = 0, starts_size = 0;

	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__TEXT.__thread_starts")) {
			starts_offset = sections[i].offset;
			starts_size = sections[i].size;
			break;
		}
	}

	RZ_FREE(sections);

	ut64 kernel_base = 0;

	struct MACH0_(segment_command) * seg;
	int nsegs = RZ_MIN(mach0->nsegs, 128);
	for (i = 0; i < nsegs; i++) {
		char segname[17];
		seg = &mach0->segs[i];
		rz_str_ncpy(segname, seg->segname, 17);
		if (!strncmp(segname, "__TEXT", 6) && segname[6] == '\0') {
			kernel_base = seg->vmaddr;
			break;
		}
	}

	if (starts_offset == 0 || starts_size == 0 || kernel_base == 0) {
		return NULL;
	}

	int n_starts = starts_size / 4;
	if (n_starts <= 1) {
		return NULL;
	}
	rebase_ranges = RZ_NEWS0(RzXNUKernelCacheFileRange, n_starts - 1);
	if (rebase_ranges == NULL) {
		return NULL;
	}

	ut64 multiplier = 4;
	for (i = 0; i != n_starts; i++) {
		ut8 bytes[4];
		if (rz_buf_read_at(cache_buf, starts_offset + i * 4, bytes, 4) < 4) {
			goto beach;
		}

		if (i == 0) {
			multiplier += 4 * (rz_read_le32(bytes) & 1);
			continue;
		}

		rebase_ranges[i - 1].offset = rz_read_le32(bytes);
		rebase_ranges[i - 1].size = UT64_MAX;
	}

	RzXNUKernelCacheRebaseInfo *rebase_info = RZ_NEW0(RzXNUKernelCacheRebaseInfo);
	if (rebase_info == NULL) {
		goto beach;
	}
	rebase_info->ranges = rebase_ranges;
	rebase_info->n_ranges = n_starts - 1;
	rebase_info->multiplier = multiplier;
	rebase_info->kernel_base = kernel_base;

	return rebase_info;

beach:

	RZ_FREE(rebase_ranges);
	return NULL;
}

static void rz_rebase_info_free(RzXNUKernelCacheRebaseInfo *info) {
	if (!info) {
		return;
	}

	if (info->ranges) {
		RZ_FREE(info->ranges);
		info->ranges = NULL;
	}

	RZ_FREE(info);
}

RzBinPlugin rz_bin_plugin_xnu_kernelcache = {
	.name = "kernelcache",
	.desc = "kernelcache bin plugin",
	.license = "LGPL3",
	.destroy = &destroy,
	.load_buffer = &load_buffer,
	.entries = &entries,
	.baddr = &baddr,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.symbols = &symbols,
	.sections = &sections,
	.check_buffer = &check_buffer,
	.info = &info
};

#ifndef RZ_PLUGIN_INCORE
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_xnu_kernelcache,
	.version = RZ_VERSION
};
#endif
