// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

#define VTABLE_BUFF_SIZE  10
#define VTABLE_CHUNK_SIZE 65536

#define VTABLE_READ_ADDR_FUNC(fname, read_fname, sz) \
	static bool fname(RzAnalysis *analysis, ut64 addr, ut64 *buf) { \
		ut8 tmp[sz]; \
		if (!analysis->iob.read_at(analysis->iob.io, addr, tmp, sz)) { \
			return false; \
		} \
		*buf = read_fname(tmp); \
		return true; \
	}
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le8, rz_read_le8, 1)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le16, rz_read_le16, 2)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le32, rz_read_le32, 4)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le64, rz_read_le64, 8)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be8, rz_read_be8, 1)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be16, rz_read_be16, 2)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be32, rz_read_be32, 4)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be64, rz_read_be64, 8)

static bool vtable_has_default_read_addr(const RVTableContext *context) {
	const bool be = context->analysis->big_endian;
	switch (context->word_size) {
	case 1:
		return context->read_addr == (be ? vtable_read_addr_be8 : vtable_read_addr_le8);
	case 2:
		return context->read_addr == (be ? vtable_read_addr_be16 : vtable_read_addr_le16);
	case 4:
		return context->read_addr == (be ? vtable_read_addr_be32 : vtable_read_addr_le32);
	case 8:
		return context->read_addr == (be ? vtable_read_addr_be64 : vtable_read_addr_le64);
	default:
		return false;
	}
}

static inline ut64 vtable_decode_word(const ut8 *p, ut8 word_size, bool big_endian) {
	switch (word_size) {
	case 1:
		return big_endian ? rz_read_be8(p) : rz_read_le8(p);
	case 2:
		return big_endian ? rz_read_be16(p) : rz_read_le16(p);
	case 4:
		return big_endian ? rz_read_be32(p) : rz_read_le32(p);
	case 8:
		return big_endian ? rz_read_be64(p) : rz_read_le64(p);
	default:
		return 0;
	}
}

typedef struct vtable_section_interval_t {
	ut64 from;
	ut64 to;
	bool is_text;
	bool is_rtti;
} VTableSectionInterval;

typedef struct vtable_section_cache_t {
	VTableSectionInterval *intervals;
	size_t count;
	ut64 min_text;
	ut64 max_text;
	bool has_text;
	bool overlaps;
} VTableSectionCache;

static int vtable_section_interval_cmp(const void *a, const void *b) {
	const VTableSectionInterval *ia = a;
	const VTableSectionInterval *ib = b;
	if (ia->from != ib->from) {
		return RZ_NUM_CMP(ia->from, ib->from);
	}
	return RZ_NUM_CMP(ia->to, ib->to);
}

RZ_API void rz_analysis_vtable_info_free(RVTableInfo *vtable) {
	if (!vtable) {
		return;
	}
	rz_vector_clear(&vtable->methods);
	free(vtable);
}

RZ_API ut64 rz_analysis_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable) {
	return (ut64)vtable->methods.len * context->word_size;
}

RZ_API bool rz_analysis_vtable_begin(RzAnalysis *analysis, RVTableContext *context) {
	context->analysis = analysis;
	context->abi = analysis->cpp_abi;
	context->word_size = (ut8)(analysis->bits / 8);
	const bool is_arm = analysis->cur->arch && rz_str_startswith(analysis->cur->arch, "arm");
	if (is_arm && context->word_size < 4) {
		context->word_size = 4;
	}
	switch (context->word_size) {
	case 1:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be8 : vtable_read_addr_le8;
		break;
	case 2:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be16 : vtable_read_addr_le16;
		break;
	case 4:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be32 : vtable_read_addr_le32;
		break;
	case 8:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be64 : vtable_read_addr_le64;
		break;
	default:
		return false;
	}
	return true;
}

static bool vtable_addr_in_text_section(RVTableContext *context, ut64 curAddress) {
	// section of the curAddress
	RzBinSection *value = context->analysis->binb.get_vsect_at(context->analysis->binb.bin, curAddress);
	// If the pointed value lies in .text section
	return value && strstr(value->name, "text") && (value->perm & 1) != 0;
}

static bool vtable_is_value_in_text_section(RVTableContext *context, ut64 curAddress, ut64 *value) {
	// value at the current address
	ut64 curAddressValue;
	if (!context->read_addr(context->analysis, curAddress, &curAddressValue)) {
		return false;
	}
	// if the value is in text section
	bool ret = vtable_addr_in_text_section(context, curAddressValue);
	if (value) {
		*value = curAddressValue;
	}
	return ret;
}

static bool vtable_section_can_contain_vtables(RzBinSection *section) {
	if (section->is_segment) {
		return false;
	}
	return !strcmp(section->name, ".rodata") ||
		!strcmp(section->name, ".rdata") ||
		!strcmp(section->name, ".data.rel.ro") ||
		!strcmp(section->name, ".data.rel.ro.local") ||
		rz_str_endswith(section->name, "__const");
}

static bool section_can_contain_rtti(RzBinSection *section) {
	if (!section) {
		return false;
	}
	if (section->is_data) {
		return true;
	}
	return !strcmp(section->name, ".data.rel.ro") ||
		!strcmp(section->name, ".data.rel.ro.local") ||
		rz_str_endswith(section->name, "__const");
}

static bool vtable_is_addr_vtable_start_itanium(RVTableContext *context, RzBinSection *section, ut64 curAddress) {
	ut64 value;
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section(context, curAddress, NULL)) { // Vtable beginning referenced from the code
		return false;
	}
	if (!context->read_addr(context->analysis, curAddress - context->word_size, &value)) { // get the RTTI pointer
		return false;
	}
	RzBinSection *rtti_section = context->analysis->binb.get_vsect_at(context->analysis->binb.bin, value);
	if (value && !section_can_contain_rtti(rtti_section)) { // RTTI ptr must point somewhere in the data section
		return false;
	}
	if (!context->read_addr(context->analysis, curAddress - 2 * context->word_size, &value)) { // Offset to top
		return false;
	}
	if ((st32)value > 0) { // Offset to top has to be negative
		return false;
	}
	return true;
}

static bool vtable_is_addr_vtable_start_msvc(RVTableContext *context, ut64 curAddress) {
	RzAnalysisXRef *xref;
	RzListIter *xrefIter;

	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section(context, curAddress, NULL)) {
		return false;
	}
	// total xref's to curAddress
	RzList *xrefs = rz_analysis_xrefs_get_to(context->analysis, curAddress);
	if (rz_list_empty(xrefs)) {
		rz_list_free(xrefs);
		return false;
	}
	rz_list_foreach (xrefs, xrefIter, xref) {
		// section in which currenct xref lies
		if (vtable_addr_in_text_section(context, xref->from)) {
			ut8 buf[VTABLE_BUFF_SIZE];
			context->analysis->iob.read_at(context->analysis->iob.io, xref->from, buf, sizeof(buf));

			RzAnalysisOp aop = { 0 };
			rz_analysis_op_init(&aop);
			rz_analysis_op(context->analysis, &aop, xref->from, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);

			if (aop.type == RZ_ANALYSIS_OP_TYPE_MOV || aop.type == RZ_ANALYSIS_OP_TYPE_LEA) {
				rz_list_free(xrefs);
				rz_analysis_op_fini(&aop);
				return true;
			}

			rz_analysis_op_fini(&aop);
		}
	}
	rz_list_free(xrefs);
	return false;
}

static bool vtable_is_addr_vtable_start(RVTableContext *context, RzBinSection *section, ut64 curAddress) {
	if (context->abi == RZ_ANALYSIS_CPP_ABI_MSVC) {
		return vtable_is_addr_vtable_start_msvc(context, curAddress);
	}
	if (context->abi == RZ_ANALYSIS_CPP_ABI_ITANIUM) {
		return vtable_is_addr_vtable_start_itanium(context, section, curAddress);
	}
	rz_return_val_if_reached(false);
}

RZ_API RVTableInfo *rz_analysis_vtable_parse_at(RVTableContext *context, ut64 addr) {
	ut64 offset_to_top;
	if (!context->read_addr(context->analysis, addr - 2 * context->word_size, &offset_to_top)) {
		return NULL;
	}

	RVTableInfo *vtable = calloc(1, sizeof(RVTableInfo));
	if (!vtable) {
		return NULL;
	}

	vtable->saddr = addr;

	rz_vector_init(&vtable->methods, sizeof(RVTableMethodInfo), NULL, NULL);

	RVTableMethodInfo meth;
	while (vtable_is_value_in_text_section(context, addr, &meth.addr)) {
		meth.vtable_offset = addr - vtable->saddr;
		if (!rz_vector_push(&vtable->methods, &meth)) {
			break;
		}

		addr += context->word_size;

		// a ref means the vtable has ended
		RzList *ll = rz_analysis_xrefs_get_to(context->analysis, addr);
		if (!rz_list_empty(ll)) {
			rz_list_free(ll);
			break;
		}
		rz_list_free(ll);
	}
	return vtable;
}

/**
 * \brief Initialize a sorted section interval cache for fast text/RTTI lookup.
 *
 * Falls back to uncached lookups when sections overlap or allocation fails.
 *
 * \param cache Cache structure to initialize
 * \param obj Current RzBinObject used to resolve section base addresses
 * \param sections Binary sections vector
 */
static void vtable_section_cache_init(VTableSectionCache *cache, RzBinObject *obj, const RzPVector /*<RzBinSection *>*/ *sections) {
	memset(cache, 0, sizeof(*cache));
	cache->min_text = UT64_MAX;
	if (!sections || rz_pvector_empty(sections)) {
		return;
	}
	size_t cap = rz_pvector_len(sections);
	cache->intervals = RZ_NEWS(VTableSectionInterval, cap);
	if (!cache->intervals) {
		cache->overlaps = true;
		cache->has_text = true;
		cache->min_text = 0;
		cache->max_text = UT64_MAX;
		return;
	}
	void **iter;
	rz_pvector_foreach (sections, iter) {
		RzBinSection *sec = *iter;
		if (!sec || sec->is_segment || !sec->vsize) {
			continue;
		}
		bool is_text = sec->name && strstr(sec->name, "text") && (sec->perm & 1) != 0;
		ut64 from = rz_bin_object_addr_with_base(obj, sec->vaddr);
		ut64 to = from + sec->vsize;
		if (to < from) {
			cache->overlaps = true;
			if (is_text) {
				cache->has_text = true;
				if (from < cache->min_text) {
					cache->min_text = from;
				}
				cache->max_text = UT64_MAX;
			}
			continue;
		}
		bool is_rtti = section_can_contain_rtti(sec);
		if (is_text) {
			cache->has_text = true;
			if (from < cache->min_text) {
				cache->min_text = from;
			}
			if (to > cache->max_text) {
				cache->max_text = to;
			}
		}
		cache->intervals[cache->count++] = (VTableSectionInterval){
			.from = from,
			.to = to,
			.is_text = is_text,
			.is_rtti = is_rtti,
		};
	}
	if (cache->count > 1) {
		qsort(cache->intervals, cache->count, sizeof(*cache->intervals), vtable_section_interval_cmp);
		for (size_t i = 1; i < cache->count; i++) {
			if (cache->intervals[i].from < cache->intervals[i - 1].to) {
				cache->overlaps = true;
				break;
			}
		}
	}
}

static void vtable_section_cache_fini(VTableSectionCache *cache) {
	free(cache->intervals);
	cache->intervals = NULL;
	cache->count = 0;
}

/**
 * \brief Find the cached non-overlapping section interval containing \p addr.
 *
 * \param cache Initialized section cache
 * \param addr Virtual address to look up
 * \return Matching interval, or NULL if \p addr is not covered
 */
static const VTableSectionInterval *vtable_section_cache_find(const VTableSectionCache *cache, ut64 addr) {
	size_t lo = 0, hi = cache->count;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (cache->intervals[mid].from <= addr) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (!lo) {
		return NULL;
	}
	const VTableSectionInterval *iv = &cache->intervals[lo - 1];
	return (addr >= iv->from && addr < iv->to) ? iv : NULL;
}

static inline bool vtable_cache_addr_in_text(const VTableSectionCache *cache, RVTableContext *context, ut64 addr) {
	if (!cache->has_text) {
		return false;
	}
	if (cache->overlaps) {
		return vtable_addr_in_text_section(context, addr);
	}
	if (addr < cache->min_text || addr >= cache->max_text) {
		return false;
	}
	const VTableSectionInterval *iv = vtable_section_cache_find(cache, addr);
	return iv && iv->is_text;
}

static inline bool vtable_cache_addr_in_rtti(const VTableSectionCache *cache, RVTableContext *context, ut64 addr) {
	if (!addr) {
		return true;
	}
	if (cache->overlaps) {
		RzBinSection *rtti_section = context->analysis->binb.get_vsect_at(context->analysis->binb.bin, addr);
		return section_can_contain_rtti(rtti_section);
	}
	const VTableSectionInterval *iv = vtable_section_cache_find(cache, addr);
	return iv && iv->is_rtti;
}

/**
 * \brief Check whether \p curAddress starts an Itanium ABI vtable using cached section and chunk data.
 *
 * \param context VTable analysis context
 * \param cache Initialized section interval cache
 * \param curAddress Candidate vtable start address
 * \param curAddressValue Word decoded at \p curAddress
 * \param chunk Buffered chunk bytes, or NULL if unbuffered
 * \param chunk_base Base address of \p chunk
 * \param chunk_len Valid byte length of \p chunk
 * \param chunk_valid Whether \p chunk holds valid data
 * \return true if \p curAddress matches an Itanium vtable start
 */
static bool vtable_is_addr_vtable_start_itanium_cached(
	RVTableContext *context,
	const VTableSectionCache *cache,
	ut64 curAddress,
	ut64 curAddressValue,
	const ut8 *chunk,
	ut64 chunk_base,
	size_t chunk_len,
	bool chunk_valid) {
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (!vtable_cache_addr_in_text(cache, context, curAddressValue)) {
		return false;
	}
	const ut8 ws = context->word_size;
	const bool be = context->analysis->big_endian;
	const bool in_chunk = chunk_valid && chunk_len >= ws && curAddress >= chunk_base &&
		(curAddress - chunk_base) <= chunk_len - ws;
	ut64 rtti_val;
	if (in_chunk && (curAddress - chunk_base) >= ws) {
		rtti_val = vtable_decode_word(chunk + (curAddress - chunk_base - ws), ws, be);
	} else if (!context->read_addr(context->analysis, curAddress - ws, &rtti_val)) {
		return false;
	}
	if (!vtable_cache_addr_in_rtti(cache, context, rtti_val)) {
		return false;
	}
	ut64 off_to_top;
	if (in_chunk && (curAddress - chunk_base) >= 2 * (ut64)ws) {
		off_to_top = vtable_decode_word(chunk + (curAddress - chunk_base - 2 * (ut64)ws), ws, be);
	} else if (!context->read_addr(context->analysis, curAddress - 2 * (ut64)ws, &off_to_top)) {
		return false;
	}
	if ((st32)off_to_top > 0) {
		return false;
	}
	return true;
}

/**
 * \brief Parse a vtable at \p addr using the cached section lookup table.
 *
 * \param context VTable analysis context
 * \param cache Initialized section interval cache
 * \param addr Start address of the vtable method entries
 * \return Parsed RVTableInfo, or NULL on read/allocation failure
 */
static RVTableInfo *vtable_parse_at_cached(RVTableContext *context, const VTableSectionCache *cache, ut64 addr) {
	ut64 offset_to_top;
	if (!context->read_addr(context->analysis, addr - 2 * context->word_size, &offset_to_top)) {
		return NULL;
	}

	RVTableInfo *vtable = calloc(1, sizeof(RVTableInfo));
	if (!vtable) {
		return NULL;
	}

	vtable->saddr = addr;
	rz_vector_init(&vtable->methods, sizeof(RVTableMethodInfo), NULL, NULL);

	RVTableMethodInfo meth;
	while (context->read_addr(context->analysis, addr, &meth.addr) &&
		vtable_cache_addr_in_text(cache, context, meth.addr)) {
		meth.vtable_offset = addr - vtable->saddr;
		if (!rz_vector_push(&vtable->methods, &meth)) {
			break;
		}

		if (UT64_ADD_OVFCHK(addr, context->word_size)) {
			break;
		}
		addr += context->word_size;

		// a ref means the vtable has ended
		RzList *ll = rz_analysis_xrefs_get_to(context->analysis, addr);
		if (!rz_list_empty(ll)) {
			rz_list_free(ll);
			break;
		}
		rz_list_free(ll);
	}
	return vtable;
}

RZ_API RzList /*<RVTableInfo *>*/ *rz_analysis_vtable_search(RVTableContext *context) {
	RzAnalysis *analysis = context->analysis;
	if (!analysis) {
		return NULL;
	}

	RzList *vtables = rz_list_newf((RzListFree)rz_analysis_vtable_info_free);
	if (!vtables) {
		return NULL;
	}

	RzBinObject *obj = rz_bin_cur_object(analysis->binb.bin);
	const RzPVector *sections = obj ? analysis->binb.get_sections(obj) : NULL;
	if (!sections) {
		rz_list_free(vtables);
		return NULL;
	}

	VTableSectionCache sec_cache;
	vtable_section_cache_init(&sec_cache, obj, sections);
	if (!sec_cache.has_text) {
		vtable_section_cache_fini(&sec_cache);
		rz_list_free(vtables);
		return NULL;
	}

	const bool use_buffered = vtable_has_default_read_addr(context);
	ut8 *chunk = use_buffered ? malloc(VTABLE_CHUNK_SIZE) : NULL;
	const ut8 ws = context->word_size;
	const bool be = analysis->big_endian;

	rz_interrupt_break_push(analysis->intr, NULL, NULL);

	void **iter;
	RzBinSection *section;
	rz_pvector_foreach (sections, iter) {
		section = *iter;
		if (rz_interrupt_is_breaked(analysis->intr)) {
			break;
		}

		if (!vtable_section_can_contain_vtables(section)) {
			continue;
		}

		if (section->vsize < ws || section->vsize - ws > ST32_MAX ||
			UT64_ADD_OVFCHK(section->vaddr, section->vsize - ws)) {
			continue;
		}

		const ut64 sec_base = section->vaddr;
		const ut64 max_off = section->vsize - ws;
		ut64 off = 0;
		ut64 chunk_base = 0;
		size_t chunk_len = 0;
		bool chunk_valid = false;
		bool chunk_all_mapped = false;

		while (off <= max_off) {
			const ut64 startAddress = sec_base + off;
			if (!chunk_valid || startAddress < chunk_base || (startAddress - chunk_base) > chunk_len - ws) {
				if (rz_interrupt_is_breaked(analysis->intr)) {
					break;
				}
				if (!analysis->iob.is_valid_offset(analysis->iob.io, startAddress, 0)) {
					break;
				}
				chunk_valid = false;
				chunk_all_mapped = false;
				chunk_len = 0;
				if (chunk && analysis->iob.nread_at) {
					ut64 remaining = (max_off - off) + ws;
					ut64 max_nowrap = UT64_MAX - startAddress;
					if (remaining > max_nowrap) {
						remaining = max_nowrap;
					}
					size_t req_len = (size_t)RZ_MIN(remaining, (ut64)VTABLE_CHUNK_SIZE);
					if (req_len >= ws) {
						int nread = analysis->iob.nread_at(analysis->iob.io, startAddress, chunk, req_len);
						if (nread >= ws) {
							chunk_base = startAddress;
							chunk_len = (size_t)nread;
							chunk_valid = true;
							RzIO *io = analysis->iob.io;
							if (io && io->va) {
								chunk_all_mapped = !io->p_cache;
							} else if (io && io->desc && analysis->iob.desc_size) {
								chunk_all_mapped = (startAddress + (ut64)nread - ws) <=
									analysis->iob.desc_size(io->desc);
							}
						}
					}
				}
			} else if (!chunk_all_mapped) {
				if (!analysis->iob.is_valid_offset(analysis->iob.io, startAddress, 0)) {
					break;
				}
			}

			ut64 cur_val;
			if (chunk_valid && startAddress >= chunk_base && (startAddress - chunk_base) <= chunk_len - ws) {
				cur_val = vtable_decode_word(chunk + (startAddress - chunk_base), ws, be);
			} else if (!context->read_addr(analysis, startAddress, &cur_val)) {
				off += ws;
				continue;
			}

			bool is_start = false;
			if (vtable_cache_addr_in_text(&sec_cache, context, cur_val)) {
				if (context->abi == RZ_ANALYSIS_CPP_ABI_ITANIUM) {
					is_start = vtable_is_addr_vtable_start_itanium_cached(
						context, &sec_cache, startAddress, cur_val, chunk, chunk_base, chunk_len, chunk_valid);
				} else if (context->abi == RZ_ANALYSIS_CPP_ABI_MSVC) {
					is_start = vtable_is_addr_vtable_start_msvc(context, startAddress);
				} else {
					is_start = vtable_is_addr_vtable_start(context, section, startAddress);
				}
			}

			if (is_start) {
				if (rz_interrupt_is_breaked(analysis->intr)) {
					break;
				}
				RVTableInfo *vtable = vtable_parse_at_cached(context, &sec_cache, startAddress);
				if (vtable) {
					rz_list_append(vtables, vtable);
					ut64 size = rz_analysis_vtable_info_get_size(context, vtable);
					if (size > 0) {
						if (size > max_off - off) {
							break;
						}
						off += size;
						continue;
					}
				}
			}
			off += ws;
		}
	}

	rz_interrupt_break_pop(analysis->intr);
	free(chunk);
	vtable_section_cache_fini(&sec_cache);

	if (rz_list_empty(vtables)) {
		// stripped binary?
		rz_list_free(vtables);
		return NULL;
	}
	return vtables;
}

RZ_API void rz_analysis_list_vtables(RzAnalysis *analysis, RzOutputMode mode, RZ_NONNULL RZ_BORROW RzCons *cons) {
	RVTableContext context;
	rz_analysis_vtable_begin(analysis, &context);

	const char *noMethodName = "No Name found";
	RVTableMethodInfo *curMethod;
	RzListIter *vtableIter;
	RVTableInfo *table;

	RzList *vtables = rz_analysis_vtable_search(&context);

	if (mode == RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			rz_list_free(vtables);
			return;
		}
		pj_a(pj);
		rz_list_foreach (vtables, vtableIter, table) {
			pj_o(pj);
			pj_kN(pj, "offset", table->saddr);
			pj_ka(pj, "methods");
			rz_vector_foreach (&table->methods, curMethod) {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				pj_o(pj);
				pj_kN(pj, "offset", curMethod->addr);
				pj_ks(pj, "name", name ? name : noMethodName);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
		}
		pj_end(pj);
		rz_cons_print(cons, pj_string(pj));
		rz_cons_print(cons, "\n");
		pj_free(pj);
	} else {
		rz_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			rz_cons_printf(cons, "\nVtable Found at 0x%08" PFMT64x "\n", vtableStartAddress);
			rz_vector_foreach (&table->methods, curMethod) {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				rz_cons_printf(cons, "0x%08" PFMT64x " : %s\n", vtableStartAddress, name ? name : noMethodName);
				vtableStartAddress += context.word_size;
			}
			rz_cons_printf(cons, "\n");
		}
	}
	rz_list_free(vtables);
}
