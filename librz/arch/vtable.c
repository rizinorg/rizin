// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

#define VTABLE_BUFF_SIZE  10
#define VTABLE_CHUNK_SIZE 65536

static bool vtable_read_addr_8(RzAnalysis *analysis, ut64 addr, ut64 *buf) {
	ut8 tmp[1];
	if (!analysis->iob.read_at(analysis->iob.io, addr, tmp, 1)) {
		return false;
	}
	*buf = rz_read_ble8(tmp);
	return true;
}

#define VTABLE_READ_ADDR_FUNC(fname, read_fname, sz) \
	static bool fname(RzAnalysis *analysis, ut64 addr, ut64 *buf) { \
		ut8 tmp[sz]; \
		if (!analysis->iob.read_at(analysis->iob.io, addr, tmp, sz)) { \
			return false; \
		} \
		*buf = read_fname(tmp, analysis->big_endian); \
		return true; \
	}
VTABLE_READ_ADDR_FUNC(vtable_read_addr_16, rz_read_ble16, 2)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_32, rz_read_ble32, 4)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_64, rz_read_ble64, 8)

static bool vtable_has_default_read_addr(const RVTableContext *context) {
	switch (context->word_size) {
	case 1:
		return context->read_addr == vtable_read_addr_8;
	case 2:
		return context->read_addr == vtable_read_addr_16;
	case 4:
		return context->read_addr == vtable_read_addr_32;
	case 8:
		return context->read_addr == vtable_read_addr_64;
	default:
		return false;
	}
}

typedef struct vtable_section_interval_t {
	ut64 from;
	ut64 to;
	bool is_text;
	bool is_rtti;
} VTableSectionInterval;

typedef struct vtable_section_cache_t {
	RzVector /*<VTableSectionInterval>*/ intervals;
	ut64 min_text;
	ut64 max_text;
	bool has_text;
	bool overlaps;
} VTableSectionCache;

static int vtable_section_interval_cmp(const void *a, const void *b, void *user) {
	(void)user;
	const VTableSectionInterval *ia = a;
	const VTableSectionInterval *ib = b;
	int cmp = RZ_NUM_CMP(ia->from, ib->from);
	return cmp ? cmp : RZ_NUM_CMP(ia->to, ib->to);
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
		context->read_addr = vtable_read_addr_8;
		break;
	case 2:
		context->read_addr = vtable_read_addr_16;
		break;
	case 4:
		context->read_addr = vtable_read_addr_32;
		break;
	case 8:
		context->read_addr = vtable_read_addr_64;
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

/**
 * \brief Initialize a sorted section interval cache for fast text/RTTI lookup.
 *
 * Falls back to uncached lookups when sections overlap or allocation fails.
 *
 * \param cache Cache structure to initialize
 * \param obj Current RzBinObject used to resolve section base addresses
 * \param sections Binary sections vector
 */
static void vtable_section_cache_init(
	VTableSectionCache *cache,
	RzBinObject *obj,
	const RzPVector /*<RzBinSection *>*/ *sections) {
	rz_return_if_fail(cache);
	memset(cache, 0, sizeof(*cache));
	rz_vector_init(&cache->intervals, sizeof(VTableSectionInterval), NULL, NULL);
	cache->min_text = UT64_MAX;
	rz_return_if_fail(sections);
	size_t cap = rz_pvector_len(sections);
	if (!cap) {
		return;
	}
	if (!rz_vector_reserve(&cache->intervals, cap)) {
		cache->overlaps = true;
		cache->has_text = true;
		return;
	}
	void **iter;
	rz_pvector_foreach (sections, iter) {
		RzBinSection *sec = *iter;
		if (!sec || sec->is_segment || !sec->vsize) {
			continue;
		}
		bool is_text = sec->name && strstr(sec->name, "text") && (sec->perm & RZ_PERM_X) != 0;
		ut64 from = rz_bin_object_addr_with_base(obj, sec->vaddr);
		ut64 to = from + sec->vsize;
		if (to < from) {
			cache->overlaps = true;
			if (is_text) {
				cache->has_text = true;
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
		VTableSectionInterval interval = {
			.from = from,
			.to = to,
			.is_text = is_text,
			.is_rtti = is_rtti,
		};
		if (!rz_vector_push(&cache->intervals, &interval)) {
			cache->overlaps = true;
			cache->has_text = true;
			return;
		}
	}
	size_t count = rz_vector_len(&cache->intervals);
	if (count > 1) {
		rz_vector_sort(&cache->intervals, vtable_section_interval_cmp, false, NULL);
		for (size_t i = 1; i < count; i++) {
			const VTableSectionInterval *prev = rz_vector_index_ptr(&cache->intervals, i - 1);
			const VTableSectionInterval *curr = rz_vector_index_ptr(&cache->intervals, i);
			if (curr->from < prev->to) {
				cache->overlaps = true;
				break;
			}
		}
	}
}

static void vtable_section_cache_fini(VTableSectionCache *cache) {
	rz_vector_fini(&cache->intervals);
}

/**
 * \brief Find the cached non-overlapping section interval containing \p addr.
 *
 * \param cache Initialized section cache
 * \param addr Virtual address to look up
 * \return Matching interval, or NULL if \p addr is not covered
 */
static const VTableSectionInterval *vtable_section_cache_find(
	const VTableSectionCache *cache, ut64 addr) {
	rz_return_val_if_fail(cache, NULL);
	size_t lo = 0, hi = rz_vector_len(&cache->intervals);
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const VTableSectionInterval *iv = rz_vector_index_ptr(&cache->intervals, mid);
		if (iv->from <= addr) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (!lo) {
		return NULL;
	}
	const VTableSectionInterval *iv = rz_vector_index_ptr(&cache->intervals, lo - 1);
	return addr < iv->to ? iv : NULL;
}

static bool vtable_cache_addr_in_text(
	RZ_NULLABLE const VTableSectionCache *cache, RVTableContext *context, ut64 addr) {
	if (!cache || cache->overlaps) {
		return vtable_addr_in_text_section(context, addr);
	}
	if (addr < cache->min_text || addr >= cache->max_text) {
		return false;
	}
	const VTableSectionInterval *iv = vtable_section_cache_find(cache, addr);
	return iv && iv->is_text;
}

static bool vtable_cache_addr_in_rtti(
	const VTableSectionCache *cache, RVTableContext *context, ut64 addr) {
	if (!addr) {
		return true;
	}
	if (cache->overlaps) {
		RzBinBind *binb = &context->analysis->binb;
		RzBinSection *rtti_section = binb->get_vsect_at(binb->bin, addr);
		return section_can_contain_rtti(rtti_section);
	}
	const VTableSectionInterval *iv = vtable_section_cache_find(cache, addr);
	return iv && iv->is_rtti;
}

/**
 * \brief Check whether \p curAddress starts an Itanium ABI vtable using
 * cached section and chunk data.
 *
 * Caller must ensure the word at \p curAddress lies in a text section, and that when \p chunk_valid
 * is true, \p curAddress lies within \p chunk starting at \p chunk_base.
 *
 * \param context VTable analysis context
 * \param cache Initialized section interval cache
 * \param curAddress Candidate vtable start address
 * \param chunk Buffered chunk bytes, or NULL if unbuffered
 * \param chunk_base Base address of \p chunk
 * \param chunk_valid Whether \p chunk holds valid data covering \p curAddress
 * \return true if \p curAddress matches an Itanium vtable start
 */
static bool vtable_is_addr_vtable_start_itanium_cached(
	RVTableContext *context,
	const VTableSectionCache *cache,
	ut64 curAddress,
	const ut8 *chunk,
	ut64 chunk_base,
	bool chunk_valid) {
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	const ut8 ws = context->word_size;
	const bool be = context->analysis->big_endian;
	ut64 rtti_val;
	if (chunk_valid && (curAddress - chunk_base) >= ws) {
		rtti_val = rz_read_ble(chunk + (curAddress - chunk_base - ws), be, ws * 8);
	} else if (!context->read_addr(context->analysis, curAddress - ws, &rtti_val)) {
		return false;
	}
	if (!vtable_cache_addr_in_rtti(cache, context, rtti_val)) {
		return false;
	}
	ut64 offset_to_top;
	if (chunk_valid && (curAddress - chunk_base) >= 2 * (ut64)ws) {
		size_t top_off = (size_t)(curAddress - chunk_base - 2 * (ut64)ws);
		offset_to_top = rz_read_ble(chunk + top_off, be, ws * 8);
	} else if (!context->read_addr(context->analysis, curAddress - 2 * (ut64)ws, &offset_to_top)) {
		return false;
	}
	if ((st32)offset_to_top > 0) {
		return false;
	}
	return true;
}

/**
 * \brief Parse a vtable at \p addr, optionally using the cached section lookup table.
 *
 * \param context VTable analysis context
 * \param cache Initialized section interval cache, or NULL for uncached lookup
 * \param addr Start address of the vtable method entries
 * \return Parsed RVTableInfo, or NULL on read/allocation failure
 */
static RVTableInfo *vtable_parse_at_cached(
	RVTableContext *context, RZ_NULLABLE const VTableSectionCache *cache, ut64 addr) {
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

RZ_API RVTableInfo *rz_analysis_vtable_parse_at(RVTableContext *context, ut64 addr) {
	return vtable_parse_at_cached(context, NULL, addr);
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
	RzIOBind *iob = &analysis->iob;

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
			if (!chunk_valid || (startAddress - chunk_base) > chunk_len - ws) {
				if (rz_interrupt_is_breaked(analysis->intr)) {
					break;
				}
				if (!iob->is_valid_offset(iob->io, startAddress, 0)) {
					break;
				}
				chunk_valid = false;
				chunk_all_mapped = false;
				chunk_len = 0;
				if (chunk && iob->nread_at) {
					ut64 remaining = (max_off - off) + ws;
					ut64 max_nowrap = UT64_MAX - startAddress;
					if (remaining > max_nowrap) {
						remaining = max_nowrap;
					}
					size_t req_len = (size_t)RZ_MIN(
						remaining, (ut64)VTABLE_CHUNK_SIZE);
					if (req_len >= ws) {
						int nread = iob->nread_at(
							iob->io, startAddress, chunk, req_len);
						if (nread >= ws) {
							chunk_base = startAddress;
							chunk_len = (size_t)nread;
							chunk_valid = true;
							RzIO *io = iob->io;
							if (io->va) {
								chunk_all_mapped = !io->p_cache;
							} else if (io->desc && iob->desc_size) {
								ut64 end = startAddress;
								end += (ut64)nread - ws;
								ut64 dsz = iob->desc_size(io->desc);
								chunk_all_mapped = end <= dsz;
							}
						}
					}
				}
			} else if (!chunk_all_mapped) {
				if (!iob->is_valid_offset(iob->io, startAddress, 0)) {
					break;
				}
			}

			ut64 cur_val;
			if (chunk_valid) {
				size_t off_in_chunk = (size_t)(startAddress - chunk_base);
				cur_val = rz_read_ble(chunk + off_in_chunk, be, ws * 8);
			} else if (!context->read_addr(analysis, startAddress, &cur_val)) {
				off += ws;
				continue;
			}

			bool is_start = false;
			if (vtable_cache_addr_in_text(&sec_cache, context, cur_val)) {
				if (context->abi == RZ_ANALYSIS_CPP_ABI_ITANIUM) {
					is_start = vtable_is_addr_vtable_start_itanium_cached(
						context, &sec_cache, startAddress, chunk,
						chunk_base, chunk_valid);
				} else if (context->abi == RZ_ANALYSIS_CPP_ABI_MSVC) {
					is_start = vtable_is_addr_vtable_start_msvc(
						context, startAddress);
				} else {
					rz_warn_if_reached();
				}
			}

			if (is_start) {
				if (rz_interrupt_is_breaked(analysis->intr)) {
					break;
				}
				RVTableInfo *vtable = vtable_parse_at_cached(
					context, &sec_cache, startAddress);
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
