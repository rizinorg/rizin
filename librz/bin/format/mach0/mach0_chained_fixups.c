// SPDX-FileCopyrightText: 2021-2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Handling of modern "chained fixups" in Mach-O binaries
 *
 * This is used in Mach-O binaries that either contain a LC_DYLD_CHANGED_FIXUPS
 * load commands or BIND_OPCODE_THREADED in their dyld info. This is especially present in, but not
 * limited to binaries with the "arm64e" architecture, as Apple calls it, which is essentially
 * arm64 with pointer authentication.
 * In particular, we strip away additional info stored inside of pointers in the binary so we get
 * the raw pointers out for convenient analysis.
 *
 * see also mach0_relocs.c for additional modification of the data that might happen.
 */

#include "mach0.h"

#include "mach0_utils.inc"

static bool read_dyld_chained_fixups_header(struct dyld_chained_fixups_header *header, RzBuffer *buf, ut64 base) {
	ut64 offset = base;
	return rz_buf_read_le32_offset(buf, &offset, &header->fixups_version) &&
		rz_buf_read_le32_offset(buf, &offset, &header->starts_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &header->imports_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &header->symbols_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &header->imports_count) &&
		rz_buf_read_le32_offset(buf, &offset, &header->imports_format) &&
		rz_buf_read_le32_offset(buf, &offset, &header->symbols_format);
}

static bool read_dyld_chained_starts_in_segment(struct rz_dyld_chained_starts_in_segment *segment, RzBuffer *buf, ut64 base) {
	ut64 offset = base;
	return rz_buf_read_le32_offset(buf, &offset, &segment->size) &&
		rz_buf_read_le16_offset(buf, &offset, &segment->page_size) &&
		rz_buf_read_le16_offset(buf, &offset, &segment->pointer_format) &&
		rz_buf_read_le64_offset(buf, &offset, &segment->segment_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &segment->max_valid_pointer) &&
		rz_buf_read_le16_offset(buf, &offset, &segment->page_count);
}

static void parse_chained_imports(RzBuffer *buf, ut32 offset, struct dyld_chained_fixups_header *header, struct mach0_chained_fixups_t *cf) {
	// MachOAnalyzer::forEachChainedFixupTarget
	if (header->imports_format != DYLD_CHAINED_IMPORT &&
		header->imports_format != DYLD_CHAINED_IMPORT_ADDEND &&
		header->imports_format != DYLD_CHAINED_IMPORT_ADDEND64) {
		RZ_LOG_WARN("Unsupported Mach-O chained import format: %d\n", (int)header->imports_format);
		return;
	}
	if (!header->imports_count) {
		return;
	}
	cf->imports_format = header->imports_format;
	size_t import_sz = dyld_chained_import_format_size(cf->imports_format);
	rz_return_if_fail(import_sz);
	rz_vector_init(&cf->imports, import_sz, NULL, NULL);
	if (SZT_MUL_OVFCHK(header->imports_count, import_sz)) {
		return;
	}
	size_t imports_buf_sz = (size_t)header->imports_count * import_sz;
	ut8 *imports_buf = malloc(imports_buf_sz);
	if (!imports_buf) {
		return;
	}
	if (rz_buf_read_at(buf, offset + header->imports_offset, imports_buf, imports_buf_sz) < imports_buf_sz) {
		free(imports_buf);
		return;
	}
	rz_vector_reserve(&cf->imports, header->imports_count);
	for (size_t i = 0; i < header->imports_count; i++) {
		void *dst = rz_vector_push(&cf->imports, NULL);
		if (!dst) {
			break;
		}
		switch (cf->imports_format) {
		case DYLD_CHAINED_IMPORT:
			dyld_chained_import_read(dst, imports_buf + import_sz * i);
			break;
		case DYLD_CHAINED_IMPORT_ADDEND:
			dyld_chained_import_addend_read(dst, imports_buf + import_sz * i);
			break;
		case DYLD_CHAINED_IMPORT_ADDEND64:
			dyld_chained_import_addend64_read(dst, imports_buf + import_sz * i);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	free(imports_buf);
}

/**
 * Maximum chained import ordinal + 1
 */
RZ_API size_t MACH0_(chained_imports_count)(struct MACH0_(obj_t) * obj) {
	return rz_vector_len(&obj->chained_fixups.imports);
}

/**
 * Copy contents of a dyld_chained_import* of the binary into \p dst
 * \param ordinal index of the import, given by chained pointers
 * \return true if an import with the given ordinal was found and read successfully
 */
RZ_API bool MACH0_(get_chained_import)(struct MACH0_(obj_t) * obj, ut32 ordinal, struct MACH0_(chained_import_t) * dst) {
	// MachOAnalyzer::forEachChainedFixupTarget
	if (ordinal >= rz_vector_len(&obj->chained_fixups.imports)) {
		return false;
	}
	void *raw = rz_vector_index_ptr(&obj->chained_fixups.imports, ordinal);
	switch (obj->chained_fixups.imports_format) {
	case DYLD_CHAINED_IMPORT_THREADED: {
		RzDyldChainedImportThreaded *s = raw;
		dst->lib_ordinal = s->lib_ord;
		dst->weak_import = false;
		dst->name_offset = 0;
		dst->name = s->sym_name;
		dst->addend = s->addend;
		break;
	}
	case DYLD_CHAINED_IMPORT: {
		struct dyld_chained_import *s = raw;
		dst->lib_ordinal = s->lib_ordinal > 0xf0 ? (st8)s->lib_ordinal : s->lib_ordinal;
		dst->weak_import = s->weak_import != 0;
		dst->name_offset = s->name_offset;
		dst->name = NULL;
		dst->addend = 0;
		break;
	}
	case DYLD_CHAINED_IMPORT_ADDEND: {
		struct dyld_chained_import_addend *s = raw;
		dst->lib_ordinal = s->lib_ordinal > 0xf0 ? (st8)s->lib_ordinal : s->lib_ordinal;
		dst->weak_import = s->weak_import != 0;
		dst->name_offset = s->name_offset;
		dst->name = NULL;
		dst->addend = s->addend;
		break;
	}
	case DYLD_CHAINED_IMPORT_ADDEND64: {
		struct dyld_chained_import_addend64 *s = raw;
		dst->lib_ordinal = s->lib_ordinal > 0xfff0 ? (st8)s->lib_ordinal : s->lib_ordinal;
		dst->weak_import = s->weak_import != 0;
		dst->name_offset = s->name_offset;
		dst->name = NULL;
		dst->addend = s->addend;
		break;
	}
	default:
		rz_warn_if_reached();
		return false;
	}
	return true;
}

RZ_API RZ_OWN char *MACH0_(chained_import_read_symbol_name)(struct MACH0_(obj_t) * obj, struct MACH0_(chained_import_t) * imp) {
	if (imp->name) {
		return rz_str_dup(imp->name);
	}
	return MACH0_(read_chained_symbol)(obj, imp->name_offset);
}

RZ_API RZ_OWN char *MACH0_(read_chained_symbol)(struct MACH0_(obj_t) * obj, ut32 name_offset) {
	ut64 paddr = obj->chained_fixups.symbols_base_paddr;
	if (paddr == UT64_MAX) {
		return NULL;
	}
	paddr += name_offset;
	return rz_buf_get_nstring(obj->b, paddr, RZ_BIN_MACH0_STRING_LENGTH);
}

RZ_IPI bool MACH0_(parse_chained_fixups)(struct MACH0_(obj_t) * bin, ut32 offset, ut32 size) {
	struct dyld_chained_fixups_header header;
	if (size < sizeof(header)) {
		return false;
	}
	if (!read_dyld_chained_fixups_header(&header, bin->b, offset)) {
		return false;
	}
	if (header.fixups_version > 0) {
		RZ_LOG_ERROR("Unsupported fixups version: %u\n", header.fixups_version);
		return false;
	}
	ut64 starts_at = offset + header.starts_offset;
	if (header.starts_offset > size) {
		return false;
	}
	if (!rz_buf_read_le32_at(bin->b, starts_at, &bin->chained_fixups.starts_count)) {
		return false;
	}
	struct mach0_chained_fixups_t *cf = &bin->chained_fixups;

	// chained starts
	cf->starts = RZ_NEWS0(struct rz_dyld_chained_starts_in_segment *, cf->starts_count);
	if (!cf->starts) {
		return false;
	}
	ut64 cursor = starts_at + sizeof(ut32);
	size_t max_count = RZ_MAX(bin->nsegs, cf->starts_count);
	for (size_t i = 0; i < max_count; i++) {
		ut32 seg_off = 0;
		if (!rz_buf_read_le32_at(bin->b, cursor, &seg_off)) {
			RZ_LOG_ERROR("Failed to read segment offset at: %" PFMT64x "\n", cursor);
			return false;
		} else if (!seg_off) {
			cursor += sizeof(ut32);
			continue;
		}
		struct rz_dyld_chained_starts_in_segment *cur_seg = RZ_NEW0(struct rz_dyld_chained_starts_in_segment);
		if (!cur_seg) {
			return false;
		}
		cf->starts[i] = cur_seg;
		if (!read_dyld_chained_starts_in_segment(cur_seg, bin->b, starts_at + seg_off)) {
			return false;
		}
		if (cur_seg->page_count > 0) {
			ut16 *page_start = RZ_NEWS0(ut16, cur_seg->page_count);
			if (!page_start) {
				cur_seg->page_count = 0;
				return false;
			}
			ut64 offset_page = starts_at + seg_off + 22;
			for (size_t j = 0; j < cur_seg->page_count; ++j) {
				if (!rz_buf_read_le16_offset(bin->b, &offset_page, &page_start[j])) {
					free(page_start);
					return false;
				}
			}
			cur_seg->page_start = page_start;
		}
		cursor += sizeof(ut32);
	}

	parse_chained_imports(bin->b, offset, &header, cf);

	if (header.symbols_format == 0) {
		// Only 0 is implemented in ld64 at the time of writing
		cf->symbols_base_paddr = (ut64)offset + header.symbols_offset;
	} else {
		RZ_LOG_WARN("Unsupported Mach-O chained symbols format: %d\n", (int)header.symbols_format);
		cf->symbols_base_paddr = UT64_MAX;
	}
	return true;
}

typedef struct {
	struct MACH0_(obj_t) * bin;
	struct rz_dyld_chained_starts_in_segment *cur_seg;
	size_t cur_seg_idx;
	bool found_threaded;
} ReconstructThreadedCtx;

static void chained_import_threaded_fini(void *e, void *user) {
	RzDyldChainedImportThreaded *imp = e;
	free(imp->sym_name);
}

static void reconstruct_threaded_table_size(ut64 table_size, void *user) {
	ReconstructThreadedCtx *ctx = user;
	ctx->found_threaded = true;
	struct mach0_chained_fixups_t *cf = &ctx->bin->chained_fixups;
	rz_vector_fini(&cf->imports);
	cf->imports_format = DYLD_CHAINED_IMPORT_THREADED;
	rz_vector_init(&cf->imports, sizeof(RzDyldChainedImportThreaded), chained_import_threaded_fini, NULL);
	void *v = rz_vector_insert_range(&cf->imports, 0, NULL, table_size);
	if (!v) {
		return;
	}
	memset(v, 0, table_size * sizeof(RzDyldChainedImportThreaded));
}

static void reconstruct_threaded_bind(ut64 paddr, ut64 vaddr, st64 addend, ut8 rel_type, int lib_ord, int sym_ord, const char *sym_name, void *user) {
	if (sym_ord < 0 || !sym_name) {
		return;
	}
	ReconstructThreadedCtx *ctx = user;
	struct mach0_chained_fixups_t *cf = &ctx->bin->chained_fixups;
	if (cf->imports_format != DYLD_CHAINED_IMPORT_THREADED) {
		RZ_LOG_ERROR("Missing BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB before bind\n");
		return;
	}
	if (sym_ord >= rz_vector_len(&cf->imports)) {
		RZ_LOG_ERROR("Imports overflow BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB value\n");
		return;
	}
	RzDyldChainedImportThreaded *imp = rz_vector_index_ptr(&cf->imports, sym_ord);
	free(imp->sym_name);
	imp->sym_name = rz_str_dup(sym_name);
	imp->lib_ord = lib_ord;
	imp->addend = addend;
}

static void reconstruct_threaded_apply(int seg_idx, ut64 seg_off, void *user) {
	ReconstructThreadedCtx *ctx = user;
	struct mach0_chained_fixups_t *cf = &ctx->bin->chained_fixups;
	const size_t ps = 0x1000;
	if (!ctx->cur_seg || ctx->cur_seg_idx != seg_idx) {
		ctx->cur_seg_idx = seg_idx;
		ctx->cur_seg = cf->starts[seg_idx];
		if (!ctx->cur_seg) {
			ctx->cur_seg = RZ_NEW0(struct rz_dyld_chained_starts_in_segment);
			if (!ctx->cur_seg) {
				return;
			}
			cf->starts[seg_idx] = ctx->cur_seg;
			ctx->cur_seg->pointer_format = DYLD_CHAINED_PTR_ARM64E;
			ctx->cur_seg->page_size = ps;
			ctx->cur_seg->page_count = ((ctx->bin->segs[seg_idx].vmsize + (ps - 1)) & ~(ps - 1)) / ps;
			if (ctx->cur_seg->page_count > 0) {
				ctx->cur_seg->page_start = RZ_NEWS0(ut16, ctx->cur_seg->page_count);
				if (!ctx->cur_seg->page_start) {
					ctx->cur_seg->page_count = 0;
					return;
				}
				memset(ctx->cur_seg->page_start, 0xff, sizeof(ut16) * ctx->cur_seg->page_count);
			}
		}
	}
	if (ctx->cur_seg) {
		ut32 page_index = (ut32)(seg_off / ps);
		if (page_index < ctx->cur_seg->page_count) {
			ctx->cur_seg->page_start[page_index] = seg_off & 0xfff;
		}
	}
}

RZ_IPI void MACH0_(reconstruct_chained_fixups_from_threaded)(struct MACH0_(obj_t) * bin) {
	struct mach0_chained_fixups_t *cf = &bin->chained_fixups;
	cf->starts_count = bin->nsegs;
	cf->starts = RZ_NEWS0(struct rz_dyld_chained_starts_in_segment *, cf->starts_count);
	if (!cf->starts) {
		return;
	}
	cf->symbols_base_paddr = UT64_MAX;
	ReconstructThreadedCtx ctx = {
		.bin = bin
	};
	// clang-format off
	MACH0_(bind_opcodes_foreach)(bin, reconstruct_threaded_table_size, reconstruct_threaded_bind, reconstruct_threaded_apply, &ctx);
	// clang-format on
	if (!ctx.found_threaded) {
		// found no BIND_OPCODE_THREADED to reconstruct chained relocs from,
		// so allow MACH0_(has_chained_fixups)() to still be false
		RZ_FREE(cf->starts);
		cf->starts_count = 0;
	}
}

#define IS_PTR_AUTH(x) ((x & (1ULL << 63)) != 0)
#define IS_PTR_BIND(x) ((x & (1ULL << 62)) != 0)
#define IS_FMT_32(fmt) (fmt == DYLD_CHAINED_PTR_32 || fmt == DYLD_CHAINED_PTR_32_CACHE || fmt == DYLD_CHAINED_PTR_32_FIRMWARE)

static bool read_raw_ptr(ut16 fmt, RzBuffer *buf, ut64 cursor, ut64 *out) {
	if (IS_FMT_32(fmt)) {
		ut32 val = 0;
		bool r = rz_buf_read_le32_at(buf, cursor, &val);
		*out = val;
		return r;
	}
	return rz_buf_read_le64_at(buf, cursor, out);
}

RZ_API void MACH0_(chained_fixups_foreach)(struct MACH0_(obj_t) * obj, mach0_chained_fixup_foreach_cb cb, void *user) {
	rz_return_if_fail(obj && cb);
	ut64 eob = rz_buf_size(obj->b);
	ut64 nsegs_to_rebase = RZ_MIN(obj->chained_fixups.starts_count, obj->nsegs);
	for (int i = 0; i < nsegs_to_rebase; i++) {
		if (!obj->chained_fixups.starts[i]) {
			continue;
		}
		struct rz_dyld_chained_starts_in_segment *segment = obj->chained_fixups.starts[i];
		ut64 page_size = segment->page_size;
		ut64 start = obj->segs[i].fileoff;
		ut64 end = start + obj->segs[i].filesize;
		if (start > eob || page_size < 1) {
			continue;
		}
		ut64 page_end_idx = (RZ_MIN(eob, end) - start) / page_size;
		for (ut64 page_idx = 0; page_idx <= page_end_idx; page_idx++) {
			if (!segment->page_start || page_idx >= segment->page_count) {
				break;
			}
			ut16 page_start = segment->page_start[page_idx];
			if (page_start == DYLD_CHAINED_PTR_START_NONE) {
				continue;
			}
			ut64 cursor = start + page_idx * page_size + page_start;
			while (cursor < eob && cursor < end) {
				ut64 raw_ptr = 0;
				if (!read_raw_ptr(segment->pointer_format, obj->b, cursor, &raw_ptr)) {
					break;
				}
				struct mach0_chained_fixup_t fixup = {
					.paddr = cursor,
					.size = IS_FMT_32(segment->pointer_format) ? 4 : 8,
					.result = raw_ptr
				};
				bool is_auth = IS_PTR_AUTH(raw_ptr);
				ut64 delta;
				ut64 stride = 8;
				switch (segment->pointer_format) {
				case DYLD_CHAINED_PTR_ARM64E: {
					bool is_bind = IS_PTR_BIND(raw_ptr);
					if (is_auth && is_bind) {
						struct dyld_chained_ptr_arm64e_auth_bind p;
						dyld_chained_ptr_arm64e_auth_bind_read(&p, raw_ptr);
						delta = p.next;
						fixup.is_bind = true;
						fixup.bind_ordinal = p.ordinal;
					} else if (!is_auth && is_bind) {
						struct dyld_chained_ptr_arm64e_bind p;
						dyld_chained_ptr_arm64e_bind_read(&p, raw_ptr);
						delta = p.next;
						fixup.addend = p.addend;
						fixup.is_bind = true;
						fixup.bind_ordinal = p.ordinal;
					} else if (is_auth && !is_bind) {
						struct dyld_chained_ptr_arm64e_auth_rebase p;
						dyld_chained_ptr_arm64e_auth_rebase_read(&p, raw_ptr);
						delta = p.next;
						fixup.result = p.target + obj->baddr;
					} else {
						struct dyld_chained_ptr_arm64e_rebase p;
						dyld_chained_ptr_arm64e_rebase_read(&p, raw_ptr);
						delta = p.next;
						fixup.result = ((ut64)p.high8 << 56) | p.target;
					}
					break;
				}
				case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				case DYLD_CHAINED_PTR_ARM64E_KERNEL: {
					stride = 4;
					if (is_auth) {
						struct dyld_chained_ptr_arm64e_cache_auth_rebase p;
						dyld_chained_ptr_arm64e_cache_auth_rebase_read(&p, raw_ptr);
						delta = p.next;
						fixup.result = p.target + obj->baddr;
					} else {
						struct dyld_chained_ptr_arm64e_cache_rebase p;
						dyld_chained_ptr_arm64e_cache_rebase_read(&p, raw_ptr);
						delta = p.next;
						fixup.result = ((ut64)p.high8 << 56) | p.target;
						fixup.result += obj->baddr;
					}
					break;
				}
				case DYLD_CHAINED_PTR_64:
				case DYLD_CHAINED_PTR_64_OFFSET: {
					stride = 4;
					struct dyld_chained_ptr_64_bind bind;
					dyld_chained_ptr_64_bind_read(&bind, raw_ptr);
					if (bind.bind) {
						delta = bind.next;
						fixup.addend = bind.addend;
						fixup.is_bind = true;
						fixup.bind_ordinal = bind.ordinal;
					} else {
						struct dyld_chained_ptr_64_rebase p;
						dyld_chained_ptr_64_rebase_read(&p, raw_ptr);
						delta = p.next;
						fixup.result = (((ut64)p.high8 << 56) | p.target);
						if (segment->pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
							fixup.result += obj->baddr;
						}
					}
					break;
				}
				case DYLD_CHAINED_PTR_ARM64E_USERLAND24: {
					stride = 8;
					struct dyld_chained_ptr_arm64e_bind24 bind;
					dyld_chained_ptr_arm64e_bind24_read(&bind, raw_ptr);
					if (bind.bind) {
						// void ClosureBuilder::addChainedFixupInfo(ImageWriter& writer, BuilderLoadedImage& forImage)
						// bool MachOAnalyzerSet::wmo_findSymbolFrom
						fixup.is_bind = true;
						if (bind.auth) {
							struct dyld_chained_ptr_arm64e_auth_bind24 p;
							dyld_chained_ptr_arm64e_auth_bind24_read(&p, raw_ptr);
							fixup.bind_ordinal = p.ordinal;
							delta = p.next;
						} else {
							fixup.addend = bind.addend;
							fixup.bind_ordinal = bind.ordinal;
							delta = bind.next;
						}
					} else {
						if (bind.auth) {
							struct dyld_chained_ptr_arm64e_auth_rebase p;
							dyld_chained_ptr_arm64e_auth_rebase_read(&p, raw_ptr);
							delta = p.next;
							fixup.result = p.target + obj->baddr;
						} else {
							struct dyld_chained_ptr_arm64e_rebase p;
							dyld_chained_ptr_arm64e_rebase_read(&p, raw_ptr);
							delta = p.next;
							fixup.result = obj->baddr + (((ut64)p.high8 << 56) | p.target);
						}
					}
					break;
				}
				case DYLD_CHAINED_PTR_32: {
					stride = 4;
					struct dyld_chained_ptr_32_bind bind;
					dyld_chained_ptr_32_bind_read(&bind, raw_ptr);
					if (bind.bind) {
						delta = bind.next;
						fixup.addend = bind.addend;
						fixup.is_bind = true;
						fixup.bind_ordinal = bind.ordinal;
					} else {
						struct dyld_chained_ptr_32_rebase rebase;
						dyld_chained_ptr_32_rebase_read(&rebase, raw_ptr);
						delta = rebase.next;
						if (rebase.target > segment->max_valid_pointer) {
							// "stolen" non-ptr integers to make a chain, see OutputFile::chain32bitPointers in ld64
							fixup.result = rebase.target - (0x04000000 + segment->max_valid_pointer) / 2;
						} else {
							fixup.result = rebase.target;
						}
					}
					break;
				}
				default:
					RZ_LOG_WARN("Unsupported Mach-O pointer format: %u at paddr 0x%" PFMT64x "\n",
						segment->pointer_format, cursor);
					goto break_it_all;
				}
				if (cursor <= eob - fixup.size) {
					cb(&fixup, user);
				}
				cursor += delta * stride;
				if (!delta) {
					break;
				}
				continue;
			break_it_all:
				break;
			}
		}
	}
}

RZ_API bool MACH0_(has_chained_fixups)(struct MACH0_(obj_t) * obj) {
	return !!obj->chained_fixups.starts;
}

RZ_API bool MACH0_(segment_has_chained_fixups)(struct MACH0_(obj_t) * obj, size_t seg_index) {
	if (seg_index >= obj->nsegs || seg_index >= obj->chained_fixups.starts_count) {
		return false;
	}
	return obj->chained_fixups.starts && obj->chained_fixups.starts[seg_index];
}

static void fixups_patch_cb(struct mach0_chained_fixup_t *fixup, void *user) {
	RzBuffer *dst = user;
	if (fixup->is_bind) {
		// patching bind relocs is handled in MACH0_(patch_relocs)() before already
		return;
	}
	switch (fixup->size) {
	case 4:
		rz_buf_write_le32_at(dst, fixup->paddr, fixup->result);
		break;
	case 8:
		rz_buf_write_le64_at(dst, fixup->paddr, fixup->result);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

/**
 * Patch all non-bind chained fixups into \p dst
 */
RZ_API void MACH0_(patch_chained_fixups)(struct MACH0_(obj_t) * obj, RzBuffer *dst) {
	// clang-format off
	MACH0_(chained_fixups_foreach)(obj, fixups_patch_cb, dst);
	// clang-format on
}
