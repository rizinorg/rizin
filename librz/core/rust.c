// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_endian.h>
#include <rz_util/rz_utf8.h>

#define RUST_MAX_STRING_SIZE    4096
#define RUST_MIN_CODE_STR_LEN   4
#define RUST_MIN_DATA_STR_LEN   4
#define RUST_MIN_UNRELOC_LEN    6
#define RUST_MAX_PANIC_PATH_LEN 512
#define RUST_MAX_PANIC_LINE     500000
#define RUST_MAX_PANIC_COL      4096
#define RUST_SCAN_CHUNK_SZ      65536
#define RUST_MAX_BB_SIZE        (16U * 1024U * 1024U)
#define RUST_TRACK_STACK_SLOTS  8

typedef struct {
	ut64 start;
	ut64 end;
	bool is_exec;
} RustMemRange;

typedef struct {
	bool has_ptr;
	bool has_imm;
	ut64 ptr_val;
	ut64 ptr_pc;
	ut64 imm_val;
} RustRegVal;

typedef struct {
	bool valid;
	bool is_rbp;
	st64 disp;
	bool has_ptr;
	bool has_imm;
	ut64 ptr_val;
	ut64 ptr_pc;
	ut64 imm_val;
} RustStackSlot;

typedef struct {
	RzCore *core;
	RzBinObject *obj;
	RzVector /*<RustMemRange>*/ data_ranges;
	RzVector /*<RustMemRange>*/ exec_ranges;
	HtUP /*<ut64, RzCoreRustPanicLoc *>*/ *loc_by_addr;
	RzSetU *seen_strings;
	RzSetU *seen_loc_xrefs;
	RzCoreRustInfo *info;
	ut32 word_size;
	ut32 bits;
	bool big_endian;
	bool has_relocs;
	bool is_pe;
	ut64 pe_baddr;
	char *raw_buf;
	char *flag_buf;
	size_t buf_cap;
} RustRecoverCtx;

static void rust_panic_loc_free(RzCoreRustPanicLoc *loc) {
	if (!loc) {
		return;
	}
	free(loc->file);
	free(loc->crate_name);
	free(loc);
}

/**
 * \brief Frees an \ref RzCoreRustInfo structure and all owned collections.
 * \param info Structure to free (NULL-safe)
 */
RZ_API void rz_core_rust_info_free(RZ_NULLABLE RzCoreRustInfo *info) {
	if (!info) {
		return;
	}
	rz_pvector_free(info->panic_locs);
	rz_pvector_free(info->crates);
	rz_pvector_free(info->user_files);
	rz_pvector_free(info->source_files);
	free(info);
}

static int compare_str_ptr(const void *a, const void *b, void *user) {
	return strcmp((const char *)a, (const char *)b);
}

static int reloc_vaddr_cmp(ut64 ref, RzBinReloc *reloc) {
	return RZ_NUM_CMP(ref, reloc->vaddr);
}

static bool range_contains(const RzVector /*<RustMemRange>*/ *ranges, ut64 addr, ut64 len);

static bool detect_data_relocs(const RustRecoverCtx *ctx) {
	if (!ctx->obj || !ctx->obj->relocs || !ctx->obj->relocs->relocs_count) {
		return false;
	}
	RzBinRelocStorage *storage = ctx->obj->relocs;
	for (size_t i = 0; i < storage->relocs_count; i++) {
		RzBinReloc *rel = storage->relocs[i];
		if (!rel || (ctx->is_pe && rel->type == 0)) {
			continue;
		}
		ut64 va;
		if (ctx->is_pe) {
			if (ctx->pe_baddr == UT64_MAX || rel->vaddr > UT64_MAX - ctx->pe_baddr) {
				continue;
			}
			va = ctx->pe_baddr + rel->vaddr;
		} else {
			va = rz_bin_object_addr_with_base(ctx->obj, rel->vaddr);
		}
		if (range_contains(&ctx->data_ranges, va, 1)) {
			return true;
		}
	}
	return false;
}

static bool rust_addr_has_reloc(const RustRecoverCtx *ctx, ut64 addr) {
	if (!ctx->has_relocs) {
		return false;
	}
	ut64 query;
	if (ctx->is_pe) {
		if (ctx->pe_baddr == UT64_MAX || addr < ctx->pe_baddr) {
			return false;
		}
		query = addr - ctx->pe_baddr;
	} else {
		query = addr - ctx->obj->baddr_shift;
	}
	RzBinRelocStorage *storage = ctx->obj->relocs;
	size_t idx = 0;
	rz_array_lower_bound(storage->relocs, storage->relocs_count, query, idx, reloc_vaddr_cmp);
	for (; idx < storage->relocs_count && storage->relocs[idx]->vaddr == query; idx++) {
		if (ctx->is_pe && storage->relocs[idx]->type == 0) {
			continue;
		}
		return true;
	}
	return false;
}

static bool section_is_named_rodata(const RzBinSection *sec) {
	if (!sec || sec->is_segment || !sec->name || !sec->vsize) {
		return false;
	}
	return strstr(sec->name, "rodata") ||
		strstr(sec->name, "rdata") ||
		!strcmp(sec->name, ".data.rel.ro") ||
		!strcmp(sec->name, ".data.rel.ro.local") ||
		rz_str_endswith(sec->name, "__const") ||
		rz_str_endswith(sec->name, "__cstring");
}

static bool section_is_rust_data_candidate(const RzBinSection *sec, bool allow_fallback) {
	if (!sec || sec->is_segment || !sec->size || !sec->vsize ||
		!(sec->perm & RZ_PERM_R) || (sec->perm & RZ_PERM_X)) {
		return false;
	}
	if (section_is_named_rodata(sec) ||
		(sec->name && (!strcmp(sec->name, ".data") || rz_str_endswith(sec->name, "__data")))) {
		return true;
	}
	if (!allow_fallback) {
		return false;
	}
	if (sec->name && (!strcmp(sec->name, ".rsrc") || !strcmp(sec->name, ".reloc") || !strcmp(sec->name, ".pdata") || !strcmp(sec->name, ".idata") || !strcmp(sec->name, ".tls") || !strcmp(sec->name, ".eh_frame") || !strcmp(sec->name, ".symtab") || !strcmp(sec->name, ".strtab") || !strcmp(sec->name, ".shstrtab") || rz_str_startswith(sec->name, ".debug"))) {
		return false;
	}
	return true;
}

static void collect_memory_ranges(RustRecoverCtx *ctx) {
	const RzPVector *sections = rz_bin_object_get_sections_all(ctx->obj);
	if (!sections) {
		return;
	}
	bool has_named = false;
	void **it;
	rz_pvector_foreach (sections, it) {
		if (section_is_named_rodata(*it)) {
			has_named = true;
			break;
		}
	}
	rz_pvector_foreach (sections, it) {
		RzBinSection *sec = *it;
		if (!sec || sec->is_segment || !sec->vsize) {
			continue;
		}
		ut64 start = rz_bin_object_addr_with_base(ctx->obj, sec->vaddr);
		if (sec->vsize > UT64_MAX - start) {
			continue;
		}
		ut64 end = start + sec->vsize;
		if (sec->perm & RZ_PERM_X) {
			RustMemRange r = { .start = start, .end = end, .is_exec = true };
			rz_vector_push(&ctx->exec_ranges, &r);
		} else if (section_is_rust_data_candidate(sec, !has_named)) {
			RustMemRange r = { .start = start, .end = end, .is_exec = false };
			rz_vector_push(&ctx->data_ranges, &r);
		}
	}
}

static bool range_contains(const RzVector /*<RustMemRange>*/ *ranges, ut64 addr, ut64 len) {
	if (!addr || addr == UT64_MAX || len > UT64_MAX - addr) {
		return false;
	}
	ut64 end = addr + len;
	RustMemRange *r;
	rz_vector_foreach (ranges, r) {
		if (addr >= r->start && end <= r->end) {
			return true;
		}
	}
	return false;
}

static bool ensure_str_buf(RustRecoverCtx *ctx, size_t str_len) {
	size_t req = str_len + 64;
	if (req <= ctx->buf_cap) {
		return true;
	}
	size_t new_cap = RZ_MAX(req, (size_t)512);
	char *nraw = realloc(ctx->raw_buf, new_cap);
	if (!nraw) {
		return false;
	}
	ctx->raw_buf = nraw;
	char *nflag = realloc(ctx->flag_buf, new_cap);
	if (!nflag) {
		return false;
	}
	ctx->flag_buf = nflag;
	ctx->buf_cap = new_cap;
	return true;
}

static bool is_valid_rust_utf8(const ut8 *buf, size_t len, bool strict_unreloc) {
	if (len == 0 || len > RUST_MAX_STRING_SIZE) {
		return false;
	}
	size_t off = 0;
	size_t printable = 0;
	size_t ascii_alnum = 0;
	ut8 first = buf[0];
	bool all_same = true;
	while (off < len) {
		if (buf[off] != first) {
			all_same = false;
		}
		RzCodePoint cp = 0;
		size_t clen = rz_utf8_decode(buf + off, len - off, &cp, true);
		if (clen == 0 || cp == 0) {
			return false;
		}
		if (cp < 0x20) {
			if (cp != '\t' && cp != '\n' && cp != '\r') {
				return false;
			}
		} else if (cp == 0x7f || (cp >= 0x80 && cp <= 0x9f) ||
			(cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) {
			return false;
		} else {
			if (cp != ' ') {
				printable++;
			}
			if ((cp >= '0' && cp <= '9') || (cp >= 'A' && cp <= 'Z') ||
				(cp >= 'a' && cp <= 'z') || cp == '_' || cp == '/' ||
				cp == '\\' || cp == '.' || cp == ':') {
				ascii_alnum++;
			}
		}
		off += clen;
	}
	if (printable < 2) {
		return false;
	}
	if (strict_unreloc && (all_same || ascii_alnum * 2 < printable)) {
		return false;
	}
	return true;
}

static bool add_or_update_rust_bin_string(RzCore *core, const char *str, ut64 vaddr, ut32 size) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->strings) {
		return false;
	}
	RzBinString *existing = rz_bin_object_get_string_at(bf->o, vaddr, true);
	if (existing && existing->vaddr == vaddr) {
		if (existing->size == size) {
			return true;
		}
		char *dup = rz_str_ndup(str, size);
		if (!dup) {
			return false;
		}
		free(existing->string);
		existing->string = dup;
		existing->length = size;
		existing->size = size;
		existing->type = RZ_STRING_ENC_UTF8;
		return true;
	}

	char *dup = rz_str_ndup(str, size);
	if (!dup) {
		return false;
	}
	RzBinString *bstr = RZ_NEW0(RzBinString);
	if (!bstr) {
		free(dup);
		return false;
	}
	bstr->paddr = rz_io_v2p(core->io, vaddr);
	bstr->vaddr = vaddr;
	bstr->length = size;
	bstr->size = size;
	bstr->string = dup;
	bstr->type = RZ_STRING_ENC_UTF8;
	if (!rz_bin_string_database_add(bf->o->strings, bstr)) {
		rz_bin_string_free(bstr);
		return false;
	}
	return true;
}

static bool register_rust_string(RustRecoverCtx *ctx, ut64 str_addr, ut64 str_size,
	ut64 xref_from, bool strict_unreloc, bool is_code_src) {
	if (str_size < 2 || str_size > RUST_MAX_STRING_SIZE ||
		!range_contains(&ctx->data_ranges, str_addr, str_size)) {
		return false;
	}

	RzFlagItem *sym_fi = rz_flag_get_by_spaces(ctx->core->flags, str_addr, RZ_FLAGS_FS_SYMBOLS, NULL);
	if (sym_fi && rz_str_startswith(sym_fi->name, "sym.")) {
		return false;
	}

	if (!ensure_str_buf(ctx, (size_t)str_size)) {
		return false;
	}
	int nread = rz_io_nread_at(ctx->core->io, str_addr, (ut8 *)ctx->raw_buf, (int)str_size);
	if (nread < 0 || (!ctx->core->io->ff && (ut64)nread != str_size)) {
		return false;
	}
	ctx->raw_buf[str_size] = '\0';
	if (!is_valid_rust_utf8((const ut8 *)ctx->raw_buf, (size_t)str_size, strict_unreloc)) {
		return false;
	}

	if (xref_from != UT64_MAX) {
		rz_analysis_xrefs_set(ctx->core->analysis, xref_from, str_addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	}

	if (rz_set_u_contains(ctx->seen_strings, str_addr)) {
		return true;
	}

	if (!add_or_update_rust_bin_string(ctx->core, ctx->raw_buf, str_addr, (ut32)str_size)) {
		return false;
	}

	rz_meta_set_with_subtype(ctx->core->analysis, RZ_META_TYPE_STRING,
		RZ_STRING_ENC_UTF8, str_addr, str_size, ctx->raw_buf);

	size_t flag_len = RZ_MIN((size_t)str_size, (size_t)48);
	memcpy(ctx->flag_buf, "str.", 4);
	memcpy(ctx->flag_buf + 4, ctx->raw_buf, flag_len);
	ctx->flag_buf[4 + flag_len] = '\0';
	rz_name_filter(ctx->flag_buf + 4, (int)flag_len, true);
	if (strlen(ctx->flag_buf) < 5) {
		snprintf(ctx->flag_buf, ctx->buf_cap, "str.rust.%" PFMT64x, str_addr);
	} else {
		RzFlagItem *clash = rz_flag_get(ctx->core->flags, ctx->flag_buf);
		if (clash && clash->offset != str_addr) {
			size_t cur_len = strlen(ctx->flag_buf);
			snprintf(ctx->flag_buf + cur_len, ctx->buf_cap - cur_len, "_%" PFMT64x, str_addr);
		}
	}

	RzFlagItem *old_str = rz_flag_get_by_spaces(ctx->core->flags, str_addr, RZ_FLAGS_FS_STRINGS, NULL);
	if (old_str) {
		rz_flag_unset(ctx->core->flags, old_str);
	}
	rz_flag_space_push(ctx->core->flags, RZ_FLAGS_FS_STRINGS);
	rz_flag_set(ctx->core->flags, ctx->flag_buf, str_addr, (ut32)str_size);
	rz_flag_space_pop(ctx->core->flags);

	rz_set_u_add(ctx->seen_strings, str_addr);
	ctx->info->strings_recovered++;
	if (is_code_src) {
		ctx->info->code_strings_recovered++;
	} else {
		ctx->info->data_strings_recovered++;
	}
	return true;
}

static bool is_valid_rust_source_path(const char *path, size_t len) {
	if (len < 4 || len > RUST_MAX_PANIC_PATH_LEN || memcmp(path + len - 3, ".rs", 3)) {
		return false;
	}
	bool has_sep = false;
	for (size_t i = 0; i < len; i++) {
		ut8 c = (ut8)path[i];
		if (c < 0x20 || c >= 0x7f) {
			return false;
		}
		if (c == '"' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|' || c == ';') {
			return false;
		}
		if (c == '/' || c == '\\') {
			has_sep = true;
		}
	}
	if (!has_sep) {
		// Bare filename like "main.rs": require identifier-like characters only.
		for (size_t i = 0; i < len - 3; i++) {
			ut8 c = (ut8)path[i];
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				    (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
				return false;
			}
		}
	}
	return true;
}

static bool is_rust_stdlib_path(const char *path) {
	return strstr(path, "/library/core/") || strstr(path, "\\library\\core\\") ||
		strstr(path, "/library/std/") || strstr(path, "\\library\\std\\") ||
		strstr(path, "/library/alloc/") || strstr(path, "\\library\\alloc\\") ||
		strstr(path, "/library/panic_") || strstr(path, "\\library\\panic_") ||
		strstr(path, "/rustc/") || strstr(path, "\\rustc\\") ||
		rz_str_startswith(path, "library/core/") || rz_str_startswith(path, "library\\core\\") ||
		rz_str_startswith(path, "library/std/") || rz_str_startswith(path, "library\\std\\") ||
		rz_str_startswith(path, "library/alloc/") || rz_str_startswith(path, "library\\alloc\\") ||
		rz_str_startswith(path, "library/panic_") || rz_str_startswith(path, "library\\panic_") ||
		rz_str_startswith(path, "core/src/") || rz_str_startswith(path, "core\\src\\") ||
		rz_str_startswith(path, "std/src/") || rz_str_startswith(path, "std\\src\\") ||
		rz_str_startswith(path, "alloc/src/") || rz_str_startswith(path, "alloc\\src\\");
}

static RZ_OWN char *extract_cargo_crate_name(const char *path) {
	const char *p = strstr(path, "registry/src/");
	size_t skip_prefix = 13;
	bool skip_index_dir = true;
	if (!p) {
		p = strstr(path, "registry\\src\\");
	}
	if (!p) {
		p = strstr(path, "/cargo/registry/");
		skip_prefix = 16;
		skip_index_dir = true;
	}
	if (!p) {
		p = strstr(path, "\\cargo\\registry\\");
		skip_prefix = 16;
		skip_index_dir = true;
	}
	if (!p) {
		p = strstr(path, "/rust/deps/");
		skip_prefix = 11;
		skip_index_dir = false;
	}
	if (!p) {
		p = strstr(path, "/rust/deps\\");
		skip_prefix = 11;
		skip_index_dir = false;
	}
	if (!p) {
		p = strstr(path, "\\rust\\deps\\");
		skip_prefix = 11;
		skip_index_dir = false;
	}
	if (!p) {
		p = strstr(path, ".cargo/git/checkouts/");
		skip_prefix = 21;
		skip_index_dir = false;
	}
	if (!p) {
		p = strstr(path, ".cargo\\git\\checkouts\\");
		skip_prefix = 21;
		skip_index_dir = false;
	}
	if (!p) {
		return NULL;
	}
	p += skip_prefix;
	if (skip_index_dir) {
		const char *sep = strpbrk(p, "/\\");
		if (!sep || !sep[1]) {
			return NULL;
		}
		p = sep + 1;
	}
	const char *end = strpbrk(p, "/\\");
	size_t clen = end ? (size_t)(end - p) : strlen(p);
	if (clen == 0 || clen > 128) {
		return NULL;
	}
	return rz_str_ndup(p, clen);
}

static void add_unique_string(RzPVector /*<char *>*/ *vec, const char *s) {
	if (RZ_STR_ISEMPTY(s)) {
		return;
	}
	if (rz_pvector_find(vec, s, (RzPVectorComparator)compare_str_ptr, NULL)) {
		return;
	}
	char *dup = rz_str_dup(s);
	if (dup && !rz_pvector_push(vec, dup)) {
		free(dup);
	}
}

static void annotate_panic_location_ref(RustRecoverCtx *ctx, ut64 pc, const RzCoreRustPanicLoc *loc) {
	if (!loc || rz_set_u_contains(ctx->seen_loc_xrefs, pc)) {
		return;
	}
	rz_set_u_add(ctx->seen_loc_xrefs, pc);
	rz_analysis_xrefs_set(ctx->core->analysis, pc, loc->addr, RZ_ANALYSIS_XREF_TYPE_DATA);
	char *comment = rz_str_newf("rust panic: %s:%u:%u", loc->file, loc->line, loc->col);
	if (comment) {
		rz_meta_set_string(ctx->core->analysis, RZ_META_TYPE_COMMENT, pc, comment);
		free(comment);
	}
}

static void recover_rust_panic_locations_and_data_strings(RustRecoverCtx *ctx) {
	ut8 *buf = malloc(RUST_SCAN_CHUNK_SZ);
	if (!buf) {
		return;
	}
	const ut32 loc_size = (ctx->word_size * 2) + 8;
	const ut32 pair_size = ctx->word_size * 2;

	RustMemRange *r;
	rz_vector_foreach (&ctx->data_ranges, r) {
		if (rz_interrupt_is_breaked(ctx->core->intr)) {
			break;
		}
		ut64 cur = RZ_ROUND(r->start, ctx->word_size);
		while (cur < r->end && r->end - cur >= pair_size) {
			if (rz_interrupt_is_breaked(ctx->core->intr)) {
				break;
			}
			size_t chunk_len = (size_t)RZ_MIN(r->end - cur, (ut64)RUST_SCAN_CHUNK_SZ);
			if (chunk_len < pair_size) {
				break;
			}
			int nread = rz_io_nread_at(ctx->core->io, cur, buf, (int)chunk_len);
			if (nread < (int)pair_size) {
				break;
			}
			size_t avail = (size_t)nread;
			size_t i = 0;
			while (i + pair_size <= avail) {
				if (i > 0 && cur + chunk_len < r->end && i + loc_size > avail) {
					break;
				}
				ut64 entry_va = cur + i;
				ut64 str_ptr = rz_read_ble(buf + i, ctx->big_endian, ctx->bits);
				ut64 str_len = rz_read_ble(buf + i + ctx->word_size, ctx->big_endian, ctx->bits);

				bool reloc_ok = !ctx->has_relocs ||
					(rust_addr_has_reloc(ctx, entry_va) &&
						!rust_addr_has_reloc(ctx, entry_va + ctx->word_size));

				// Check core::panic::Location { file: &str (ptr, len), line: u32, col: u32 }
				if (reloc_ok && i + loc_size <= avail &&
					str_len >= 4 && str_len <= RUST_MAX_PANIC_PATH_LEN &&
					range_contains(&ctx->data_ranges, str_ptr, str_len)) {
					ut32 line = rz_read_ble32(buf + i + pair_size, ctx->big_endian);
					ut32 col = rz_read_ble32(buf + i + pair_size + 4, ctx->big_endian);
					if (line >= 1 && line <= RUST_MAX_PANIC_LINE &&
						col >= 1 && col <= RUST_MAX_PANIC_COL &&
						ensure_str_buf(ctx, (size_t)str_len)) {
						int pr = rz_io_nread_at(ctx->core->io, str_ptr, (ut8 *)ctx->raw_buf, (int)str_len);
						if (pr == (int)str_len) {
							ctx->raw_buf[str_len] = '\0';
							if (is_valid_rust_source_path(ctx->raw_buf, (size_t)str_len)) {
								RzCoreRustPanicLoc *loc = RZ_NEW0(RzCoreRustPanicLoc);
								if (loc) {
									loc->addr = entry_va;
									loc->file_addr = str_ptr;
									loc->file = rz_str_ndup(ctx->raw_buf, (size_t)str_len);
									loc->crate_name = loc->file ? extract_cargo_crate_name(loc->file) : NULL;
									loc->line = line;
									loc->col = col;
									loc->is_user_code = loc->file && !loc->crate_name && !is_rust_stdlib_path(loc->file);
									if (loc->file && rz_pvector_push(ctx->info->panic_locs, loc)) {
										ht_up_insert(ctx->loc_by_addr, entry_va, loc);
										add_unique_string(ctx->info->source_files, loc->file);
										if (loc->crate_name) {
											add_unique_string(ctx->info->crates, loc->crate_name);
										} else if (loc->is_user_code) {
											add_unique_string(ctx->info->user_files, loc->file);
										}
										register_rust_string(ctx, str_ptr, str_len, entry_va, false, false);
										// Annotate any existing xrefs pointing to this panic::Location.
										RzList *xrefs = rz_analysis_xrefs_get_to(ctx->core->analysis, entry_va);
										if (xrefs) {
											RzListIter *xit;
											RzAnalysisXRef *xr;
											rz_list_foreach (xrefs, xit, xr) {
												annotate_panic_location_ref(ctx, xr->from, loc);
											}
											rz_list_free(xrefs);
										}
										i += loc_size;
										continue;
									}
									rust_panic_loc_free(loc);
								}
							}
						}
					}
				}

				// Static &str slice (ptr, len): e.g., const &str, &[&str], fmt::Arguments pieces
				ut64 min_data_len = ctx->has_relocs ? RUST_MIN_DATA_STR_LEN : RUST_MIN_UNRELOC_LEN;
				if (reloc_ok && str_len >= min_data_len && str_len <= RUST_MAX_STRING_SIZE &&
					range_contains(&ctx->data_ranges, str_ptr, str_len)) {
					if (register_rust_string(ctx, str_ptr, str_len, entry_va, !ctx->has_relocs, false)) {
						i += pair_size;
						continue;
					}
				}

				i += ctx->word_size;
			}
			if (i == 0) {
				break;
			}
			cur += i;
		}
	}
	free(buf);
}

static bool x64_is_str_reg_pair(int ptr_reg, int len_reg) {
	// Win64 & SysV Rust/C ABI adjacent argument and return register pairs:
	// (rcx=1, rdx=2), (rdx=2, r8=8), (r8=8, r9=9),
	// (rdi=7, rsi=6), (rsi=6, rdx=2), (rdx=2, rcx=1), (rcx=1, r8=8),
	// (rax=0, rdx=2)
	return (ptr_reg == 1 && len_reg == 2) ||
		(ptr_reg == 2 && len_reg == 8) ||
		(ptr_reg == 8 && len_reg == 9) ||
		(ptr_reg == 7 && len_reg == 6) ||
		(ptr_reg == 6 && len_reg == 2) ||
		(ptr_reg == 2 && len_reg == 1) ||
		(ptr_reg == 1 && len_reg == 8) ||
		(ptr_reg == 0 && len_reg == 2);
}

static void stack_slot_record_ptr(RustStackSlot *slots, bool is_rbp, st64 disp, ut64 ptr_val, ut64 ptr_pc) {
	for (size_t i = 0; i < RUST_TRACK_STACK_SLOTS; i++) {
		if (slots[i].valid && slots[i].is_rbp == is_rbp && slots[i].disp == disp) {
			slots[i].has_ptr = true;
			slots[i].has_imm = false;
			slots[i].ptr_val = ptr_val;
			slots[i].ptr_pc = ptr_pc;
			return;
		}
	}
	for (size_t i = 0; i < RUST_TRACK_STACK_SLOTS; i++) {
		if (!slots[i].valid) {
			slots[i] = (RustStackSlot){
				.valid = true,
				.is_rbp = is_rbp,
				.disp = disp,
				.has_ptr = true,
				.ptr_val = ptr_val,
				.ptr_pc = ptr_pc,
			};
			return;
		}
	}
	memmove(slots, slots + 1, (RUST_TRACK_STACK_SLOTS - 1) * sizeof(RustStackSlot));
	slots[RUST_TRACK_STACK_SLOTS - 1] = (RustStackSlot){
		.valid = true,
		.is_rbp = is_rbp,
		.disp = disp,
		.has_ptr = true,
		.ptr_val = ptr_val,
		.ptr_pc = ptr_pc,
	};
}

static void stack_slot_record_imm(RustStackSlot *slots, bool is_rbp, st64 disp, ut64 imm_val) {
	for (size_t i = 0; i < RUST_TRACK_STACK_SLOTS; i++) {
		if (slots[i].valid && slots[i].is_rbp == is_rbp && slots[i].disp == disp) {
			slots[i].has_imm = true;
			slots[i].has_ptr = false;
			slots[i].imm_val = imm_val;
			return;
		}
	}
	for (size_t i = 0; i < RUST_TRACK_STACK_SLOTS; i++) {
		if (!slots[i].valid) {
			slots[i] = (RustStackSlot){
				.valid = true,
				.is_rbp = is_rbp,
				.disp = disp,
				.has_imm = true,
				.imm_val = imm_val,
			};
			return;
		}
	}
	memmove(slots, slots + 1, (RUST_TRACK_STACK_SLOTS - 1) * sizeof(RustStackSlot));
	slots[RUST_TRACK_STACK_SLOTS - 1] = (RustStackSlot){
		.valid = true,
		.is_rbp = is_rbp,
		.disp = disp,
		.has_imm = true,
		.imm_val = imm_val,
	};
}

static void flush_stack_str_pairs(RustRecoverCtx *ctx, RustStackSlot *slots) {
	for (size_t i = 0; i < RUST_TRACK_STACK_SLOTS; i++) {
		if (!slots[i].valid || !slots[i].has_ptr) {
			continue;
		}
		for (size_t j = 0; j < RUST_TRACK_STACK_SLOTS; j++) {
			if (!slots[j].valid || !slots[j].has_imm || slots[j].is_rbp != slots[i].is_rbp) {
				continue;
			}
			if (slots[j].disp == slots[i].disp + (st64)ctx->word_size &&
				slots[j].imm_val >= RUST_MIN_CODE_STR_LEN &&
				slots[j].imm_val <= RUST_MAX_STRING_SIZE) {
				register_rust_string(ctx, slots[i].ptr_val, slots[j].imm_val,
					slots[i].ptr_pc, true, true);
				slots[i].has_ptr = false;
				slots[j].has_imm = false;
				break;
			}
		}
	}
}

static void try_emit_x64_reg_pairs(RustRecoverCtx *ctx, RustRegVal regs[16]) {
	for (int p = 0; p < 16; p++) {
		if (!regs[p].has_ptr) {
			continue;
		}
		for (int l = 0; l < 16; l++) {
			if (!regs[l].has_imm || !x64_is_str_reg_pair(p, l)) {
				continue;
			}
			if (regs[l].imm_val >= RUST_MIN_CODE_STR_LEN &&
				regs[l].imm_val <= RUST_MAX_STRING_SIZE &&
				register_rust_string(ctx, regs[p].ptr_val, regs[l].imm_val,
					regs[p].ptr_pc, true, true)) {
				regs[p].has_ptr = false;
				regs[l].has_imm = false;
				break;
			}
		}
	}
}

static bool decode_x64_stack_modrm(const ut8 *b, size_t len, size_t modrm_off,
	bool *is_rbp_out, st64 *disp_out, size_t *after_disp_out) {
	if (modrm_off >= len) {
		return false;
	}
	ut8 modrm = b[modrm_off];
	ut8 mod = (modrm >> 6) & 3;
	ut8 rm = modrm & 7;
	size_t pos = modrm_off + 1;
	bool is_rbp = false;
	if (rm == 4 && mod != 3) {
		if (pos >= len) {
			return false;
		}
		ut8 sib = b[pos++];
		if ((sib & 7) != 4 || ((sib >> 3) & 7) != 4) {
			return false;
		}
		is_rbp = false;
	} else if (rm == 5 && (mod == 1 || mod == 2)) {
		is_rbp = true;
	} else {
		return false;
	}
	st64 disp = 0;
	if (mod == 1) {
		if (pos >= len) {
			return false;
		}
		disp = (st8)b[pos++];
	} else if (mod == 2) {
		if (pos + 4 > len) {
			return false;
		}
		disp = (st32)rz_read_le32(b + pos);
		pos += 4;
	} else if (mod != 0) {
		return false;
	}
	*is_rbp_out = is_rbp;
	*disp_out = disp;
	*after_disp_out = pos;
	return true;
}

static void scan_x64_insn_window(RustRecoverCtx *ctx, ut64 pc, const ut8 *b, size_t len,
	RustRegVal regs[16], RustStackSlot slots[RUST_TRACK_STACK_SLOTS]) {
	// 1. LEA r64, [rip + disp32]: 48|4c 8d modrm disp32 (7 bytes)
	if (len >= 7 && (b[0] == 0x48 || b[0] == 0x4c) && b[1] == 0x8d && (b[2] & 0xc7) == 0x05) {
		int reg = ((b[0] & 0x04) << 1) | ((b[2] >> 3) & 7);
		st32 disp = (st32)rz_read_le32(b + 3);
		ut64 target = pc + 7 + (st64)disp;
		RzCoreRustPanicLoc *loc = ht_up_find(ctx->loc_by_addr, target, NULL);
		if (loc) {
			annotate_panic_location_ref(ctx, pc, loc);
		}
		regs[reg] = (RustRegVal){ 0 };
		if (range_contains(&ctx->data_ranges, target, 1)) {
			regs[reg].has_ptr = true;
			regs[reg].ptr_val = target;
			regs[reg].ptr_pc = pc;
			try_emit_x64_reg_pairs(ctx, regs);
		}
		return;
	}

	// 2. MOV r32, imm32: b8..bf imm32 (5 bytes) or 41 b8..bf imm32 (6 bytes)
	if (len >= 5 && b[0] >= 0xb8 && b[0] <= 0xbf) {
		int reg = b[0] - 0xb8;
		ut32 imm = rz_read_le32(b + 1);
		regs[reg] = (RustRegVal){ .has_imm = true, .imm_val = imm };
		try_emit_x64_reg_pairs(ctx, regs);
		return;
	}
	if (len >= 6 && b[0] == 0x41 && b[1] >= 0xb8 && b[1] <= 0xbf) {
		int reg = 8 + (b[1] - 0xb8);
		ut32 imm = rz_read_le32(b + 2);
		regs[reg] = (RustRegVal){ .has_imm = true, .imm_val = imm };
		try_emit_x64_reg_pairs(ctx, regs);
		return;
	}

	// 3. MOV r64, sign-ext imm32: 48|49 c7 c0..c7 imm32 (7 bytes)
	if (len >= 7 && (b[0] == 0x48 || b[0] == 0x49) && b[1] == 0xc7 && (b[2] & 0xf8) == 0xc0) {
		int reg = ((b[0] & 0x01) << 3) | (b[2] & 7);
		st32 simm = (st32)rz_read_le32(b + 3);
		regs[reg] = (RustRegVal){ 0 };
		if (simm > 0) {
			regs[reg].has_imm = true;
			regs[reg].imm_val = (ut64)simm;
			try_emit_x64_reg_pairs(ctx, regs);
		}
		return;
	}

	// 4. MOV [rsp/rbp + disp], r64: 48|4c 89 modrm ...
	if (len >= 4 && (b[0] == 0x48 || b[0] == 0x4c) && b[1] == 0x89) {
		int src_reg = ((b[0] & 0x04) << 1) | ((b[2] >> 3) & 7);
		bool is_rbp = false;
		st64 disp = 0;
		size_t after = 0;
		if (decode_x64_stack_modrm(b, len, 2, &is_rbp, &disp, &after)) {
			if (regs[src_reg].has_ptr) {
				stack_slot_record_ptr(slots, is_rbp, disp, regs[src_reg].ptr_val, regs[src_reg].ptr_pc);
				flush_stack_str_pairs(ctx, slots);
			} else if (regs[src_reg].has_imm) {
				stack_slot_record_imm(slots, is_rbp, disp, regs[src_reg].imm_val);
				flush_stack_str_pairs(ctx, slots);
			}
			return;
		}
	}

	// 5. MOV qword [rsp/rbp + disp], imm32: 48 c7 modrm [sib] [disp] imm32
	if (len >= 8 && b[0] == 0x48 && b[1] == 0xc7 && ((b[2] >> 3) & 7) == 0) {
		bool is_rbp = false;
		st64 disp = 0;
		size_t after = 0;
		if (decode_x64_stack_modrm(b, len, 2, &is_rbp, &disp, &after) && after + 4 <= len) {
			st32 simm = (st32)rz_read_le32(b + after);
			if (simm > 0) {
				stack_slot_record_imm(slots, is_rbp, disp, (ut64)simm);
				flush_stack_str_pairs(ctx, slots);
			}
			return;
		}
	}

	// 6. Clobber tracking for XOR reg, reg (zeroing) and MOV r64, r/m64
	if (len >= 2 && (b[0] == 0x31 || b[0] == 0x33) && (b[1] & 0xc0) == 0xc0) {
		int reg = (b[1] >> 3) & 7;
		int rm = b[1] & 7;
		if (reg == rm) {
			regs[reg] = (RustRegVal){ 0 };
			return;
		}
	}
	if (len >= 3 && (b[0] & 0xf0) == 0x40 && (b[1] == 0x31 || b[1] == 0x33) && (b[2] & 0xc0) == 0xc0) {
		int reg = ((b[0] & 0x04) << 1) | ((b[2] >> 3) & 7);
		int rm = ((b[0] & 0x01) << 3) | (b[2] & 7);
		if (reg == rm) {
			regs[reg] = (RustRegVal){ 0 };
			return;
		}
	}
	if (len >= 3 && (b[0] == 0x48 || b[0] == 0x49 || b[0] == 0x4c || b[0] == 0x4d) && b[1] == 0x8b) {
		int dst_reg = ((b[0] & 0x04) << 1) | ((b[2] >> 3) & 7);
		if ((b[2] & 0xc0) == 0xc0) {
			int src_reg = ((b[0] & 0x01) << 3) | (b[2] & 7);
			regs[dst_reg] = regs[src_reg];
			try_emit_x64_reg_pairs(ctx, regs);
		} else {
			regs[dst_reg] = (RustRegVal){ 0 };
		}
		return;
	}

	// 7. Reset tracking on CALL / JMP / RET boundaries
	if (b[0] == 0xe8 || b[0] == 0xe9 || b[0] == 0xeb || b[0] == 0xc3 || b[0] == 0xc2 ||
		(len >= 2 && b[0] == 0xff && (((b[1] >> 3) & 7) == 2 || ((b[1] >> 3) & 7) == 4))) {
		try_emit_x64_reg_pairs(ctx, regs);
		flush_stack_str_pairs(ctx, slots);
		memset(regs, 0, sizeof(RustRegVal) * 16);
		if (b[0] == 0xc3 || b[0] == 0xc2 || b[0] == 0xe9 || b[0] == 0xeb) {
			memset(slots, 0, sizeof(RustStackSlot) * RUST_TRACK_STACK_SLOTS);
		}
	}
}

static void scan_arm64_block(RustRecoverCtx *ctx, ut64 base_addr, const ut8 *buf, size_t size) {
	RustRegVal regs[32] = { 0 };
	ut64 page_base[32] = { 0 };
	bool has_page[32] = { 0 };
	ut64 page_pc[32] = { 0 };
	RustStackSlot slots[RUST_TRACK_STACK_SLOTS] = { 0 };

	for (size_t off = 0; off + 4 <= size; off += 4) {
		ut64 pc = base_addr + off;
		ut32 insn = rz_read_ble32(buf + off, ctx->big_endian);
		ut32 rd = insn & 0x1f;

		// ADRP Xd, label: op=1, bit 28..24 = 10000
		if ((insn & 0x9f000000) == 0x90000000) {
			ut64 immlo = (insn >> 29) & 0x3;
			ut64 immhi = (insn >> 5) & 0x7ffff;
			st64 imm21 = (st64)((immhi << 2) | immlo);
			if (imm21 & (1LL << 20)) {
				imm21 |= ~((1LL << 21) - 1);
			}
			page_base[rd] = (pc & ~0xfffULL) + ((ut64)imm21 << 12);
			has_page[rd] = true;
			page_pc[rd] = pc;
			regs[rd] = (RustRegVal){ 0 };
			continue;
		}

		// ADR Xd, label
		if ((insn & 0x9f000000) == 0x10000000) {
			ut64 immlo = (insn >> 29) & 0x3;
			ut64 immhi = (insn >> 5) & 0x7ffff;
			st64 imm21 = (st64)((immhi << 2) | immlo);
			if (imm21 & (1LL << 20)) {
				imm21 |= ~((1LL << 21) - 1);
			}
			ut64 target = pc + (ut64)imm21;
			has_page[rd] = false;
			regs[rd] = (RustRegVal){ 0 };
			RzCoreRustPanicLoc *loc = ht_up_find(ctx->loc_by_addr, target, NULL);
			if (loc) {
				annotate_panic_location_ref(ctx, pc, loc);
			}
			if (range_contains(&ctx->data_ranges, target, 1)) {
				regs[rd].has_ptr = true;
				regs[rd].ptr_val = target;
				regs[rd].ptr_pc = pc;
				if (rd < 7 && regs[rd + 1].has_imm &&
					regs[rd + 1].imm_val >= RUST_MIN_CODE_STR_LEN &&
					regs[rd + 1].imm_val <= RUST_MAX_STRING_SIZE) {
					register_rust_string(ctx, target, regs[rd + 1].imm_val,
						pc, true, true);
				}
			}
			continue;
		}

		// ADD Xd, Xn, #imm12 (64-bit immediate)
		if ((insn & 0xff800000) == 0x91000000) {
			ut32 rn = (insn >> 5) & 0x1f;
			ut64 imm12 = (insn >> 10) & 0xfff;
			if (insn & (1U << 22)) {
				imm12 <<= 12;
			}
			if (has_page[rn]) {
				ut64 target = page_base[rn] + imm12;
				ut64 ref_pc = page_pc[rn];
				has_page[rd] = false;
				regs[rd] = (RustRegVal){ 0 };
				RzCoreRustPanicLoc *loc = ht_up_find(ctx->loc_by_addr, target, NULL);
				if (loc) {
					annotate_panic_location_ref(ctx, ref_pc, loc);
				}
				if (range_contains(&ctx->data_ranges, target, 1)) {
					regs[rd].has_ptr = true;
					regs[rd].ptr_val = target;
					regs[rd].ptr_pc = ref_pc;
					if (rd < 7 && regs[rd + 1].has_imm &&
						regs[rd + 1].imm_val >= RUST_MIN_CODE_STR_LEN &&
						regs[rd + 1].imm_val <= RUST_MAX_STRING_SIZE) {
						register_rust_string(ctx, target, regs[rd + 1].imm_val,
							ref_pc, true, true);
					}
				}
				continue;
			}
		}

		// MOVZ Wd/Xd, #imm16 (shift 0)
		if ((insn & 0x7fe00000) == 0x52800000 && rd < 31) {
			ut64 imm16 = (insn >> 5) & 0xffff;
			has_page[rd] = false;
			regs[rd] = (RustRegVal){ .has_imm = true, .imm_val = imm16 };
			if (rd > 0 && rd <= 7 && regs[rd - 1].has_ptr &&
				imm16 >= RUST_MIN_CODE_STR_LEN && imm16 <= RUST_MAX_STRING_SIZE) {
				register_rust_string(ctx, regs[rd - 1].ptr_val, imm16,
					regs[rd - 1].ptr_pc, true, true);
			}
			continue;
		}

		// STR Xt, [sp, #uimm12*8]
		if ((insn & 0xffc003e0) == 0xf90003e0) {
			ut64 disp = ((insn >> 10) & 0xfff) * 8;
			if (regs[rd].has_ptr) {
				stack_slot_record_ptr(slots, false, (st64)disp, regs[rd].ptr_val, regs[rd].ptr_pc);
				flush_stack_str_pairs(ctx, slots);
			} else if (regs[rd].has_imm) {
				stack_slot_record_imm(slots, false, (st64)disp, regs[rd].imm_val);
				flush_stack_str_pairs(ctx, slots);
			}
			continue;
		}

		// BL / B / RET reset caller-saved state
		if ((insn & 0x7c000000) == 0x14000000 || insn == 0xd65f03c0) {
			flush_stack_str_pairs(ctx, slots);
			memset(regs, 0, sizeof(regs));
			memset(has_page, 0, sizeof(has_page));
			if (insn == 0xd65f03c0) {
				memset(slots, 0, sizeof(slots));
			}
		}
	}
}

static void scan_x64_analyzed_fcns(RustRecoverCtx *ctx, ut64 *covered_bytes_out) {
	RzList *fcns = rz_analysis_function_list(ctx->core->analysis);
	if (!fcns) {
		return;
	}
	ut8 *bb_buf = NULL;
	ut32 bb_cap = 0;
	ut64 covered = 0;
	RzListIter *lit;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, lit, fcn) {
		if (rz_interrupt_is_breaked(ctx->core->intr)) {
			break;
		}
		void **vit;
		rz_pvector_foreach (fcn->bbs, vit) {
			RzAnalysisBlock *bb = *vit;
			if (!bb->size || bb->size > RUST_MAX_BB_SIZE) {
				continue;
			}
			covered += bb->size;
			if (bb->size > bb_cap) {
				ut8 *nb = realloc(bb_buf, bb->size);
				if (!nb) {
					free(bb_buf);
					*covered_bytes_out = covered;
					return;
				}
				bb_buf = nb;
				bb_cap = bb->size;
			}
			int nr = rz_io_nread_at(ctx->core->io, bb->addr, bb_buf, (int)bb->size);
			if (nr <= 0 || (!ctx->core->io->ff && (ut64)nr != bb->size)) {
				continue;
			}
			RustRegVal regs[16] = { 0 };
			RustStackSlot slots[RUST_TRACK_STACK_SLOTS] = { 0 };
			if (bb->ninstr > 0 && bb->size <= UT16_MAX) {
				for (int idx = 0; idx < bb->ninstr; idx++) {
					ut16 off = rz_analysis_block_get_op_offset(bb, idx);
					if (off >= bb->size) {
						break;
					}
					scan_x64_insn_window(ctx, bb->addr + off, bb_buf + off,
						bb->size - off, regs, slots);
				}
			} else {
				for (ut64 off = 0; off < bb->size;) {
					scan_x64_insn_window(ctx, bb->addr + off, bb_buf + off,
						bb->size - off, regs, slots);
					RzAnalysisOp aop = { 0 };
					rz_analysis_op_init(&aop);
					int sz = rz_analysis_op(ctx->core->analysis, &aop, bb->addr + off,
						bb_buf + off, (int)RZ_MIN(bb->size - off, (ut64)16),
						RZ_ANALYSIS_OP_MASK_BASIC);
					rz_analysis_op_fini(&aop);
					off += sz > 0 ? (ut64)sz : 1;
				}
			}
			try_emit_x64_reg_pairs(ctx, regs);
			flush_stack_str_pairs(ctx, slots);
		}
	}
	free(bb_buf);
	*covered_bytes_out = covered;
}

static void scan_x64_exec_sections_fast(RustRecoverCtx *ctx) {
	ut8 *buf = malloc(RUST_SCAN_CHUNK_SZ + 72);
	if (!buf) {
		return;
	}
	RustMemRange *r;
	rz_vector_foreach (&ctx->exec_ranges, r) {
		if (rz_interrupt_is_breaked(ctx->core->intr)) {
			break;
		}
		ut64 cur = r->start;
		while (cur < r->end) {
			if (rz_interrupt_is_breaked(ctx->core->intr)) {
				break;
			}
			size_t prefix = (cur > r->start) ? (size_t)RZ_MIN(cur - r->start, (ut64)8) : 0;
			ut64 read_va = cur - prefix;
			size_t want = prefix + (size_t)RZ_MIN(r->end - cur, (ut64)(RUST_SCAN_CHUNK_SZ + 64));
			int nread = rz_io_nread_at(ctx->core->io, read_va, buf, (int)want);
			if (nread < (int)(prefix + 7)) {
				break;
			}
			size_t avail = (size_t)nread;
			size_t scan_end = (read_va + avail < r->end && avail > prefix + 64) ? (avail - 64) : avail;
			for (size_t i = prefix; i < scan_end && i + 7 <= avail; i++) {
				// Fast pre-filter for x86-64 RIP-relative LEA: 48|4c 8d [mod=00,rm=101] disp32
				if ((buf[i] != 0x48 && buf[i] != 0x4c) || buf[i + 1] != 0x8d ||
					(buf[i + 2] & 0xc7) != 0x05) {
					continue;
				}
				ut64 lea_pc = read_va + i;
				st32 disp = (st32)rz_read_le32(buf + i + 3);
				ut64 target = lea_pc + 7 + (st64)disp;
				if (!range_contains(&ctx->data_ranges, target, 1)) {
					continue;
				}
				// Check panic::Location direct reference first
				RzCoreRustPanicLoc *loc = ht_up_find(ctx->loc_by_addr, target, NULL);
				if (loc) {
					annotate_panic_location_ref(ctx, lea_pc, loc);
					continue;
				}

				int ptr_reg = ((buf[i] & 0x04) << 1) | ((buf[i + 2] >> 3) & 7);
				RustRegVal regs[16] = { 0 };
				RustStackSlot slots[RUST_TRACK_STACK_SLOTS] = { 0 };
				regs[ptr_reg].has_ptr = true;
				regs[ptr_reg].ptr_val = target;
				regs[ptr_reg].ptr_pc = lea_pc;

				// Check immediately preceding mov imm (5, 6, or 7 bytes before LEA)
				if (i >= 5 && buf[i - 5] >= 0xb8 && buf[i - 5] <= 0xbf) {
					int lr = buf[i - 5] - 0xb8;
					if (x64_is_str_reg_pair(ptr_reg, lr)) {
						ut32 imm = rz_read_le32(buf + i - 4);
						if (imm >= RUST_MIN_CODE_STR_LEN && imm <= RUST_MAX_STRING_SIZE &&
							register_rust_string(ctx, target, imm, lea_pc, true, true)) {
							continue;
						}
					}
				}
				if (i >= 6 && buf[i - 6] == 0x41 && buf[i - 5] >= 0xb8 && buf[i - 5] <= 0xbf) {
					int lr = 8 + (buf[i - 5] - 0xb8);
					if (x64_is_str_reg_pair(ptr_reg, lr)) {
						ut32 imm = rz_read_le32(buf + i - 4);
						if (imm >= RUST_MIN_CODE_STR_LEN && imm <= RUST_MAX_STRING_SIZE &&
							register_rust_string(ctx, target, imm, lea_pc, true, true)) {
							continue;
						}
					}
				}
				if (i >= 7 && (buf[i - 7] == 0x48 || buf[i - 7] == 0x49) &&
					buf[i - 6] == 0xc7 && (buf[i - 5] & 0xf8) == 0xc0) {
					int lr = ((buf[i - 7] & 0x01) << 3) | (buf[i - 5] & 7);
					if (x64_is_str_reg_pair(ptr_reg, lr)) {
						st32 simm = (st32)rz_read_le32(buf + i - 4);
						if (simm >= RUST_MIN_CODE_STR_LEN && simm <= RUST_MAX_STRING_SIZE &&
							register_rust_string(ctx, target, (ut64)simm, lea_pc, true, true)) {
							continue;
						}
					}
				}

				// Decode up to 4 subsequent instructions within 32 bytes for len or stack pair
				size_t pos = i + 7;
				size_t win_end = RZ_MIN(avail, pos + 32);
				for (int step = 0; step < 4 && pos < win_end && regs[ptr_reg].has_ptr; step++) {
					scan_x64_insn_window(ctx, read_va + pos, buf + pos, win_end - pos, regs, slots);
					RzAnalysisOp aop = { 0 };
					rz_analysis_op_init(&aop);
					int sz = rz_analysis_op(ctx->core->analysis, &aop, read_va + pos,
						buf + pos, (int)RZ_MIN(win_end - pos, (size_t)16),
						RZ_ANALYSIS_OP_MASK_BASIC);
					rz_analysis_op_fini(&aop);
					if (sz <= 0) {
						break;
					}
					pos += (size_t)sz;
				}
			}
			if (read_va + avail >= r->end || scan_end <= prefix) {
				break;
			}
			cur += (scan_end - prefix);
		}
	}
	free(buf);
}

static void scan_arm64_code(RustRecoverCtx *ctx) {
	RzList *fcns = rz_analysis_function_list(ctx->core->analysis);
	ut64 covered = 0;
	ut8 *bb_buf = NULL;
	ut32 bb_cap = 0;
	if (fcns) {
		RzListIter *lit;
		RzAnalysisFunction *fcn;
		rz_list_foreach (fcns, lit, fcn) {
			if (rz_interrupt_is_breaked(ctx->core->intr)) {
				break;
			}
			void **vit;
			rz_pvector_foreach (fcn->bbs, vit) {
				RzAnalysisBlock *bb = *vit;
				if (bb->size < 8 || bb->size > RUST_MAX_BB_SIZE) {
					continue;
				}
				covered += bb->size;
				if (bb->size > bb_cap) {
					ut8 *nb = realloc(bb_buf, bb->size);
					if (!nb) {
						free(bb_buf);
						return;
					}
					bb_buf = nb;
					bb_cap = bb->size;
				}
				int nr = rz_io_nread_at(ctx->core->io, bb->addr, bb_buf, (int)bb->size);
				if (nr >= 8) {
					scan_arm64_block(ctx, bb->addr, bb_buf, (size_t)nr);
				}
			}
		}
	}
	free(bb_buf);

	ut64 total_exec = 0;
	RustMemRange *r;
	rz_vector_foreach (&ctx->exec_ranges, r) {
		total_exec += r->end - r->start;
	}
	if (total_exec > 0 && covered * 10 < total_exec) {
		ut8 *buf = malloc(RUST_SCAN_CHUNK_SZ);
		if (!buf) {
			return;
		}
		rz_vector_foreach (&ctx->exec_ranges, r) {
			ut64 cur = r->start;
			while (cur < r->end) {
				size_t want = (size_t)RZ_MIN(r->end - cur, (ut64)RUST_SCAN_CHUNK_SZ);
				int nr = rz_io_nread_at(ctx->core->io, cur, buf, (int)want);
				if (nr < 8) {
					break;
				}
				scan_arm64_block(ctx, cur, buf, (size_t)nr);
				cur += (ut64)nr;
			}
		}
		free(buf);
	}
}

static bool inspect_x64_lang_start_wrapper(RustRecoverCtx *ctx, ut64 wrapper_va,
	ut64 *user_main_out, ut64 *lang_start_out) {
	if (!range_contains(&ctx->exec_ranges, wrapper_va, 12)) {
		return false;
	}
	ut8 code[128] = { 0 };
	int nr = rz_io_nread_at(ctx->core->io, wrapper_va, code, sizeof(code));
	if (nr < 12) {
		return false;
	}
	ut64 reg_text[16];
	for (size_t i = 0; i < 16; i++) {
		reg_text[i] = UT64_MAX;
	}
	ut64 cand_rcx = UT64_MAX;
	ut64 cand_rdi = UT64_MAX;
	ut64 stack_fn_va = UT64_MAX;
	bool stack_fn_is_rbp = false;
	st64 stack_fn_disp = 0;
	bool arg0_points_to_stack_fn = false;
	bool has_vtable_arg1 = false;
	ut64 call_target = UT64_MAX;
	ut32 calls = 0;
	for (size_t off = 0; off < (size_t)nr;) {
		ut64 pc = wrapper_va + off;
		// LEA r64, [rip + disp32]
		if (off + 7 <= (size_t)nr && (code[off] == 0x48 || code[off] == 0x4c) &&
			code[off + 1] == 0x8d && (code[off + 2] & 0xc7) == 0x05) {
			int reg = ((code[off] & 0x04) << 1) | ((code[off + 2] >> 3) & 7);
			ut64 t = pc + 7 + (st64)(st32)rz_read_le32(code + off + 3);
			if (range_contains(&ctx->exec_ranges, t, 1)) {
				reg_text[reg] = t;
				if (reg == 1) {
					cand_rcx = t;
				} else if (reg == 7) {
					cand_rdi = t;
				}
			} else if (range_contains(&ctx->data_ranges, t, 1)) {
				// Inlined lang_start_internal passes trait vtable in rdx (Win64) or rsi (SysV)
				if ((ctx->is_pe && reg == 2) || (!ctx->is_pe && (reg == 6 || reg == 2))) {
					has_vtable_arg1 = true;
				}
			}
		} else if (off + 4 <= (size_t)nr && (code[off] == 0x48 || code[off] == 0x4c) &&
			code[off + 1] == 0x89) {
			// MOV [rsp/rbp + disp], r64 (storing user_main pointer for fat pointer arg)
			int src_reg = ((code[off] & 0x04) << 1) | ((code[off + 2] >> 3) & 7);
			bool is_rbp = false;
			st64 disp = 0;
			size_t after = 0;
			if (reg_text[src_reg] != UT64_MAX &&
				decode_x64_stack_modrm(code, (size_t)nr, off + 2, &is_rbp, &disp, &after)) {
				stack_fn_va = reg_text[src_reg];
				stack_fn_is_rbp = is_rbp;
				stack_fn_disp = disp;
			}
		} else if (off + 4 <= (size_t)nr && code[off] == 0x48 && code[off + 1] == 0x8d) {
			// LEA rcx/rdi, [rsp/rbp + disp] matching stored user_main slot
			int dst_reg = (code[off + 2] >> 3) & 7;
			bool is_rbp = false;
			st64 disp = 0;
			size_t after = 0;
			if (((ctx->is_pe && dst_reg == 1) || (!ctx->is_pe && (dst_reg == 7 || dst_reg == 1))) &&
				stack_fn_va != UT64_MAX &&
				decode_x64_stack_modrm(code, (size_t)nr, off + 2, &is_rbp, &disp, &after) &&
				is_rbp == stack_fn_is_rbp && disp == stack_fn_disp) {
				arg0_points_to_stack_fn = true;
			}
		}
		// Direct CALL rel32 or tail JMP rel32
		if (off + 5 <= (size_t)nr && (code[off] == 0xe8 || code[off] == 0xe9)) {
			ut64 t = pc + 5 + (st64)(st32)rz_read_le32(code + off + 1);
			if (range_contains(&ctx->exec_ranges, t, 1)) {
				call_target = t;
				calls++;
			}
			if (code[off] == 0xe9) {
				break;
			}
		}
		if (code[off] == 0xc3 || code[off] == 0xc2) {
			break;
		}
		RzAnalysisOp aop = { 0 };
		rz_analysis_op_init(&aop);
		int sz = rz_analysis_op(ctx->core->analysis, &aop, pc, code + off,
			(int)RZ_MIN((size_t)nr - off, (size_t)16), RZ_ANALYSIS_OP_MASK_BASIC);
		rz_analysis_op_fini(&aop);
		if (sz <= 0) {
			break;
		}
		off += (size_t)sz;
	}
	ut64 user_main = ctx->is_pe ? cand_rcx : (cand_rdi != UT64_MAX ? cand_rdi : cand_rcx);
	if (user_main == UT64_MAX && arg0_points_to_stack_fn && has_vtable_arg1) {
		user_main = stack_fn_va;
	}
	if (calls == 1 && user_main != UT64_MAX && call_target != UT64_MAX &&
		user_main != wrapper_va && user_main != call_target) {
		*user_main_out = user_main;
		*lang_start_out = call_target;
		return true;
	}
	return false;
}

static bool inspect_arm64_lang_start_wrapper(RustRecoverCtx *ctx, ut64 wrapper_va,
	ut64 *user_main_out, ut64 *lang_start_out) {
	if (!range_contains(&ctx->exec_ranges, wrapper_va, 12)) {
		return false;
	}
	ut8 code[128] = { 0 };
	int nr = rz_io_nread_at(ctx->core->io, wrapper_va, code, sizeof(code));
	if (nr < 12) {
		return false;
	}
	ut64 x0_page = 0;
	bool x0_has_page = false;
	ut64 cand_x0 = UT64_MAX;
	ut64 call_target = UT64_MAX;
	ut32 calls = 0;
	for (size_t off = 0; off + 4 <= (size_t)nr; off += 4) {
		ut64 pc = wrapper_va + off;
		ut32 insn = rz_read_ble32(code + off, ctx->big_endian);
		if ((insn & 0x9f00001f) == 0x90000000) {
			ut64 immlo = (insn >> 29) & 0x3;
			ut64 immhi = (insn >> 5) & 0x7ffff;
			st64 imm21 = (st64)((immhi << 2) | immlo);
			if (imm21 & (1LL << 20)) {
				imm21 |= ~((1LL << 21) - 1);
			}
			x0_page = (pc & ~0xfffULL) + ((ut64)imm21 << 12);
			x0_has_page = true;
		} else if ((insn & 0xff8003ff) == 0x91000000 && x0_has_page) {
			ut64 imm12 = (insn >> 10) & 0xfff;
			if (insn & (1U << 22)) {
				imm12 <<= 12;
			}
			ut64 t = x0_page + imm12;
			if (range_contains(&ctx->exec_ranges, t, 1)) {
				cand_x0 = t;
			}
		} else if ((insn & 0x7c000000) == 0x14000000) {
			st64 imm26 = (st64)(insn & 0x03ffffff);
			if (imm26 & (1LL << 25)) {
				imm26 |= ~((1LL << 26) - 1);
			}
			ut64 t = pc + ((ut64)imm26 << 2);
			if (range_contains(&ctx->exec_ranges, t, 1)) {
				call_target = t;
				calls++;
			}
			if ((insn & 0x80000000) == 0) {
				break;
			}
		} else if (insn == 0xd65f03c0) {
			break;
		}
	}
	if (calls == 1 && cand_x0 != UT64_MAX && call_target != UT64_MAX &&
		cand_x0 != wrapper_va && cand_x0 != call_target) {
		*user_main_out = cand_x0;
		*lang_start_out = call_target;
		return true;
	}
	return false;
}

static void recover_rust_main(RustRecoverCtx *ctx) {
	const char *asm_arch = rz_config_get(ctx->core->config, "asm.arch");
	if (RZ_STR_ISEMPTY(asm_arch) || ctx->bits != 64) {
		return;
	}

	ut64 main_va = UT64_MAX;
	const RzBinAddr *bin_main = rz_bin_object_get_special_symbol(ctx->obj, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	if (bin_main && bin_main->vaddr != UT64_MAX) {
		main_va = rz_bin_object_addr_with_base(ctx->obj, bin_main->vaddr);
	}
	if (main_va == UT64_MAX) {
		RzFlagItem *fi = rz_flag_get(ctx->core->flags, "main");
		if (!fi) {
			fi = rz_flag_get(ctx->core->flags, "sym.main");
		}
		if (fi) {
			main_va = fi->offset;
		}
	}
	if (main_va == UT64_MAX) {
		return;
	}

	ut64 user_main = UT64_MAX;
	ut64 lang_start = UT64_MAX;
	bool found = false;
	if (!strcmp(asm_arch, "x86")) {
		found = inspect_x64_lang_start_wrapper(ctx, main_va, &user_main, &lang_start);
	} else if (!strcmp(asm_arch, "arm")) {
		found = inspect_arm64_lang_start_wrapper(ctx, main_va, &user_main, &lang_start);
	}
	if (!found) {
		return;
	}

	ctx->info->main_addr = user_main;
	ctx->info->lang_start_addr = lang_start;
	rz_flag_space_push(ctx->core->flags, RZ_FLAGS_FS_SYMBOLS);
	if (!rz_flag_get(ctx->core->flags, "sym.rust.main")) {
		rz_flag_set(ctx->core->flags, "sym.rust.main", user_main, 1);
	}
	if (!rz_flag_get(ctx->core->flags, "sym.rust.lang_start")) {
		rz_flag_set(ctx->core->flags, "sym.rust.lang_start", lang_start, 1);
	}
	rz_flag_space_pop(ctx->core->flags);
}

static void recover_rust_code_strings(RustRecoverCtx *ctx) {
	const char *asm_arch = rz_config_get(ctx->core->config, "asm.arch");
	if (RZ_STR_ISEMPTY(asm_arch) || ctx->bits != 64) {
		return;
	}
	if (!strcmp(asm_arch, "x86")) {
		ut64 covered = 0;
		scan_x64_analyzed_fcns(ctx, &covered);
		ut64 total_exec = 0;
		RustMemRange *r;
		rz_vector_foreach (&ctx->exec_ranges, r) {
			total_exec += r->end - r->start;
		}
		if (total_exec > 0 && covered * 10 < total_exec) {
			scan_x64_exec_sections_fast(ctx);
		}
	} else if (!strcmp(asm_arch, "arm")) {
		scan_arm64_code(ctx);
	}
}

/**
 * \brief Recovers Rust `&str` literals, `core::panic::Location` entries, Cargo crates,
 *        user `.rs` source files, and user `main` via `std::rt::lang_start`.
 *
 * \param core RzCore pointer
 * \return Owned \ref RzCoreRustInfo summary, or NULL on error
 */
RZ_API RZ_OWN RzCoreRustInfo *rz_core_analysis_recover_rust_metadata(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core && core->bin && core->io && core->analysis, NULL);

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		return NULL;
	}

	RzCoreRustInfo *info = RZ_NEW0(RzCoreRustInfo);
	if (!info) {
		return NULL;
	}
	info->main_addr = UT64_MAX;
	info->lang_start_addr = UT64_MAX;
	info->panic_locs = rz_pvector_new((RzPVectorFree)rust_panic_loc_free);
	info->crates = rz_pvector_new(free);
	info->user_files = rz_pvector_new(free);
	info->source_files = rz_pvector_new(free);
	if (!info->panic_locs || !info->crates || !info->user_files || !info->source_files) {
		rz_core_rust_info_free(info);
		return NULL;
	}

	RustRecoverCtx ctx = { 0 };
	ctx.core = core;
	ctx.obj = obj;
	ctx.info = info;
	ctx.bits = rz_asm_get_bits(core->rasm);
	ctx.word_size = ctx.bits / 8;
	ctx.big_endian = rz_asm_is_big_endian_set(core->rasm);
	ctx.is_pe = obj->info && obj->info->rclass && strstr(obj->info->rclass, "pe");
	ctx.pe_baddr = ctx.is_pe ? rz_bin_get_baddr(core->bin) : UT64_MAX;
	rz_vector_init(&ctx.data_ranges, sizeof(RustMemRange), NULL, NULL);
	rz_vector_init(&ctx.exec_ranges, sizeof(RustMemRange), NULL, NULL);
	ctx.loc_by_addr = ht_up_new(NULL, NULL);
	ctx.seen_strings = rz_set_u_new();
	ctx.seen_loc_xrefs = rz_set_u_new();

	if ((ctx.word_size != 4 && ctx.word_size != 8) ||
		!ctx.loc_by_addr || !ctx.seen_strings || !ctx.seen_loc_xrefs) {
		goto cleanup;
	}

	collect_memory_ranges(&ctx);
	if (rz_vector_empty(&ctx.data_ranges)) {
		goto cleanup;
	}
	ctx.has_relocs = detect_data_relocs(&ctx);

	rz_interrupt_break_push(core->intr, NULL, NULL);
	recover_rust_panic_locations_and_data_strings(&ctx);
	if (!rz_interrupt_is_breaked(core->intr)) {
		recover_rust_code_strings(&ctx);
	}
	if (!rz_interrupt_is_breaked(core->intr)) {
		recover_rust_main(&ctx);
	}
	rz_interrupt_break_pop(core->intr);

	rz_pvector_sort(info->crates, (RzPVectorComparator)compare_str_ptr, NULL);
	rz_pvector_sort(info->user_files, (RzPVectorComparator)compare_str_ptr, NULL);
	rz_pvector_sort(info->source_files, (RzPVectorComparator)compare_str_ptr, NULL);

cleanup:
	rz_vector_fini(&ctx.data_ranges);
	rz_vector_fini(&ctx.exec_ranges);
	ht_up_free(ctx.loc_by_addr);
	rz_set_u_free(ctx.seen_strings);
	rz_set_u_free(ctx.seen_loc_xrefs);
	free(ctx.raw_buf);
	free(ctx.flag_buf);
	return info;
}

/**
 * \brief Recovers Rust strings and metadata and returns the number of registered strings.
 * \param core RzCore pointer
 * \return Number of recovered Rust strings
 */
RZ_API ut32 rz_core_analysis_resolve_rust_strings(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core && core->bin && core->io && core->analysis, 0);
	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	if (!info) {
		return 0;
	}
	ut32 count = info->strings_recovered;
	rz_core_rust_info_free(info);
	return count;
}
