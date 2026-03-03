// SPDX-FileCopyrightText: 2017 javierptd <javierptd@gmail.com>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-FileCopyrightText: 2026 suleif <suleif@proton.me>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_heap_musl.h>

static ut64 musl_get_va_symbol(RzCore *core, const char *path, const char *sym_name, bool *is_pie) {
	ut64 vaddr = UT64_MAX;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	void **iter;
	RzBinSymbol *s;

	if (is_pie) {
		*is_pie = false;
	}

	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.obj_opts.elf_load_sections = rz_config_get_b(core->config, "elf.load.sections");
	opt.obj_opts.elf_checks_sections = rz_config_get_b(core->config, "elf.checks.sections");
	opt.obj_opts.elf_checks_segments = rz_config_get_b(core->config, "elf.checks.segments");

	RzBinFile *libc_bf = rz_bin_open(bin, path, &opt);
	if (!libc_bf) {
		return vaddr;
	}

	RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *syms = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	rz_pvector_foreach (syms, iter) {
		s = *iter;
		if (!strcmp(s->name, sym_name)) {
			vaddr = s->vaddr;
			break;
		}
	}

	// Check if binary is PIE/shared object
	if (is_pie && o && o->info) {
		*is_pie = o->info->has_pi;
	}

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
	return vaddr;
}

static bool rz_resolve_musl(RzCore *core, const char *symname, ut64 *symbol) {
	RzListIter *iter;
	RzDebugMap *map;
	const char *musl_path = NULL;
	ut64 musl_addr = UT64_MAX;
	const char *binary_path = NULL;
	ut64 binary_addr = UT64_MAX;

	if (!core || !core->dbg || !core->dbg->maps) {
		return false;
	}
	rz_debug_map_sync(core->dbg);

	rz_list_foreach (core->dbg->maps, iter, map) {
		if (strstr(map->name, "musl/lib/libc.so")) {
			if (musl_addr == UT64_MAX || map->addr < musl_addr) {
				musl_addr = map->addr;
				musl_path = map->name;
			}
		}
		if (!strstr(map->name, ".so") && !strstr(map->name, "lib") &&
			!strstr(map->name, "[") && strlen(map->name) > 0) {
			if (binary_addr == UT64_MAX || map->addr < binary_addr) {
				binary_addr = map->addr;
				binary_path = map->name;
			}
		}
	}

	// Try dynamic library first
	if (musl_path) {
		char *path = rz_str_newf("%s", musl_path);
		if (rz_file_exists(path)) {
			bool is_pie = false;
			ut64 vaddr = musl_get_va_symbol(core, path, symname, &is_pie);
			if (musl_addr != UT64_MAX && vaddr != UT64_MAX) {
				// For shared libraries, always add base address
				*symbol = musl_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}

	// Fall back to static linking
	if (binary_path) {
		char *path = rz_str_newf("%s", binary_path);
		if (rz_file_exists(path)) {
			bool is_pie = false;
			ut64 vaddr = musl_get_va_symbol(core, path, symname, &is_pie);
			if (binary_addr != UT64_MAX && vaddr != UT64_MAX) {
				// For PIE binaries, add base address (Linux PIE binaries)
				// For non-PIE binaries, vaddr is already absolute (FreeBSD non-PIE)
				*symbol = is_pie ? (binary_addr + vaddr) : vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}
	return false;
}

static inline bool read_ptr_at(RzIO *io, ut64 addr, ut64 *value, ut8 ptr_size) {
	if (ptr_size == 8) {
		ut8 buf[8];
		if (!rz_io_read_at_mapped(io, addr, buf, 8)) {
			return false;
		}
		*value = rz_read_le64(buf);
	} else {
		ut8 buf[4];
		if (!rz_io_read_at_mapped(io, addr, buf, 4)) {
			return false;
		}
		*value = rz_read_le32(buf);
	}
	return true;
}

typedef enum {
	MUSL_UNKNOWN,
	MUSL_OLDMALLOC,
	MUSL_MALLOCNG,
} MuslAllocator;

MuslAllocator musl_get_allocator_kind(RzCore *core) {
	ut64 ctx_addr;
	if (rz_resolve_musl(core, "__malloc_context", &ctx_addr))
		return MUSL_MALLOCNG;
	return MUSL_OLDMALLOC;
}

void musl_mallocng_print_context(RzCore *core, bool has_specified_addr, ut64 addr) {
	ut64 secret = 0;
	ut64 ctx_addr = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	mallocng_ctx ctx;
	if (!has_specified_addr) {
		if (rz_resolve_musl(core, "__malloc_context", &ctx_addr)) {
			if (!read_ptr_at(core->io, ctx_addr, &secret, 8)) {
				RZ_LOG_ERROR("Failed to read __malloc_context\n");
				return;
			}
		}
		if (!read_and_parse_ctx(core->io, ctx_addr, &ctx)) {
			RZ_LOG_ERROR("Failed to read __malloc_context at 0x%" PFMT64x "\n", ctx_addr);
			return;
		}
		PRINTF_GA("__malloc_context @ 0x%" PFMT64x " {\n", ctx_addr);
		PRINTF_BA("  secret = 0x%" PFMT64x "\n", ctx.secret);
		PRINTF_BA("  init_done = 0x%x\n", ctx.init_done);
		PRINTF_BA("  mmap_counter = 0x%x\n", ctx.mmap_counter);
		PRINTF_BA("  free_meta_head = 0x%" PFMT64x "\n", ctx.free_meta_head);
		PRINTF_BA("  avail_meta = 0x%" PFMT64x "\n", ctx.avail_meta);
		PRINT_GA("  active = [\n");
		for (int i = 0; i < 48; i++) {
			if (ctx.active[i]) {
				PRINTF_BA("    active[%d] = 0x%" PFMT64x " (%ld bytes)\n", i, ctx.active[i],
					ctx.usage_by_class[i]);
			}
		}
		PRINT_GA("  ]\n");
		PRINTF_BA("  avail_meta_count = 0x%ld\n", ctx.avail_meta_count);
		PRINTF_BA("  avail_meta_area_count = 0x%ld\n", ctx.avail_meta_area_count);
		PRINTF_BA("  meta_alloc_shift = 0x%lx\n", ctx.meta_alloc_shift);
		PRINTF_BA("  meta_area_head = 0x%" PFMT64x "\n", ctx.meta_area_head);
		PRINTF_BA("  meta_area_tail = 0x%" PFMT64x "\n", ctx.meta_area_tail);
		PRINTF_BA("  avail_meta_areas = 0x%" PFMT64x "\n", ctx.avail_meta_areas);
		PRINT_GA("}\n");
	}
}

void musl_mallocng_print_meta_areas(RzCore *core, bool has_specified_addr, ut64 addr) {
	ut64 secret = 0;
	ut64 ctx_addr = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	mallocng_ctx ctx;
	mallocng_meta_area area;
	mallocng_meta meta;
	if (!has_specified_addr) {
		if (rz_resolve_musl(core, "__malloc_context", &ctx_addr)) {
			if (!read_ptr_at(core->io, ctx_addr, &secret, 8)) {
				RZ_LOG_ERROR("Failed to read __malloc_context\n");
				return;
			}
		}
		if (!read_and_parse_ctx(core->io, ctx_addr, &ctx)) {
			RZ_LOG_ERROR("Failed to parse __malloc_context @ 0x%" PFMT64x "\n", ctx_addr);
			return;
		}

		ut64 curr_meta = ctx.meta_area_head;
		while (curr_meta) {
			if (!read_and_parse_meta_area(core->io, curr_meta, &area)) {
				RZ_LOG_ERROR("Failed to parse meta_area @ 0x%" PFMT64x "\n", curr_meta);
				return;
			}

			PRINTF_GA("meta_area @ 0x%" PFMT64x " {\n", curr_meta);
			PRINTF_BA("  check = 0x%" PFMT64x "\n", area.check);
			PRINTF_BA("  next = 0x%" PFMT64x "\n", area.next);
			PRINT_BA("  slots = [\n");
			for (int i = 0; i < area.nslots; i += 1) {
				ut64 start_addr;
				ut64 meta_addr;
				if (!read_ptr_at(core->io, area.slots, &start_addr, 8) ||
					!read_ptr_at(core->io, start_addr + i * sizeof(mallocng_meta), &meta_addr, 8) ||
					!read_and_parse_meta(core->io, meta_addr, &meta)) {
					RZ_LOG_ERROR("Failed to parse meta_area @ 0x%" PFMT64x "\n", curr_meta);
					return;
				}

				if (meta_addr) {
					PRINTF_BA("    slot %d: 0x%" PFMT64x " (size %d)\n", i,
						meta_addr, UNIT * ng_size_classes[meta.sizeclass] - IB);
				}
			}
			PRINT_BA("  ]\n");
			curr_meta = area.next;
		}
	}
}

RZ_IPI RzCmdStatus rz_heap_mallocng_cmd_c(RzCore *core, bool has_specified_addr, ut64 addr) {
	if (musl_get_allocator_kind(core) != MUSL_MALLOCNG) {
		RZ_LOG_ERROR("This command requires musl ver >= 1.2.1\n");
		return RZ_CMD_STATUS_ERROR;
	}

	musl_mallocng_print_context(core, has_specified_addr, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_heap_mallocng_cmd_a(RzCore *core, bool has_specified_addr, ut64 addr) {
	if (musl_get_allocator_kind(core) != MUSL_MALLOCNG) {
		RZ_LOG_ERROR("This command requires musl ver >= 1.2.1\n");
		return RZ_CMD_STATUS_ERROR;
	}

	musl_mallocng_print_meta_areas(core, has_specified_addr, addr);
	return RZ_CMD_STATUS_OK;
}
