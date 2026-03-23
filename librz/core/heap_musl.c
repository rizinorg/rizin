// SPDX-FileCopyrightText: 2017 javierptd <javierptd@gmail.com>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-FileCopyrightText: 2026 suleif <suleif@proton.me>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_heap_musl.h>
#include "core_private.h"

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
		if (strstr(map->name, "libc")) {
			if (musl_addr == UT64_MAX || map->addr < musl_addr) {
				musl_addr = map->addr;
				musl_path = map->name;
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

/**
 * \brief Sets up a RzStructuredData for the mallocng context.
 * \param addr address for the mallocng context
 * \param ctx initialized mallocng context struct
 * \return RzStructureData map containing context data
 */
static RzStructuredData *ctx_structured_data(ut64 addr, mallocng_ctx ctx) {
	RzStructuredData *ctx_data = rz_structured_data_new_map();
	rz_structured_data_map_add_unsigned(ctx_data, "context address", addr, true);
	rz_structured_data_map_add_unsigned(ctx_data, "secret", ctx.secret, true);
	rz_structured_data_map_add_unsigned(ctx_data, "init_done", ctx.init_done, true);
	rz_structured_data_map_add_unsigned(ctx_data, "mmap_counter", ctx.mmap_counter, true);
	rz_structured_data_map_add_unsigned(ctx_data, "free_meta_head", ctx.free_meta_head, true);
	rz_structured_data_map_add_unsigned(ctx_data, "avail_meta", ctx.avail_meta, true);
	rz_structured_data_map_add_unsigned(ctx_data, "avail_meta_count", ctx.avail_meta_count, true);
	rz_structured_data_map_add_unsigned(ctx_data, "avail_meta_area_count", ctx.avail_meta_area_count, true);
	rz_structured_data_map_add_unsigned(ctx_data, "meta_alloc_shift", ctx.meta_alloc_shift, true);
	rz_structured_data_map_add_unsigned(ctx_data, "meta_area_head", ctx.meta_area_head, true);
	rz_structured_data_map_add_unsigned(ctx_data, "meta_area_tail", ctx.meta_area_tail, true);
	rz_structured_data_map_add_unsigned(ctx_data, "avail_meta_areas", ctx.avail_meta_areas, true);

	RzStructuredData *active_metas = rz_structured_data_map_add_array(ctx_data, "active");
	for (int i = 0; i < 48; i++) {
		if (ctx.active[i]) {
			rz_structured_data_array_add_unsigned(active_metas, ctx.active[i], true);
		}
	}
	return ctx_data;
}

/**
 * \brief Prints mallocng context in the appropriate format.
 * \param addr address for the mallocng context
 * \param config mallocng config struct containing info on the architecture
 * \return
 */
void musl_mallocng_print_context(RzCore *core, bool has_specified_addr,
	ut64 addr, RzMallocngConfig config) {
	ut64 secret = 0;
	ut64 ctx_addr = 0;
	mallocng_ctx ctx;
	if (!has_specified_addr) {
		if (rz_resolve_musl(core, "__malloc_context", &ctx_addr)) {
			if (!read_ptr_at(core->io, ctx_addr, &secret, 8)) {
				RZ_LOG_ERROR("Failed to read __malloc_context\n");
				return;
			}
		}
	} else {
		ctx_addr = addr;
	}
	if (!read_and_parse_ctx(core->io, ctx_addr, &ctx, config)) {
		RZ_LOG_ERROR("Failed to read __malloc_context at 0x%" PFMT64x "\n", ctx_addr);
		return;
	}
	RzStructuredData *ctx_data = ctx_structured_data(ctx_addr, ctx);

	char *ctx_data_str = rz_structured_data_to_yaml(ctx_data);
	if (ctx_data_str) {
		rz_cons_print(ctx_data_str);
		free(ctx_data_str);
	}
	rz_structured_data_free(ctx_data);
}

/**
 * \brief Sets up a RzStructuredData for the mallocng meta area.
 * \param addr address for the mallocng meta area
 * \param area initialized mallocng meta area struct
 * \param config mallocng config struct containing info on the architecture
 * \return RzStructureData map containing meta area data
 */
static RzStructuredData *meta_area_structured_data(ut64 addr, mallocng_meta_area area,
	RzCore *core, RzMallocngConfig config) {

	RzStructuredData *meta_area_data = rz_structured_data_new_map();
	rz_structured_data_map_add_unsigned(meta_area_data, "meta area address", addr, true);
	rz_structured_data_map_add_unsigned(meta_area_data, "check", area.check, true);
	rz_structured_data_map_add_unsigned(meta_area_data, "next", area.next, true);
	rz_structured_data_map_add_unsigned(meta_area_data, "nslots", area.nslots, true);

	RzStructuredData *slots = rz_structured_data_map_add_array(meta_area_data, "slots");
	for (int i = 0; i < area.nslots; i++) {
		ut64 start_addr;
		ut64 meta_addr;
		if (!read_ptr_at(core->io, area.slots, &start_addr, config.ptr_size) ||
			!read_ptr_at(core->io, start_addr + i * config.meta_size, &meta_addr, config.ptr_size)) {
			return NULL;
		}
		if (meta_addr) {
			rz_structured_data_array_add_unsigned(slots, meta_addr, true);
		}
	}
	return meta_area_data;
}

ut64 print_meta_area(RzCore *core, ut64 curr_meta, RzMallocngConfig config) {
	RzStructuredData *area_data;

	mallocng_meta_area area;
	if (!read_and_parse_meta_area(core->io, curr_meta, &area, config)) {
		RZ_LOG_ERROR("Failed to parse meta_area @ 0x%" PFMT64x "\n", curr_meta);
		return 0;
	}

	area_data = meta_area_structured_data(curr_meta, area, core, config);
	if (!area_data) {
		RZ_LOG_ERROR("Failed to parse meta_area @ 0x%" PFMT64x "\n", curr_meta);
		return 0;
	}
	char *area_str = rz_structured_data_to_yaml(area_data);
	if (area_str) {
		rz_cons_print(area_str);
		free(area_str);
	}
	rz_structured_data_free(area_data);
	return area.next;
}

/**
 * \brief Prints mallocng meta area in the appropriate format.
 * \param addr address for the mallocng context
 * \param config mallocng config struct containing info on the architecture
 * \return
 */
void musl_mallocng_print_meta_areas(RzCore *core, bool has_specified_addr,
	ut64 addr, RzMallocngConfig config) {
	ut32 idx = 1;
	ut64 secret = 0;
	ut64 ctx_addr = 0;
	ut64 curr_meta = 0;
	mallocng_ctx ctx;
	if (!has_specified_addr) {
		if (rz_resolve_musl(core, "__malloc_context", &ctx_addr)) {
			if (!read_ptr_at(core->io, ctx_addr, &secret, 8)) {
				RZ_LOG_ERROR("Failed to read __malloc_context\n");
				return;
			}
		}
		if (!read_and_parse_ctx(core->io, ctx_addr, &ctx, config)) {
			RZ_LOG_ERROR("Failed to parse __malloc_context @ 0x%" PFMT64x "\n", ctx_addr);
			return;
		}

		curr_meta = ctx.meta_area_head;
		while (curr_meta) {
			printf("meta_area #%d:\n", idx++);
			curr_meta = print_meta_area(core, curr_meta, config);
		}
	} else {
		print_meta_area(core, addr, config);
	}
}

static void print_meta(RzCore *core, ut64 addr, RzMallocngConfig config, ut32 lines) {
	mallocng_meta meta;
	mallocng_group group;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!read_and_parse_meta(core->io, addr, &meta, config)) {
		RZ_LOG_ERROR("Failed to read meta @ 0x%" PFMT64x "\n", addr);
		return;
	}
	if (!read_and_parse_group(core->io, meta.mem, &group, config)) {
		RZ_LOG_ERROR("Failed to read group @ 0x%" PFMT64x "\n", meta.mem);
		return;
	}
	int size = UNIT * ng_size_classes[meta.sizeclass];
	PRINTF_BA("meta @ 0x%" PFMT64x ": \n", addr);
	PRINTF_BA("  size: 0x%x, prev: 0x%" PFMT64x ", next: 0x%" PFMT64x ", group: 0x%" PFMT64x "\n",
		size, meta.prev, meta.next, meta.mem);

	lines = RZ_MIN(lines, size);
	rz_core_print_dump(core, RZ_OUTPUT_MODE_STANDARD, group.storage, config.ptr_size, lines,
		RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL);
	PRINT_BA("\n");
}

/**
 * \brief Prints mallocng meta(s) in the appropriate format.
 * \param addr address for the mallocng meta
 * \param config mallocng config struct containing info on the architecture
 * \param lines integer representing the number of lines shown from group data
 * \return

	Prints mallocng meta(s) info + the data contained in their group(s)
 */
void musl_mallocng_print_meta(RzCore *core, bool has_specified_addr, ut64 addr, RzMallocngConfig config, ut32 lines) {
	ut64 secret = 0;
	ut64 ctx_addr = 0;
	mallocng_ctx ctx;
	if (!has_specified_addr) {
		if (rz_resolve_musl(core, "__malloc_context", &ctx_addr)) {
			if (!read_ptr_at(core->io, ctx_addr, &secret, 8)) {
				RZ_LOG_ERROR("Failed to read __malloc_context\n");
				return;
			}
		}
		if (!read_and_parse_ctx(core->io, ctx_addr, &ctx, config)) {
			RZ_LOG_ERROR("Failed to read __malloc_context @ 0x%" PFMT64x "\n", ctx_addr);
			return;
		}

		for (int i = 0; i < 48; i++) {
			if (ctx.active[i]) {
				print_meta(core, ctx.active[i], config, lines);
			}
		}
	} else {
		print_meta(core, addr, config, lines);
	}
}

/**
 * \brief Command for showing mallocng context information.
 * \param addr address for the mallocng context
 * \return

	Command for showing mallocng context information, if addr is not provided automatic symbol
	resolution is attempted.
 */
RZ_IPI RzCmdStatus rz_heap_mallocng_cmd_c(RzCore *core, bool has_specified_addr, ut64 addr) {
	const int bits = rz_config_get_i(core->config, "asm.bits");
	if (musl_get_allocator_kind(core) != MUSL_MALLOCNG) {
		RZ_LOG_ERROR("This command requires musl ver >= 1.2.1\n");
		return RZ_CMD_STATUS_ERROR;
	}
	const RzMallocngConfig ng_config = rz_musl_ng_get_config(bits);
	musl_mallocng_print_context(core, has_specified_addr, addr, ng_config);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Command for showing meta area(s)
 * \param addr address for the mallocng meta area
 * \return

	Command for showing meta area(s), if no addr is provided it will show all the available
	meta areas.
 */
RZ_IPI RzCmdStatus rz_heap_mallocng_cmd_a(RzCore *core, bool has_specified_addr, ut64 addr) {
	const int bits = rz_config_get_i(core->config, "asm.bits");
	if (musl_get_allocator_kind(core) != MUSL_MALLOCNG) {
		RZ_LOG_ERROR("This command requires musl ver >= 1.2.1\n");
		return RZ_CMD_STATUS_ERROR;
	}
	const RzMallocngConfig ng_config = rz_musl_ng_get_config(bits);
	musl_mallocng_print_meta_areas(core, has_specified_addr, addr, ng_config);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Command for showing meta(s).
 * \param lines integer representing the number of lines shown from group data
 * \param addr address for the mallocng meta
 * \return

	Command for showing meta(s), if no addr is provided it will show all the available metas.
 */
RZ_IPI RzCmdStatus rz_heap_mallocng_cmd_m(RzCore *core, bool has_specified_addr, ut64 addr, ut32 lines) {
	const int bits = rz_config_get_i(core->config, "asm.bits");
	if (musl_get_allocator_kind(core) != MUSL_MALLOCNG) {
		RZ_LOG_ERROR("This command requires musl ver >= 1.2.1\n");
		return RZ_CMD_STATUS_ERROR;
	}
	const RzMallocngConfig ng_config = rz_musl_ng_get_config(bits);
	musl_mallocng_print_meta(core, has_specified_addr, addr, ng_config, lines);
	return RZ_CMD_STATUS_OK;
}
