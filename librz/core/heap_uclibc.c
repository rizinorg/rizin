// SPDX-FileCopyrightText: 2026 Abdallh <abdallhdawi3@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "core_private.h"
#include <rz_core.h>
#include <rz_heap_uclibc.h>
#include <rz_heap_glibc.h>

static ut64 uclibc_get_heap_base(RzCore *core, RzDebugMap *map) {
	rz_return_val_if_fail(core && map, UT64_MAX);

	char *path = rz_str_dup(map->name);
	if (!path || !rz_file_exists(path)) {
		free(path);
		return UT64_MAX;
	}

	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	ut64 vaddr = UT64_MAX;

	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.obj_opts.elf_load_sections = rz_config_get_b(core->config, "elf.load.sections");
	opt.obj_opts.elf_checks_sections = rz_config_get_b(core->config, "elf.checks.sections");
	opt.obj_opts.elf_checks_segments = rz_config_get_b(core->config, "elf.checks.segments");

	RzBinFile *libc_bf = rz_bin_open(bin, path, &opt);
	if (!libc_bf) {
		free(path);
		return UT64_MAX;
	}

	RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *syms = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	if (syms) {
		void **iter;
		RzBinSymbol *s;
		rz_pvector_foreach (syms, iter) {
			s = *iter;
			if (!strcmp(s->name, "__malloc_heap")) {
				vaddr = s->vaddr;
				break;
			}
		}
	}

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
	free(path);

	return (vaddr != UT64_MAX) ? (map->addr + vaddr) : UT64_MAX;
}

static ut64 uclibc_find_heap_ptr(RzCore *core) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (map->name && (strstr(map->name, "uClibc") ||
			                   strstr(map->name, "/libc.") ||
			                   strstr(map->name, "libuClibc"))) {
				ut64 heap_sym = uclibc_get_heap_base(core, map);
				if (heap_sym != UT64_MAX) {
					ut64 heap_ptr = 0;
					ut8 ptr_size = (core->rasm->bits == 64) ? 8 : 4;
					if (rz_io_read_at_mapped(core->io, heap_sym, (ut8 *)&heap_ptr, ptr_size)) {
						return heap_ptr;
					}
				}
			}
		}
	}
	return UT64_MAX;
}

static bool uclibc_get_heap_bounds(RzCore *core, ut64 *brk_start, ut64 *brk_end) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (map->name) {
				if (strstr(map->name, "[heap]")) {
					*brk_start = map->addr;
					*brk_end = map->addr_end;
					return true;
				}
			}
		}
	} else {
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (map->name) {
				if (strstr(map->name, "[heap]")) {
					*brk_start = map->itv.addr;
					*brk_end = map->itv.addr + map->itv.size;
					return true;
				}
			}
		}
	}
	return false;
}

static bool uclibc_read_free_area(RzCore *core, ut64 addr, RzHeapFreeAreaUClibc *out) {
	rz_return_val_if_fail(core && out, false);
	ut8 bits = (ut8)core->rasm->bits;
	int ptr_size = bits / 8;
	int struct_size = 3 * ptr_size;
	ut8 buf[24] = { 0 };

	if (!rz_io_read_at_mapped(core->io, addr, buf, struct_size)) {
		return false;
	}

	if (bits == 64) {
		out->size = rz_read_le64(buf);
		out->next = rz_read_le64(buf + 8);
		out->prev = rz_read_le64(buf + 16);
	} else {
		out->size = rz_read_le32(buf);
		out->next = rz_read_le32(buf + 4);
		out->prev = rz_read_le32(buf + 8);
	}
	return true;
}

static inline void uclibc_print_free_area(RzCore *core, ut64 addr, const RzHeapFreeAreaUClibc *area) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	rz_cons_printf("  ");
	PRINTF_BA("0x%016" PFMT64x, addr);
	rz_cons_printf("  ");
	PRINTF_YA("0x%08" PFMT64x, area->size);
	rz_cons_printf("  ");
	PRINTF_GA("0x%016" PFMT64x, area->next);
	rz_cons_printf("  ");
	PRINTF_RA("0x%016" PFMT64x, area->prev);
	rz_cons_newline();
}

RZ_IPI RzCmdStatus rz_heap_uclibc_print_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core, RZ_CMD_STATUS_ERROR);

	ut64 addr = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (addr == 0) {
		addr = uclibc_find_heap_ptr(core);
		if (addr == UT64_MAX) {
			RZ_LOG_ERROR("Cannot find uClibc heap. Make sure you are debugging a uClibc binary.\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}

	ut64 brk_start = 0, brk_end = 0;
	if (!uclibc_get_heap_bounds(core, &brk_start, &brk_end)) {
		RZ_LOG_WARN("Cannot find heap boundaries, skipping bounds check\n");
	}

	ut64 start = addr;
	ut32 count = 0;
	const ut32 max_chunks = 1024;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	rz_cons_println("uClibc Heap Free List:");
	rz_cons_println("Addr               Size         Next                Prev");
	rz_cons_println("----------------------------------------------------------------");

	while (count < max_chunks) {
		RzHeapFreeAreaUClibc area;
		if (!uclibc_read_free_area(core, addr, &area)) {
			break;
		}

		if (area.size < sizeof(ut64) * 3 || area.size > 0x10000000) {
			PRINTF_RA("Invalid size at 0x%" PFMT64x ": 0x%" PFMT64x "\n", addr, area.size);
			break;
		}

		uclibc_print_free_area(core, addr, &area);

		if (area.next == 0 || area.next == start) {
			break;
		}
		if (brk_start && brk_end && (area.next < brk_start || area.next > brk_end)) {
			PRINT_RA("  [WARNING: next pointer outside heap bounds]\n");
		}
		addr = area.next;
		count++;
	}

	rz_cons_printf("\nTotal free areas: %" PFMT32u "\n", count + 1);
	return RZ_CMD_STATUS_OK;
}
