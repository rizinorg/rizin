// SPDX-FileCopyrightText: 2026 Abdallh <abdallhdawi3@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "core_private.h"
#include <rz_core.h>
#include <rz_heap_uclibc.h>

static inline ut8 uclibc_ptr_size(RzCore *core) {
	ut8 bits = (ut8)rz_asm_get_bits(core->rasm);
	if (!bits) {
		bits = (ut8)core->dbg->bits;
	}
	return bits ? (ut8)(bits / 8) : 0;
}

/**
 * \brief Get the virtual address of __heap_free_areas symbol from a uClibc library map.
 *
 * Opens the library file and searches for the __heap_free_areas symbol,
 * returning its virtual address adjusted by the map's base address.
 *
 * \param core RzCore instance
 * \param map Debug map of the uClibc library
 * \return Virtual address of __malloc_heap symbol, or UT64_MAX on failure
 */
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
			if (!strcmp(s->name, "__heap_free_areas")) {
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

/**
 * \brief Find the uClibc heap pointer by searching debug maps for uClibc libraries.
 *
 * Iterates through debug maps looking for uClibc/uClibc-ng libraries,
 * then reads the __heap_free_areas pointer from the library's data section.
 *
 * \param core RzCore instance
 * \return Heap pointer value, or UT64_MAX if not found
 */
static ut64 uclibc_find_heap_ptr(RzCore *core) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (map->name && (strstr(map->name, "uClibc") ||
			                   strstr(map->name, "libuClibc-ng") ||
			                   strstr(map->name, "libuClibc") ||
			                   (strstr(map->name, "libc.so.0")))) {
				ut64 heap_sym = uclibc_get_heap_base(core, map);
				if (heap_sym != UT64_MAX) {
					ut64 heap_ptr = 0;
					ut8 ptr_size = uclibc_ptr_size(core);
					if (rz_io_read_at_mapped(core->io, heap_sym, (ut8 *)&heap_ptr, ptr_size)) {
						return heap_ptr;
					}
				}
			}
		}
	}
	return UT64_MAX;
}

/**
 * \brief Get the heap boundaries (brk_start and brk_end) from debug maps.
 *
 * Searches for the [heap] mapping to determine heap boundaries for bounds checking.
 *
 * \param core RzCore instance
 * \param brk_start Pointer to store heap start address
 * \param brk_end Pointer to store heap end address
 * \return true if heap boundaries found, false otherwise
 */
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

/**
 * \brief Read a uClibc heap_free_area structure from memory.
 *
 * Reads the free area header at the given address. The structure contains
 * size, next pointer, and prev pointer in a doubly-linked free list.
 *
 * \param core RzCore instance
 * \param addr Address to read from
 * \param out Pointer to store the result
 * \return true on success, false on failure
 */
static bool uclibc_read_free_area(RzCore *core, ut64 addr, RzHeapFreeAreaUClibc *out) {
	rz_return_val_if_fail(core && out, false);
	ut8 ptr_size = uclibc_ptr_size(core);
	int struct_size = 3 * ptr_size;
	ut8 buf[24] = { 0 };
	bool be = rz_config_get_b(core->config, "cfg.bigendian");

	if (!rz_io_read_at_mapped(core->io, addr, buf, struct_size)) {
		return false;
	}

	if (ptr_size == 8) {
		out->size = rz_read_ble64(buf, be);
		out->next = rz_read_ble64(buf + 8, be);
		out->prev = rz_read_ble64(buf + 16, be);
	} else {
		out->size = rz_read_ble32(buf, be);
		out->next = rz_read_ble32(buf + 4, be);
		out->prev = rz_read_ble32(buf + 8, be);
	}
	return true;
}

/**
 * \brief Print uClibc heap free list handler.
 *
 * Prints the uClibc heap free list starting from the given address or
 * automatically detects the heap location if not specified.
 *
 * Supports both standard text output and JSON format.
 *
 * \param core RzCore instance
 * \param argc Argument count
 * \param argv Argument values
 * \param state Output state containing mode (standard/JSON)
 * \return RZ_CMD_STATUS_OK on success, RZ_CMD_STATUS_ERROR on failure
 */
RZ_IPI RzCmdStatus rz_heap_uclibc_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
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
	ut64 total_size = 0, largest = 0, smallest = UT64_MAX;
	const ut32 max_chunks = 1024;
	RzOutputMode mode = state->mode;
	PJ *pj = state->d.pj;

	if (mode == RZ_OUTPUT_MODE_JSON) {
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}
		pj_o(pj);
		pj_ka(pj, "free_areas");
	} else {
		rz_cons_println("uClibc Heap Free List:");
		rz_cons_println("Addr               Size         Next                Prev");
		rz_cons_println("----------------------------------------------------------------");
}

	ut8 ptr_size = uclibc_ptr_size(core);
	while (count < max_chunks) {
		RzHeapFreeAreaUClibc area;
		if (!uclibc_read_free_area(core, addr, &area)) {
			break;
		}

		bool corrupt_next = false, corrupt_prev = false;
		ut64 next_prev_val = 0, prev_next_val = 0;
		if (area.next) {
			RzHeapFreeAreaUClibc next_area = { 0 };
			if (uclibc_read_free_area(core, area.next, &next_area)) {
				next_prev_val = next_area.prev;
				if (next_area.prev != addr) {
					corrupt_next = true;
				}
			}
		}
		if (area.prev) {
			RzHeapFreeAreaUClibc prev_area = { 0 };
			if (uclibc_read_free_area(core, area.prev, &prev_area)) {
				prev_next_val = prev_area.next;
				if (prev_area.next != addr) {
					corrupt_prev = true;
				}
			}
		}

		if (area.size < (ut64)(3 * ptr_size) || area.size > 0x10000000) {
			break;
		}

		total_size += area.size;
		if (area.size > largest) {
			largest = area.size;
		}
		if (area.size < smallest) {
			smallest = area.size;
		}

		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_o(pj);
			pj_kn(pj, "addr", addr);
			pj_kn(pj, "size", area.size);
			pj_kn(pj, "next", area.next);
			pj_kn(pj, "prev", area.prev);
			if (corrupt_next || corrupt_prev) {
				pj_kb(pj, "corrupt", true);
			}
			pj_end(pj);
		} else {
			rz_cons_printf("  0x%016" PFMT64x "  0x%08" PFMT64x "  0x%016" PFMT64x "  0x%016" PFMT64x "\n",
				addr, area.size, area.next, area.prev);
			if (corrupt_next) {
				rz_cons_printf("  [CORRUPT: next(0x%" PFMT64x ")->prev = 0x%" PFMT64x ", expected 0x%" PFMT64x " - possible unlink attack]\n",
					area.next, next_prev_val, addr);
			}
			if (corrupt_prev) {
				rz_cons_printf("  [CORRUPT: prev(0x%" PFMT64x ")->next = 0x%" PFMT64x ", expected 0x%" PFMT64x " - possible unlink attack]\n",
					area.prev, prev_next_val, addr);
			}
			if (brk_start && brk_end && (area.next < brk_start || area.next > brk_end)) {
				rz_cons_printf("  [WARNING: next pointer outside heap bounds]\n");
			}
		}

		if (area.next == 0 || area.next == start) {
			break;
		}
		addr = area.next;
		count++;
	}

	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		pj_kn(pj, "total", count + 1);
		pj_kn(pj, "total_size", total_size);
		pj_kn(pj, "largest", largest);
		pj_kn(pj, "smallest", smallest == UT64_MAX ? 0 : smallest);
		if (brk_start) {
			pj_kn(pj, "brk_start", brk_start);
		}
		if (brk_end) {
			pj_kn(pj, "brk_end", brk_end);
		}
		pj_end(pj);
	} else {
		rz_cons_printf("\nTotal free areas: %" PFMT32u "\n", count + 1);
		rz_cons_printf("Total size: 0x%" PFMT64x " bytes\n", total_size);
		rz_cons_printf("Largest: 0x%" PFMT64x " bytes\n", largest);
		rz_cons_printf("Smallest: 0x%" PFMT64x " bytes\n", smallest == UT64_MAX ? 0 : smallest);
	}
	return RZ_CMD_STATUS_OK;
}
