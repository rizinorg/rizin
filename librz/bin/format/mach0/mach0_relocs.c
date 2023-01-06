// SPDX-FileCopyrightText: 2021-2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-FileCopyrightText: 2010-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "mach0.h"
#include <ht_uu.h>

#include "mach0_utils.inc"

#define RELOCATION_INFO_SIZE 8 // sizeof(struct relocation_info)

/**
 * \param buf buffer of at least RELOCATION_INFO_SIZE bytes
 */
static void read_relocation_info(struct relocation_info *dst, ut8 *src, bool big_endian) {
	dst->r_address = (st32)rz_read_at_ble32(src, 0, big_endian);
	uint32_t field = rz_read_at_ble32(src, 4, big_endian);
	if (big_endian) {
		dst->r_type = field & rz_num_bitmask(4);
		field >>= 4;
		dst->r_extern = field & rz_num_bitmask(1);
		field >>= 1;
		dst->r_length = field & rz_num_bitmask(2);
		field >>= 2;
		dst->r_pcrel = field & rz_num_bitmask(1);
		field >>= 1;
		dst->r_symbolnum = field & rz_num_bitmask(24);
	} else {
		dst->r_symbolnum = field & rz_num_bitmask(24);
		field >>= 24;
		dst->r_pcrel = field & rz_num_bitmask(1);
		field >>= 1;
		dst->r_length = field & rz_num_bitmask(2);
		field >>= 2;
		dst->r_extern = field & rz_num_bitmask(1);
		field >>= 1;
		dst->r_type = field & rz_num_bitmask(4);
	}
}

static int reloc_comparator(struct reloc_t *a, struct reloc_t *b) {
	return a->addr - b->addr;
}

static void parse_relocation_info(struct MACH0_(obj_t) * bin, RzSkipList *relocs, ut32 offset, ut32 num) {
	if (!num || !offset || (st32)num < 0) {
		return;
	}

	ut64 total_size = (ut64)num * RELOCATION_INFO_SIZE;
	ut8 *infos = malloc(total_size);
	if (!infos) {
		return;
	}
	if (rz_buf_read_at(bin->b, offset, infos, total_size) < total_size) {
		free(infos);
		return;
	}

	size_t i;
	for (i = 0; i < num; i++) {
		struct relocation_info a_info;
		read_relocation_info(&a_info, infos + i * RELOCATION_INFO_SIZE, bin->big_endian);
		ut32 sym_num = a_info.r_symbolnum;
		if (sym_num >= bin->nsymtab) {
			continue;
		}

		ut32 stridx = bin->symtab[sym_num].n_strx;
		char *sym_name = MACH0_(get_name)(bin, stridx, false);
		if (!sym_name) {
			continue;
		}

		struct reloc_t *reloc = RZ_NEW0(struct reloc_t);
		if (!reloc) {
			free(infos);
			free(sym_name);
			return;
		}

		reloc->addr = MACH0_(paddr_to_vaddr)(bin, a_info.r_address);
		reloc->offset = a_info.r_address;
		reloc->ord = sym_num;
		reloc->type = a_info.r_type; // enum RelocationInfoType
		reloc->external = a_info.r_extern;
		reloc->pc_relative = a_info.r_pcrel;
		reloc->size = 1 << a_info.r_length; // macho/reloc.h says: 0=byte, 1=word, 2=long, 3=quad
		rz_str_ncpy(reloc->name, sym_name, sizeof(reloc->name) - 1);
		rz_skiplist_insert(relocs, reloc);
		free(sym_name);
	}
	free(infos);
}

static bool is_valid_ordinal_table_size(ut64 size) {
	return size > 0 && size <= UT16_MAX;
}

static int parse_import_ptr(struct MACH0_(obj_t) * bin, struct reloc_t *reloc, int idx) {
	int i, j, sym;
	size_t wordsize;
	ut32 stype;
	wordsize = get_word_size(bin);
	if (idx < 0 || idx >= bin->nsymtab) {
		return 0;
	}
	if ((bin->symtab[idx].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY) {
		stype = S_LAZY_SYMBOL_POINTERS;
	} else {
		stype = S_NON_LAZY_SYMBOL_POINTERS;
	}

	reloc->offset = 0;
	reloc->addr = 0;
	reloc->addend = 0;
#define CASE(T) \
	case ((T) / 8): reloc->type = RZ_BIN_RELOC_##T; break
	switch (wordsize) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	default: return false;
	}
#undef CASE

	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
			for (j = 0, sym = -1; bin->sects[i].reserved1 + j < bin->nindirectsyms; j++) {
				int indidx = bin->sects[i].reserved1 + j;
				if (indidx < 0 || indidx >= bin->nindirectsyms) {
					break;
				}
				if (idx == bin->indirectsyms[indidx]) {
					sym = j;
					break;
				}
			}
			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
			return true;
		}
	}
	return false;
}

RZ_BORROW RzSkipList *MACH0_(get_relocs)(struct MACH0_(obj_t) * bin) {
	rz_return_val_if_fail(bin, NULL);
	if (bin->relocs_parsed) {
		return bin->relocs;
	}
	bin->relocs_parsed = true;
	RzSkipList *relocs = NULL;
	RzPVector *threaded_binds = NULL;
	size_t wordsize = get_word_size(bin);
	if (bin->dyld_info) {
		ut8 *opcodes, rel_type = 0;
		size_t bind_size, lazy_size, weak_size;

#define CASE(T) \
	case ((T) / 8): rel_type = RZ_BIN_RELOC_##T; break
		switch (wordsize) {
			CASE(8);
			CASE(16);
			CASE(32);
			CASE(64);
		default: return NULL;
		}
#undef CASE
		bind_size = bin->dyld_info->bind_size;
		lazy_size = bin->dyld_info->lazy_bind_size;
		weak_size = bin->dyld_info->weak_bind_size;

		if (!bind_size && !lazy_size) {
			return NULL;
		}

		if ((bind_size + lazy_size) < 1) {
			return NULL;
		}
		if (bin->dyld_info->bind_off > bin->size || bin->dyld_info->bind_off + bind_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->lazy_bind_off > bin->size ||
			bin->dyld_info->lazy_bind_off + lazy_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->bind_off + bind_size + lazy_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->weak_bind_off + weak_size > bin->size) {
			return NULL;
		}
		ut64 amount = bind_size + lazy_size + weak_size;
		if (amount == 0 || amount > UT32_MAX) {
			return NULL;
		}
		if (!bin->segs) {
			return NULL;
		}
		relocs = rz_skiplist_new((RzListFree)&free, (RzListComparator)&reloc_comparator);
		if (!relocs) {
			return NULL;
		}
		opcodes = calloc(1, amount + 1);
		if (!opcodes) {
			rz_skiplist_free(relocs);
			return NULL;
		}

		int len = rz_buf_read_at(bin->b, bin->dyld_info->bind_off, opcodes, bind_size);
		len += rz_buf_read_at(bin->b, bin->dyld_info->lazy_bind_off, opcodes + bind_size, lazy_size);
		len += rz_buf_read_at(bin->b, bin->dyld_info->weak_bind_off, opcodes + bind_size + lazy_size, weak_size);
		if (len < amount) {
			RZ_LOG_ERROR("Error: read (dyld_info bind) at 0x%08" PFMT64x "\n", (ut64)(size_t)bin->dyld_info->bind_off);
			RZ_FREE(opcodes);
			rz_skiplist_free(relocs);
			return NULL;
		}

		size_t partition_sizes[] = { bind_size, lazy_size, weak_size };
		size_t pidx;
		int opcodes_offset = 0;
		for (pidx = 0; pidx < RZ_ARRAY_SIZE(partition_sizes); pidx++) {
			size_t partition_size = partition_sizes[pidx];

			ut8 type = 0;
			int lib_ord = 0, seg_idx = -1, sym_ord = -1;
			char *sym_name = NULL;
			size_t j, count, skip;
			st64 addend = 0;
			ut64 addr = bin->segs[0].vmaddr;
			ut64 segment_end_addr = addr + bin->segs[0].vmsize;

			ut8 *p = opcodes + opcodes_offset;
			ut8 *end = p + partition_size;
			bool done = false;
			while (!done && p < end) {
				ut8 imm = *p & BIND_IMMEDIATE_MASK;
				ut8 op = *p & BIND_OPCODE_MASK;
				p++;
				switch (op) {
				case BIND_OPCODE_DONE: {
					bool in_lazy_binds = pidx == 1;
					if (!in_lazy_binds) {
						done = true;
					}
					break;
				}
				case BIND_OPCODE_THREADED: {
					switch (imm) {
					case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: {
						ut64 table_size = read_uleb128(&p, end);
						if (!is_valid_ordinal_table_size(table_size)) {
							RZ_LOG_ERROR("Error: BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB size is wrong\n");
							break;
						}
						if (threaded_binds) {
							rz_pvector_free(threaded_binds);
						}
						threaded_binds = rz_pvector_new_with_len((RzPVectorFree)&free, table_size);
						if (threaded_binds) {
							sym_ord = 0;
						}
						break;
					}
					case BIND_SUBOPCODE_THREADED_APPLY:
						if (threaded_binds) {
							int cur_seg_idx = (seg_idx != -1) ? seg_idx : 0;
							size_t n_threaded_binds = rz_pvector_len(threaded_binds);
							while (addr < segment_end_addr) {
								ut8 tmp[8];
								ut64 paddr = addr - bin->segs[cur_seg_idx].vmaddr + bin->segs[cur_seg_idx].fileoff;
								if (rz_buf_read_at(bin->b, paddr, tmp, 8) != 8) {
									break;
								}
								ut64 raw_ptr = rz_read_le64(tmp);
								bool is_auth = (raw_ptr & (1ULL << 63)) != 0;
								bool is_bind = (raw_ptr & (1ULL << 62)) != 0;
								int ordinal = -1;
								int addend = -1;
								ut64 delta;
								if (is_auth && is_bind) {
									struct dyld_chained_ptr_arm64e_auth_bind p;
									dyld_chained_ptr_arm64e_auth_bind_read(&p, raw_ptr);
									delta = p.next;
									ordinal = p.ordinal;
								} else if (!is_auth && is_bind) {
									struct dyld_chained_ptr_arm64e_bind p;
									dyld_chained_ptr_arm64e_bind_read(&p, raw_ptr);
									delta = p.next;
									ordinal = p.ordinal;
									addend = p.addend;
								} else if (is_auth && !is_bind) {
									struct dyld_chained_ptr_arm64e_auth_rebase p;
									dyld_chained_ptr_arm64e_auth_rebase_read(&p, raw_ptr);
									delta = p.next;
								} else {
									struct dyld_chained_ptr_arm64e_rebase p;
									dyld_chained_ptr_arm64e_rebase_read(&p, raw_ptr);
									delta = p.next;
								}
								if (ordinal != -1) {
									if (ordinal >= n_threaded_binds) {
										RZ_LOG_ERROR("Error: Malformed bind chain\n");
										break;
									}
									struct reloc_t *ref = rz_pvector_at(threaded_binds, ordinal);
									if (!ref) {
										RZ_LOG_ERROR("Error: Inconsistent bind opcodes\n");
										break;
									}
									struct reloc_t *reloc = RZ_NEW0(struct reloc_t);
									if (!reloc) {
										break;
									}
									*reloc = *ref;
									reloc->addr = addr;
									reloc->offset = paddr;
									if (addend != -1) {
										reloc->addend = addend;
									}
									rz_skiplist_insert(relocs, reloc);
								}
								addr += delta * wordsize;
								if (!delta) {
									break;
								}
							}
						}
						break;
					default:
						RZ_LOG_ERROR("Error: Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x\n", imm);
					}
					break;
				}
				case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
					lib_ord = imm;
					break;
				case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
					lib_ord = read_uleb128(&p, end);
					break;
				case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
					lib_ord = imm ? (st8)(BIND_OPCODE_MASK | imm) : 0;
					break;
				case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
					sym_name = (char *)p;
					while (*p++ && p < end) {
						/* empty loop */
					}
					if (threaded_binds) {
						break;
					}
					sym_ord = -1;
					if (bin->symtab && bin->dysymtab.nundefsym < UT16_MAX) {
						for (j = 0; j < bin->dysymtab.nundefsym; j++) {
							size_t stridx = 0;
							bool found = false;
							int iundefsym = bin->dysymtab.iundefsym;
							if (iundefsym >= 0 && iundefsym < bin->nsymtab) {
								int sidx = iundefsym + j;
								if (sidx < 0 || sidx >= bin->nsymtab) {
									continue;
								}
								stridx = bin->symtab[sidx].n_strx;
								if (stridx >= bin->symstrlen) {
									continue;
								}
								found = true;
							}
							if (found && !strcmp((const char *)bin->symstr + stridx, sym_name)) {
								sym_ord = j;
								break;
							}
						}
					}
					break;
				}
				case BIND_OPCODE_SET_TYPE_IMM:
					type = imm;
					break;
				case BIND_OPCODE_SET_ADDEND_SLEB:
					addend = rz_sleb128((const ut8 **)&p, end);
					break;
				case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
					seg_idx = imm;
					if (seg_idx >= bin->nsegs) {
						RZ_LOG_ERROR("Error: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
							     " has unexistent segment %d\n",
							seg_idx);
						free(opcodes);
						rz_skiplist_free(relocs);
						rz_pvector_free(threaded_binds);
						return NULL; // early exit to avoid future mayhem
					}
					addr = bin->segs[seg_idx].vmaddr + read_uleb128(&p, end);
					segment_end_addr = bin->segs[seg_idx].vmaddr + bin->segs[seg_idx].vmsize;
					break;
				case BIND_OPCODE_ADD_ADDR_ULEB:
					addr += read_uleb128(&p, end);
					break;
#define DO_BIND() \
	do { \
		if (sym_ord < 0 && !sym_name) \
			break; \
		if (!threaded_binds) { \
			if (seg_idx < 0) \
				break; \
			if (!addr) \
				break; \
		} \
		struct reloc_t *reloc = RZ_NEW0(struct reloc_t); \
		reloc->addr = addr; \
		if (seg_idx >= 0) { \
			reloc->offset = addr - bin->segs[seg_idx].vmaddr + bin->segs[seg_idx].fileoff; \
			if (type == BIND_TYPE_TEXT_PCREL32) \
				reloc->addend = addend - (bin->baddr + addr); \
			else \
				reloc->addend = addend; \
		} else { \
			reloc->addend = addend; \
		} \
		/* library ordinal ??? */ \
		reloc->ord = lib_ord; \
		reloc->ord = sym_ord; \
		reloc->type = rel_type; \
		if (sym_name) \
			rz_str_ncpy(reloc->name, sym_name, 256); \
		if (threaded_binds) \
			rz_pvector_set(threaded_binds, sym_ord, reloc); \
		else \
			rz_skiplist_insert(relocs, reloc); \
	} while (0)
				case BIND_OPCODE_DO_BIND:
					if (!threaded_binds && addr >= segment_end_addr) {
						RZ_LOG_ERROR("Error: Malformed DO bind opcode 0x%" PFMT64x "\n", addr);
						goto beach;
					}
					DO_BIND();
					if (!threaded_binds) {
						addr += wordsize;
					} else {
						sym_ord++;
					}
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
					if (addr >= segment_end_addr) {
						RZ_LOG_ERROR("Error: Malformed ADDR ULEB bind opcode\n");
						goto beach;
					}
					DO_BIND();
					addr += read_uleb128(&p, end) + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
					if (addr >= segment_end_addr) {
						RZ_LOG_ERROR("Error: Malformed IMM SCALED bind opcode\n");
						goto beach;
					}
					DO_BIND();
					addr += (ut64)imm * (ut64)wordsize + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
					count = read_uleb128(&p, end);
					skip = read_uleb128(&p, end);
					for (j = 0; j < count; j++) {
						if (addr >= segment_end_addr) {
							RZ_LOG_ERROR("Error: Malformed ULEB TIMES bind opcode\n");
							goto beach;
						}
						DO_BIND();
						addr += skip + wordsize;
					}
					break;
#undef DO_BIND
				default:
					RZ_LOG_ERROR("Error: unknown bind opcode 0x%02x in dyld_info\n", *p);
					RZ_FREE(opcodes);
					goto beach;
				}
			}

			opcodes_offset += partition_size;
		}

		RZ_FREE(opcodes);
		rz_pvector_free(threaded_binds);
		threaded_binds = NULL;
	}

	if (bin->symtab && bin->symstr && bin->sects && bin->indirectsyms) {
		int amount = bin->dysymtab.nundefsym;
		if (amount < 0) {
			amount = 0;
		}
		if (!relocs) {
			relocs = rz_skiplist_new((RzListFree)&free, (RzListComparator)&reloc_comparator);
			if (!relocs) {
				return NULL;
			}
		}
		for (int j = 0; j < amount; j++) {
			struct reloc_t *reloc = RZ_NEW0(struct reloc_t);
			if (!reloc || !parse_import_ptr(bin, reloc, bin->dysymtab.iundefsym + j)) {
				free(reloc);
				break;
			}
			reloc->ord = j;
			rz_skiplist_insert(relocs, reloc);
		}
	}

	if (bin->symtab && bin->dysymtab.extreloff && bin->dysymtab.nextrel) {
		if (!relocs) {
			relocs = rz_skiplist_new((RzListFree)&free, (RzListComparator)&reloc_comparator);
			if (!relocs) {
				return NULL;
			}
		}
		parse_relocation_info(bin, relocs, bin->dysymtab.extreloff, bin->dysymtab.nextrel);
	}
beach:
	rz_pvector_free(threaded_binds);
	bin->relocs = relocs;
	return relocs;
}

static RzPVector /*<struct reloc_t *>*/ *get_patchable_relocs(struct MACH0_(obj_t) * obj) {
	if (!obj->options.patch_relocs) {
		return NULL;
	}
	if (obj->patchable_relocs) {
		return obj->patchable_relocs;
	}
	RzSkipList *relocs = MACH0_(get_relocs)(obj);
	if (!relocs) {
		return NULL;
	}
	obj->patchable_relocs = rz_pvector_new(NULL);
	if (!obj->patchable_relocs) {
		return NULL;
	}
	RzSkipListNode *it;
	struct reloc_t *reloc;
	rz_skiplist_foreach (relocs, it, reloc) {
		if (!reloc->external) {
			// right now, we only care about patching external relocs
			// others might be interesting too in the future though, for example in object files.
			continue;
		}
		rz_pvector_push(obj->patchable_relocs, reloc);
	}
	return obj->patchable_relocs;
}

RZ_API bool MACH0_(needs_reloc_patching)(struct MACH0_(obj_t) * obj) {
	rz_return_val_if_fail(obj, false);
	RzPVector *patchable_relocs = get_patchable_relocs(obj);
	return patchable_relocs && rz_pvector_len(patchable_relocs);
}

static ut64 reloc_target_size(struct MACH0_(obj_t) * obj) {
	int bits = MACH0_(get_bits_from_hdr)(&obj->hdr);
	if (bits) {
		return 8;
	}
	return bits / 8;
}

/// size of the artificial reloc target vfile
RZ_API ut64 MACH0_(reloc_targets_vfile_size)(struct MACH0_(obj_t) * obj) {
	RzPVector *patchable_relocs = get_patchable_relocs(obj);
	if (!patchable_relocs) {
		return 0;
	}
	return rz_pvector_len(patchable_relocs) * reloc_target_size(obj);
}

/// base vaddr where to map the artificial reloc target vfile
RZ_API ut64 MACH0_(reloc_targets_map_base)(RzBinFile *bf, struct MACH0_(obj_t) * obj) {
	if (obj->reloc_targets_map_base_calculated) {
		return obj->reloc_targets_map_base;
	}
	RzList *maps = MACH0_(get_maps_unpatched)(bf);
	obj->reloc_targets_map_base = rz_bin_relocs_patch_find_targets_map_base(maps, reloc_target_size(obj));
	rz_list_free(maps);
	obj->reloc_targets_map_base_calculated = true;
	return obj->reloc_targets_map_base;
}

static bool _patch_reloc(struct MACH0_(obj_t) * bin, struct reloc_t *reloc, ut64 symbol_at) {
	ut64 pc = reloc->addr;
	ut64 ins_len = 0;

	switch (bin->hdr.cputype) {
	case CPU_TYPE_X86_64: {
		switch (reloc->type) {
		case X86_64_RELOC_UNSIGNED:
			break;
		case X86_64_RELOC_BRANCH:
			pc -= 1;
			ins_len = 5;
			break;
		default:
			RZ_LOG_ERROR("Warning: unsupported reloc type for X86_64 (%d), please file a bug.\n", reloc->type);
			return false;
		}
		break;
	}
	case CPU_TYPE_ARM64:
	case CPU_TYPE_ARM64_32:
		pc = reloc->addr & ~3;
		ins_len = 4;
		break;
	case CPU_TYPE_ARM:
		break;
	default:
		RZ_LOG_ERROR("Warning: unsupported architecture for patching relocs, please file a bug. %s\n", MACH0_(get_cputype_from_hdr)(&bin->hdr));
		return false;
	}

	ut64 val = symbol_at;
	if (reloc->pc_relative) {
		val = symbol_at - pc - ins_len;
	}

	ut8 buf[8];
	rz_write_ble(buf, val, false, reloc->size * 8);
	rz_buf_write_at(bin->buf_patched, reloc->offset, buf, RZ_MIN(sizeof(buf), reloc->size));
	return true;
}

/**
 * \brief Patching of external relocs in a sparse overlay buffer
 *
 * This patches both classic Mach-O relocs and modern dyld chained pointers
 */
RZ_API void MACH0_(patch_relocs)(RzBinFile *bf, struct MACH0_(obj_t) * obj) {
	rz_return_if_fail(obj);
	if (obj->relocs_patched) {
		return;
	}
	bool needs_reloc_patch = MACH0_(needs_reloc_patching)(obj);
	bool needs_rebasing = MACH0_(needs_rebasing_and_stripping)(obj);
	if (obj->relocs_patched || (!needs_reloc_patch && !needs_rebasing)) {
		return;
	}
	obj->relocs_patched = true; // run this function just once (lazy relocs patching)
	obj->buf_patched = rz_buf_new_sparse_overlay(obj->b, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!obj->buf_patched) {
		return;
	}

	if (needs_reloc_patch) {
		ut64 cdsz = reloc_target_size(obj);
		ut64 size = MACH0_(reloc_targets_vfile_size)(obj);
		if (!size) {
			return;
		}
		RzBinRelocTargetBuilder *targets = rz_bin_reloc_target_builder_new(cdsz, MACH0_(reloc_targets_map_base)(bf, obj));
		if (!targets) {
			return;
		}
		RzPVector *patchable_relocs = get_patchable_relocs(obj);
		void **it;
		rz_pvector_foreach (patchable_relocs, it) {
			struct reloc_t *reloc = *it;
			ut64 sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->ord);
			reloc->target = sym_addr;
			_patch_reloc(obj, reloc, sym_addr);
		}
		rz_bin_reloc_target_builder_free(targets);
	}

	if (needs_rebasing) {
		MACH0_(rebase_buffer)
		(obj, obj->buf_patched);
	}

	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(obj->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
}
