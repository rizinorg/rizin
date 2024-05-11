// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include <rz_util/ht_uu.h>

struct relocs_segment {
	ut64 offset;
	ut64 size;
	ut64 entry_size;
	ut64 mode;
};

static struct relocs_segment relocs_segment_init(ut64 offset, ut64 size, ut64 entry_size, ut64 mode) {
	return (struct relocs_segment){
		.offset = offset,
		.size = size,
		.entry_size = entry_size,
		.mode = mode,
	};
}

static void fix_rva_and_offset_relocable_file(ELFOBJ *bin, RzBinElfReloc *reloc, RzBinElfSection *section) {
	RzBinElfSection *sub_section = Elf_(rz_bin_elf_get_section)(bin, section->info);

	if (!sub_section) {
		reloc->paddr = UT64_MAX;
		reloc->vaddr = reloc->offset;
	} else {
		reloc->paddr = sub_section->offset + reloc->offset;
		reloc->vaddr = Elf_(rz_bin_elf_p2v)(bin, reloc->paddr);
		reloc->section = section->info;
	}
}

static void fix_rva_and_offset_exec_file(ELFOBJ *bin, RzBinElfReloc *reloc) {
	reloc->paddr = Elf_(rz_bin_elf_v2p)(bin, reloc->offset);

	if (reloc->paddr == UT64_MAX) {
		reloc->paddr = reloc->offset;
	}

	reloc->vaddr = reloc->offset;
}

static void fix_rva_and_offset(ELFOBJ *bin, RzBinElfReloc *reloc, RzBinElfSection *section) {
	if (section && Elf_(rz_bin_elf_is_relocatable)(bin)) {
		fix_rva_and_offset_relocable_file(bin, reloc, section);
	} else {
		fix_rva_and_offset_exec_file(bin, reloc);
	}
}

static ut64 get_size_rel_mode(ut64 mode) {
	return mode == DT_REL ? sizeof(Elf_(Rel)) : sizeof(Elf_(Rela));
}

static bool read_reloc_entry_aux(ELFOBJ *bin, Elf_(Rela) * reloc, ut64 offset, ut64 mode) {
	if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &reloc->rz_offset) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &reloc->rz_info)) {
		return false;
	}

	if (mode == DT_REL) {
		reloc->rz_addend = 0;
		return true;
	}

	return Elf_(rz_bin_elf_read_sword_sxword)(bin, &offset, &reloc->rz_addend);
}

static bool read_reloc_entry(ELFOBJ *bin, Elf_(Rela) * reloc, ut64 offset, ut64 mode) {
	if (!read_reloc_entry_aux(bin, reloc, offset, mode)) {
		RZ_LOG_WARN("Failed to read reloc at 0x%" PFMT64x ".\n", offset);
		return false;
	}

	return true;
}

static bool get_reloc_entry(ELFOBJ *bin, RzBinElfReloc *reloc, ut64 offset, ut64 mode) {
	Elf_(Rela) tmp;
	if (!read_reloc_entry(bin, &tmp, offset, mode)) {
		return false;
	}

	reloc->mode = mode;
	reloc->offset = tmp.rz_offset;
	reloc->sym = ELF_R_SYM(tmp.rz_info);
	reloc->type = ELF_R_TYPE(tmp.rz_info);
	reloc->addend = tmp.rz_addend;

	return true;
}

static bool has_already_been_processed(ELFOBJ *bin, ut64 offset, HtUU *set) {
	bool found;
	ht_uu_find(set, offset, &found);

	return found;
}

static bool get_relocs_entry(ELFOBJ *bin, RzBinElfSection *section, RzVector /*<RzBinElfReloc>*/ *relocs, struct relocs_segment *segment, HtUU *set) {
	for (ut64 entry_offset = 0; entry_offset < segment->size; entry_offset += segment->entry_size) {
		if (has_already_been_processed(bin, segment->offset + entry_offset, set)) {
			continue;
		}

		if (!ht_uu_insert(set, segment->offset + entry_offset, segment->offset + entry_offset, NULL)) {
			return false;
		}

		RzBinElfReloc tmp = { 0 };
		if (!get_reloc_entry(bin, &tmp, segment->offset + entry_offset, segment->mode)) {
			return false;
		}
		fix_rva_and_offset(bin, &tmp, section);

		if (!rz_vector_push(relocs, &tmp)) {
			return false;
		}
	}

	return true;
}

static bool get_relocs_entry_from_dt_dynamic_aux(ELFOBJ *bin, RzVector /*<RzBinElfReloc>*/ *relocs, ut64 dt_addr, ut64 dt_size, ut64 entry_size, ut64 mode, HtUU *set) {
	ut64 addr;
	ut64 size;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, dt_addr, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, dt_size, &size)) {
		return true;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (offset == UT64_MAX) {
		return false;
	}

	struct relocs_segment segment = relocs_segment_init(offset, size, entry_size, mode);

	return get_relocs_entry(bin, NULL, relocs, &segment, set);
}

static bool get_relocs_entry_from_dt_dynamic(ELFOBJ *bin, RzVector /*<RzBinElfReloc>*/ *relocs, HtUU *set) {
	ut64 entry_size;

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return true;
	}

	ut64 dt_pltrel;
	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTREL, &dt_pltrel)) {
		entry_size = get_size_rel_mode(dt_pltrel);
		if (!get_relocs_entry_from_dt_dynamic_aux(bin, relocs, DT_JMPREL, DT_PLTRELSZ, entry_size, dt_pltrel, set)) {
			return false;
		}
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELENT, &entry_size)) {
		if (!get_relocs_entry_from_dt_dynamic_aux(bin, relocs, DT_REL, DT_RELSZ, entry_size, DT_REL, set)) {
			return false;
		}
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELAENT, &entry_size)) {
		if (!entry_size) {
			return false;
		}

		if (!get_relocs_entry_from_dt_dynamic_aux(bin, relocs, DT_RELA, DT_RELASZ, entry_size, DT_RELA, set)) {
			return false;
		}
	}

	return true;
}

static ut64 get_section_relocation_mode(RzBinElfSection *section) {
	return section->type == SHT_REL ? DT_REL : DT_RELA;
}

static bool get_relocs_entry_from_sections(ELFOBJ *bin, RzVector /*<RzBinElfReloc>*/ *relocs, HtUU *set) {
	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(bin, section) {
		if (!section->is_valid || (section->type != SHT_REL && section->type != SHT_RELA)) {
			continue;
		}

		ut64 mode = get_section_relocation_mode(section);
		ut64 entry_size = get_size_rel_mode(mode);

		struct relocs_segment segment = relocs_segment_init(section->offset, section->size, entry_size, mode);

		if (!get_relocs_entry(bin, section, relocs, &segment, set)) {
			return false;
		}
	}

	return true;
}

RZ_OWN RzVector /*<RzBinElfReloc>*/ *Elf_(rz_bin_elf_relocs_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	HtUU *set = ht_uu_new();
	if (!set) {
		return NULL;
	}

	RzVector *result = rz_vector_new(sizeof(RzBinElfReloc), NULL, NULL);
	if (!result) {
		ht_uu_free(set);
		return NULL;
	}

	if (!get_relocs_entry_from_dt_dynamic(bin, result, set)) {
		rz_vector_free(result);
		ht_uu_free(set);
		return NULL;
	}

	if (!get_relocs_entry_from_sections(bin, result, set)) {
		rz_vector_free(result);
		ht_uu_free(set);
		return NULL;
	}

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		ht_uu_free(set);
		return NULL;
	}

	ht_uu_free(set);

	return result;
}

bool Elf_(rz_bin_elf_has_relocs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->relocs && (rz_vector_len(bin->relocs) > 0);
}

size_t Elf_(rz_bin_elf_get_relocs_count)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (!bin->relocs) {
		return 0;
	}

	return rz_vector_len(bin->relocs);
}

ut64 Elf_(rz_bin_elf_get_num_relocs_dynamic_plt)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	ut64 dt_pltrel;
	ut64 size;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTREL, &dt_pltrel) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTRELSZ, &size)) {
		return 0;
	}

	ut64 entry_size = get_size_rel_mode(dt_pltrel);
	return size / entry_size;
}
