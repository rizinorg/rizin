// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void fix_rva_and_offset_relocable_file(ELFOBJ *bin, RzBinElfReloc *reloc, RzBinElfSection *section) {
	RzBinElfSection *sub_section = Elf_(rz_bin_elf_get_section)(bin, section->info);

	if (!sub_section) {
		reloc->paddr = UT64_MAX;
		reloc->vaddr = reloc->offset;
	} else {
		reloc->paddr = sub_section->offset + reloc->offset;
		reloc->vaddr = Elf_(rz_bin_elf_p2v_new)(bin, reloc->paddr);
	}
}

static void fix_rva_and_offset_exec_file(ELFOBJ *bin, RzBinElfReloc *reloc) {
	reloc->paddr = Elf_(rz_bin_elf_v2p_new)(bin, reloc->offset);

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

static bool read_reloc_entry(ELFOBJ *bin, Elf_(Rela) * reloc, ut64 offset, ut64 mode) {
	if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &reloc->rz_offset)) {
		return false;
	}

	if (!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &reloc->rz_info)) {
		return false;
	}

	if (mode == DT_REL) {
		reloc->rz_addend = 0;
		return true;
	}

	if (!Elf_(rz_bin_elf_read_sword_sxword)(bin, &offset, &reloc->rz_addend)) {
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

static bool has_already_been_processed(RzVector *relocs, RzBinElfReloc *reloc) {
	RzBinElfReloc *iter;
	rz_vector_foreach(relocs, iter) {
		if (!memcmp(iter, reloc, sizeof(RzBinElfReloc))) {
			return true;
		}
	}

	return false;
}

static bool get_relocs_entry(ELFOBJ *bin, RzBinElfSection *section, RzVector *relocs, ut64 offset, ut64 size, ut64 entry_size, ut64 mode) {
	for (ut64 entry_offset = 0; entry_offset < size; entry_offset += entry_size) {
		RzBinElfReloc tmp = { 0 };
		if (!get_reloc_entry(bin, &tmp, offset + entry_offset, mode)) {
			return false;
		}

		fix_rva_and_offset(bin, &tmp, section);

		if (has_already_been_processed(relocs, &tmp)) {
			break;
		}

		if (!rz_vector_push(relocs, &tmp)) {
			return false;
		}
	}

	return true;
}

static bool get_relocs_entry_from_dt_dynamic_aux(ELFOBJ *bin, RzVector *relocs, ut64 dt_addr, ut64 dt_size, ut64 entry_size, ut64 mode) {
	ut64 addr;
	ut64 size;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, dt_addr, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, dt_size, &size)) {
		return true;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	if (offset == UT64_MAX) {
		return false;
	}

	return get_relocs_entry(bin, NULL, relocs, offset, size, entry_size, mode);
}

static bool get_relocs_entry_from_dt_dynamic(ELFOBJ *bin, RzVector *relocs) {
	ut64 entry_size;

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return true;
	}

	ut64 dt_pltrel;
	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTREL, &dt_pltrel)) {
		entry_size = get_size_rel_mode(dt_pltrel);
		if (!get_relocs_entry_from_dt_dynamic_aux(bin, relocs, DT_JMPREL, DT_PLTRELSZ, entry_size, dt_pltrel)) {
			return false;
		}
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELENT, &entry_size)) {
		if (!get_relocs_entry_from_dt_dynamic_aux(bin, relocs, DT_REL, DT_RELSZ, entry_size, DT_REL)) {
			return false;
		}
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELAENT, &entry_size)) {
		if (!get_relocs_entry_from_dt_dynamic_aux(bin, relocs, DT_RELA, DT_RELASZ, entry_size, DT_RELA)) {
			return false;
		}
	}

	return true;
}

static ut64 get_section_relocation_mode(RzBinElfSection *section) {
	return section->type == SHT_REL ? DT_REL : DT_RELA;
}

static bool get_relocs_entry_from_sections(ELFOBJ *bin, RzVector *relocs) {
	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(bin, section) {
		if (!section->is_valid || (section->type != SHT_REL && section->type != SHT_RELA)) {
			continue;
		}

		ut64 mode = get_section_relocation_mode(section);
		ut64 entry_size = get_size_rel_mode(mode);

		if (!get_relocs_entry(bin, section, relocs, section->offset, section->size, entry_size, mode)) {
			return false;
		}
	}

	return true;
}

RZ_OWN RzVector *Elf_(rz_bin_elf_relocs_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzVector *result = rz_vector_new(sizeof(RzBinElfReloc), NULL, NULL);
	if (!result) {
		return NULL;
	}

	if (!get_relocs_entry_from_dt_dynamic(bin, result)) {
		free(result);
		return NULL;
	}

	if (!get_relocs_entry_from_sections(bin, result)) {
		free(result);
		return NULL;
	}

	if (!rz_vector_len(result)) {
		free(result);
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_has_relocs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->relocs && Elf_(rz_bin_elf_get_relocs_count)(bin);
}

size_t Elf_(rz_bin_elf_get_relocs_count)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->relocs, 0);
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
