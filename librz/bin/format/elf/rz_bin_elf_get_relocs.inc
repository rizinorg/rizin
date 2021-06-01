// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool has_valid_section_header(ELFOBJ *bin, size_t pos) {
	return bin->g_sections[pos].info < bin->ehdr.e_shnum && bin->shdr;
}

static void fix_rva_and_offset_relocable_file(ELFOBJ *bin, RzBinElfReloc *r, size_t pos) {
	if (has_valid_section_header(bin, pos)) {
		r->paddr = bin->shdr[bin->g_sections[pos].info].sh_offset + r->offset;
		r->vaddr = Elf_(rz_bin_elf_p2v)(bin, r->paddr);
	} else {
		r->paddr = UT64_MAX;
		r->vaddr = r->offset;
	}
}

static void fix_rva_and_offset_exec_file(ELFOBJ *bin, RzBinElfReloc *r) {
	r->paddr = Elf_(rz_bin_elf_v2p)(bin, r->offset);
	r->vaddr = r->offset;
}

static void fix_rva_and_offset(ELFOBJ *bin, RzBinElfReloc *r, size_t pos) {
	if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
		fix_rva_and_offset_relocable_file(bin, r, pos);
	} else {
		fix_rva_and_offset_exec_file(bin, r);
	}
}

static bool read_reloc(ELFOBJ *bin, RzBinElfReloc *r, Elf_(Xword) rel_mode, ut64 vaddr) {
	ut64 offset = Elf_(rz_bin_elf_v2p_new)(bin, vaddr);
	if (offset == UT64_MAX) {
		return false;
	}

	size_t size_struct = get_size_rel_mode(rel_mode);

	ut8 buf[sizeof(Elf_(Rela))] = { 0 };
	int res = rz_buf_read_at(bin->b, offset, buf, size_struct);
	if (res != size_struct) {
		return false;
	}

	size_t i = 0;
	Elf_(Rela) reloc_info;

	reloc_info.rz_offset = RZ_BIN_ELF_READWORD(buf, i);
	reloc_info.rz_info = RZ_BIN_ELF_READWORD(buf, i);

	if (rel_mode == DT_RELA) {
		reloc_info.rz_addend = RZ_BIN_ELF_READWORD(buf, i);
		r->addend = reloc_info.rz_addend;
	}

	r->rel_mode = rel_mode;
	r->last = 0;
	r->offset = reloc_info.rz_offset;
	r->sym = ELF_R_SYM(reloc_info.rz_info);
	r->type = ELF_R_TYPE(reloc_info.rz_info);

	return true;
}

static size_t get_num_relocs_dynamic(ELFOBJ *bin) {
	size_t res = 0;

	if (bin->dyn_info.dt_relaent) {
		res += bin->dyn_info.dt_relasz / bin->dyn_info.dt_relaent;
	}

	if (bin->dyn_info.dt_relent) {
		res += bin->dyn_info.dt_relsz / bin->dyn_info.dt_relent;
	}

	return res + get_num_relocs_dynamic_plt(bin);
}

static bool sectionIsValid(ELFOBJ *bin, RzBinElfSection *sect) {
	return (sect->offset + sect->size <= bin->size);
}

static Elf_(Xword) get_section_mode(ELFOBJ *bin, size_t pos) {
	if (rz_str_startswith(bin->g_sections[pos].name, ".rela.")) {
		return DT_RELA;
	}
	if (rz_str_startswith(bin->g_sections[pos].name, ".rel.")) {
		return DT_REL;
	}
	return 0;
}

static bool is_reloc_section(Elf_(Xword) rel_mode) {
	return rel_mode == DT_REL || rel_mode == DT_RELA;
}

static size_t get_num_relocs_sections(ELFOBJ *bin) {
	size_t i, size, ret = 0;
	Elf_(Xword) rel_mode;

	if (!bin->g_sections) {
		return 0;
	}

	for (i = 0; !bin->g_sections[i].last; i++) {
		if (!sectionIsValid(bin, &bin->g_sections[i])) {
			continue;
		}
		rel_mode = get_section_mode(bin, i);
		if (!is_reloc_section(rel_mode)) {
			continue;
		}
		size = get_size_rel_mode(rel_mode);
		ret += NUMENTRIES_ROUNDUP(bin->g_sections[i].size, size);
	}

	return ret;
}

static size_t get_num_relocs_approx(ELFOBJ *bin) {
	return get_num_relocs_dynamic(bin) + get_num_relocs_sections(bin);
}

static size_t populate_relocs_record_from_dynamic(ELFOBJ *bin, RzBinElfReloc *relocs, size_t pos, size_t num_relocs) {
	size_t offset;
	size_t size = get_size_rel_mode(bin->dyn_info.dt_pltrel);

	for (offset = 0; offset < bin->dyn_info.dt_pltrelsz && pos < num_relocs; offset += size, pos++) {
		if (!read_reloc(bin, relocs + pos, bin->dyn_info.dt_pltrel, bin->dyn_info.dt_jmprel + offset)) {
			break;
		}
		fix_rva_and_offset_exec_file(bin, relocs + pos);
	}

	for (offset = 0; offset < bin->dyn_info.dt_relasz && pos < num_relocs; offset += bin->dyn_info.dt_relaent, pos++) {
		if (!read_reloc(bin, relocs + pos, DT_RELA, bin->dyn_info.dt_rela + offset)) {
			break;
		}
		fix_rva_and_offset_exec_file(bin, relocs + pos);
	}

	for (offset = 0; offset < bin->dyn_info.dt_relsz && pos < num_relocs; offset += bin->dyn_info.dt_relent, pos++) {
		if (!read_reloc(bin, relocs + pos, DT_REL, bin->dyn_info.dt_rel + offset)) {
			break;
		}
		fix_rva_and_offset_exec_file(bin, relocs + pos);
	}

	return pos;
}

static size_t get_next_not_analysed_offset(ELFOBJ *bin, size_t section_vaddr, size_t offset) {
	size_t gvaddr = section_vaddr + offset;

	if (bin->dyn_info.dt_rela != RZ_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_rela <= gvaddr && gvaddr < bin->dyn_info.dt_rela + bin->dyn_info.dt_relasz) {
		return bin->dyn_info.dt_rela + bin->dyn_info.dt_relasz - section_vaddr;
	}

	if (bin->dyn_info.dt_rel != RZ_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_rel <= gvaddr && gvaddr < bin->dyn_info.dt_rel + bin->dyn_info.dt_relsz) {
		return bin->dyn_info.dt_rel + bin->dyn_info.dt_relsz - section_vaddr;
	}

	if (bin->dyn_info.dt_jmprel != RZ_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_jmprel <= gvaddr && gvaddr < bin->dyn_info.dt_jmprel + bin->dyn_info.dt_pltrelsz) {
		return bin->dyn_info.dt_jmprel + bin->dyn_info.dt_pltrelsz - section_vaddr;
	}

	return offset;
}

static size_t populate_relocs_record_from_section(ELFOBJ *bin, RzBinElfReloc *relocs, size_t pos, size_t num_relocs) {
	size_t size, i, j;
	Elf_(Xword) rel_mode;

	if (!bin->g_sections) {
		return pos;
	}

	for (i = 0; !bin->g_sections[i].last; i++) {
		rel_mode = get_section_mode(bin, i);

		if (!is_reloc_section(rel_mode) || bin->g_sections[i].size > bin->size || bin->g_sections[i].offset > bin->size) {
			continue;
		}

		size = get_size_rel_mode(rel_mode);

		for (j = get_next_not_analysed_offset(bin, bin->g_sections[i].rva, 0);
			j < bin->g_sections[i].size && pos < num_relocs;
			j = get_next_not_analysed_offset(bin, bin->g_sections[i].rva, j + size)) {

			if (!read_reloc(bin, relocs + pos, rel_mode, bin->g_sections[i].rva + j)) {
				break;
			}

			fix_rva_and_offset(bin, relocs + pos, i);
			pos++;
		}
	}

	return pos;
}

static RzBinElfReloc *populate_relocs_record(ELFOBJ *bin) {
	size_t i = 0;
	size_t num_relocs = get_num_relocs_approx(bin);
	RzBinElfReloc *relocs = RZ_NEWS0(RzBinElfReloc, num_relocs + 1);
	if (!relocs) {
		// In case we can't allocate enough memory for all the claimed
		// relocation entries, try to parse only the ones specified in
		// the dynamic segment.
		num_relocs = get_num_relocs_dynamic(bin);
		relocs = RZ_NEWS0(RzBinElfReloc, num_relocs + 1);
		if (!relocs) {
			return NULL;
		}
	}

	i = populate_relocs_record_from_dynamic(bin, relocs, i, num_relocs);
	i = populate_relocs_record_from_section(bin, relocs, i, num_relocs);
	relocs[i].last = 1;

	bin->g_reloc_num = i;
	return relocs;
}

/**
 * \brief Get the list of relocations
 * \param elf binary
 * \return a borrowed array of relocations
 *
 * Get a list of relocations from the binary object or compute the list of
 * relocations.
 */
RZ_BORROW RzBinElfReloc *Elf_(rz_bin_elf_get_relocs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->g_relocs) {
		bin->g_relocs = populate_relocs_record(bin);
	}

	return bin->g_relocs;
}
