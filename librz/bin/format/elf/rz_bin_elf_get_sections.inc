// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void create_section_from_phdr(ELFOBJ *bin, RzBinElfSection *ret, size_t *i, const char *name, ut64 addr, ut64 sz) {
	if (!addr) {
		return;
	}

	ret[*i].offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	ret[*i].rva = addr;
	ret[*i].size = sz;
	strncpy(ret[*i].name, name, RZ_ARRAY_SIZE(ret[*i].name) - 1);
	ret[*i].name[RZ_ARRAY_SIZE(ret[*i].name) - 1] = '\0';
	ret[*i].last = 0;
	*i = *i + 1;
}

static RzBinElfSection *get_sections_from_phdr(ELFOBJ *bin) {
	RzBinElfSection *ret;
	size_t num_sections = 0;
	ut64 reldyn = 0, relava = 0, pltgotva = 0, relva = 0;
	ut64 reldynsz = 0, relasz = 0, pltgotsz = 0;
	rz_return_val_if_fail(bin && bin->phdr, NULL);

	if (!bin->ehdr.e_phnum) {
		return NULL;
	}

	if (bin->dyn_info.dt_rel != RZ_BIN_ELF_ADDR_MAX) {
		reldyn = bin->dyn_info.dt_rel;
		num_sections++;
	}
	if (bin->dyn_info.dt_rela != RZ_BIN_ELF_ADDR_MAX) {
		relva = bin->dyn_info.dt_rela;
		num_sections++;
	}
	if (bin->dyn_info.dt_relsz) {
		reldynsz = bin->dyn_info.dt_relsz;
	}
	if (bin->dyn_info.dt_relasz) {
		relasz = bin->dyn_info.dt_relasz;
	}
	if (bin->dyn_info.dt_pltgot != RZ_BIN_ELF_ADDR_MAX) {
		pltgotva = bin->dyn_info.dt_pltgot;
		num_sections++;
	}
	if (bin->dyn_info.dt_pltrelsz) {
		pltgotsz = bin->dyn_info.dt_pltrelsz;
	}
	if (bin->dyn_info.dt_jmprel != RZ_BIN_ELF_ADDR_MAX) {
		relava = bin->dyn_info.dt_jmprel;
		num_sections++;
	}

	ret = calloc(num_sections + 1, sizeof(RzBinElfSection));
	if (!ret) {
		return NULL;
	}

	size_t i = 0;
	create_section_from_phdr(bin, ret, &i, ".rel.dyn", reldyn, reldynsz);
	create_section_from_phdr(bin, ret, &i, ".rela.plt", relava, pltgotsz);
	create_section_from_phdr(bin, ret, &i, ".rel.plt", relva, relasz);
	create_section_from_phdr(bin, ret, &i, ".got.plt", pltgotva, pltgotsz);
	ret[i].last = 1;

	return ret;
}

RzBinElfSection *Elf_(rz_bin_elf_get_sections)(ELFOBJ *bin) {
	RzBinElfSection *ret = NULL;
	char unknown_s[32], invalid_s[32];
	int i, nidx, unknown_c = 0, invalid_c = 0;

	rz_return_val_if_fail(bin, NULL);
	if (bin->g_sections) {
		return bin->g_sections;
	}
	if (!bin->shdr) {
		//we don't give up search in phdr section
		return get_sections_from_phdr(bin);
	}
	if (!(ret = calloc((bin->ehdr.e_shnum + 1), sizeof(RzBinElfSection)))) {
		return NULL;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		ret[i].offset = bin->shdr[i].sh_offset;
		ret[i].size = bin->shdr[i].sh_size;
		ret[i].align = bin->shdr[i].sh_addralign;
		ret[i].flags = bin->shdr[i].sh_flags;
		ret[i].link = bin->shdr[i].sh_link;
		ret[i].info = bin->shdr[i].sh_info;
		ret[i].type = bin->shdr[i].sh_type;
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			ret[i].rva = bin->baddr + bin->shdr[i].sh_offset;
		} else {
			ret[i].rva = bin->shdr[i].sh_addr;
		}

		const int SHNAME = (int)bin->shdr[i].sh_name;
		const int SHSIZE = (int)bin->shstrtab_size;
		nidx = SHNAME;
		if (nidx < 0 || !bin->shstrtab_section || !bin->shstrtab_size || nidx > bin->shstrtab_size) {
			snprintf(invalid_s, sizeof(invalid_s), "invalid%d", invalid_c);
			strncpy(ret[i].name, invalid_s, sizeof(ret[i].name) - 1);
			invalid_c++;
		} else if (bin->shstrtab && (SHNAME > 0) && (SHNAME < SHSIZE)) {
			strncpy(ret[i].name, &bin->shstrtab[SHNAME], sizeof(ret[i].name) - 1);
		} else if (bin->shdr[i].sh_type == SHT_NULL) {
			//to follow the same behaviour as readelf
			ret[i].name[0] = '\0';
		} else {
			snprintf(unknown_s, sizeof(unknown_s), "unknown%d", unknown_c);
			strncpy(ret[i].name, unknown_s, sizeof(ret[i].name) - 1);
			unknown_c++;
		}
		ret[i].name[ELF_STRING_LENGTH - 1] = '\0';
		ret[i].last = 0;
	}
	ret[i].last = 1;
	return ret;
}
