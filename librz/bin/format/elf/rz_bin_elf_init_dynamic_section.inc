// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool fill_dynamic_entry(ELFOBJ *bin, ut64 entry_offset, Elf_(Dyn) * d) {
	ut8 sdyn[sizeof(Elf_(Dyn))] = { 0 };
	int j = 0;
	int len = rz_buf_read_at(bin->b, entry_offset, sdyn, sizeof(Elf_(Dyn)));
	if (len < 1) {
		return false;
	}

	d->d_tag = RZ_BIN_ELF_READWORD(sdyn, j);
	d->d_un.d_ptr = RZ_BIN_ELF_READWORD(sdyn, j);

	return true;
}

static size_t get_maximum_number_of_dynamic_entries(ut64 dyn_size) {
	return dyn_size / sizeof(Elf_(Dyn));
}

static void fill_dynamic_entries(ELFOBJ *bin, ut64 loaded_offset, ut64 dyn_size) {
	Elf_(Dyn) d = { 0 };
	size_t i;
	size_t number_of_entries = get_maximum_number_of_dynamic_entries(dyn_size);

	for (i = 0; i < number_of_entries; i++) {
		ut64 entry_offset = loaded_offset + i * sizeof(Elf_(Dyn));
		if (!fill_dynamic_entry(bin, entry_offset, &d)) {
			break;
		}

		switch (d.d_tag) {
		case DT_NULL:
			break;
		case DT_PLTRELSZ:
			bin->dyn_info.dt_pltrelsz = d.d_un.d_val;
			break;
		case DT_PLTGOT:
			bin->dyn_info.dt_pltgot = d.d_un.d_ptr;
			break;
		case DT_HASH:
			bin->dyn_info.dt_hash = d.d_un.d_ptr;
			break;
		case DT_STRTAB:
			bin->dyn_info.dt_strtab = d.d_un.d_ptr;
			break;
		case DT_SYMTAB:
			bin->dyn_info.dt_symtab = d.d_un.d_ptr;
			break;
		case DT_RELA:
			bin->dyn_info.dt_rela = d.d_un.d_ptr;
			break;
		case DT_RELASZ:
			bin->dyn_info.dt_relasz = d.d_un.d_val;
			break;
		case DT_RELAENT:
			bin->dyn_info.dt_relaent = d.d_un.d_val;
			break;
		case DT_STRSZ:
			bin->dyn_info.dt_strsz = d.d_un.d_val;
			break;
		case DT_SYMENT:
			bin->dyn_info.dt_syment = d.d_un.d_val;
			break;
		case DT_REL:
			bin->dyn_info.dt_rel = d.d_un.d_ptr;
			break;
		case DT_RELSZ:
			bin->dyn_info.dt_relsz = d.d_un.d_val;
			break;
		case DT_RELENT:
			bin->dyn_info.dt_relent = d.d_un.d_val;
			break;
		case DT_PLTREL:
			bin->dyn_info.dt_pltrel = d.d_un.d_val;
			break;
		case DT_JMPREL:
			bin->dyn_info.dt_jmprel = d.d_un.d_ptr;
			break;
		case DT_MIPS_PLTGOT:
			bin->dyn_info.dt_mips_pltgot = d.d_un.d_ptr;
			break;
		case DT_BIND_NOW:
			bin->dyn_info.dt_bind_now = true;
			break;
		case DT_FLAGS:
			bin->dyn_info.dt_flags = d.d_un.d_val;
			break;
		case DT_FLAGS_1:
			bin->dyn_info.dt_flags_1 = d.d_un.d_val;
			break;
		case DT_RPATH:
			bin->dyn_info.dt_rpath = d.d_un.d_val;
			break;
		case DT_RUNPATH:
			bin->dyn_info.dt_runpath = d.d_un.d_val;
			break;
		case DT_NEEDED:
			rz_vector_push(&bin->dyn_info.dt_needed, &d.d_un.d_val);
			break;
		case DT_INIT:
			bin->dyn_info.dt_init = d.d_un.d_ptr;
			break;
		case DT_FINI:
			bin->dyn_info.dt_fini = d.d_un.d_ptr;
			break;
		case DT_DEBUG:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_PREINIT_ARRAY:
		case DT_PREINIT_ARRAYSZ:
		case DT_SONAME:
		case DT_GNU_HASH:
			// common dynamic entries in ELF, but we don't need to
			// do anything with them.
			break;
		default:
			if ((d.d_tag >= DT_VERSYM) && (d.d_tag <= DT_VERNEEDNUM)) {
				bin->version_info[DT_VERSIONTAGIDX(d.d_tag)] = d.d_un.d_val;
			} else {
				RZ_LOG_DEBUG("Dynamic tag %" PFMT64d " not handled\n", (ut64)d.d_tag);
			}
			break;
		}
		if (d.d_tag == DT_NULL) {
			break;
		}
	}
}

static void set_default_value_dynamic_info(ELFOBJ *bin) {
	bin->dyn_info.dt_init = 0;
	bin->dyn_info.dt_fini = 0;
	bin->dyn_info.dt_pltrelsz = 0;
	bin->dyn_info.dt_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_hash = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_strtab = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_symtab = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_rela = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_relasz = 0;
	bin->dyn_info.dt_relaent = 0;
	bin->dyn_info.dt_strsz = 0;
	bin->dyn_info.dt_syment = 0;
	bin->dyn_info.dt_rel = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_relsz = 0;
	bin->dyn_info.dt_relent = 0;
	bin->dyn_info.dt_pltrel = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_jmprel = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_mips_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_bind_now = false;
	bin->dyn_info.dt_flags = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_flags_1 = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_rpath = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_runpath = RZ_BIN_ELF_XWORD_MAX;
	rz_vector_init(&bin->dyn_info.dt_needed, sizeof(Elf_(Off)), NULL, NULL);
}

static void init_dynamic_section_sdb(ELFOBJ *bin) {
	int r = Elf_(rz_bin_elf_has_relro)(bin);
	switch (r) {
	case RZ_BIN_ELF_FULL_RELRO:
		sdb_set(bin->kv, "elf.relro", "full", 0);
		break;
	case RZ_BIN_ELF_PART_RELRO:
		sdb_set(bin->kv, "elf.relro", "partial", 0);
		break;
	default:
		sdb_set(bin->kv, "elf.relro", "no", 0);
		break;
	}
}

static Elf_(Phdr) * get_dynamic_segment(ELFOBJ *bin) {
	int i;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			if (bin->phdr[i].p_filesz > bin->size) {
				return NULL;
			}
			if (bin->phdr[i].p_offset > bin->size) {
				return NULL;
			}
			if (bin->phdr[i].p_offset + sizeof(Elf_(Dyn)) > bin->size) {
				return NULL;
			}
			return &bin->phdr[i];
		}
	}
	return NULL;
}

RZ_IPI bool Elf_(rz_bin_elf_init_dynamic_section)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	ut64 dyn_size = 0, loaded_offset;
	set_default_value_dynamic_info(bin);

	rz_return_val_if_fail(bin, false);
	if (!bin->phdr || !bin->ehdr.e_phnum) {
		return false;
	}

	Elf_(Phdr) *dyn_phdr = get_dynamic_segment(bin);
	if (!dyn_phdr) {
		return false;
	}

	dyn_size = dyn_phdr->p_filesz;
	loaded_offset = Elf_(rz_bin_elf_v2p_new)(bin, dyn_phdr->p_vaddr);
	if (loaded_offset == UT64_MAX) {
		return false;
	}

	if (!dyn_size || loaded_offset + dyn_size > bin->size) {
		return false;
	}

	fill_dynamic_entries(bin, loaded_offset, dyn_size);
	init_dynamic_section_sdb(bin);

	return true;
}
