// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static const char *sdb_elf_s_type_cparse = "enum elf_s_type {SHT_NULL=0,SHT_PROGBITS=1,"
					   "SHT_SYMTAB=2,SHT_STRTAB=3,SHT_RELA=4,SHT_HASH=5,SHT_DYNAMIC=6,SHT_NOTE=7,"
					   "SHT_NOBITS=8,SHT_REL=9,SHT_SHLIB=10,SHT_DYNSYM=11,SHT_LOOS=0x60000000,"
					   "SHT_HIOS=0x6fffffff,SHT_LOPROC=0x70000000,SHT_HIPROC=0x7fffffff};";

#if RZ_BIN_ELF64
static const char *sdb_elf_s_flags_64_cparse = "enum elf_s_flags_64 {SF64_None=0,SF64_Exec=1,"
					       "SF64_Alloc=2,SF64_Alloc_Exec=3,SF64_Write=4,SF64_Write_Exec=5,"
					       "SF64_Write_Alloc=6,SF64_Write_Alloc_Exec=7};";
static const char *sdb_elf_shdr_format = "x[4]E[8]Eqqqxxqq name (elf_s_type)type"
					 " (elf_s_flags_64)flags addr offset size link info addralign entsize";
#else
static const char *sdb_elf_s_flags_32_cparse = "enum elf_s_flags_32 {SF32_None=0,SF32_Exec=1,"
					       "SF32_Alloc=2,SF32_Alloc_Exec=3,SF32_Write=4,SF32_Write_Exec=5,"
					       "SF32_Write_Alloc=6,SF32_Write_Alloc_Exec=7};";
static const char *sdb_elf_shdr_format = "x[4]E[4]Exxxxxxx name (elf_s_type)type"
					 " (elf_s_flags_32)flags addr offset size link info addralign entsize";
#endif

static void init_shdr_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_num_set(bin->kv, "elf_shdr.size", sizeof(Elf_(Shdr)), 0);
#if RZ_BIN_ELF64
	sdb_set(bin->kv, "elf_s_flags_64.cparse", sdb_elf_s_flags_64_cparse, 0);
#else
	sdb_set(bin->kv, "elf_s_flags_32.cparse", sdb_elf_s_flags_32_cparse, 0);
#endif
	sdb_set(bin->kv, "elf_s_type.cparse", sdb_elf_s_type_cparse, 0);
	sdb_set(bin->kv, "elf_shdr.format", sdb_elf_shdr_format, 0);
}

static void set_shdr_entry(ELFOBJ *bin, size_t shdr_entry_index, ut8 *entry) {
	size_t pos = 0;

	bin->shdr[shdr_entry_index].sh_name = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_type = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_flags = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_addr = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_offset = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_size = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_link = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_info = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_addralign = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_entsize = RZ_BIN_ELF_READWORD(entry, pos);
}

static bool read_shdr_entry(ELFOBJ *bin, size_t shdr_entry_index) {
	const size_t offset = bin->ehdr.e_shoff + shdr_entry_index * sizeof(Elf_(Shdr));
	ut8 shdr[sizeof(Elf_(Shdr))] = { 0 };

	if (rz_buf_read_at(bin->b, offset, shdr, sizeof(Elf_(Shdr))) < 0) {
		bprintf("read (shdr) at 0x%" PFMT64x "\n", (ut64)bin->ehdr.e_shoff);
		RZ_FREE(bin->shdr);
		return false;
	}

	set_shdr_entry(bin, shdr_entry_index, shdr);

	return true;
}

static bool read_shdr(ELFOBJ *bin) {
	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		if (!read_shdr_entry(bin, i)) {
			return false;
		}
	}

	return true;
}

static bool init_shdr_header(ELFOBJ *bin) {
	bin->shdr = RZ_NEWS0(Elf_(Shdr), bin->ehdr.e_shnum);
	if (!bin->shdr) {
		perror("malloc (shdr)");
		return false;
	}

	if (!read_shdr(bin)) {
		return false;
	}

	return true;
}

static bool check_shdr_size(ELFOBJ *bin) {
	ut32 shdr_size;

	if (!UT32_MUL(&shdr_size, bin->ehdr.e_shnum, sizeof(Elf_(Shdr)))) {
		return false;
	}

	if (!shdr_size || bin->ehdr.e_shoff + shdr_size > bin->size) {
		return false;
	}

	return true;
}

RZ_IPI bool Elf_(rz_bin_elf_init_shdr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->ehdr.e_shnum || !check_shdr_size(bin)) {
		return false;
	}

	init_shdr_sdb(bin);

	return init_shdr_header(bin);
}
