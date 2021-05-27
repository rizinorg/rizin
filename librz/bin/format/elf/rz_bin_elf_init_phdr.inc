// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static const char *sdb_elf_p_type_cparse = "enum elf_p_type {PT_NULL=0,PT_LOAD=1,PT_DYNAMIC=2,"
					   "PT_INTERP=3,PT_NOTE=4,PT_SHLIB=5,PT_PHDR=6,PT_LOOS=0x60000000,"
					   "PT_HIOS=0x6fffffff,PT_LOPROC=0x70000000,PT_HIPROC=0x7fffffff};";

static const char *sdb_elf_p_flags_cparse = "enum elf_p_flags {PF_None=0,PF_Exec=1,"
					    "PF_Write=2,PF_Write_Exec=3,PF_Read=4,PF_Read_Exec=5,PF_Read_Write=6,"
					    "PF_Read_Write_Exec=7};";

#if RZ_BIN_ELF64
static const char *sdb_elf_phdr_format = "[4]E[4]Eqqqqqq (elf_p_type)type (elf_p_flags)flags"
					 " offset vaddr paddr filesz memsz align";
#else
static const char *sdb_elf_phdr_format = "[4]Exxxxx[4]Ex (elf_p_type)type offset vaddr paddr"
					 " filesz memsz (elf_p_flags)flags align";
#endif

static void init_phdr_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_num_set(bin->kv, "elf_phdr.size", sizeof(Elf_(Phdr)), 0);
	sdb_set(bin->kv, "elf_p_flags.cparse", sdb_elf_p_flags_cparse, 0);
	sdb_set(bin->kv, "elf_p_type.cparse", sdb_elf_p_type_cparse, 0);
	sdb_set(bin->kv, "elf_phdr.format", sdb_elf_phdr_format, 0);
}

static void set_phdr_entry(ELFOBJ *bin, size_t phdr_entry_index, ut8 *entry) {
	size_t pos = 0;

	bin->phdr[phdr_entry_index].p_type = READ32(entry, pos);
#if RZ_BIN_ELF64
	bin->phdr[phdr_entry_index].p_flags = READ32(entry, pos);
#endif
	bin->phdr[phdr_entry_index].p_offset = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_vaddr = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_paddr = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_filesz = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_memsz = RZ_BIN_ELF_READWORD(entry, pos);
#ifndef RZ_BIN_ELF64
	bin->phdr[phdr_entry_index].p_flags = READ32(entry, pos);
#endif
	bin->phdr[phdr_entry_index].p_align = RZ_BIN_ELF_READWORD(entry, pos);
}

static bool read_phdr_entry(ELFOBJ *bin, size_t phdr_entry_index) {
	const size_t offset = bin->ehdr.e_phoff + phdr_entry_index * sizeof(Elf_(Phdr));
	ut8 phdr[sizeof(Elf_(Phdr))] = { 0 };

	if (rz_buf_read_at(bin->b, offset, phdr, sizeof(Elf_(Phdr))) < 0) {
		bprintf("read (phdr)\n");
		RZ_FREE(bin->phdr);
		return false;
	}

	set_phdr_entry(bin, phdr_entry_index, phdr);

	return true;
}

static bool read_phdr(ELFOBJ *bin, bool need_linux_kernel_hack) {
	bool phdr_found = false;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (!read_phdr_entry(bin, i)) {
			return false;
		}

		if (need_linux_kernel_hack && bin->phdr[i].p_type == PT_PHDR) {
			phdr_found = true;
		}
	}

	if (need_linux_kernel_hack && phdr_found) {
		ut64 load_addr = Elf_(rz_bin_elf_get_baddr)(bin);
		bin->ehdr.e_phoff = Elf_(rz_bin_elf_v2p)(bin, load_addr + bin->ehdr.e_phoff);
		return read_phdr(bin, false);
	}

	return true;
}

/* Here is the where all the fun starts.
 * Linux kernel since 2005 calculates phdr offset wrongly
 * adding it to the load address (va of the LOAD0).
 * See `fs/binfmt_elf.c` file this line:
 *    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
 * So after the first read, we fix the address and read it again
 */
static bool need_linux_kernel_hack(ELFOBJ *bin) {
	return bin->size > 128 * 1024 && (bin->ehdr.e_machine == EM_X86_64 || bin->ehdr.e_machine == EM_386);
}

static bool init_phdr_header(ELFOBJ *bin) {
	bin->phdr = RZ_NEWS0(Elf_(Phdr), bin->ehdr.e_phnum);
	if (!bin->phdr) {
		perror("malloc (phdr)");
		return false;
	}

	if (!read_phdr(bin, need_linux_kernel_hack(bin))) {
		return false;
	}

	return true;
}

static bool check_phdr_size(ELFOBJ *bin) {
	ut32 phdr_size;

	if (!UT32_MUL(&phdr_size, (ut32)bin->ehdr.e_phnum, sizeof(Elf_(Phdr)))) {
		return false;
	}

	if (!phdr_size || bin->ehdr.e_phoff + phdr_size > bin->size) {
		return false;
	}

	return true;
}

RZ_IPI bool Elf_(rz_bin_elf_init_phdr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->ehdr.e_phnum || !check_phdr_size(bin)) {
		return false;
	}

	init_phdr_sdb(bin);
	return init_phdr_header(bin);
}
