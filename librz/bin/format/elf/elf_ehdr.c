// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static Elf_(Half) get_tiny_elf_phnum(ELFOBJ *bin) {
	ut64 offset = 44;

	ut8 tmp;
	if (!Elf_(rz_bin_elf_read_char)(bin, &offset, &tmp)) {
		RZ_LOG_WARN("Failed to read ELF header (e_phnum) in tiny elf mode.\n")
	}

	return tmp;
}

static bool is_tiny_elf(ELFOBJ *bin) {
	return bin->size == RZ_BIN_ELF_TINY_SIZE;
}

static bool read_ehdr_other_aux(ELFOBJ *bin, ut64 *offset) {
	return Elf_(rz_bin_elf_read_half)(bin, offset, &bin->ehdr.e_type) &&
		Elf_(rz_bin_elf_read_half)(bin, offset, &bin->ehdr.e_machine) &&
		Elf_(rz_bin_elf_read_word)(bin, offset, &bin->ehdr.e_version) &&
		Elf_(rz_bin_elf_read_addr)(bin, offset, &bin->ehdr.e_entry) &&
		Elf_(rz_bin_elf_read_off)(bin, offset, &bin->ehdr.e_phoff) &&
		Elf_(rz_bin_elf_read_off)(bin, offset, &bin->ehdr.e_shoff) &&
		Elf_(rz_bin_elf_read_word)(bin, offset, &bin->ehdr.e_flags) &&
		Elf_(rz_bin_elf_read_half)(bin, offset, &bin->ehdr.e_ehsize) &&
		Elf_(rz_bin_elf_read_half)(bin, offset, &bin->ehdr.e_phentsize);
}

static bool read_ehdr_other(ELFOBJ *bin) {
	ut64 offset = EI_NIDENT;

	if (!read_ehdr_other_aux(bin, &offset)) {
		RZ_LOG_WARN("Failed to read beginning of the ELF header (until e_phnum).\n")
		return false;
	}

	if (!Elf_(rz_bin_elf_read_half)(bin, &offset, &bin->ehdr.e_phnum)) {
		RZ_LOG_WARN("Failed to read ELF header (e_phnum).\n")
	}

	if (!Elf_(rz_bin_elf_read_half)(bin, &offset, &bin->ehdr.e_shentsize)) {
		RZ_LOG_WARN("Failed to read ELF header (e_shentsize).\n")
	}

	if (!Elf_(rz_bin_elf_read_half)(bin, &offset, &bin->ehdr.e_shnum)) {
		RZ_LOG_WARN("Failed to read ELF header (e_shnum).\n")
	}

	if (!Elf_(rz_bin_elf_read_half)(bin, &offset, &bin->ehdr.e_shstrndx)) {
		RZ_LOG_WARN("Failed to read ELF header (e_shstrndx).\n")
	}

	if (is_tiny_elf(bin)) {
		RZ_LOG_WARN("The binary seems to be a tiny elf (45 bytes). Reload e_phnum value.\n");
		bin->ehdr.e_phnum = get_tiny_elf_phnum(bin);
	}

	return true;
}

static bool is_valid_elf_ident(ut8 *e_ident) {
	return !memcmp(e_ident, ELFMAG, SELFMAG) || !memcmp(e_ident, CGCMAG, SCGCMAG);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_ehsize_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%d", bin->ehdr.e_ehsize);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_entry_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%08" PFMT64x, (ut64)bin->ehdr.e_entry);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_flags_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%04x", bin->ehdr.e_flags);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_indent_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
		bin->ehdr.e_ident[0],
		bin->ehdr.e_ident[1],
		bin->ehdr.e_ident[2],
		bin->ehdr.e_ident[3],
		bin->ehdr.e_ident[4],
		bin->ehdr.e_ident[5],
		bin->ehdr.e_ident[6],
		bin->ehdr.e_ident[7],
		bin->ehdr.e_ident[8],
		bin->ehdr.e_ident[9],
		bin->ehdr.e_ident[10],
		bin->ehdr.e_ident[11],
		bin->ehdr.e_ident[12],
		bin->ehdr.e_ident[13],
		bin->ehdr.e_ident[14],
		bin->ehdr.e_ident[15]);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_machine_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%04x", bin->ehdr.e_machine);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_phentsize_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%d", bin->ehdr.e_phentsize);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_phnum_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%d", bin->ehdr.e_phnum);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_phoff_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%08" PFMT64x, (ut64)bin->ehdr.e_phoff);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_shentsize_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%d", bin->ehdr.e_shentsize);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_shnum_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%d", bin->ehdr.e_shnum);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_shoff_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%08" PFMT64x, (ut64)bin->ehdr.e_shoff);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_shstrndx_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("%d", bin->ehdr.e_shstrndx);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_type_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%04x", bin->ehdr.e_type);
}

RZ_OWN char *Elf_(rz_bin_elf_get_e_version_as_string)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	return rz_str_newf("0x%08x", bin->ehdr.e_version);
}

bool Elf_(rz_bin_elf_get_ehdr)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	memset(&bin->ehdr, 0, sizeof(Elf_(Ehdr)));

	if (rz_buf_read_at(bin->b, 0, bin->ehdr.e_ident, EI_NIDENT) < EI_NIDENT) {
		RZ_LOG_WARN("Failed to read ELF header e_ident.\n")
		return false;
	}

	if (!is_valid_elf_ident(bin->ehdr.e_ident)) {
		RZ_LOG_WARN("Invalid ELF identification.\n");
		return false;
	}

	bin->big_endian = bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB;

	return read_ehdr_other(bin);
}

RzStructuredData *Elf_(rz_bin_elf_ehdr)(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzStructuredData *header = rz_structured_data_new_map();
	if (!header) {
		return NULL;
	}

	RzStructuredData *elf = rz_structured_data_map_add_map(header, "elf");
	if (!elf) {
		goto fail;
	}

	RzStructuredData *e_ident = rz_structured_data_map_add_map(elf, "e_ident");
	if (!e_ident) {
		goto fail;
	}

	char *e_ident_bytes = Elf_(rz_bin_elf_get_e_indent_as_string)(bin);
	if (!e_ident_bytes) {
		goto fail;
	}

	if (!(rz_structured_data_map_add_string(e_ident, "bytes", e_ident_bytes) &&
		    rz_structured_data_map_add_unsigned(e_ident, "ei_class", bin->ehdr.e_ident[EI_CLASS], false) &&
		    rz_structured_data_map_add_unsigned(e_ident, "ei_data", bin->ehdr.e_ident[EI_DATA], false) &&
		    rz_structured_data_map_add_unsigned(e_ident, "ei_version", bin->ehdr.e_ident[EI_VERSION], false) &&
		    rz_structured_data_map_add_unsigned(e_ident, "ei_osabi", bin->ehdr.e_ident[EI_OSABI], false) &&
		    rz_structured_data_map_add_unsigned(e_ident, "ei_abiversion", bin->ehdr.e_ident[EI_ABIVERSION], false))) {
		goto fail;
	}
	free(e_ident_bytes);

	if (!(rz_structured_data_map_add_unsigned(elf, "e_machine", bin->ehdr.e_machine, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_version", bin->ehdr.e_version, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_entry", bin->ehdr.e_entry, true) &&
		    rz_structured_data_map_add_unsigned(elf, "e_phoff", bin->ehdr.e_phoff, true) &&
		    rz_structured_data_map_add_unsigned(elf, "e_shoff", bin->ehdr.e_shoff, true) &&
		    rz_structured_data_map_add_unsigned(elf, "e_flags", bin->ehdr.e_flags, true) &&
		    rz_structured_data_map_add_unsigned(elf, "e_ehsize", bin->ehdr.e_ehsize, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_phentsize", bin->ehdr.e_phentsize, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_phnum", bin->ehdr.e_phnum, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_shentsize", bin->ehdr.e_shentsize, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_shnum", bin->ehdr.e_shnum, false) &&
		    rz_structured_data_map_add_unsigned(elf, "e_shstrndx", bin->ehdr.e_shstrndx, false))) {
		goto fail;
	}

	return header;

fail:
	rz_structured_data_free(header);
	return NULL;
}
