// SPDX-FileCopyrightText: 2024 Roee Toledano <roeetoledano10@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

bool PE_(bin_pe_has_base_relocs)(RZ_NONNULL RzBinPEObj *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->relocs && (rz_vector_len(bin->relocs) > 0);
}

static bool read_reloc_ent_from_block(RZ_NONNULL RzVector /*<RzBinPeRelocEnt>*/ *relocs,
	RzBuffer *b, RzBinPeRelocBlock *block, ut64 *offset, const int big_endian) {
	// block size includes the size of the next blocks entry, which is 8 bytes long
	const ut32 reloc_block_end = *offset + block->block_size - 8;
	do {
		RzBinPeRelocEnt reloc = { 0 };
		if (!rz_buf_read_ble16_offset(b, offset, &reloc.raw_val, big_endian)) {
			return false;
		}
		reloc.page_rva = block->page_rva;

		rz_vector_push(relocs, &reloc);

	} while (*offset < reloc_block_end);

	return true;
}

static bool get_relocs_from_data_dir(RZ_NONNULL RzBinPEObj *bin, RZ_BORROW RZ_NONNULL RzVector /*<RzBinPeRelocEnt>*/ *relocs) {
	rz_return_val_if_fail(bin->b && bin->nt_headers && bin->optional_header, false);
	RzBuffer *b = bin->b;
	const st64 o_addr = rz_buf_tell(b);

	// get offset in file of first reloc block
	ut64 offset = PE_(bin_pe_rva_to_paddr)(bin, bin->optional_header->DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	const ut64 relocs_end_offset = offset + bin->optional_header->DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	do {
		RzBinPeRelocBlock block = { 0 };
		if (!rz_buf_read_ble32_offset(b, &offset, &block.page_rva, bin->big_endian) ||
			!rz_buf_read_ble32_offset(b, &offset, &block.block_size, bin->big_endian) ||
			!read_reloc_ent_from_block(relocs, b, &block, &offset, bin->big_endian)) {
			return false;
		}

	} while (offset < relocs_end_offset);

	rz_buf_seek(b, o_addr, RZ_BUF_SET);

	return true;
}

int PE_(bin_pe_init_relocs)(RZ_NONNULL RzBinPEObj *bin) {
	rz_return_val_if_fail(bin, false);

	RzVector *ret = rz_vector_new(sizeof(RzBinPeRelocEnt), NULL, NULL);
	if (!ret) {
		bin->relocs = NULL;
		return false;
	}

	if (PE_(rz_bin_pe_is_stripped_relocs)(bin) || !get_relocs_from_data_dir(bin, ret)) {
		rz_vector_free(ret);
		bin->relocs = NULL;
		return false;
	}

	bin->relocs = ret;

	return true;
}
