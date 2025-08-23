// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The functions in this file are an API for binary modules which need
 * ELF parsing capabilities.
 * Most of the ELF plugin was not build as library and can't be used without
 * code duplication.
 *
 * These functions here are a wrapper around Rizin's ELF binary plugin
 * so it can be used by other plugins to parse ELF headers
 * and get the Object representation of it.
 *
 * The function here only work for 64bit ELF headers.
 * For 32bit headers please refer to elf_parser.c
 */

#define RZ_BIN_ELF64 1
#include "bin/p/bin_elf.inc"
#include "elf64_parser.h"

Sdb *elf64_get_sdb(RzBinFile *bf) {
	return get_sdb(bf);
}

bool elf64_load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb) {
	return load_buffer(bf, obj, buf, sdb);
}

ut64 elf64_baddr(RzBinFile *bf) {
	return baddr(bf);
}

ut64 elf64_boffset(RzBinFile *bf) {
	return boffset(bf);
}

RzBinAddr *elf64_binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	return binsym(bf, sym);
}

RzPVector /*<RzBinAddr *>*/ *elf64_entries(RzBinFile *bf) {
	return entries(bf);
}

RzPVector /*<RzBinVirtualFile *>*/ *elf64_virtual_files(RzBinFile *bf) {
	return virtual_files(bf);
}

RzPVector /*<RzBinMap *>*/ *elf64_maps(RzBinFile *bf) {
	return maps(bf);
}

RzPVector /*<RzBinSection *>*/ *elf64_sections(RzBinFile *bf) {
	return sections(bf);
}

RzPVector /*<RzBinSymbol *>*/ *elf64_symbols_obj(void *elf_obj) {
	return symbols_obj(elf_obj);
}

RzPVector /*<RzBinSymbol *>*/ *elf64_symbols(RzBinFile *bf) {
	return symbols(bf);
}

RzPVector /*<RzBinImport *>*/ *elf64_imports(RzBinFile *bf) {
	return imports(bf);
}

RzBinInfo *elf64_info(RzBinFile *bf) {
	return info(bf);
}

RzStructuredData *elf64_structure(ELFOBJ *bin) {
	return Elf_(rz_bin_elf_ehdr)(bin);
}

RzPVector /*<RzBinField *>*/ *elf64_fields(RzBinFile *bf) {
	return fields(bf);
}

ut64 elf64_size(RzBinFile *bf) {
	return size(bf);
}

RzPVector /*<char *>*/ *elf64_libs(RzBinFile *bf) {
	return libs(bf);
}

RzPVector /*<RzBinReloc *>*/ *elf64_relocs(RzBinFile *bf) {
	return relocs(bf);
}

int elf64_get_file_type(RzBinFile *bf) {
	return get_file_type(bf);
}

char *elf64_regstate(RzBinFile *bf) {
	return regstate(bf);
}

void elf64_destroy(RzBinFile *bf) {
	return destroy(bf);
}

int elf64_check_buffer_aux(RzBuffer *buf) {
	return check_buffer_aux(buf);
}

RzBuffer *elf64_create_elf(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	return create_elf(bin, code, codelen, data, datalen, opt);
}

RzPVector /*<RzBinMap *>*/ *elf64_maps_unpatched_obj(void *elf_obj, size_t size) {
	return maps_unpatched_obj(elf_obj, size);
}

RzBinAddr *elf64_addr_new_from_paddr(ELFOBJ *bin, ut64 paddr) {
	return rz_bin_addr_new_from_paddr(bin, paddr);
}

RzBinReloc *elf64_reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	return Elf_(rz_bin_elf_convert_relocation)(bin, rel, GOT);
}

ut64 elf64_get_got_addr(ELFOBJ *bin) {
	return get_got_addr(bin);
}
