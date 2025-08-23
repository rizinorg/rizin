// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_assert.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include <rz_cons.h>
#include "elf/elf.h"
#include <rz_util/ht_uu.h>

Sdb *elf64_get_sdb(RzBinFile *bf);
bool elf64_load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb);
ut64 elf64_baddr(RzBinFile *bf);
ut64 elf64_boffset(RzBinFile *bf);
RzBinAddr *elf64_binsym(RzBinFile *bf, RzBinSpecialSymbol sym);
RzPVector /*<RzBinAddr *>*/ *elf64_entries(RzBinFile *bf);
RzPVector /*<RzBinVirtualFile *>*/ *elf64_virtual_files(RzBinFile *bf);
RzPVector /*<RzBinMap *>*/ *elf64_maps(RzBinFile *bf);
RzPVector /*<RzBinSection *>*/ *elf64_sections(RzBinFile *bf);
RzPVector /*<RzBinSymbol *>*/ *elf64_symbols_obj(void *elf_obj);
RzPVector /*<RzBinSymbol *>*/ *elf64_symbols(RzBinFile *bf);
RzPVector /*<RzBinImport *>*/ *elf64_imports(RzBinFile *bf);
RzBinInfo *elf64_info(RzBinFile *bf);
RzStructuredData *elf64_structure(ELFOBJ *bin);
RzPVector /*<RzBinField *>*/ *elf64_fields(RzBinFile *bf);
ut64 elf64_size(RzBinFile *bf);
RzPVector /*<char *>*/ *elf64_libs(RzBinFile *bf);
RzPVector /*<RzBinReloc *>*/ *elf64_relocs(RzBinFile *bf);
int elf64_get_file_type(RzBinFile *bf);
char *elf64_regstate(RzBinFile *bf);
void elf64_destroy(RzBinFile *bf);
int elf64_check_buffer_aux(RzBuffer *buf);
RzBuffer *elf64_create_elf(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt);
RzPVector /*<RzBinMap *>*/ *elf64_maps_unpatched_obj(void *elf_obj, size_t size);
RzBinAddr *elf64_addr_new_from_paddr(ELFOBJ *bin, ut64 paddr);
ut64 elf64_get_got_addr(ELFOBJ *bin);
RzBinReloc *elf64_reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT);
