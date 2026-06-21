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

Sdb *elf_get_sdb(RzBinFile *bf);
bool elf_load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb);
ut64 elf_baddr(RzBinFile *bf);
ut64 elf_boffset(RzBinFile *bf);
RzBinAddr *elf_binsym(RzBinFile *bf, RzBinSpecialSymbol sym);
RzPVector /*<RzBinAddr *>*/ *elf_entries(RzBinFile *bf);
RzPVector /*<RzBinVirtualFile *>*/ *elf_virtual_files(RzBinFile *bf);
RzPVector /*<RzBinMap *>*/ *elf_maps(RzBinFile *bf);
RzPVector /*<RzBinSection *>*/ *elf_sections(RzBinFile *bf);
RzPVector /*<RzBinSymbol *>*/ *elf_symbols_obj(void *elf_obj);
RzPVector /*<RzBinSymbol *>*/ *elf_symbols(RzBinFile *bf);
RzPVector /*<RzBinImport *>*/ *elf_imports(RzBinFile *bf);
RzBinInfo *elf_info(RzBinFile *bf);
RzStructuredData *elf_structure(ELFOBJ *bin);
RzPVector /*<RzBinField *>*/ *elf_fields(RzBinFile *bf);
ut64 elf_size(RzBinFile *bf);
RzPVector /*<char *>*/ *elf_libs(RzBinFile *bf);
RzPVector /*<RzBinReloc *>*/ *elf_relocs(RzBinFile *bf);
int elf_get_file_type(RzBinFile *bf);
char *elf_regstate(RzBinFile *bf);
void elf_destroy(RzBinFile *bf);
int elf_check_buffer_aux(RzBuffer *buf);
RzBuffer *elf_create_elf(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt);
RzPVector /*<RzBinMap *>*/ *elf_maps_unpatched_obj(void *elf_obj, size_t size);
RzBinAddr *elf_addr_new_from_paddr(ELFOBJ *bin, ut64 paddr);
void elf_patch_relocs_bin_only(ELFOBJ *bin, RzBuffer *buf, ut64 baseaddr);
RzPVector /*<RzBinMap *>*/ *patched_maps_elf_only(ELFOBJ *obj, ut64 psize, RzBuffer *obj_buf, ut64 baseaddr, const char *patches_vfile_name, const char *reloc_vfile_name);
ut64 elf_reloc_targets_vfile_size(ELFOBJ *obj);
void elf_patch_relocs_elfobj_only(ELFOBJ *obj, RzBuffer *bin_buf, ut64 baseaddr);
ut64 elf_get_got_addr(ELFOBJ *bin);
RzBinReloc *elf_reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT);
RzPVector /*<RzBinSection *>*/ *elf_sections_obj(ELFOBJ *obj, size_t psize);
void elf_patch_relocs_obj(ELFOBJ *bin, ut64 baddr, RzBuffer *patch_buf);
RzPVector /*<RzBinReloc *>*/ *elf_relocs_obj(ELFOBJ *obj, ut64 baddr, RzBuffer *patch_buf);
