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
 * The function here only work for 32bit ELF headers.
 * For 64bit headers please refer to elf64_parser.c
 */

#include "elf_parser.h"
#include "bin/p/bin_elf.inc"

ut64 elf_reloc_targets_vfile_size(ELFOBJ *obj) {
	return Elf_(rz_bin_elf_get_relocs_count)(obj) * reloc_target_size(obj);
}

void elf_patch_relocs_elfobj_only(ELFOBJ *obj, RzBuffer *bin_buf, ut64 baseaddr) {
	rz_return_if_fail(bin_buf && obj);
	if (obj->relocs_patched || !Elf_(rz_bin_elf_has_relocs)(obj)) {
		return;
	}
	obj->relocs_patched = true; // run this function just once (lazy relocs patching)
	if ((obj->ehdr.e_type != ET_REL && obj->ehdr.e_type != ET_DYN)) {
		return;
	}
	ut64 cdsz = reloc_target_size(obj);
	ut64 size = elf_reloc_targets_vfile_size(obj);
	if (!size || !Elf_(rz_bin_elf_has_relocs)(obj)) {
		return;
	}
	RzBinRelocTargetBuilder *targets = rz_bin_reloc_target_builder_new(cdsz, obj->reloc_targets_map_base);
	if (!targets) {
		return;
	}
	obj->buf_patched = rz_buf_new_sparse_overlay(bin_buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!obj->buf_patched) {
		rz_bin_reloc_target_builder_free(targets);
		return;
	}
	RzBinElfReloc *reloc;
	ut64 got_addr = get_got_addr(obj);
	ut64 baddr = baseaddr;
	ut64 mips_AHL = 0;

	rz_bin_elf_foreach_relocs(obj, reloc) {
		ut64 sym_addr = 0;
		ut64 sym_size = 0;
		if (!reloc->sym) {
			continue;
		}
		RzBinElfSymbol *import = Elf_(rz_bin_elf_get_import)(obj, reloc->sym);
		if (import) {
			sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
		} else {
			RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbol)(obj, reloc->sym);
			if (symbol) {
				sym_addr = symbol->vaddr;
				if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(obj) && Elf_(rz_bin_elf_is_thumb_addr)(sym_addr)) {
					Elf_(rz_bin_elf_fix_arm_thumb_addr)(&sym_addr);
				}
			} else {
				sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
			}
			sym_size = symbol->size;
		}
		Elf_(rz_bin_elf_patch_relocation)(obj, reloc, sym_addr, sym_size, baddr, sym_addr, got_addr, &mips_AHL);
		reloc->target_vaddr = sym_addr;
	}
	rz_bin_reloc_target_builder_free(targets);
	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(obj->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
}

RzPVector /*<RzBinMap *>*/ *patched_maps_elf_only(ELFOBJ *obj, ut64 psize, RzBuffer *obj_buf, ut64 baseaddr, const char *patches_vfile_name, const char *reloc_vfile_name) {
	if (!obj) {
		return NULL;
	}
	RzPVector *ret = maps_unpatched_obj(obj, psize);
	if (!ret) {
		return NULL;
	}

	elf_patch_relocs_elfobj_only(obj, obj_buf, baseaddr);
	ut64 size = elf_reloc_targets_vfile_size(obj);
	rz_bin_relocs_patch_maps(ret, obj->buf_patched, 0, obj->reloc_targets_map_base,
		size,
		patches_vfile_name,
		reloc_vfile_name);
	return ret;
}

Sdb *elf_get_sdb(RzBinFile *bf) {
	return get_sdb(bf);
}

bool elf_load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb) {
	return load_buffer(bf, obj, buf, sdb);
}

ut64 elf_baddr(RzBinFile *bf) {
	return baddr(bf);
}

ut64 elf_boffset(RzBinFile *bf) {
	return boffset(bf);
}

RzBinAddr *elf_binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	return binsym(bf, sym);
}

RzPVector /*<RzBinAddr *>*/ *elf_entries(RzBinFile *bf) {
	return entries(bf);
}

RzPVector /*<RzBinVirtualFile *>*/ *elf_virtual_files(RzBinFile *bf) {
	return virtual_files(bf);
}

RzPVector /*<RzBinMap *>*/ *elf_maps(RzBinFile *bf) {
	return maps(bf);
}

RzPVector /*<RzBinSection *>*/ *elf_sections(RzBinFile *bf) {
	return sections(bf);
}

RzPVector /*<RzBinSymbol *>*/ *elf_symbols_obj(void *elf_obj) {
	return symbols_obj(elf_obj);
}

RzPVector /*<RzBinSymbol *>*/ *elf_symbols(RzBinFile *bf) {
	return symbols(bf);
}

RzPVector /*<RzBinImport *>*/ *elf_imports(RzBinFile *bf) {
	return imports(bf);
}

RzBinInfo *elf_info(RzBinFile *bf) {
	return info(bf);
}

RzStructuredData *elf_structure(ELFOBJ *bin) {
	return Elf_(rz_bin_elf_ehdr)(bin);
}

RzPVector /*<RzBinField *>*/ *elf_fields(RzBinFile *bf) {
	return fields(bf);
}

ut64 elf_size(RzBinFile *bf) {
	return size(bf);
}

RzPVector /*<char *>*/ *elf_libs(RzBinFile *bf) {
	return libs(bf);
}

RzPVector /*<RzBinReloc *>*/ *elf_relocs(RzBinFile *bf) {
	return relocs(bf);
}

int elf_get_file_type(RzBinFile *bf) {
	return get_file_type(bf);
}

char *elf_regstate(RzBinFile *bf) {
	return regstate(bf);
}

void elf_destroy(RzBinFile *bf) {
	return destroy(bf);
}

int elf_check_buffer_aux(RzBuffer *buf) {
	return check_buffer_aux(buf);
}

RzBuffer *elf_create_elf(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	return create_elf(bin, code, codelen, data, datalen, opt);
}

RzPVector /*<RzBinMap *>*/ *elf_maps_unpatched_obj(void *elf_obj, size_t size) {
	return maps_unpatched_obj(elf_obj, size);
}

RzBinAddr *elf_addr_new_from_paddr(ELFOBJ *bin, ut64 paddr) {
	return rz_bin_addr_new_from_paddr(bin, paddr);
}

RzBinReloc *elf_reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	return Elf_(rz_bin_elf_convert_relocation)(bin, rel, GOT);
}

ut64 elf_get_got_addr(ELFOBJ *bin) {
	return get_got_addr(bin);
}

RzPVector /*<RzBinSection *>*/ *elf_sections_obj(ELFOBJ *obj, size_t psize) {
	return sections_obj(obj, psize);
}

void elf_patch_relocs_obj(ELFOBJ *bin, ut64 baddr, RzBuffer *patch_buf) {
	patch_relocs_obj(bin, baddr, patch_buf);
}

RzPVector /*<RzBinReloc *>*/ *elf_relocs_obj(ELFOBJ *obj, ut64 baddr, RzBuffer *patch_buf) {
	return relocs_obj(obj, baddr, patch_buf);
}
