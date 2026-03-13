// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_assert.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include <rz_cons.h>
#include "../i/private.h"
#include "elf/elf.h"
#include "elf/glibc_elf.h"
#include "rz_vector.h"
#include <rz_analysis.h>
#include <rz_util/ht_uu.h>

#define rz_bin_file_get_elf(bf) ((ELFOBJ *)bf->o->bin_obj)

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

#ifdef RZ_BIN_ELF64
#define rz_buf_append_word rz_buf_append_ut64
#else
#define rz_buf_append_word rz_buf_append_ut32
#endif

static RzBinInfo *info(RzBinFile *bf);
static void patch_relocs(RzBinFile *bf, struct Elf_(rz_bin_elf_obj_t) * bin);
static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf);

struct special_symbol_translation {
	RzBinSpecialSymbol symbol;
	ut64 (*get_addr)(ELFOBJ *bin);
};

static struct special_symbol_translation special_symbol_translation_table[] = {
	{ RZ_BIN_SPECIAL_SYMBOL_ENTRY, Elf_(rz_bin_elf_get_entry_offset) },
	{ RZ_BIN_SPECIAL_SYMBOL_MAIN, Elf_(rz_bin_elf_get_main_offset) },
	{ RZ_BIN_SPECIAL_SYMBOL_INIT, Elf_(rz_bin_elf_get_init_offset) },
	{ RZ_BIN_SPECIAL_SYMBOL_FINI, Elf_(rz_bin_elf_get_fini_offset) },
};

static Sdb *get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);
	return bin->kv;
}

static int check_buffer_aux(RzBuffer *buf) {
	rz_return_val_if_fail(buf, ELFCLASSNONE);

	ut8 tmp[SELFMAG + 1] = { 0 };

	if (rz_buf_read_at(buf, 0, tmp, SELFMAG + 1) < 0) {
		return ELFCLASSNONE;
	}

	if (memcmp(tmp, ELFMAG, SELFMAG)) {
		return ELFCLASSNONE;
	}

	return tmp[SELFMAG];
}

static bool load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb) {
	rz_return_val_if_fail(obj, false);

	ELFOBJ *bin = Elf_(rz_bin_elf_new_buf)(buf, &obj->opts);
	if (!bin) {
		return false;
	}

	obj->bin_obj = bin;
	return true;
}

static ut64 baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, UT64_MAX);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);
	return Elf_(rz_bin_elf_get_baddr)(bin, &bf->o->opts);
}

static ut64 boffset(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, UT64_MAX);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);
	return Elf_(rz_bin_elf_get_boffset)(bin);
}

static ut64 binsym_aux(ELFOBJ *bin, RzBinSpecialSymbol sym) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(special_symbol_translation_table); i++) {
		if (sym == special_symbol_translation_table[i].symbol) {
			return special_symbol_translation_table[i].get_addr(bin);
		}
	}

	return UT64_MAX;
}

static RzBinAddr *rz_bin_addr_new_aux(ELFOBJ *bin, ut64 paddr, ut64 vaddr) {
	RzBinAddr *result = RZ_NEW0(RzBinAddr);
	if (!result) {
		return NULL;
	}

	result->paddr = paddr;
	result->vaddr = vaddr;
	result->bits = bin->bits;

	if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin)) {
		rz_bin_elf_fix_arm_thumb_object_dispatch(result);
	}

	return result;
}

static RzBinAddr *rz_bin_addr_new_from_paddr(ELFOBJ *bin, ut64 paddr) {
	ut64 vaddr = Elf_(rz_bin_elf_p2v)(bin, paddr);
	if (vaddr == UT64_MAX) {
		vaddr = paddr;
	}

	return rz_bin_addr_new_aux(bin, paddr, vaddr);
}

static RzBinAddr *rz_bin_addr_new_from_vaddr(ELFOBJ *bin, ut64 vaddr) {
	ut64 paddr = Elf_(rz_bin_elf_v2p)(bin, vaddr);

	return rz_bin_addr_new_aux(bin, paddr, vaddr);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	rz_return_val_if_fail(bf && bf->o && bf->o, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	ut64 paddr = binsym_aux(bin, sym);
	if (paddr == UT64_MAX) {
		return NULL;
	}

	return rz_bin_addr_new_from_paddr(bin, paddr);
}

static void add_constructor(ELFOBJ *bin, ut64 addr, ut64 size, int type, RzPVector /*<RzBinAddr *>*/ *result) {
	ut64 constructor_offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (constructor_offset == UT64_MAX) {
		return;
	}

	ut64 pos = 0;

	while (pos < size) {
		ut64 offset = constructor_offset + pos;

		Elf_(Addr) vaddr;
		if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &vaddr)) {
			break;
		}

		if (!vaddr) {
			pos += sizeof(Elf_(Addr));
			continue;
		}

		RzBinAddr *tmp = rz_bin_addr_new_from_vaddr(bin, vaddr);
		if (!tmp) {
			break;
		}

		tmp->hpaddr = constructor_offset + pos;
		tmp->hvaddr = addr + pos;
		tmp->type = type;

		rz_pvector_push(result, tmp);

		pos += sizeof(Elf_(Addr));
	}
}

static void add_constructors(ELFOBJ *bin, RzPVector /*<RzBinAddr *>*/ *result) {
	ut64 addr, size;

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PREINIT_ARRAY, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_PREINIT_ARRAYSZ, &size)) {
		add_constructor(bin, addr, size, RZ_BIN_ENTRY_TYPE_PREINIT, result);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_INIT_ARRAY, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_INIT_ARRAYSZ, &size)) {
		add_constructor(bin, addr, size, RZ_BIN_ENTRY_TYPE_INIT, result);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_FINI_ARRAY, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_FINI_ARRAYSZ, &size)) {
		add_constructor(bin, addr, size, RZ_BIN_ENTRY_TYPE_FINI, result);
	}
}

static void add_entry_offset(ELFOBJ *bin, RzPVector /*<RzBinAddr *>*/ *result) {
	ut64 paddr = Elf_(rz_bin_elf_get_entry_offset)(bin);
	if (paddr == UT64_MAX) {
		return;
	}

	RzBinAddr *tmp = rz_bin_addr_new_from_paddr(bin, paddr);
	if (!tmp) {
		return;
	}

	tmp->hpaddr = E_ENTRYPOINT_OFFSET;
	tmp->hvaddr = bin->baddr + tmp->hpaddr;

	ut64 e_entry = (ut64)bin->ehdr.e_entry;
	if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin) && Elf_(rz_bin_elf_is_thumb_addr)(e_entry)) {
		Elf_(rz_bin_elf_fix_arm_thumb_addr)(&e_entry);
	}

	if (tmp->vaddr != e_entry && Elf_(rz_bin_elf_is_executable)(bin)) {
		RZ_LOG_ERROR("Cannot determine entrypoint, using 0x%08" PFMT64x ".\n", tmp->vaddr);
	}

	rz_pvector_push(result, tmp);
}

static void add_java_libraries(ELFOBJ *bin, RzPVector /*<RzBinAddr *>*/ *result) {
	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		if (symbol->name && rz_str_startswith(symbol->name, "Java") && rz_str_endswith(symbol->name, "_init")) {
			RzBinAddr *tmp = rz_bin_addr_new_from_paddr(bin, symbol->paddr);
			tmp->type = RZ_BIN_ENTRY_TYPE_INIT;

			rz_pvector_push(result, tmp);
			break;
		}
	}
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	RzPVector *result = rz_pvector_new((RzPVectorFree)free);
	if (!result) {
		return NULL;
	}

	add_entry_offset(bin, result);
	add_java_libraries(bin, result);
	add_constructors(bin, result);

	return result;
}

static bool create_set_e_ident(RzBuffer *result) {
	return rz_buf_append_bytes(result, (ut8 *)ELFMAG, SELFMAG) &&
#ifdef RZ_BIN_ELF64
		rz_buf_append_bytes(result, (ut8 *)"\x2\x1\x1\x0", 4) &&
#else
		rz_buf_append_bytes(result, (ut8 *)"\x1\x1\x1\x0", 4) &&
#endif
		rz_buf_append_nbytes(result, 8);
}

static bool create_set_e_machine(RzBuffer *result, bool is_arm) {
#ifdef RZ_BIN_ELF64
	return rz_buf_append_ut16(result, EM_X86_64);
#else
	if (is_arm) {
		return rz_buf_append_ut16(result, EM_ARM);
	}

	return rz_buf_append_ut16(result, EM_386);
#endif
}

static bool create_set_ehdr(RzBuffer *result, Elf_(Word) baddr, bool is_arm) {
	return create_set_e_ident(result) &&
		rz_buf_append_ut16(result, ET_EXEC) &&
		create_set_e_machine(result, is_arm) &&
		rz_buf_append_ut32(result, EV_CURRENT) &&
		rz_buf_append_word(result, baddr + sizeof(Elf_(Ehdr)) + sizeof(Elf_(Phdr))) && // e_entry
		rz_buf_append_word(result, sizeof(Elf_(Ehdr))) && // e_phoff
		rz_buf_append_word(result, 0) && // e_shoff
		rz_buf_append_ut32(result, 0) && // e_flags
		rz_buf_append_ut16(result, sizeof(Elf_(Ehdr))) && // e_ehsize
		rz_buf_append_ut16(result, sizeof(Elf_(Phdr))) && // e_phentsize
		rz_buf_append_ut16(result, 1) && // e_phnum
		rz_buf_append_ut16(result, 0) && // e_shentsize
		rz_buf_append_ut16(result, 0) && // e_shnum
		rz_buf_append_ut16(result, 0); // e_shstrndx
}

static bool create_set_phdr(RzBuffer *result, Elf_(Word) baddr, int codelen) {
	ut64 length = sizeof(Elf_(Ehdr)) + sizeof(Elf_(Phdr)) + codelen;

	return rz_buf_append_ut32(result, PT_LOAD) &&
#ifdef RZ_BIN_ELF64
		rz_buf_append_ut32(result, PF_X | PF_R) &&
		rz_buf_append_ut64(result, 0) && // p_offset
		rz_buf_append_ut64(result, baddr) && // p_vaddr
		rz_buf_append_ut64(result, baddr) && // p_paddr
		rz_buf_append_ut64(result, length) && // p_filesz
		rz_buf_append_ut64(result, length) && // p_memsz
		rz_buf_append_ut64(result, 0x200000); // p_align
#else
		rz_buf_append_ut32(result, 0) && // p_offset
		rz_buf_append_ut32(result, baddr) && // p_vaddr
		rz_buf_append_ut32(result, baddr) && // p_paddr
		rz_buf_append_ut32(result, length) && // p_filesz
		rz_buf_append_ut32(result, length) && // p_memsz
		rz_buf_append_ut32(result, PF_X | PF_R) && // p_flags
		rz_buf_append_ut32(result, 0x1000); // p_align
#endif
}

static Elf_(Word) create_get_baddr(bool is_arm) {
#ifdef RZ_BIN_ELF64
	return 0x400000LL;
#else
	if (is_arm) {
		return 0x40000;
	}

	return 0x8048000;
#endif
}

static RzBuffer *create_elf(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	rz_return_val_if_fail(bin && opt && opt->arch, NULL);

	RzBuffer *result = rz_buf_new_with_bytes(NULL, 0);

	bool is_arm = !strcmp(opt->arch, "arm");
	Elf_(Word) baddr = create_get_baddr(is_arm);

	if (!create_set_ehdr(result, baddr, is_arm) ||
		!create_set_phdr(result, baddr, codelen) ||
		!rz_buf_append_bytes(result, code, codelen)) {
		rz_buf_free(result);
		return NULL;
	}

	if (data && datalen > 0) {
		// ut32 data_section = buf->length;
		RZ_LOG_WARN("DATA section not support for ELF yet\n");
		rz_buf_append_bytes(result, data, datalen);
	}

	return result;
}

static void destroy(RzBinFile *bf) {
	Elf_(rz_bin_elf_free)(bf->o->bin_obj);
}

static int get_file_type(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = bf->o->bin_obj;
	char *type = Elf_(rz_bin_elf_get_file_type(obj));
	int res = type ? ((!strncmp(type, "CORE", 4)) ? RZ_BIN_TYPE_CORE : RZ_BIN_TYPE_DEFAULT) : -1;
	free(type);
	return res;
}

static char *regstate(RzBinFile *bf) {
	ELFOBJ *obj = bf->o->bin_obj;

	RzVector *notes;
	rz_bin_elf_foreach_notes_segment(obj, notes) {
		RzBinElfNote *tmp;
		rz_vector_foreach (notes, tmp) {
			switch (tmp->type) {
			default:
				continue;
			case NT_PRSTATUS:
			case NT_FPREGSET:
			case NT_OPENBSD_REGS:
			case NT_OPENBSD_FPREGS:
			case NT_OPENBSD_XFPREGS: {
				RzBinElfNotePrStatus *note = &tmp->prstatus;
				return rz_hex_bin2strdup(note->regstate, note->regstate_size);
			}
			}
		}
	}

	char *machine_name = Elf_(rz_bin_elf_get_machine_name)(obj);
	RZ_LOG_ERROR("Cannot retrieve regstate on: %s (not yet supported)\n", machine_name);
	free(machine_name);
	return NULL;
}

static char *setphname(ut16 mach, Elf_(Word) ptyp) {
	// TODO to complete over time
	if (mach == EM_ARM) {
		if (ptyp == SHT_ARM_EXIDX) {
			return rz_str_dup("EXIDX");
		}
	} else if (mach == EM_MIPS) {
		if (ptyp == PT_MIPS_ABIFLAGS) {
			return rz_str_dup("ABIFLAGS");
		} else if (ptyp == PT_MIPS_REGINFO) {
			return rz_str_dup("REGINFO");
		}
	}

	return rz_str_dup("UNKNOWN");
}

static bool is_wordable_section(const char *name) {
	if (!strcmp(name, ".init_array")) {
		return true;
	}
	if (!strcmp(name, ".fini_array")) {
		return true;
	}
	if (!strcmp(name, ".data.rel.ro")) {
		return true;
	}
	if (!strcmp(name, ".dynamic")) {
		return true;
	}
	if (!strcmp(name, ".got")) {
		return true;
	}
	if (strstr(name, ".rela.")) {
		return true;
	}
	return false;
}

static RzBinElfNoteFile *note_file_for_load_segment(ELFOBJ *obj, Elf_(Phdr) * phdr) {
	if (!Elf_(rz_bin_elf_has_notes)(obj)) {
		return false;
	}

	RzVector *notes;
	rz_bin_elf_foreach_notes_segment(obj, notes) {
		RzBinElfNote *tmp;
		rz_vector_foreach (notes, tmp) {
			if (tmp->type != NT_FILE) {
				continue;
			}

			RzBinElfNoteFile *note = &tmp->file;

			if (note->start_vaddr == phdr->p_vaddr) {
				return note;
			}
		}
	}

	return NULL;
}

static ut32 section_perms_from_flags(ut32 flags) {
	ut32 r = 0;
	if (RZ_BIN_ELF_SCN_IS_EXECUTABLE(flags)) {
		r |= RZ_PERM_X;
	}
	if (RZ_BIN_ELF_SCN_IS_WRITABLE(flags)) {
		r |= RZ_PERM_W;
	}
	if (RZ_BIN_ELF_SCN_IS_READABLE(flags)) {
		r |= RZ_PERM_R;
	}
	return r;
}

static RzPVector /*<RzBinMap *>*/ *maps_unpatched_obj(void *elf_obj, size_t size) {
	struct Elf_(rz_bin_elf_obj_t) *obj = elf_obj;
	if (!obj) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	if (Elf_(rz_bin_elf_has_segments)(obj)) {
		ut64 core_sp = Elf_(rz_bin_elf_get_sp_val)(obj);
		int n = 0;

		RzBinElfSegment *iter;
		rz_bin_elf_foreach_segments(obj, iter) {
			if (iter->data.p_type != PT_LOAD) {
				continue;
			}

			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				break;
			}

			map->paddr = iter->data.p_offset;
			map->psize = iter->data.p_filesz;
			map->vsize = iter->data.p_memsz;
			map->vaddr = iter->data.p_vaddr;
			map->perm = iter->data.p_flags | RZ_PERM_R;

			// map names specific to core files...
			if (core_sp && core_sp != UT64_MAX && core_sp >= iter->data.p_vaddr && core_sp < iter->data.p_vaddr + iter->data.p_memsz) {
				map->name = rz_str_dup("[stack]");
			} else {
				RzBinElfNoteFile *nf = note_file_for_load_segment(obj, &iter->data);
				if (nf && nf->file) {
					map->name = rz_str_dup(nf->file);
				}
			}
			// generic names
			if (!map->name) {
				map->name = rz_str_newf("LOAD%d", n);
			}
			n++;
			rz_pvector_push(ret, map);
		}
	} else {
		// Load sections if there is no PHDR

		RzBinElfSection *section;
		rz_bin_elf_foreach_sections(obj, section) {
			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				break;
			}

			map->name = rz_str_dup(section->name);
			map->paddr = section->offset;
			map->psize = section->type != SHT_NOBITS ? section->size : 0;
			map->vsize = section->size;
			map->vaddr = section->rva;
			map->perm = section_perms_from_flags(section->flags);
			rz_pvector_push(ret, map);
		}
	}

	if (rz_pvector_empty(ret)) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->name = rz_str_dup("uphdr");
		map->paddr = 0;
		map->psize = size;
		map->vaddr = 0x10000;
		map->vsize = size;
		map->perm = RZ_PERM_RWX;
		rz_pvector_push(ret, map);
	}

	if (obj->ehdr.e_type == ET_REL) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		ut64 ehdr_size = sizeof(obj->ehdr);
		if (size < ehdr_size) {
			ehdr_size = size;
		}
		map->name = rz_str_dup("ehdr");
		map->paddr = 0;
		map->psize = ehdr_size;
		map->vaddr = obj->baddr;
		map->vsize = ehdr_size;
		map->perm = RZ_PERM_RW;
		rz_pvector_push(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps_unpatched(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	return maps_unpatched_obj(obj, bf->size);
}

static ut64 reloc_target_size(ELFOBJ *obj) {
	if (!obj->bits) {
		return 8;
	}
	return obj->bits / 8;
}

/// size of the artificial reloc target vfile
static ut64 reloc_targets_vfile_size(RzBinFile *bf, ELFOBJ *obj) {
	if (!bf->o || !bf->o->opts.patch_relocs || !Elf_(rz_bin_elf_has_relocs)(obj)) {
		return 0;
	}

	return Elf_(rz_bin_elf_get_relocs_count)(obj) * reloc_target_size(obj);
}

static ut64 get_got_addr(ELFOBJ *bin) {
	if (!Elf_(rz_bin_elf_has_sections)(bin)) {
		return 0;
	}

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".got");
	if (section) {
		return section->offset;
	}

	section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".got.plt");
	if (section) {
		return section->offset;
	}

	return 0;
}

/**
 * \brief Returns the offset into the GOT where the symbol with \p sym_id
 * has it's relocation address.
 *
 * \param bin The Elf object.
 * \param sym_id The symbol id retrieved via ELF_R_SYM().
 *
 * \return The offset into the GOT in bytes. Or UT64_MAX if no GOT exists or
 * the symbol has no indirection in the GOT.
 */
RZ_IPI ut64 Elf_(rz_bin_get_reloc_sym_offset_in_got)(RZ_NONNULL ELFOBJ *bin, ut64 sym_id) {
	RzBinElfSection *got = Elf_(rz_bin_elf_get_section_with_name)(bin, ".got");
	if (!got) {
		got = Elf_(rz_bin_elf_get_section_with_name)(bin, ".got.plt");
		if (!got) {
			return UT64_MAX;
		}
	}
	// Search all entries of the GOT for the matching symbol id.
	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (!RZ_BETWEEN(got->rva, reloc->vaddr, got->rva + got->size)) {
			// Not a GOT entry.
			continue;
		}
		if (sym_id == reloc->sym) {
			return reloc->offset;
		}
	}
	return UT64_MAX;
}

static void patch_relocs_obj(ELFOBJ *bin, ut64 baddr, RzBuffer *patch_buf) {
	rz_return_if_fail(bin && patch_buf);
	if (bin->relocs_patched || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return;
	}
	bin->relocs_patched = true; // run this function just once (lazy relocs patching)
	if ((bin->ehdr.e_type != ET_REL && bin->ehdr.e_type != ET_DYN)) {
		return;
	}
	ut64 cdsz = reloc_target_size(bin);
	ut64 size = Elf_(rz_bin_elf_get_relocs_count)(bin) * reloc_target_size(bin);
	if (!size) {
		return;
	}
	RzBinRelocTargetBuilder *targets = rz_bin_reloc_target_builder_new(cdsz, bin->reloc_targets_map_base);
	if (!targets) {
		return;
	}
	bin->buf_patched = rz_buf_new_sparse_overlay(patch_buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!bin->buf_patched) {
		rz_bin_reloc_target_builder_free(targets);
		return;
	}
	RzBinElfReloc *reloc;
	ut64 got_addr = get_got_addr(bin);
	ut64 mips_AHL = 0;

	rz_bin_elf_foreach_relocs(bin, reloc) {
		ut64 sym_addr = 0;
		ut64 sym_size = 0;
		if (reloc->sym) {
			RzBinElfSymbol *import = Elf_(rz_bin_elf_get_import)(bin, reloc->sym);
			if (import) {
				sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
			} else {
				RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbol)(bin, reloc->sym);
				if (symbol) {
					sym_addr = symbol->vaddr;
					if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin) && Elf_(rz_bin_elf_is_thumb_addr)(sym_addr)) {
						Elf_(rz_bin_elf_fix_arm_thumb_addr)(&sym_addr);
					}
					sym_size = symbol->size;
				} else {
					sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
				}
			}
		}
		Elf_(rz_bin_elf_patch_relocation)(bin, reloc, sym_addr, sym_size, baddr, sym_addr, got_addr, &mips_AHL);
		reloc->target_vaddr = sym_addr;
	}
	rz_bin_reloc_target_builder_free(targets);
	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(bin->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
}

static void patch_relocs(RzBinFile *bf, ELFOBJ *bin) {
	rz_return_if_fail(bf && bin);
	RzBinObject *obj = bf->o;
	if (!obj || !obj->opts.patch_relocs || (bin->ehdr.e_type != ET_REL && bin->ehdr.e_type != ET_DYN)) {
		return;
	}
	patch_relocs_obj(bin, bf->o->opts.baseaddr, bf->buf);
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzPVector *r = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!r) {
		return NULL;
	}
	RzBinObject *o = bf->o;
	struct Elf_(rz_bin_elf_obj_t) *obj = o ? o->bin_obj : NULL;
	if (!obj) {
		return r;
	}
	patch_relocs(bf, obj);
	// virtual file for reloc targets (where the relocs will point into)
	ut64 rtmsz = reloc_targets_vfile_size(bf, obj);
	if (rtmsz) {
		RzBuffer *buf = rz_buf_new_empty(rtmsz);
		if (!buf) {
			return r;
		}
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			rz_buf_free(buf);
			return r;
		}
		vf->buf = buf;
		vf->buf_owned = true;
		vf->name = rz_str_dup(VFILE_NAME_RELOC_TARGETS);
		rz_pvector_push(r, vf);
	}
	// virtual file mirroring the raw file, but with relocs patched
	if (obj->buf_patched) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return r;
		}
		vf->buf = obj->buf_patched;
		vf->name = rz_str_dup(VFILE_NAME_PATCHED);
		rz_pvector_push(r, vf);
	}
	return r;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	RzPVector *ret = maps_unpatched(bf);
	if (!ret) {
		return NULL;
	}

	// if relocs should be patched, use the patched vfile for everything from the file
	patch_relocs(bf, obj);
	rz_bin_relocs_patch_maps(ret, obj->buf_patched, 0, obj->reloc_targets_map_base,
		reloc_targets_vfile_size(bf, obj),
		VFILE_NAME_PATCHED,
		VFILE_NAME_RELOC_TARGETS);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections_obj(ELFOBJ *obj, size_t psize) {
	RzBinSection *ptr = NULL;
	RzPVector *ret = NULL;

	if (!obj || !(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}

	// there is not leak in section since they are cached by elf.c
	// and freed within Elf_(rz_bin_elf_free)
	size_t i;
	RzBinElfSection *section;
	rz_bin_elf_enumerate_sections(obj, section, i) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		ptr->name = rz_str_dup(section->name);
		if (!ptr->name) {
			ptr->name = rz_str_dup("");
		}
		if (strstr(ptr->name, "data") && !strstr(ptr->name, "rel") && !strstr(ptr->name, "pydata")) {
			ptr->is_data = true;
		} else if (!strcmp(ptr->name, "C")) {
			ptr->is_data = true;
		}
		if (is_wordable_section(ptr->name)) {
			ptr->layout.type = RZ_META_TYPE_DATA;
			ptr->layout.element_size = sizeof(Elf_(Addr));
			ptr->layout.count = section->size / sizeof(Elf_(Addr));
		}
		ptr->size = section->type != SHT_NOBITS ? section->size : 0;
		ptr->vsize = section->size;
		ptr->paddr = section->offset;
		ptr->vaddr = section->rva;
		ptr->type = section->type;
		ptr->flags = section->flags;
		ptr->perm = section_perms_from_flags(section->flags);
		rz_pvector_push(ret, ptr);
	}

	// program headers is another section
	ut16 mach = obj->ehdr.e_machine;

	size_t n = 0;
	RzBinElfSegment *iter;
	rz_bin_elf_foreach_segments(obj, iter) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}

		ptr->size = iter->data.p_filesz;
		ptr->vsize = iter->data.p_memsz;
		ptr->paddr = iter->data.p_offset;
		ptr->vaddr = iter->data.p_vaddr;
		ptr->perm = iter->data.p_flags;
		ptr->align = iter->data.p_align;
		ptr->is_segment = true;

		switch (iter->data.p_type) {
		case PT_DYNAMIC:
			ptr->name = rz_str_dup("DYNAMIC");
			break;
		case PT_LOAD: {
			ptr->name = rz_str_newf("LOAD%zu", n++);
			ptr->perm |= RZ_PERM_R;
			break;
		}
		case PT_INTERP:
			ptr->name = rz_str_dup("INTERP");
			break;
		case PT_GNU_STACK:
			ptr->name = rz_str_dup("GNU_STACK");
			break;
		case PT_GNU_RELRO:
			ptr->name = rz_str_dup("GNU_RELRO");
			break;
		case PT_GNU_EH_FRAME:
			ptr->name = rz_str_dup("GNU_EH_FRAME");
			break;
		case PT_PHDR:
			ptr->name = rz_str_dup("PHDR");
			break;
		case PT_TLS:
			ptr->name = rz_str_dup("TLS");
			break;
		case PT_NOTE:
			ptr->name = rz_str_dup("NOTE");
			break;
		case PT_OPENBSD_RANDOMIZE:
			ptr->name = rz_str_dup("OPENBSD_RANDOMIZE");
			break;
		case PT_OPENBSD_WXNEEDED:
			ptr->name = rz_str_dup("OPENBSD_WXNEEDED");
			break;
		case PT_OPENBSD_BOOTDATA:
			ptr->name = rz_str_dup("OPENBSD_BOOTDATA");
			break;
		case PT_OPENBSD_NOBTCFI:
			ptr->name = rz_str_dup("OPENBSD_NOBTCFI");
			break;
		default:
			if (ptr->size == 0 && ptr->vsize == 0) {
				ptr->name = rz_str_dup("NONE");
			} else {
				ptr->name = setphname(mach, iter->data.p_type);
			}
			break;
		}
		rz_pvector_push(ret, ptr);
	}

	// add entry for ehdr
	ptr = RZ_NEW0(RzBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof(obj->ehdr);
		if (psize < ehdr_size) {
			ehdr_size = psize;
		}
		ptr->name = rz_str_dup("ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->perm = RZ_PERM_RW;
		ptr->is_segment = true;
		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	ELFOBJ *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	return sections_obj(obj, bf->size);
}

static RzPVector /*<RzBinSymbol *>*/ *symbols_obj(void *elf_obj) {
	ELFOBJ *bin = elf_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		RzBinSymbol *tmp = Elf_(rz_bin_elf_convert_symbol)(bin, symbol);
		if (!tmp) {
			rz_pvector_free(ret);
			return NULL;
		}

		rz_pvector_push(ret, tmp);
	}

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		RzBinSymbol *tmp = Elf_(rz_bin_elf_convert_symbol)(bin, import);
		if (!tmp) {
			rz_pvector_free(ret);
			return NULL;
		}

		tmp->is_imported = true;

		rz_pvector_push(ret, tmp);
	}

	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = bf->o->bin_obj;
	return symbols_obj(bin);
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	ELFOBJ *bin = bf->o->bin_obj;

	if (!Elf_(rz_bin_elf_has_imports)(bin)) {
		return NULL;
	}

	RzPVector *result = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	if (!result) {
		return NULL;
	}

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		RzBinImport *tmp = Elf_(rz_bin_elf_convert_import)(import);
		if (!tmp) {
			rz_pvector_free(result);
			return NULL;
		}

		rz_pvector_push(result, tmp);
	}

	return result;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	return Elf_(rz_bin_elf_get_libs)(bf->o->bin_obj);
}

static RzPVector /*<RzBinReloc *>*/ *relocs_obj(ELFOBJ *obj, ut64 baddr, RzBuffer *patch_buf) {
	rz_return_val_if_fail(obj, NULL);
	RzPVector *ret = NULL;
	RzBinReloc *ptr = NULL;
	patch_relocs_obj(obj, baddr, patch_buf);

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free))) {
		return NULL;
	}

	ut64 got_addr = get_got_addr(obj);

	if (!got_addr) {
		got_addr = obj->reloc_targets_map_base;
	}

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(obj, reloc) {
		if (!(ptr = Elf_(rz_bin_elf_convert_relocation)(obj, reloc, got_addr))) {
			continue;
		}

		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static RzPVector /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	if (!bf->o) {
		return NULL;
	}

	ELFOBJ *bin = bf->o->bin_obj;
	if (!bin || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return NULL;
	}

	return relocs_obj(bin, bf->o->opts.baseaddr, bf->buf);
}

static void lookup_symbols(RzBinFile *bf, RzBinInfo *ret) {
	RzPVector *symbols_vec = symbols(bf);
	void **iter;
	RzBinSymbol *symbol;
	bool is_rust = false;
	if (symbols_vec) {
		rz_pvector_foreach (symbols_vec, iter) {
			symbol = *iter;
			if (ret->has_canary && is_rust) {
				break;
			}
			if (!strcmp(symbol->name, "_NSConcreteGlobalBlock")) {
				ret->lang = (ret->lang && !strcmp(ret->lang, "c++")) ? "c++ blocks ext." : "c blocks ext.";
			}
			if (!ret->has_canary) {
				if (strstr(symbol->name, "__stack_chk_fail") || strstr(symbol->name, "__stack_smash_handler")) {
					ret->has_canary = true;
				}
			}
			if (!is_rust && !strcmp(symbol->name, "__rust_oom")) {
				is_rust = true;
				ret->lang = "rust";
			}
		}
		rz_pvector_free(symbols_vec);
	}
}

static void lookup_sections(RzBinFile *bf, RzBinInfo *ret) {
	RzPVector *sections_vec = sections(bf);
	void **iter;
	RzBinSection *section;
	ret->has_retguard = -1;
	rz_pvector_foreach (sections_vec, iter) {
		section = *iter;
		if (ret->has_retguard != -1) {
			break;
		}
#define RZ_BIN_RANDOMDATA_RETGUARD_SZ 48
		if (!strcmp(section->name, ".openbsd.randomdata")) {
			// The retguard cookie adds 8 per return function inst.
			ret->has_retguard = (section->size >= RZ_BIN_RANDOMDATA_RETGUARD_SZ);
			break;
		}
	}
	rz_pvector_free(sections_vec);
}

static bool has_sanitizers(RzBinFile *bf) {
	bool ret = false;
	RzPVector *imports_vec = imports(bf);
	if (!imports_vec) {
		return ret;
	}
	void **iter;
	RzBinImport *import;
	rz_pvector_foreach (imports_vec, iter) {
		import = *iter;
		if (strstr(import->name, "__sanitizer") ||
			strstr(import->name, "__ubsan")) {
			ret = true;
			break;
		}
	}
	rz_pvector_free(imports_vec);
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	char *str;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ELFOBJ *obj = bf->o->bin_obj;
	if ((str = Elf_(rz_bin_elf_get_rpath)(obj))) {
		ret->rpath = rz_str_dup(str);
		free(str);
	} else {
		ret->rpath = rz_str_dup("NONE");
	}
	if (!(str = Elf_(rz_bin_elf_get_file_type)(obj))) {
		free(ret);
		return NULL;
	}
	ret->type = str;
	ret->has_pi = (strstr(str, "DYN")) ? 1 : 0;
	ret->has_sanitizers = has_sanitizers(bf);
	if (!(str = Elf_(rz_bin_elf_get_elf_class)(obj))) {
		free(ret);
		return NULL;
	}
	ret->bclass = str;
	if (!(str = Elf_(rz_bin_elf_get_osabi_name)(obj))) {
		free(ret);
		return NULL;
	}
	ret->os = str;
	if (!(str = Elf_(rz_bin_elf_get_osabi_name)(obj))) {
		free(ret);
		return NULL;
	}
	ret->subsystem = str;
	if (!(str = Elf_(rz_bin_elf_get_machine_name)(obj))) {
		free(ret);
		return NULL;
	}
	ret->machine = str;
	if (!(str = Elf_(rz_bin_elf_get_head_flag)(obj))) {
		free(ret);
		return NULL;
	}
	ret->head_flag = str;
	if (!(str = Elf_(rz_bin_elf_get_arch)(obj))) {
		free(ret);
		return NULL;
	}
	ret->arch = str;

	if ((str = Elf_(rz_bin_elf_get_cpu)(obj))) {
		ret->cpu = str;
	}
	if ((str = Elf_(rz_bin_elf_get_abi)(obj))) {
		ret->features = str;
		if (!ret->has_pi) {
			// Elf MIPS PIE flag is in features.
			ret->has_pi = (strstr(str, "pic ")) ? 1 : 0;
		}
	}

	ret->rclass = rz_str_dup("elf");
	ret->bits = obj->bits;
	if (!strcmp(ret->arch, "avr")) {
		ret->bits = 16;
	}
	ret->big_endian = Elf_(rz_bin_elf_is_big_endian)(obj);
	ret->has_va = Elf_(rz_bin_elf_has_va)(obj);
	ret->has_nx = Elf_(rz_bin_elf_has_nx)(obj);
	ret->has_nobtcfi = Elf_(rz_bin_elf_has_nobtcfi)(obj);
	ret->intrp = Elf_(rz_bin_elf_get_intrp)(obj);
	ret->compiler = Elf_(rz_bin_elf_get_compiler)(obj);
	ret->dbg_info = 0;
	if (!Elf_(rz_bin_elf_is_stripped)(obj)) {
		ret->dbg_info |= RZ_BIN_DBG_LINENUMS | RZ_BIN_DBG_SYMS | RZ_BIN_DBG_RELOCS;
	} else {
		ret->dbg_info |= RZ_BIN_DBG_STRIPPED;
	}
	if (Elf_(rz_bin_elf_is_static)(obj)) {
		ret->dbg_info |= RZ_BIN_DBG_STATIC;
	}
	lookup_sections(bf, ret);
	lookup_symbols(bf, ret);

	return ret;
}

static bool add_fields_aux(ELFOBJ *bin, RzPVector /*<RzBinField *>*/ *result, ut64 offset, size_t size, const char *name, char *(get_value)(ELFOBJ * bin), const char *fmt) {
	char *value = get_value(bin);
	if (!value) {
		return false;
	}

	RzBinField *field = rz_bin_field_new(offset, offset, size, name, value, fmt, false);
	if (!field) {
		free(value);
		return false;
	}

	if (!rz_pvector_push(result, field)) {
		rz_bin_field_free(field);
		free(value);
		return false;
	}

	free(value);
	return true;
}

static bool add_fields(ELFOBJ *bin, RzPVector /*<RzBinField *>*/ *result) {
	size_t size = bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? 8 : 4;

	return add_fields_aux(bin, result, E_IDENT_OFFSET, 16, "MAGIC", Elf_(rz_bin_elf_get_e_indent_as_string), "x") &&
		add_fields_aux(bin, result, E_TYPE_OFFSET, 2, "Type", Elf_(rz_bin_elf_get_e_type_as_string), "x") &&
		add_fields_aux(bin, result, E_MACHINE_OFFSET, 2, "Machine", Elf_(rz_bin_elf_get_e_machine_as_string), "x") &&
		add_fields_aux(bin, result, E_VERSION_OFFSET, 4, "Version", Elf_(rz_bin_elf_get_e_version_as_string), "x") &&
		add_fields_aux(bin, result, E_ENTRYPOINT_OFFSET, size, "Entrypoint", Elf_(rz_bin_elf_get_e_entry_as_string), "x") &&
		add_fields_aux(bin, result, E_PHOFF_OFFSET, size, "PhOff", Elf_(rz_bin_elf_get_e_phoff_as_string), "x") &&
		add_fields_aux(bin, result, E_SHOFF_OFFSET, size, "ShOff", Elf_(rz_bin_elf_get_e_shoff_as_string), "x") &&
		add_fields_aux(bin, result, E_FLAGS_OFFSET, 4, "Flags", Elf_(rz_bin_elf_get_e_flags_as_string), "x") &&
		add_fields_aux(bin, result, E_EHSIZE_OFFSET, 2, "EhSize", Elf_(rz_bin_elf_get_e_ehsize_as_string), "x") &&
		add_fields_aux(bin, result, E_PHENTSIZE_OFFSET, 2, "PhentSize", Elf_(rz_bin_elf_get_e_phentsize_as_string), "d") &&
		add_fields_aux(bin, result, E_PHNUM_OFFSET, 2, "PhNum", Elf_(rz_bin_elf_get_e_phnum_as_string), "d") &&
		add_fields_aux(bin, result, E_SHENTSIZE_OFFSET, 2, "ShentSize", Elf_(rz_bin_elf_get_e_shentsize_as_string), "d") &&
		add_fields_aux(bin, result, E_SHNUM_OFFSET, 2, "ShNum", Elf_(rz_bin_elf_get_e_shnum_as_string), "d") &&
		add_fields_aux(bin, result, E_SHSTRNDX_OFFSET, 2, "ShStrndx", Elf_(rz_bin_elf_get_e_shstrndx_as_string), "d");
}

static RzPVector /*<RzBinField *>*/ *fields(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	RzPVector *result = rz_pvector_new((RzPVectorFree)rz_bin_field_free);
	if (!result) {
		return NULL;
	}

	if (!add_fields(bin, result)) {
		rz_pvector_free(result);
		return NULL;
	}

	return result;
}

static ut64 size(RzBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (!bf->o->sections) {
		void **iter;
		RzBinSection *section;
		bf->o->sections = sections(bf);
		rz_pvector_foreach (bf->o->sections, iter) {
			section = *iter;
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}
