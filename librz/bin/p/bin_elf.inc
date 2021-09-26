// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include <rz_cons.h>
#include "../i/private.h"
#include "elf/elf.h"
#include <ht_uu.h>

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

static RzBinInfo *info(RzBinFile *bf);
static void patch_relocs(RzBinFile *bf, struct Elf_(rz_bin_elf_obj_t) * bin);
static RzList *imports(RzBinFile *bf);

static RzBinSymbol *convert_symbol(ELFOBJ *bin, RzBinElfSymbol *elf_symbol) {
	RzBinSymbol *result = RZ_NEW0(RzBinSymbol);
	if (!result) {
		return NULL;
	}

	result->paddr = elf_symbol->paddr;
	result->vaddr = elf_symbol->vaddr;
	result->name = rz_str_new(elf_symbol->name);
	result->forwarder = "NONE";
	result->bind = elf_symbol->bind;
	result->type = elf_symbol->type;
	result->size = elf_symbol->size;
	result->ordinal = elf_symbol->ordinal;
	result->bits = bin->bits;

	if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin)) {
		Elf_(rz_bin_elf_fix_arm_thumb_symbol)(result);
	}

	return result;
}

static RzBinSymbol *get_symbol(ELFOBJ *bin, ut32 ordinal) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbol)(bin, ordinal);
	if (!symbol) {
		return NULL;
	}

	return convert_symbol(bin, symbol);
}

static RzBinImport *convert_import(RzBinElfSymbol *symbol) {
	RzBinImport *result = RZ_NEW0(RzBinImport);
	if (!result) {
		return NULL;
	}

	result->name = rz_str_new(symbol->name);
	result->bind = symbol->bind;
	result->type = symbol->type;
	result->ordinal = symbol->ordinal;

	return result;
}

static RzBinImport *get_import(ELFOBJ *bin, ut32 ordinal) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_import)(bin, ordinal);
	if (!symbol) {
		return NULL;
	}

	return convert_import(symbol);
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
		rz_vector_foreach(notes, tmp) {
			if (tmp->type != NT_PRSTATUS) {
				continue;
			}

			RzBinElfNotePrStatus *note = &tmp->prstatus;
			return rz_hex_bin2strdup(note->regstate, note->regstate_size);
		}
	}

	char *machine_name = Elf_(rz_bin_elf_get_machine_name)(obj);
	eprintf("Cannot retrieve regstate on: %s (not yet supported)\n", machine_name);
	free(machine_name);
	return NULL;
}

static char *setphname(ut16 mach, Elf_(Word) ptyp) {
	// TODO to complete over time
	if (mach == EM_ARM) {
		if (ptyp == SHT_ARM_EXIDX) {
			return strdup("EXIDX");
		}
	} else if (mach == EM_MIPS) {
		if (ptyp == PT_MIPS_ABIFLAGS) {
			return strdup("ABIFLAGS");
		} else if (ptyp == PT_MIPS_REGINFO) {
			return strdup("REGINFO");
		}
	}

	return strdup("UNKNOWN");
}

static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (o && o->bin_obj) {
		struct Elf_(rz_bin_elf_obj_t) *bin = (struct Elf_(rz_bin_elf_obj_t) *)o->bin_obj;
		return bin->kv;
	}
	return NULL;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ELFOBJ *res = Elf_(rz_bin_elf_new_buf)(buf, &obj->opts);
	if (res) {
		obj->bin_obj = res;
		return true;
	}

	return false;
}

static ut64 baddr(RzBinFile *bf) {
	return Elf_(rz_bin_elf_get_baddr)(bf->o->bin_obj);
}

static ut64 boffset(RzBinFile *bf) {
	return Elf_(rz_bin_elf_get_boffset)(bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	struct Elf_(rz_bin_elf_obj_t) *obj = bf->o->bin_obj;
	RzBinAddr *ret = NULL;
	ut64 addr = 0LL;

	switch (sym) {
	case RZ_BIN_SPECIAL_SYMBOL_ENTRY:
		addr = Elf_(rz_bin_elf_get_entry_offset)(bf->o->bin_obj);
		break;
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
		addr = Elf_(rz_bin_elf_get_main_offset)(bf->o->bin_obj);
		break;
	case RZ_BIN_SPECIAL_SYMBOL_INIT:
		addr = Elf_(rz_bin_elf_get_init_offset)(bf->o->bin_obj);
		break;
	case RZ_BIN_SPECIAL_SYMBOL_FINI:
		addr = Elf_(rz_bin_elf_get_fini_offset)(bf->o->bin_obj);
		break;
	default:
		break;
	}
	if (addr && addr != UT64_MAX && (ret = RZ_NEW0(RzBinAddr))) {
		struct Elf_(rz_bin_elf_obj_t) *bin = bf->o->bin_obj;
		ret->paddr = addr;
		ret->vaddr = Elf_(rz_bin_elf_p2v_new)(obj, addr);
		ret->bits = obj->bits;
		if (ret->vaddr == UT64_MAX) {
			ret->vaddr = addr;
		}
		if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin)) {
			rz_bin_elf_fix_arm_thumb_object_dispatch(ret);
		}
	}
	return ret;
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
		rz_vector_foreach(notes, tmp) {
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

static RzList *maps_unpatched(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_bin_map_free);
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
			if (core_sp != UT64_MAX && core_sp >= iter->data.p_vaddr && core_sp < iter->data.p_vaddr + iter->data.p_memsz) {
				map->name = strdup("[stack]");
			} else {
				RzBinElfNoteFile *nf = note_file_for_load_segment(obj, &iter->data);
				if (nf && nf->file) {
					map->name = strdup(nf->file);
				}
			}
			// generic names
			if (!map->name) {
				map->name = rz_str_newf("LOAD%d", n);
			}
			n++;
			rz_list_append(ret, map);
		}
	} else {
		// Load sections if there is no PHDR

		RzBinElfSection *section;
		rz_bin_elf_foreach_sections(obj, section) {
			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				break;
			}

			map->name = rz_str_new(section->name);
			map->paddr = section->offset;
			map->psize = section->type != SHT_NOBITS ? section->size : 0;
			map->vsize = section->size;
			map->vaddr = section->rva;
			map->perm = section_perms_from_flags(section->flags);
			rz_list_append(ret, map);
		}
	}

	if (rz_list_empty(ret)) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->name = strdup("uphdr");
		map->paddr = 0;
		map->psize = bf->size;
		map->vaddr = 0x10000;
		map->vsize = bf->size;
		map->perm = RZ_PERM_RWX;
		rz_list_append(ret, map);
	}

	if (obj->ehdr.e_type == ET_REL) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		ut64 ehdr_size = sizeof(obj->ehdr);
		if (bf->size < ehdr_size) {
			ehdr_size = bf->size;
		}
		map->name = strdup("ehdr");
		map->paddr = 0;
		map->psize = ehdr_size;
		map->vaddr = obj->baddr;
		map->vsize = ehdr_size;
		map->perm = RZ_PERM_RW;
		rz_list_append(ret, map);
	}
	return ret;
}

static ut64 reloc_target_size(ELFOBJ *obj) {
	if (!obj->bits) {
		return 8;
	}
	return obj->bits / 8;
}

/// base vaddr where to map the artificial reloc target vfile
static ut64 reloc_targets_map_base(RzBinFile *bf, struct Elf_(rz_bin_elf_obj_t) * obj) {
	if (obj->reloc_targets_map_base_calculated) {
		return obj->reloc_targets_map_base;
	}
	RzList *maps = maps_unpatched(bf);
	obj->reloc_targets_map_base = rz_bin_relocs_patch_find_targets_map_base(maps, reloc_target_size(obj));
	rz_list_free(maps);
	obj->reloc_targets_map_base_calculated = true;
	return obj->reloc_targets_map_base;
}

/// size of the artificial reloc target vfile
static ut64 reloc_targets_vfile_size(RzBinFile *bf, ELFOBJ *obj) {
	if (!bf->o || !bf->o->opts.patch_relocs || !Elf_(rz_bin_elf_has_relocs)(obj)) {
		return 0;
	}

	return Elf_(rz_bin_elf_get_relocs_count)(obj) * reloc_target_size(obj);
}

static void patch_reloc(struct Elf_(rz_bin_elf_obj_t) * obj, RzBinElfReloc *rel, ut64 S, ut64 B, ut64 L) {
	ut16 e_machine = obj->ehdr.e_machine;
	ut64 val;
	ut64 A = rel->addend, P = rel->vaddr;
	ut64 patch_addr = rel->paddr != UT64_MAX ? rel->paddr : Elf_(rz_bin_elf_v2p_new)(obj, rel->vaddr);
	ut8 buf[8];
	switch (e_machine) {
	case EM_ARM:
		val = S + A;
		rz_write_le32(buf, val);
		rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
		break;
	case EM_AARCH64:
		val = S + A;
		rz_write_le64(buf, val);
		rz_buf_write_at(obj->buf_patched, patch_addr, buf, 8);
		break;
	case EM_PPC64: {
		int low = 0, word = 0;
		switch (rel->type) {
		case RZ_PPC64_REL16_HA:
			word = 2;
			val = (S + A - P + 0x8000) >> 16;
			break;
		case RZ_PPC64_REL16_LO:
			word = 2;
			val = (S + A - P) & 0xffff;
			break;
		case RZ_PPC64_REL14:
			low = 14;
			val = (st64)(S + A - P) >> 2;
			break;
		case RZ_PPC64_REL24:
			low = 24;
			val = (st64)(S + A - P) >> 2;
			break;
		case RZ_PPC64_REL32:
			word = 4;
			val = S + A - P;
			break;
		default:
			break;
		}
		if (low) {
			// TODO big-endian
			switch (low) {
			case 14:
				val &= (1 << 14) - 1;
				rz_buf_read_at(obj->buf_patched, patch_addr, buf, 2);
				rz_write_le32(buf, (rz_read_le32(buf) & ~((1 << 16) - (1 << 2))) | val << 2);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 2);
				break;
			case 24:
				val &= (1 << 24) - 1;
				rz_buf_read_at(obj->buf_patched, patch_addr, buf, 4);
				rz_write_le32(buf, (rz_read_le32(buf) & ~((1 << 26) - (1 << 2))) | val << 2);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
				break;
			}
		} else if (word) {
			// TODO big-endian
			switch (word) {
			case 2:
				rz_write_le16(buf, val);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 2);
				break;
			case 4:
				rz_write_le32(buf, val);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
				break;
			}
		}
		break;
	}
	case EM_X86_64: {
		int word = 0;
		switch (rel->type) {
		case RZ_X86_64_8:
			word = 1;
			val = S + A;
			break;
		case RZ_X86_64_16:
			word = 2;
			val = S + A;
			break;
		case RZ_X86_64_32:
		case RZ_X86_64_32S:
			word = 4;
			val = S + A;
			break;
		case RZ_X86_64_64:
			word = 8;
			val = S + A;
			break;
		case RZ_X86_64_GLOB_DAT:
		case RZ_X86_64_JUMP_SLOT:
			word = 4;
			val = S;
			break;
		case RZ_X86_64_PC8:
			word = 1;
			val = S + A - P;
			break;
		case RZ_X86_64_PC16:
			word = 2;
			val = S + A - P;
			break;
		case RZ_X86_64_PC32:
			word = 4;
			val = S + A - P;
			break;
		case RZ_X86_64_PC64:
			word = 8;
			val = S + A - P;
			break;
		case RZ_X86_64_PLT32:
			word = 4;
			val = L + A - P;
			break;
		case RZ_X86_64_RELATIVE:
			word = 8;
			val = B + A;
			break;
		default:
			//eprintf ("relocation %d not handle at this time\n", rel->type);
			break;
		}
		switch (word) {
		case 0:
			break;
		case 1:
			buf[0] = val;
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 1);
			break;
		case 2:
			rz_write_le16(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 2);
			break;
		case 4:
			rz_write_le32(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
			break;
		case 8:
			rz_write_le64(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 8);
			break;
		}
		break;
	}
	}
}

static RzBinReloc *reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	rz_return_val_if_fail(bin && rel, NULL);

	ut64 B = bin->baddr;
	ut64 P = rel->vaddr; // rva has taken baddr into account
	RzBinReloc *r = RZ_NEW0(RzBinReloc);
	if (!r) {
		return NULL;
	}
	r->import = NULL;
	r->symbol = NULL;
	r->is_ifunc = false;
	r->addend = rel->addend;
	if (rel->sym) {
		r->import = get_import(bin, rel->sym);
		if (!r->import) {
			r->symbol = get_symbol(bin, rel->sym);
		}
	}
	r->vaddr = rel->vaddr;
	r->paddr = rel->paddr;
	r->target_vaddr = rel->target_vaddr;

#define SET(T) \
	r->type = RZ_BIN_RELOC_##T; \
	r->additive = 0; \
	return r
#define ADD(T, A) \
	r->type = RZ_BIN_RELOC_##T; \
	r->addend += A; \
	r->additive = rel->mode == DT_RELA; \
	return r

	switch (bin->ehdr.e_machine) {
	case EM_386:
		switch (rel->type) {
		case RZ_386_NONE: break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case RZ_386_32: ADD(32, 0);
		case RZ_386_PC32: ADD(32, -P);
		case RZ_386_GLOB_DAT: SET(32);
		case RZ_386_JMP_SLOT: SET(32);
		case RZ_386_RELATIVE: ADD(32, B);
		case RZ_386_GOTOFF: ADD(32, -GOT);
		case RZ_386_GOTPC: ADD(32, GOT - P);
		case RZ_386_16: ADD(16, 0);
		case RZ_386_PC16: ADD(16, -P);
		case RZ_386_8: ADD(8, 0);
		case RZ_386_PC8: ADD(8, -P);
		case RZ_386_COPY: ADD(32, 0); // XXX: copy symbol at runtime
		case RZ_386_IRELATIVE: r->is_ifunc = true; SET(32);
		default: break;
		}
		break;
	case EM_X86_64:
		switch (rel->type) {
		case RZ_X86_64_NONE: break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case RZ_X86_64_64: ADD(64, 0);
		case RZ_X86_64_PLT32: ADD(32, -P /* +L */);
		case RZ_X86_64_GOT32: ADD(32, GOT);
		case RZ_X86_64_PC32: ADD(32, -P);
		case RZ_X86_64_GLOB_DAT: r->vaddr -= rel->sto; SET(64);
		case RZ_X86_64_JUMP_SLOT: r->vaddr -= rel->sto; SET(64);
		case RZ_X86_64_RELATIVE: ADD(64, B);
		case RZ_X86_64_32: ADD(32, 0);
		case RZ_X86_64_32S: ADD(32, 0);
		case RZ_X86_64_16: ADD(16, 0);
		case RZ_X86_64_PC16: ADD(16, -P);
		case RZ_X86_64_8: ADD(8, 0);
		case RZ_X86_64_PC8: ADD(8, -P);
		case RZ_X86_64_GOTPCREL: ADD(64, GOT - P);
		case RZ_X86_64_COPY: ADD(64, 0); // XXX: copy symbol at runtime
		case RZ_X86_64_IRELATIVE: r->is_ifunc = true; SET(64);
		default: break;
		}
		break;
	case EM_ARM:
		switch (rel->type) {
		case RZ_ARM_NONE: break;
		case RZ_ARM_ABS32: ADD(32, 0);
		case RZ_ARM_REL32: ADD(32, -P);
		case RZ_ARM_ABS16: ADD(16, 0);
		case RZ_ARM_ABS8: ADD(8, 0);
		case RZ_ARM_SBREL32: ADD(32, -B);
		case RZ_ARM_GLOB_DAT: ADD(32, 0);
		case RZ_ARM_JUMP_SLOT: ADD(32, 0);
		case RZ_ARM_RELATIVE: ADD(32, B);
		case RZ_ARM_GOTOFF: ADD(32, -GOT);
		default: ADD(32, GOT); break; // reg relocations
		}
		break;
	case EM_RISCV:
		switch (rel->type) {
		case RZ_RISCV_NONE: break;
		case RZ_RISCV_JUMP_SLOT: ADD(64, 0);
		case RZ_RISCV_RELATIVE: ADD(64, B);
		default: ADD(64, GOT); break; // reg relocations
		}
		break;
	case EM_AARCH64:
		switch (rel->type) {
		case RZ_AARCH64_NONE: break;
		case RZ_AARCH64_ABS32: ADD(32, 0);
		case RZ_AARCH64_ABS16: ADD(16, 0);
		case RZ_AARCH64_GLOB_DAT: SET(64);
		case RZ_AARCH64_JUMP_SLOT: SET(64);
		case RZ_AARCH64_RELATIVE: ADD(64, B);
		default: break; // reg relocations
		}
		break;
	case EM_PPC:
		switch (rel->type) {
		case RZ_PPC_NONE: break;
		case RZ_PPC_GLOB_DAT: ADD(32, 0);
		case RZ_PPC_JMP_SLOT: ADD(32, 0);
		default:
			eprintf("unimplemented ELF/PPC reloc type %d\n", rel->type);
			break;
		}
		break;
	default: break;
	}

#undef SET
#undef ADD

	free(r);
	return NULL;
}

static void patch_relocs(RzBinFile *bf, ELFOBJ *bin) {
	rz_return_if_fail(bf && bin);
	if (bin->relocs_patched || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return;
	}
	bin->relocs_patched = true; // run this function just once (lazy relocs patching)
	RzBinObject *obj = bf->o;
	if (!obj || !obj->opts.patch_relocs || (bin->ehdr.e_type != ET_REL && bin->ehdr.e_type != ET_DYN)) {
		return;
	}
	ut64 cdsz = reloc_target_size(bin);
	ut64 size = reloc_targets_vfile_size(bf, bin);
	if (!size) {
		return;
	}
	RzBinRelocTargetBuilder *targets = rz_bin_reloc_target_builder_new(cdsz, reloc_targets_map_base(bf, bin));
	if (!targets) {
		return;
	}
	bin->buf_patched = rz_buf_new_sparse_overlay(bf->buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!bin->buf_patched) {
		rz_bin_reloc_target_builder_free(targets);
		return;
	}
	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		ut64 sym_addr = 0;
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
				} else {
					sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
				}
			}
		}
		// TODO relocation types B, L
		patch_reloc(bin, reloc, sym_addr, 0, sym_addr);
		reloc->target_vaddr = sym_addr;
	}
	rz_bin_reloc_target_builder_free(targets);
	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(bin->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
}

static RzList *virtual_files(RzBinFile *bf) {
	RzList *r = rz_list_newf((RzListFree)rz_bin_virtual_file_free);
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
		vf->name = strdup(VFILE_NAME_RELOC_TARGETS);
		rz_list_push(r, vf);
	}
	// virtual file mirroring the raw file, but with relocs patched
	if (obj->buf_patched) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return r;
		}
		vf->buf = obj->buf_patched;
		vf->name = strdup(VFILE_NAME_PATCHED);
		rz_list_push(r, vf);
	}
	return r;
}

static RzList *maps(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	RzList *ret = maps_unpatched(bf);
	if (!ret) {
		return NULL;
	}

	// if relocs should be patched, use the patched vfile for everything from the file
	patch_relocs(bf, obj);
	rz_bin_relocs_patch_maps(ret, obj->buf_patched, 0,
		reloc_targets_map_base(bf, obj), reloc_targets_vfile_size(bf, obj),
		VFILE_NAME_PATCHED, VFILE_NAME_RELOC_TARGETS);
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	ELFOBJ *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	RzBinSection *ptr = NULL;
	RzList *ret = NULL;

	if (!obj || !(ret = rz_list_newf((RzListFree)rz_bin_section_free))) {
		return NULL;
	}

	//there is not leak in section since they are cached by elf.c
	//and freed within Elf_(rz_bin_elf_free)
	size_t i;
	RzBinElfSection *section;
	rz_bin_elf_enumerate_sections(obj, section, i) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		ptr->name = rz_str_new(section->name);
		if (!ptr->name) {
			ptr->name = rz_str_new("");
		}
		if (strstr(ptr->name, "data") && !strstr(ptr->name, "rel") && !strstr(ptr->name, "pydata")) {
			ptr->is_data = true;
		} else if (!strcmp(ptr->name, "C")) {
			ptr->is_data = true;
		}
		if (is_wordable_section(ptr->name)) {
			ptr->format = rz_str_newf("Cd %zu[%" PFMT64d "]", sizeof(Elf_(Addr)), section->size / sizeof(Elf_(Addr)));
		}
		ptr->size = section->type != SHT_NOBITS ? section->size : 0;
		ptr->vsize = section->size;
		ptr->paddr = section->offset;
		ptr->vaddr = section->rva;
		ptr->type = section->type;
		ptr->flags = section->flags;
		ptr->perm = section_perms_from_flags(section->flags);
		rz_list_append(ret, ptr);
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
			ptr->name = strdup("DYNAMIC");
			break;
		case PT_LOAD: {
			ptr->name = rz_str_newf("LOAD%zu", n++);
			ptr->perm |= RZ_PERM_R;
			break;
		}
		case PT_INTERP:
			ptr->name = strdup("INTERP");
			break;
		case PT_GNU_STACK:
			ptr->name = strdup("GNU_STACK");
			break;
		case PT_GNU_RELRO:
			ptr->name = strdup("GNU_RELRO");
			break;
		case PT_GNU_EH_FRAME:
			ptr->name = strdup("GNU_EH_FRAME");
			break;
		case PT_PHDR:
			ptr->name = strdup("PHDR");
			break;
		case PT_TLS:
			ptr->name = strdup("TLS");
			break;
		case PT_NOTE:
			ptr->name = strdup("NOTE");
			break;
		case PT_OPENBSD_RANDOMIZE:
			ptr->name = strdup("OPENBSD_RANDOMIZE");
			break;
		case PT_OPENBSD_WXNEEDED:
			ptr->name = strdup("OPENBSD_WXNEEDED");
			break;
		case PT_OPENBSD_BOOTDATA:
			ptr->name = strdup("OPENBSD_BOOTDATA");
			break;
		default:
			if (ptr->size == 0 && ptr->vsize == 0) {
				ptr->name = strdup("NONE");
			} else {
				ptr->name = setphname(mach, iter->data.p_type);
			}
			break;
		}
		rz_list_append(ret, ptr);
	}

	// add entry for ehdr
	ptr = RZ_NEW0(RzBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof(obj->ehdr);
		if (bf->size < ehdr_size) {
			ehdr_size = bf->size;
		}
		ptr->name = strdup("ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->perm = RZ_PERM_RW;
		ptr->is_segment = true;
		rz_list_append(ret, ptr);
	}

	return ret;
}

static RzBinAddr *newEntry(RzBinFile *bf, ut64 hpaddr, ut64 hvaddr, ut64 vaddr, int type, int bits) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	struct Elf_(rz_bin_elf_obj_t) *obj = bf->o->bin_obj;
	RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
	if (ptr) {
		ptr->paddr = Elf_(rz_bin_elf_v2p_new)(obj, vaddr);
		ptr->vaddr = vaddr;
		ptr->hpaddr = hpaddr;
		ptr->hvaddr = hvaddr;
		ptr->bits = bits;
		ptr->type = type;
		//realign due to thumb
		if (bits == 16 && Elf_(rz_bin_elf_is_thumb_addr)(ptr->vaddr)) {
			ptr->paddr--;
			ptr->vaddr--;
		}
	}
	return ptr;
}

static void process_constructors(RzBinFile *bf, RzList *ret, int bits) {
	RzList *secs = sections(bf);
	RzListIter *iter;
	RzBinSection *sec;
	int i, type;
	rz_list_foreach (secs, iter, sec) {
		type = -1;
		if (!strcmp(sec->name, ".fini_array")) {
			type = RZ_BIN_ENTRY_TYPE_FINI;
		} else if (!strcmp(sec->name, ".init_array")) {
			type = RZ_BIN_ENTRY_TYPE_INIT;
		} else if (!strcmp(sec->name, ".preinit_array")) {
			type = RZ_BIN_ENTRY_TYPE_PREINIT;
		}
		if (type != -1) {
			ut8 *buf = calloc(sec->size, 1);
			if (!buf) {
				continue;
			}
			(void)rz_buf_read_at(bf->buf, sec->paddr, buf, sec->size);
			if (bits == 32) {
				for (i = 0; (i + 3) < sec->size; i += 4) {
					ut32 addr32 = rz_read_le32(buf + i);
					if (addr32) {
						RzBinAddr *ba = newEntry(bf, sec->paddr + i, sec->vaddr + i,
							(ut64)addr32, type, bits);
						rz_list_append(ret, ba);
					}
				}
			} else {
				for (i = 0; (i + 7) < sec->size; i += 8) {
					ut64 addr64 = rz_read_le64(buf + i);
					if (addr64) {
						RzBinAddr *ba = newEntry(bf, sec->paddr + i, sec->vaddr + i,
							addr64, type, bits);
						rz_list_append(ret, ba);
					}
				}
			}
			free(buf);
		}
	}
	rz_list_free(secs);
}

static RzList *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzBinAddr *ptr = NULL;
	ELFOBJ *obj = bf->o->bin_obj;
	RzList *ret = rz_list_newf((RzListFree)free);
	if (!ret) {
		return NULL;
	}
	ut64 pa = Elf_(rz_bin_elf_get_entry_offset)(obj);
	if (pa != UT64_MAX) {
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			return ret;
		}
		ptr->paddr = pa;
		ptr->vaddr = Elf_(rz_bin_elf_p2v_new)(obj, ptr->paddr);
		ptr->hpaddr = 0x18; // e_entry offset in ELF header
		ptr->hvaddr = UT64_MAX;
		ptr->bits = obj->bits;

		if (ptr->vaddr != (ut64)obj->ehdr.e_entry && Elf_(rz_bin_elf_is_executable)(obj)) {
			eprintf("Cannot determine entrypoint, using 0x%08" PFMT64x ".\n", ptr->vaddr);
		}

		if (bf->o->sections) {
			RzListIter *iter;
			RzBinSection *section;
			rz_list_foreach_prev(bf->o->sections, iter, section) {
				if (!strcmp(section->name, "ehdr")) {
					ptr->hvaddr = section->vaddr + ptr->hpaddr;
					break;
				}
			}
		}

		if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(obj)) {
			rz_bin_elf_fix_arm_thumb_object_dispatch(ptr);
		}

		rz_list_append(ret, ptr);
	}

	// add entrypoint for jni libraries
	// NOTE: this is slow, we shouldnt find for java constructors here
	if (!Elf_(rz_bin_elf_has_symbols)(obj)) {
		return ret;
	}

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(obj, symbol) {
		if (symbol->name && !strncmp(symbol->name, "Java", 4)) {
			if (rz_str_endswith(symbol->name, "_init")) {
				if (!(ptr = RZ_NEW0(RzBinAddr))) {
					return ret;
				}
				ptr->paddr = symbol->paddr;
				ptr->vaddr = symbol->vaddr;
				ptr->hpaddr = UT64_MAX;
				ptr->type = RZ_BIN_ENTRY_TYPE_INIT;
				rz_list_append(ret, ptr);
				break;
			}
		}
	}
	int bin_bits = obj->bits;
	process_constructors(bf, ret, bin_bits < 32 ? 32 : bin_bits);
	return ret;
}

static RzList *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = bf->o->bin_obj;
	RzList *ret = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		RzBinSymbol *tmp = convert_symbol(bin, symbol);
		if (!tmp) {
			rz_list_free(ret);
			return NULL;
		}

		rz_list_append(ret, tmp);
	}

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		RzBinSymbol *tmp = convert_symbol(bin, import);
		if (!tmp) {
			rz_list_free(ret);
			return NULL;
		}

		tmp->is_imported = true;

		rz_list_append(ret, tmp);
	}

	return ret;
}

static RzList *imports(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	ELFOBJ *bin = bf->o->bin_obj;

	if (!Elf_(rz_bin_elf_has_imports)(bin)) {
		return NULL;
	}

	RzList *result = rz_list_newf((RzListFree)rz_bin_import_free);
	if (!result) {
		return NULL;
	}

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		RzBinImport *tmp = convert_import(import);
		if (!tmp) {
			rz_list_free(result);
			return NULL;
		}

		rz_list_append(result, tmp);
	}

	return result;
}

static RzList *libs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	return Elf_(rz_bin_elf_get_libs)(bf->o->bin_obj);
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

static RzList *relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzList *ret = NULL;
	RzBinReloc *ptr = NULL;

	if (!bf->o) {
		return NULL;
	}

	ELFOBJ *bin = bf->o->bin_obj;
	if (!bin || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return NULL;
	}

	patch_relocs(bf, bin);

	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}

	ut64 got_addr = get_got_addr(bin);

	if (!got_addr) {
		got_addr = reloc_targets_map_base(bf, bin);
	}

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (!(ptr = reloc_convert(bin, reloc, got_addr))) {
			continue;
		}

		rz_list_append(ret, ptr);
	}

	return ret;
}

static void lookup_symbols(RzBinFile *bf, RzBinInfo *ret) {
	RzList *symbols_list = symbols(bf);
	RzListIter *iter;
	RzBinSymbol *symbol;
	bool is_rust = false;
	if (symbols_list) {
		rz_list_foreach (symbols_list, iter, symbol) {
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
		rz_list_free(symbols_list);
	}
}

static void lookup_sections(RzBinFile *bf, RzBinInfo *ret) {
	RzList *sections_list = sections(bf);
	RzListIter *iter;
	RzBinSection *section;
	bool is_go = false;
	ret->has_retguard = -1;
	rz_list_foreach (sections_list, iter, section) {
		if (ret->has_retguard != -1 && is_go == true) {
			break;
		}
		if (strstr(section->name, "note.go.buildid") ||
			strstr(section->name, ".gopclntab") ||
			strstr(section->name, ".go_export")) {
			ret->lang = "go";
			is_go = true;
		}
#define RZ_BIN_RANDOMDATA_RETGUARD_SZ 48
		if (!strcmp(section->name, ".openbsd.randomdata")) {
			// The retguard cookie adds 8 per return function inst.
			ret->has_retguard = (section->size >= RZ_BIN_RANDOMDATA_RETGUARD_SZ);
			break;
		}
	}
	rz_list_free(sections_list);
}

static bool has_sanitizers(RzBinFile *bf) {
	bool ret = false;
	RzList *imports_list = imports(bf);
	RzListIter *iter;
	RzBinImport *import;
	rz_list_foreach (imports_list, iter, import) {
		if (strstr(import->name, "__sanitizer") ||
			strstr(import->name, "__ubsan")) {
			ret = true;
			break;
		}
	}
	rz_list_free(imports_list);
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	char *str;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = bf->file
		? strdup(bf->file)
		: NULL;
	ELFOBJ *obj = bf->o->bin_obj;
	if ((str = Elf_(rz_bin_elf_get_rpath)(obj))) {
		ret->rpath = strdup(str);
		free(str);
	} else {
		ret->rpath = strdup("NONE");
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
	}

	ret->rclass = strdup("elf");
	ret->bits = obj->bits;
	if (!strcmp(ret->arch, "avr")) {
		ret->bits = 16;
	}
	ret->big_endian = Elf_(rz_bin_elf_is_big_endian)(obj);
	ret->has_va = Elf_(rz_bin_elf_has_va)(obj);
	ret->has_nx = Elf_(rz_bin_elf_has_nx)(obj);
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

static RzList *fields(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_field_free);
	if (!ret) {
		return NULL;
	}

#define ROW(name, siz, val, fmt) \
	rz_list_append(ret, rz_bin_field_new(addr, addr, siz, name, sdb_fmt("0x%08" PFMT64x, (ut64)val), fmt, false));

	if (rz_buf_size(bf->buf) < sizeof(Elf_(Ehdr))) {
		return ret;
	}

	ut32 magic;
	ut64 addr = 0;
	if (!rz_buf_read_le32_at(bf->buf, addr, &magic)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("ELF", 4, magic, "x");

	ut16 type;
	addr += 0x10;
	if (!rz_buf_read_le16_at(bf->buf, addr, &type)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("Type", 2, type, "x");

	ut16 machine;
	addr += 0x2;
	if (!rz_buf_read_le16_at(bf->buf, addr, &machine)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("Machine", 2, machine, "x");

	ut32 version;
	addr += 0x2;
	if (!rz_buf_read_le32_at(bf->buf, addr, &version)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("Version", 4, version, "x");

	ut8 tmp;
	if (!rz_buf_read8_at(bf->buf, 0x04, &tmp)) {
		rz_list_free(ret);
		return NULL;
	}

	if (tmp == 1) {
		ut32 entry;
		addr += 0x4;
		if (!rz_buf_read_le32_at(bf->buf, addr, &entry)) {
			rz_list_free(ret);
			return NULL;
		}
		ROW("Entry point", 4, entry, "x");

		ut32 phoff;
		addr += 0x4;
		if (!rz_buf_read_le32_at(bf->buf, addr, &phoff)) {
			rz_list_free(ret);
			return NULL;
		}
		ROW("PhOff", 4, phoff, "x");

		ut32 shoff;
		addr += 0x4;
		if (!rz_buf_read_le32_at(bf->buf, addr, &shoff)) {
			rz_list_free(ret);
			return NULL;
		}
		ROW("ShOff", 4, shoff, "x");

		addr += 0x4;
	} else {
		ut64 entry;
		addr += 0x4;
		if (!rz_buf_read_le64_at(bf->buf, addr, &entry)) {
			rz_list_free(ret);
			return NULL;
		}
		ROW("Entry point", 8, entry, "x");

		ut64 phoff;
		addr += 0x8;
		if (!rz_buf_read_le64_at(bf->buf, addr, &phoff)) {
			rz_list_free(ret);
			return NULL;
		}
		ROW("PhOff", 8, phoff, "x");

		ut64 shoff;
		addr += 0x8;
		if (!rz_buf_read_le64_at(bf->buf, addr, &shoff)) {
			rz_list_free(ret);
			return NULL;
		}
		ROW("ShOff", 8, shoff, "x");

		addr += 0x8;
	}

	ut32 flags;
	if (!rz_buf_read_le32_at(bf->buf, addr, &flags)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("Flags", 4, flags, "x");

	ut16 ehsize;
	addr += 0x4;
	if (!rz_buf_read_le16_at(bf->buf, addr, &ehsize)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("EhSize", 2, ehsize, "x");

	ut16 phentsize;
	addr += 0x2;
	if (!rz_buf_read_le16_at(bf->buf, addr, &phentsize)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("PhentSize", 2, phentsize, "x");

	ut16 phnum;
	addr += 0x2;
	if (!rz_buf_read_le16_at(bf->buf, addr, &phnum)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("PhNum", 2, phnum, "x");

	ut16 shentsize;
	addr += 0x2;
	if (!rz_buf_read_le16_at(bf->buf, addr, &shentsize)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("ShentSize", 2, shentsize, "x");

	ut16 shnum;
	addr += 0x2;
	if (!rz_buf_read_le16_at(bf->buf, addr, &shnum)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("ShNum", 2, shnum, "x");

	ut16 shrstrndx;
	addr += 0x2;
	if (!rz_buf_read_le16_at(bf->buf, addr, &shrstrndx)) {
		rz_list_free(ret);
		return NULL;
	}
	ROW("ShrStrndx", 2, shrstrndx, "x");

	return ret;
}

static ut64 size(RzBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (!bf->o->sections) {
		RzListIter *iter;
		RzBinSection *section;
		bf->o->sections = sections(bf);
		rz_list_foreach (bf->o->sections, iter, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}
