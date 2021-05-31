// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rz_types.h>
#include <rz_util.h>
#include "elf.h"

// Deprecated
#include "rz_bin_elf_get_p2v_new.inc"
#include "rz_bin_elf_get_v2p_new.inc"

// RZ_IPI
#include "rz_bin_elf_get_number_of_dynamic_symbols.inc"
#include "rz_bin_elf_get_prstatus.inc"
#include "rz_bin_elf_get_prstatus_layout.inc"
#include "rz_bin_elf_get_ver_flags.inc"
#include "rz_bin_elf_get_verdaux_entry.inc"
#include "rz_bin_elf_get_verdef_entry.inc"
#include "rz_bin_elf_get_vernaux_entry.inc"
#include "rz_bin_elf_get_verneed_entry.inc"
#include "rz_bin_elf_get_version_info.inc"
#include "rz_bin_elf_get_version_info_gnu_verdef.inc"
#include "rz_bin_elf_get_version_info_gnu_verneed.inc"
#include "rz_bin_elf_get_version_info_gnu_versym.inc"
#include "rz_bin_elf_init_dynamic_section.inc"
#include "rz_bin_elf_init_dynstr.inc"
#include "rz_bin_elf_init_ehdr.inc"
#include "rz_bin_elf_init_notes.inc"
#include "rz_bin_elf_init_phdr.inc"
#include "rz_bin_elf_init_shdr.inc"
#include "rz_bin_elf_init_shstrtab.inc"
#include "rz_bin_elf_init_strtab.inc"
#include "rz_bin_elf_is_sh_index_valid.inc"

// RZ_API
#include "rz_bin_elf_compiler.inc"
#include "rz_bin_elf_convert_import.inc"
#include "rz_bin_elf_convert_symbol.inc"
#include "rz_bin_elf_free.inc"
#include "rz_bin_elf_get_abi.inc"
#include "rz_bin_elf_get_arch.inc"
#include "rz_bin_elf_get_baddr.inc"
#include "rz_bin_elf_get_bits.inc"
#include "rz_bin_elf_get_boffset.inc"
#include "rz_bin_elf_get_cpu.inc"
#include "rz_bin_elf_get_data_encoding.inc"
#include "rz_bin_elf_get_elf_class.inc"
#include "rz_bin_elf_get_entry_offset.inc"
#include "rz_bin_elf_get_fields.inc"
#include "rz_bin_elf_get_file_type.inc"
#include "rz_bin_elf_get_fini_offset.inc"
#include "rz_bin_elf_get_head_flag.inc"
#include "rz_bin_elf_get_init_offset.inc"
#include "rz_bin_elf_get_libs.inc"
#include "rz_bin_elf_get_machine_name.inc"
#include "rz_bin_elf_get_main_offset.inc"
#include "rz_bin_elf_get_osabi_name.inc"
#include "rz_bin_elf_get_relocs.inc"
#include "rz_bin_elf_get_rpath.inc"
#include "rz_bin_elf_get_section.inc"
#include "rz_bin_elf_get_section_addr.inc"
#include "rz_bin_elf_get_section_addr_end.inc"
#include "rz_bin_elf_get_section_offset.inc"
#include "rz_bin_elf_get_sections.inc"
#include "rz_bin_elf_get_sp_val.inc"
#include "rz_bin_elf_get_stripped.inc"
#include "rz_bin_elf_grab_regstate.inc"
#include "rz_bin_elf_has_nx.inc"
#include "rz_bin_elf_has_relro.inc"
#include "rz_bin_elf_has_va.inc"
#include "rz_bin_elf_intrp.inc"
#include "rz_bin_elf_is_big_endian.inc"
#include "rz_bin_elf_is_executable.inc"
#include "rz_bin_elf_is_relocatable.inc"
#include "rz_bin_elf_is_static.inc"
#include "rz_bin_elf_new_buf.inc"
#include "section_flag_to_rzlist.inc"
#include "section_type_to_string.inc"

#define MAX_REL_RELA_SZ (sizeof(Elf_(Rel)) > sizeof(Elf_(Rela)) ? sizeof(Elf_(Rel)) : sizeof(Elf_(Rela)))

#define GROWTH_FACTOR 2

static void setimpord(ELFOBJ *eobj, RzBinElfSymbol *sym);

static inline int __strnlen(const char *str, int len) {
	int l = 0;
	while (IS_PRINTABLE(*str) && --len) {
		if (((ut8)*str) == 0xff) {
			break;
		}
		str++;
		l++;
	}
	return l + 1;
}

static bool is_special_arm_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	if (name[0] != '$') {
		return false;
	}
	switch (name[1]) {
	case 'a':
	case 't':
	case 'd':
	case 'x':
		return (name[2] == '\0' || name[2] == '.') &&
			ELF_ST_TYPE(sym->st_info) == STT_NOTYPE &&
			ELF_ST_BIND(sym->st_info) == STB_LOCAL &&
			ELF_ST_VISIBILITY(sym->st_info) == STV_DEFAULT;
	default:
		return false;
	}
}

static bool is_special_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return is_special_arm_symbol(bin, sym, name);
	default:
		return false;
	}
}

static const char *bind2str(Elf_(Sym) * sym) {
	switch (ELF_ST_BIND(sym->st_info)) {
	case STB_LOCAL: return RZ_BIN_BIND_LOCAL_STR;
	case STB_GLOBAL: return RZ_BIN_BIND_GLOBAL_STR;
	case STB_WEAK: return RZ_BIN_BIND_WEAK_STR;
	case STB_NUM: return RZ_BIN_BIND_NUM_STR;
	case STB_LOOS: return RZ_BIN_BIND_LOOS_STR;
	case STB_HIOS: return RZ_BIN_BIND_HIOS_STR;
	case STB_LOPROC: return RZ_BIN_BIND_LOPROC_STR;
	case STB_HIPROC: return RZ_BIN_BIND_HIPROC_STR;
	default: return RZ_BIN_BIND_UNKNOWN_STR;
	}
}

static const char *type2str(ELFOBJ *bin, struct rz_bin_elf_symbol_t *ret, Elf_(Sym) * sym) {
	if (bin && ret && is_special_symbol(bin, sym, ret->name)) {
		return RZ_BIN_TYPE_SPECIAL_SYM_STR;
	}
	switch (ELF_ST_TYPE(sym->st_info)) {
	case STT_NOTYPE: return RZ_BIN_TYPE_NOTYPE_STR;
	case STT_OBJECT: return RZ_BIN_TYPE_OBJECT_STR;
	case STT_FUNC: return RZ_BIN_TYPE_FUNC_STR;
	case STT_SECTION: return RZ_BIN_TYPE_SECTION_STR;
	case STT_FILE: return RZ_BIN_TYPE_FILE_STR;
	case STT_COMMON: return RZ_BIN_TYPE_COMMON_STR;
	case STT_TLS: return RZ_BIN_TYPE_TLS_STR;
	case STT_NUM: return RZ_BIN_TYPE_NUM_STR;
	case STT_LOOS: return RZ_BIN_TYPE_LOOS_STR;
	case STT_HIOS: return RZ_BIN_TYPE_HIOS_STR;
	case STT_LOPROC: return RZ_BIN_TYPE_LOPROC_STR;
	case STT_HIPROC: return RZ_BIN_TYPE_HIPROC_STR;
	default: return RZ_BIN_TYPE_UNKNOWN_STR;
	}
}

static void fill_symbol_bind_and_type(ELFOBJ *bin, struct rz_bin_elf_symbol_t *ret, Elf_(Sym) * sym) {
	ret->bind = bind2str(sym);
	ret->type = type2str(bin, ret, sym);
}

static RzBinElfSymbol *get_symbols_from_phdr(ELFOBJ *bin, int type) {
	Elf_(Sym) *sym = NULL;
	Elf_(Addr) addr_sym_table = 0;
	ut8 s[sizeof(Elf_(Sym))] = { 0 };
	RzBinElfSymbol *ret = NULL;
	int i, r, tsize, nsym, ret_ctr;
	ut64 toffset = 0, tmp_offset;
	ut32 size, sym_size = 0;

	if (!bin || !bin->phdr || !bin->ehdr.e_phnum) {
		return NULL;
	}

	if (bin->dyn_info.dt_symtab == RZ_BIN_ELF_ADDR_MAX || !bin->dyn_info.dt_syment) {
		return NULL;
	}

	addr_sym_table = Elf_(rz_bin_elf_v2p)(bin, bin->dyn_info.dt_symtab);
	sym_size = bin->dyn_info.dt_syment;
	if (!sym_size) {
		goto beach;
	}

	//since ELF doesn't specify the symbol table size we may read until the end of the buffer
	nsym = (bin->size - addr_sym_table) / sym_size;
	if (!UT32_MUL(&size, nsym, sizeof(Elf_(Sym)))) {
		goto beach;
	}
	if (size < 1) {
		goto beach;
	}
	if (addr_sym_table > bin->size || addr_sym_table + size > bin->size) {
		goto beach;
	}
	if (nsym < 1) {
		return NULL;
	}
	// we reserve room for 4096 and grow as needed.
	size_t capacity1 = 4096;
	size_t capacity2 = 4096;
	sym = (Elf_(Sym) *)calloc(capacity1, sym_size);
	ret = (RzBinElfSymbol *)calloc(capacity2, sizeof(struct rz_bin_elf_symbol_t));
	if (!sym || !ret) {
		goto beach;
	}
	for (i = 1, ret_ctr = 0; i < nsym; i++) {
		if (i >= capacity1) { // maybe grow
			// You take what you want, but you eat what you take.
			Elf_(Sym) *temp_sym = (Elf_(Sym) *)realloc(sym, (capacity1 * GROWTH_FACTOR) * sym_size);
			if (!temp_sym) {
				goto beach;
			}
			sym = temp_sym;
			capacity1 *= GROWTH_FACTOR;
		}
		if (ret_ctr >= capacity2) { // maybe grow
			RzBinElfSymbol *temp_ret = realloc(ret, capacity2 * GROWTH_FACTOR * sizeof(struct rz_bin_elf_symbol_t));
			if (!temp_ret) {
				goto beach;
			}
			ret = temp_ret;
			capacity2 *= GROWTH_FACTOR;
		}
		// read in one entry
		r = rz_buf_read_at(bin->b, addr_sym_table + i * sizeof(Elf_(Sym)), s, sizeof(Elf_(Sym)));
		if (r < 1) {
			goto beach;
		}
		int j = 0;
#if RZ_BIN_ELF64
		sym[i].st_name = READ32(s, j);
		sym[i].st_info = READ8(s, j);
		sym[i].st_other = READ8(s, j);
		sym[i].st_shndx = READ16(s, j);
		sym[i].st_value = READ64(s, j);
		sym[i].st_size = READ64(s, j);
#else
		sym[i].st_name = READ32(s, j);
		sym[i].st_value = READ32(s, j);
		sym[i].st_size = READ32(s, j);
		sym[i].st_info = READ8(s, j);
		sym[i].st_other = READ8(s, j);
		sym[i].st_shndx = READ16(s, j);
#endif
		bool is_sht_null = false;
		bool is_vaddr = false;
		// zero symbol is always empty
		// Examine entry and maybe store
		if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && sym[i].st_shndx == SHT_NULL) {
			if (sym[i].st_value) {
				toffset = sym[i].st_value;
			} else if ((toffset = get_import_addr(bin, i)) == -1) {
				toffset = 0;
			}
			tsize = 16;
		} else if (type == RZ_BIN_ELF_ALL_SYMBOLS) {
			tsize = sym[i].st_size;
			toffset = (ut64)sym[i].st_value;
			is_sht_null = sym[i].st_shndx == SHT_NULL;
		} else {
			continue;
		}
		// since we don't know the size of the sym table in this case,
		// let's stop at the first invalid entry
		if (!strcmp(bind2str(&sym[i]), RZ_BIN_BIND_UNKNOWN_STR) ||
			!strcmp(type2str(NULL, NULL, &sym[i]), RZ_BIN_TYPE_UNKNOWN_STR)) {
			goto done;
		}
		tmp_offset = Elf_(rz_bin_elf_v2p_new)(bin, toffset);
		if (tmp_offset == UT64_MAX) {
			tmp_offset = toffset;
			is_vaddr = true;
		}
		if (sym[i].st_name + 2 > bin->strtab_size) {
			// Since we are reading beyond the symbol table what's happening
			// is that some entry is trying to dereference the strtab beyond its capacity
			// is not a symbol so is the end
			goto done;
		}
		ret[ret_ctr].offset = tmp_offset;
		ret[ret_ctr].size = tsize;
		{
			int rest = ELF_STRING_LENGTH - 1;
			int st_name = sym[i].st_name;
			int maxsize = RZ_MIN(bin->size, bin->strtab_size);
			if (st_name < 0 || st_name >= maxsize) {
				ret[ret_ctr].name[0] = 0;
			} else {
				const int len = __strnlen(bin->strtab + st_name, rest);
				memcpy(ret[ret_ctr].name, &bin->strtab[st_name], len);
			}
		}
		ret[ret_ctr].ordinal = i;
		ret[ret_ctr].in_shdr = false;
		ret[ret_ctr].name[ELF_STRING_LENGTH - 2] = '\0';
		fill_symbol_bind_and_type(bin, &ret[ret_ctr], &sym[i]);
		ret[ret_ctr].is_sht_null = is_sht_null;
		ret[ret_ctr].is_vaddr = is_vaddr;
		ret[ret_ctr].last = 0;
		ret_ctr++;
	}
done:
	// Size everything down to only what is used
	{
		nsym = i > 0 ? i : 1;
		Elf_(Sym) *temp_sym = (Elf_(Sym) *)realloc(sym, (nsym * GROWTH_FACTOR) * sym_size);
		if (!temp_sym) {
			goto beach;
		}
		sym = temp_sym;
	}
	{
		ret_ctr = ret_ctr > 0 ? ret_ctr : 1;
		RzBinElfSymbol *p = (RzBinElfSymbol *)realloc(ret, (ret_ctr + 1) * sizeof(RzBinElfSymbol));
		if (!p) {
			goto beach;
		}
		ret = p;
	}
	ret[ret_ctr].last = 1;
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && !bin->imports_by_ord_size) {
		bin->imports_by_ord_size = ret_ctr + 1;
		if (ret_ctr > 0) {
			bin->imports_by_ord = (RzBinImport **)calloc(ret_ctr + 1, sizeof(RzBinImport *));
			for (RzBinElfSymbol *s = ret; !s->last; s++) {
				setimpord(bin, s);
			}
		} else {
			bin->imports_by_ord = NULL;
		}
	} else if (type == RZ_BIN_ELF_ALL_SYMBOLS && !bin->symbols_by_ord_size && ret_ctr) {
		bin->symbols_by_ord_size = ret_ctr + 1;
		if (ret_ctr > 0) {
			bin->symbols_by_ord = (RzBinSymbol **)calloc(ret_ctr + 1, sizeof(RzBinSymbol *));
		} else {
			bin->symbols_by_ord = NULL;
		}
	}
	free(sym);
	return ret;
beach:
	free(sym);
	free(ret);
	return NULL;
}

static RzBinElfSymbol *Elf_(rz_bin_elf_get_phdr_symbols)(ELFOBJ *bin) {
	if (!bin) {
		return NULL;
	}
	if (bin->phdr_symbols) {
		return bin->phdr_symbols;
	}
	bin->phdr_symbols = get_symbols_from_phdr(bin, RZ_BIN_ELF_ALL_SYMBOLS);
	return bin->phdr_symbols;
}

static RzBinElfSymbol *Elf_(rz_bin_elf_get_phdr_imports)(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);
	if (!bin->phdr_imports) {
		bin->phdr_imports = get_symbols_from_phdr(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);
	}
	return bin->phdr_imports;
}

static RzBinElfSymbol *Elf_(get_phdr_symbols)(ELFOBJ *bin, int type) {
	return (type != RZ_BIN_ELF_IMPORT_SYMBOLS)
		? Elf_(rz_bin_elf_get_phdr_symbols)(bin)
		: Elf_(rz_bin_elf_get_phdr_imports)(bin);
}

static int Elf_(fix_symbols)(ELFOBJ *bin, int nsym, int type, RzBinElfSymbol **sym) {
	int count = 0;
	int result = -1;
	RzBinElfSymbol *ret = *sym;
	RzBinElfSymbol *phdr_symbols = Elf_(get_phdr_symbols)(bin, type);
	RzBinElfSymbol *tmp, *p;
	HtUP *phd_offset_map = ht_up_new0();
	HtUP *phd_ordinal_map = ht_up_new0();
	if (phdr_symbols) {
		RzBinElfSymbol *d = ret;
		while (!d->last) {
			ht_up_insert(phd_offset_map, d->offset, d);
			ht_up_insert(phd_ordinal_map, d->ordinal, d);
			d++;
		}
		p = phdr_symbols;
		while (!p->last) {
			/* find match in phdr */
			d = ht_up_find(phd_offset_map, p->offset, NULL);
			if (!d) {
				d = ht_up_find(phd_ordinal_map, p->ordinal, NULL);
			}
			if (d) {
				p->in_shdr = true;
				if (*p->name && *d->name && rz_str_startswith(d->name, "$")) {
					strcpy(d->name, p->name);
				}
			}
			p++;
		}
		p = phdr_symbols;
		while (!p->last) {
			if (!p->in_shdr) {
				count++;
			}
			p++;
		}
		/*Take those symbols that are not present in the shdr but yes in phdr*/
		/*This should only should happen with invalid binaries*/
		if (count > 0) {
			/*what happens if a shdr says it has only one symbol? we should look anyway into phdr*/
			tmp = (RzBinElfSymbol *)realloc(ret, (nsym + count + 1) * sizeof(RzBinElfSymbol));
			if (!tmp) {
				result = -1;
				goto done;
			}
			ret = tmp;
			ret[nsym--].last = 0;
			p = phdr_symbols;
			while (!p->last) {
				if (!p->in_shdr) {
					memcpy(&ret[++nsym], p, sizeof(RzBinElfSymbol));
				}
				p++;
			}
			ret[nsym + 1].last = 1;
		}
		*sym = ret;
		result = nsym + 1;
		goto done;
	}
	result = nsym;
done:
	ht_up_free(phd_offset_map);
	ht_up_free(phd_ordinal_map);
	return result;
}

static bool is_section_local_sym(ELFOBJ *bin, Elf_(Sym) * sym) {
	if (sym->st_name != 0) {
		return false;
	}
	if (ELF_ST_TYPE(sym->st_info) != STT_SECTION) {
		return false;
	}
	if (ELF_ST_BIND(sym->st_info) != STB_LOCAL) {
		return false;
	}
	if (!Elf_(rz_bin_elf_is_sh_index_valid)(bin, sym->st_shndx)) {
		return false;
	}
	Elf_(Word) sh_name = bin->shdr[sym->st_shndx].sh_name;
	return bin->shstrtab && sh_name < bin->shstrtab_size;
}

static bool setsymord(ELFOBJ *eobj, ut32 ord, RzBinSymbol *ptr) {
	if (!eobj->symbols_by_ord || ord >= eobj->symbols_by_ord_size) {
		return false;
	}
	rz_bin_symbol_free(eobj->symbols_by_ord[ord]);
	eobj->symbols_by_ord[ord] = ptr;
	return true;
}

static void setimpord(ELFOBJ *eobj, RzBinElfSymbol *sym) {
	if (!eobj->imports_by_ord) {
		return;
	}
	RzBinImport *imp = Elf_(rz_bin_elf_convert_import)(eobj, sym);
	if (!imp) {
		return;
	}
	if (imp->ordinal >= eobj->imports_by_ord_size) {
		rz_bin_import_free(imp);
		return;
	}
	rz_bin_import_free(eobj->imports_by_ord[imp->ordinal]);
	eobj->imports_by_ord[imp->ordinal] = imp;
}

static ut32 hashRzBinElfSymbol(const void *obj) {
	const RzBinElfSymbol *symbol = (const RzBinElfSymbol *)obj;
	int hash = sdb_hash(symbol->name);
	hash ^= sdb_hash(symbol->type);
	hash ^= (symbol->offset >> 32);
	hash ^= (symbol->offset & 0xffffffff);
	return hash;
}

static int cmp_RzBinElfSymbol(const RzBinElfSymbol *a, const RzBinElfSymbol *b) {
	int result = 0;
	if (a->offset != b->offset) {
		return 1;
	}
	result = strcmp(a->name, b->name);
	if (result != 0) {
		return result;
	}
	return strcmp(a->type, b->type);
}

// TODO: return RzList<RzBinSymbol*> .. or run a callback with that symbol constructed, so we don't have to do it twice
static RzBinElfSymbol *Elf_(_r_bin_elf_get_symbols_imports)(ELFOBJ *bin, int type) {
	ut32 shdr_size;
	int tsize, nsym, ret_ctr = 0, i, j, r, k, newsize;
	ut64 toffset;
	ut32 size = 0;
	RzBinElfSymbol *ret = NULL, *import_ret = NULL;
	RzBinSymbol *import_sym_ptr = NULL;
	size_t ret_size = 0, prev_ret_size = 0, import_ret_ctr = 0;
	Elf_(Shdr) *strtab_section = NULL;
	Elf_(Sym) *sym = NULL;
	ut8 s[sizeof(Elf_(Sym))] = { 0 };
	char *strtab = NULL;
	HtPP *symbol_map = NULL;
	HtPPOptions symbol_map_options = {
		.cmp = (HtPPListComparator)cmp_RzBinElfSymbol,
		.hashfn = hashRzBinElfSymbol,
		.dupkey = NULL,
		.calcsizeK = NULL,
		.calcsizeV = NULL,
		.freefn = NULL,
		.elem_size = sizeof(HtPPKv),
	};

	if (!bin || !bin->shdr || !bin->ehdr.e_shnum || bin->ehdr.e_shnum == 0xffff) {
		return Elf_(get_phdr_symbols)(bin, type);
	}
	if (!UT32_MUL(&shdr_size, bin->ehdr.e_shnum, sizeof(Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size + 8 > bin->size) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (((type & RZ_BIN_ELF_SYMTAB_SYMBOLS) && bin->shdr[i].sh_type == SHT_SYMTAB) ||
			((type & RZ_BIN_ELF_DYNSYM_SYMBOLS) && bin->shdr[i].sh_type == SHT_DYNSYM)) {
			if (bin->shdr[i].sh_link < 1) {
				/* oops. fix out of range pointers */
				continue;
			}
			// hack to avoid asan cry
			if ((bin->shdr[i].sh_link * sizeof(Elf_(Shdr))) >= shdr_size) {
				/* oops. fix out of range pointers */
				continue;
			}
			strtab_section = &bin->shdr[bin->shdr[i].sh_link];
			if (strtab_section->sh_size > ST32_MAX || strtab_section->sh_size + 8 > bin->size) {
				bprintf("size (syms strtab)");
				free(ret);
				free(strtab);
				return NULL;
			}
			if (!strtab) {
				if (!(strtab = (char *)calloc(1, 8 + strtab_section->sh_size))) {
					bprintf("malloc (syms strtab)");
					goto beach;
				}
				if (strtab_section->sh_offset > bin->size ||
					strtab_section->sh_offset + strtab_section->sh_size > bin->size) {
					goto beach;
				}
				if (rz_buf_read_at(bin->b, strtab_section->sh_offset,
					    (ut8 *)strtab, strtab_section->sh_size) == -1) {
					bprintf("read (syms strtab)\n");
					goto beach;
				}
			}

			newsize = 1 + bin->shdr[i].sh_size;
			if (newsize < 0 || newsize > bin->size) {
				bprintf("invalid shdr %d size\n", i);
				goto beach;
			}
			nsym = (int)(bin->shdr[i].sh_size / sizeof(Elf_(Sym)));
			if (nsym < 0) {
				goto beach;
			}
			{
				ut64 sh_begin = bin->shdr[i].sh_offset;
				ut64 sh_end = sh_begin + bin->shdr[i].sh_size;
				if (sh_begin > bin->size) {
					goto beach;
				}
				if (sh_end > bin->size) {
					st64 newshsize = bin->size - sh_begin;
					nsym = (int)(newshsize / sizeof(Elf_(Sym)));
				}
			}
			if (!(sym = (Elf_(Sym) *)calloc(nsym, sizeof(Elf_(Sym))))) {
				bprintf("calloc (syms)");
				goto beach;
			}
			if (!UT32_MUL(&size, nsym, sizeof(Elf_(Sym)))) {
				goto beach;
			}
			if (size < 1 || size > bin->size) {
				goto beach;
			}
			if (bin->shdr[i].sh_offset > bin->size) {
				goto beach;
			}
			if (bin->shdr[i].sh_offset + size > bin->size) {
				goto beach;
			}
			for (j = 0; j < nsym; j++) {
				int k = 0;
				r = rz_buf_read_at(bin->b, bin->shdr[i].sh_offset + j * sizeof(Elf_(Sym)), s, sizeof(Elf_(Sym)));
				if (r < 1) {
					bprintf("read (sym)\n");
					goto beach;
				}
#if RZ_BIN_ELF64
				sym[j].st_name = READ32(s, k);
				sym[j].st_info = READ8(s, k);
				sym[j].st_other = READ8(s, k);
				sym[j].st_shndx = READ16(s, k);
				sym[j].st_value = READ64(s, k);
				sym[j].st_size = READ64(s, k);
#else
				sym[j].st_name = READ32(s, k);
				sym[j].st_value = READ32(s, k);
				sym[j].st_size = READ32(s, k);
				sym[j].st_info = READ8(s, k);
				sym[j].st_other = READ8(s, k);
				sym[j].st_shndx = READ16(s, k);
#endif
			}
			ret = realloc(ret, (ret_size + nsym) * sizeof(RzBinElfSymbol));
			if (!ret) {
				bprintf("Cannot allocate %d symbols\n", nsym);
				goto beach;
			}
			memset(ret + ret_size, 0, nsym * sizeof(RzBinElfSymbol));
			prev_ret_size = ret_size;
			ret_size += nsym;
			symbol_map = ht_pp_new_opt(&symbol_map_options);
			for (k = 0; k < prev_ret_size; k++) {
				if (ret[k].name[0]) {
					ht_pp_insert(symbol_map, ret + k, ret + k);
				}
			}
			for (k = 1; k < nsym; k++) {
				bool is_sht_null = false;
				bool is_vaddr = false;
				bool is_imported = false;
				if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
					if (sym[k].st_value) {
						toffset = sym[k].st_value;
					} else if ((toffset = get_import_addr(bin, k)) == -1) {
						toffset = 0;
					}
					tsize = 16;
					is_imported = sym[k].st_shndx == STN_UNDEF;
				} else {
					tsize = sym[k].st_size;
					toffset = (ut64)sym[k].st_value;
					is_sht_null = sym[k].st_shndx == SHT_NULL;
				}
				if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
					if (sym[k].st_shndx < bin->ehdr.e_shnum) {
						ret[ret_ctr].offset = sym[k].st_value + bin->shdr[sym[k].st_shndx].sh_offset;
					}
				} else {
					ret[ret_ctr].offset = Elf_(rz_bin_elf_v2p_new)(bin, toffset);
					if (ret[ret_ctr].offset == UT64_MAX) {
						ret[ret_ctr].offset = toffset;
						is_vaddr = true;
					}
				}
				ret[ret_ctr].size = tsize;
				if (sym[k].st_name + 1 > strtab_section->sh_size) {
					bprintf("index out of strtab range\n");
					continue;
				}
				{
					int st_name = sym[k].st_name;
					int maxsize = RZ_MIN(rz_buf_size(bin->b), strtab_section->sh_size);
					if (is_section_local_sym(bin, &sym[k])) {
						const char *shname = &bin->shstrtab[bin->shdr[sym[k].st_shndx].sh_name];
						rz_str_ncpy(ret[ret_ctr].name, shname, ELF_STRING_LENGTH);
					} else if (st_name <= 0 || st_name >= maxsize) {
						ret[ret_ctr].name[0] = 0;
					} else {
						rz_str_ncpy(ret[ret_ctr].name, &strtab[st_name], ELF_STRING_LENGTH);
						ret[ret_ctr].type = type2str(bin, &ret[ret_ctr], &sym[k]);

						if (ht_pp_find(symbol_map, &ret[ret_ctr], NULL)) {
							memset(ret + ret_ctr, 0, sizeof(RzBinElfSymbol));
							continue;
						}
					}
				}
				ret[ret_ctr].ordinal = k;
				ret[ret_ctr].name[ELF_STRING_LENGTH - 2] = '\0';
				fill_symbol_bind_and_type(bin, &ret[ret_ctr], &sym[k]);
				ret[ret_ctr].is_sht_null = is_sht_null;
				ret[ret_ctr].is_vaddr = is_vaddr;
				ret[ret_ctr].last = 0;
				ret[ret_ctr].is_imported = is_imported;
				ret_ctr++;
				if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && is_imported) {
					import_ret_ctr++;
				}
			}
			RZ_FREE(strtab);
			RZ_FREE(sym);
			ht_pp_free(symbol_map);
			symbol_map = NULL;
			if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
				break;
			}
		}
	}
	if (!ret) {
		return Elf_(get_phdr_symbols)(bin, type);
	}
	ret[ret_ctr].last = 1; // ugly dirty hack :D
	int max = -1;
	RzBinElfSymbol *aux = NULL;
	nsym = Elf_(fix_symbols)(bin, ret_ctr, type, &ret);
	if (nsym == -1) {
		goto beach;
	}

	// Elf_(fix_symbols) may find additional symbols, some of which could be
	// imported symbols. Let's reserve additional space for them.
	rz_warn_if_fail(nsym >= ret_ctr);
	import_ret_ctr += nsym - ret_ctr;

	aux = ret;
	while (!aux->last) {
		if ((int)aux->ordinal > max) {
			max = aux->ordinal;
		}
		aux++;
	}
	nsym = max;
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
		RZ_FREE(bin->imports_by_ord);
		bin->imports_by_ord_size = nsym + 1;
		bin->imports_by_ord = (RzBinImport **)calloc(RZ_MAX(1, nsym + 1), sizeof(RzBinImport *));
		RZ_FREE(bin->symbols_by_ord);
		bin->symbols_by_ord_size = nsym + 1;
		bin->symbols_by_ord = (RzBinSymbol **)calloc(RZ_MAX(1, nsym + 1), sizeof(RzBinSymbol *));
		import_ret = calloc(import_ret_ctr + 1, sizeof(RzBinElfSymbol));
		if (!import_ret) {
			bprintf("Cannot allocate %d symbols\n", nsym);
			goto beach;
		}
		import_ret_ctr = 0;
		i = -1;
		while (!ret[++i].last) {
			if (!(import_sym_ptr = Elf_(rz_bin_elf_convert_symbol)(bin, &ret[i], "%s"))) {
				continue;
			}

			if (!setsymord(bin, import_sym_ptr->ordinal, import_sym_ptr)) {
				free(import_sym_ptr);
			}

			if (ret[i].is_imported) {
				setimpord(bin, &ret[i]);
				memcpy(&import_ret[import_ret_ctr], &ret[i], sizeof(RzBinElfSymbol));
				++import_ret_ctr;
			}
		}
		import_ret[import_ret_ctr].last = 1;
		RZ_FREE(ret);
		return import_ret;
	}
	return ret;
beach:
	free(ret);
	free(sym);
	free(strtab);
	ht_pp_free(symbol_map);
	return NULL;
}

RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(ELFOBJ *bin) {
	if (!bin->g_symbols) {
		bin->g_symbols = Elf_(_r_bin_elf_get_symbols_imports)(bin, RZ_BIN_ELF_ALL_SYMBOLS);
	}
	return bin->g_symbols;
}

RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(ELFOBJ *bin) {
	if (!bin->g_imports) {
		bin->g_imports = Elf_(_r_bin_elf_get_symbols_imports)(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);
	}
	return bin->g_imports;
}
