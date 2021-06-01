// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define GROWTH_FACTOR 2

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

static void fill_symbol_bind_and_type(ELFOBJ *bin, struct rz_bin_elf_symbol_t *ret, Elf_(Sym) * sym) {
	ret->bind = Elf_(rz_bin_elf_symbol_bind_to_str)(sym);
	ret->type = Elf_(rz_bin_elf_symbol_type_to_str)(bin, ret, sym);
}

static int Elf_(fix_symbols)(ELFOBJ *bin, int nsym, int type, RzBinElfSymbol **sym) {
	int count = 0;
	int result = -1;
	RzBinElfSymbol *ret = *sym;
	RzBinElfSymbol *phdr_symbols = Elf_(rz_bin_elf_get_symbols_from_phdr)(bin, type);
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
RZ_IPI RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols_with_type)(ELFOBJ *bin, int type) {
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
		return Elf_(rz_bin_elf_get_symbols_from_phdr)(bin, type);
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
					} else if ((toffset = Elf_(rz_bin_elf_get_import_addr)(bin, k)) == -1) {
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
						ret[ret_ctr].type = Elf_(rz_bin_elf_symbol_type_to_str)(bin, &ret[ret_ctr], &sym[k]);

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
		return Elf_(rz_bin_elf_get_symbols_from_phdr)(bin, type);
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
				Elf_(rz_bin_elf_set_import_by_ord)(bin, &ret[i]);
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
