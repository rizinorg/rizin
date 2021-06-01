// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI RZ_OWN RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols_with_type_from_phdr)(RZ_NONNULL ELFOBJ *bin, int type) {
	rz_return_val_if_fail(bin, NULL);

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
			} else if ((toffset = Elf_(rz_bin_elf_get_import_addr)(bin, i)) == -1) {
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
		if (!strcmp(Elf_(rz_bin_elf_symbol_bind_to_str)(&sym[i]), RZ_BIN_BIND_UNKNOWN_STR) ||
			!strcmp(Elf_(rz_bin_elf_symbol_type_to_str)(NULL, NULL, &sym[i]), RZ_BIN_TYPE_UNKNOWN_STR)) {
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
				Elf_(rz_bin_elf_set_import_by_ord)(bin, s);
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
