// SPDX-FileCopyrightText: 2016-2018 Davis
// SPDX-FileCopyrightText: 2016-2018 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_list.h>

#include "mdmp_pe.h"

static void PE_(add_tls_callbacks)(struct PE_(rz_bin_pe_obj_t) * bin, RzPVector /*<RzBinAddr *>*/ *vec) {
	char *key;
	int count = 0;
	PE_DWord haddr, paddr, vaddr;
	RzBinAddr *ptr = NULL;
	char tmpbuf[64];

	do {
		key = rz_strf(tmpbuf, "pe.tls_callback%d_paddr", count);
		paddr = sdb_num_get(bin->kv, key);
		if (!paddr) {
			break;
		}

		key = rz_strf(tmpbuf, "pe.tls_callback%d_vaddr", count);
		vaddr = sdb_num_get(bin->kv, key);
		if (!vaddr) {
			break;
		}

		key = rz_strf(tmpbuf, "pe.tls_callback%d_haddr", count);
		haddr = sdb_num_get(bin->kv, key);
		if (!haddr) {
			break;
		}
		if ((ptr = RZ_NEW0(RzBinAddr))) {
			ptr->paddr = paddr;
			ptr->vaddr = vaddr;
			ptr->hpaddr = haddr;
			ptr->type = RZ_BIN_ENTRY_TYPE_TLS;
			rz_pvector_push(vec, ptr);
		}
		count++;
	} while (vaddr);
}

RzPVector /*<RzBinAddr *>*/ *PE_(rz_bin_mdmp_pe_get_entrypoint)(struct PE_(rz_bin_mdmp_pe_bin) * pe_bin) {
	ut64 offset;
	struct rz_bin_pe_addr_t *entry = NULL;
	RzBinAddr *ptr = NULL;
	RzPVector *ret;

	if (!(entry = PE_(rz_bin_pe_get_entrypoint)(pe_bin->bin))) {
		return NULL;
	}
	if (!(ret = rz_pvector_new(NULL))) {
		free(entry);
		return NULL;
	}

	if ((ptr = RZ_NEW0(RzBinAddr))) {
		offset = entry->vaddr;
		if (offset > pe_bin->vaddr) {
			offset -= pe_bin->vaddr;
		}
		ptr->paddr = offset + pe_bin->paddr;
		ptr->vaddr = offset + pe_bin->vaddr;
		ptr->hpaddr = pe_bin->paddr + entry->haddr;
		ptr->type = RZ_BIN_ENTRY_TYPE_PROGRAM;

		rz_pvector_push(ret, ptr);
	}

	PE_(add_tls_callbacks)
	(pe_bin->bin, ret);

	free(entry);

	return ret;
}

static void filter_import(ut8 *n) {
	int I;
	for (I = 0; n[I]; I++) {
		if (n[I] < 30 || n[I] >= 0x7f) {
			n[I] = 0;
			break;
		}
	}
}

RzPVector /*<RzBinImport *>*/ *PE_(rz_bin_mdmp_pe_get_imports)(struct PE_(rz_bin_mdmp_pe_bin) * pe_bin) {
	int i;
	ut64 offset;
	struct rz_bin_pe_import_t *imports = NULL;
	RzBinImport *ptr = NULL;
	RzBinReloc *rel;
	RzPVector *ret;
	RzPVector *relocs;

	imports = PE_(rz_bin_pe_get_imports)(pe_bin->bin);
	ret = rz_pvector_new(NULL);
	relocs = rz_pvector_new(free);

	if (!imports || !ret || !relocs) {
		free(imports);
		free(ret);
		free(relocs);
		return NULL;
	}

	pe_bin->bin->relocs = relocs;
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = RZ_NEW0(RzBinImport))) {
			break;
		}
		filter_import(imports[i].name);
		ptr->name = rz_str_dup((const char *)imports[i].name);
		ptr->libname = RZ_STR_ISNOTEMPTY(imports[i].libname) ? rz_str_dup((const char *)imports[i].libname) : NULL;
		ptr->bind = "NONE";
		ptr->type = RZ_BIN_TYPE_FUNC_STR;
		ptr->ordinal = imports[i].ordinal;
		rz_pvector_push(ret, ptr);

		if (!(rel = RZ_NEW0(RzBinReloc))) {
			break;
		}
#ifdef RZ_BIN_PE64
		rel->type = RZ_BIN_RELOC_64;
#else
		rel->type = RZ_BIN_RELOC_32;
#endif
		offset = imports[i].vaddr;
		if (offset > pe_bin->vaddr) {
			offset -= pe_bin->vaddr;
		}
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		rel->vaddr = offset + pe_bin->vaddr;
		rel->paddr = imports[i].paddr + pe_bin->paddr;
		rz_pvector_push(relocs, rel);
	}
	free(imports);

	return ret;
}

RzPVector /*<RzBinSection *>*/ *PE_(rz_bin_mdmp_pe_get_sections)(struct PE_(rz_bin_mdmp_pe_bin) * pe_bin) {
	/* TODO: Vet code, taken verbatim(ish) from bin_pe.c */
	int i;
	ut64 ba = pe_bin->vaddr; // baddr (arch);
	struct rz_bin_pe_section_t *sections = NULL;
	RzBinSection *ptr;
	RzPVector *ret;

	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	if (!pe_bin->bin || !(sections = pe_bin->bin->sections)) {
		rz_pvector_free(ret);
		return NULL;
	}
	PE_(rz_bin_pe_check_sections)
	(pe_bin->bin, &sections);
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		if (sections[i].name[0]) {
			ptr->name = rz_str_dup((char *)sections[i].name);
		} else {
			ptr->name = rz_str_dup("");
		}
		ptr->size = sections[i].size;
		if (ptr->size > pe_bin->bin->size) {
			if (sections[i].vsize < pe_bin->bin->size) {
				ptr->size = sections[i].vsize;
			} else {
				// hack give it page size
				ptr->size = 4096;
			}
		}
		ptr->vsize = sections[i].vsize;
		if (!ptr->vsize && ptr->size) {
			ptr->vsize = ptr->size;
		}
		ptr->paddr = sections[i].paddr + pe_bin->paddr;
		ptr->vaddr = sections[i].vaddr + ba;
		ptr->perm = 0;
		if (RZ_BIN_PE_SCN_IS_EXECUTABLE(sections[i].perm)) {
			ptr->perm |= RZ_PERM_X;
		}
		if (RZ_BIN_PE_SCN_IS_WRITABLE(sections[i].perm)) {
			ptr->perm |= RZ_PERM_W;
		}
		if (RZ_BIN_PE_SCN_IS_READABLE(sections[i].perm)) {
			ptr->perm |= RZ_PERM_R;
		}
		if (RZ_BIN_PE_SCN_IS_SHAREABLE(sections[i].perm)) {
			ptr->perm |= RZ_PERM_SHAR;
		}
		if ((ptr->perm & RZ_PERM_R) && !(ptr->perm & RZ_PERM_X) && ptr->size > 0) {
			if (!strncmp(ptr->name, ".rsrc", 5) ||
				!strncmp(ptr->name, ".data", 5) ||
				!strncmp(ptr->name, ".rdata", 6)) {
				ptr->is_data = true;
			}
		}
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

RzList /*<RzBinSymbol *>*/ *PE_(rz_bin_mdmp_pe_get_symbols)(RzBin *rbin, struct PE_(rz_bin_mdmp_pe_bin) * pe_bin) {
	int i;
	ut64 offset;
	struct rz_bin_pe_export_t *symbols = NULL;
	struct rz_bin_pe_import_t *imports = NULL;
	RzBinSymbol *ptr = NULL;
	RzList *ret;

	if (!(ret = rz_list_new())) {
		return NULL;
	}

	/* TODO: Load symbol table from pdb file */
	if ((symbols = PE_(rz_bin_pe_get_exports)(pe_bin->bin))) {
		for (i = 0; !symbols[i].last; i++) {
			if (!(ptr = RZ_NEW0(RzBinSymbol))) {
				break;
			}
			offset = symbols[i].vaddr;
			if (offset > pe_bin->vaddr) {
				offset -= pe_bin->vaddr;
			}
			ptr->name = rz_str_dup((char *)symbols[i].name);
			ptr->libname = RZ_STR_ISNOTEMPTY(symbols[i].libname) ? rz_str_dup((char *)symbols[i].libname) : NULL;
			ptr->forwarder = rz_str_constpool_get(&rbin->constpool, (char *)symbols[i].forwarder);
			ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = offset + pe_bin->vaddr;
			ptr->paddr = symbols[i].paddr + pe_bin->paddr;
			ptr->ordinal = symbols[i].ordinal;

			rz_list_append(ret, ptr);
		}
		free(symbols);
	}
	/* Calling imports is unstable at the moment, I think this is an issue in pe.c */
	if ((imports = PE_(rz_bin_pe_get_imports)(pe_bin->bin))) {
		for (i = 0; !imports[i].last; i++) {
			if (!(ptr = RZ_NEW0(RzBinSymbol))) {
				break;
			}
			offset = imports[i].vaddr;
			if (offset > pe_bin->vaddr) {
				offset -= pe_bin->vaddr;
			}
			ptr->name = rz_str_dup((const char *)imports[i].name);
			ptr->libname = RZ_STR_ISNOTEMPTY(imports[i].libname) ? rz_str_dup((const char *)imports[i].libname) : NULL;
			ptr->is_imported = true;
			ptr->bind = "NONE";
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = offset + pe_bin->vaddr;
			ptr->paddr = imports[i].paddr + pe_bin->paddr;
			ptr->ordinal = imports[i].ordinal;

			rz_list_append(ret, ptr);
		}
		free(imports);
	}

	return ret;
}
