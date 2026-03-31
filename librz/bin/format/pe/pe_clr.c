// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

RZ_OWN RzList /*<RzBinSymbol *>*/ *PE_(rz_bin_pe_get_clr_symbols)(RzBinPEObj *bin) {
	if (!bin || !bin->clr || !bin->clr->methoddefs) {
		return NULL;
	}
	RzList /*<RzBinSymbol *>*/ *methods = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!methods) {
		return NULL;
	}

	// Namespace and classes

	// Each typedef contains a methodlist field which indexes into
	// the MethodDef table and marks the start of methods
	// belonging to that type

	// In order to determine the end of the methods of that type,
	// we mark the start of the next run with `type_methods_end`
	RzListIter *type_it = rz_list_iterator(bin->clr->typedefs);

	char *type_name = NULL;
	char *type_namespace = NULL;

	ut32 type_methods_start = rz_pvector_len(bin->clr->methoddefs) + 1;
	ut32 type_methods_end = type_methods_start;

	if (type_it) {
		Pe_image_metadata_typedef *typedef_ = rz_list_val(type_it);
		type_name = rz_buf_get_string(bin->clr->strings, typedef_->name);
		type_namespace = rz_buf_get_string(bin->clr->strings, typedef_->namespace);

		type_methods_start = typedef_->methodlist;
		type_methods_end = rz_pvector_len(bin->clr->methoddefs) + 1;

		type_it = rz_list_next(type_it);
		if (type_it) {
			Pe_image_metadata_typedef *itypedef_ = rz_list_val(type_it);
			type_methods_end = itypedef_->methodlist;
		}
	}

	int i = 1;
	void **it;
	rz_pvector_foreach (bin->clr->methoddefs, it) {
		Pe_image_metadata_methoddef *methoddef = *it;

		if ((type_name || type_namespace) && i >= type_methods_start && i >= type_methods_end) {
			rz_break_if_fail(type_it);

			// Update class and namespace
			free(type_name);
			free(type_namespace);

			Pe_image_metadata_typedef *typedef_ = rz_list_val(type_it);
			type_name = rz_buf_get_string(bin->clr->strings, typedef_->name);
			type_namespace = rz_buf_get_string(bin->clr->strings, typedef_->namespace);

			// Update next end
			type_it = rz_list_next(type_it);
			if (type_it) {
				Pe_image_metadata_typedef *next_typedef_ = rz_list_val(type_it);
				type_methods_end = next_typedef_->methodlist;
			} else {
				type_methods_end = rz_pvector_len(bin->clr->methoddefs) + 1;
			}
		}

		RzBinSymbol *sym;
		if (!(sym = RZ_NEW0(RzBinSymbol))) {
			break;
		}
		char *name = rz_buf_get_string(bin->clr->strings, methoddef->name);
		sym->name = rz_str_newf("%s%s%s::%s",
			type_namespace ? type_namespace : "",
			type_namespace && type_namespace[0] != '\x00' ? "::" : "", // separator
			type_name ? type_name : "",
			name ? name : "");
		free(name);

		sym->type = RZ_BIN_TYPE_FUNC_STR;
		sym->vaddr = PE_(bin_pe_rva_to_va)(bin, methoddef->rva);
		sym->paddr = PE_(bin_pe_rva_to_paddr)(bin, methoddef->rva);

		if (!(methoddef->implflags & 0x01) && methoddef->rva) { // not native
			if (bin_pe_dotnet_read_method_header(bin->clr, bin->b, sym) < 0) {
				free(sym);
				break;
			}
		}

		rz_list_append(methods, sym);
		i++;
	}

	// Cleanup class / namespace strings
	free(type_name);
	free(type_namespace);

	return methods;
}

ut64 PE_(rz_bin_pe_get_clr_methoddef_offset)(RzBinPEObj *bin, Pe_image_metadata_methoddef *methoddef) {
	if (!bin || !bin->clr || !methoddef) {
		return UT64_MAX;
	}

	RzBinSymbol sym;
	sym.vaddr = PE_(bin_pe_rva_to_va)(bin, methoddef->rva);
	sym.paddr = PE_(bin_pe_rva_to_paddr)(bin, methoddef->rva);

	if (!(methoddef->implflags & 0x01) && methoddef->rva) { // not native
		if (bin_pe_dotnet_read_method_header(bin->clr, bin->b, &sym) < 0) {
			return UT64_MAX;
		}
	}

	return sym.vaddr;
}

int PE_(bin_pe_init_clr)(RzBinPEObj *bin) {
	PE_(image_data_directory) *clr_dir = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
	PE_DWord image_clr_hdr_paddr = PE_(bin_pe_rva_to_paddr)(bin, clr_dir->VirtualAddress);

	Pe_image_clr *clr = RZ_NEW0(Pe_image_clr);
	if (!clr) {
		return -1;
	}

	if (bin_pe_dotnet_init_clr(clr, bin->b, image_clr_hdr_paddr)) {
		return -1;
	}

	if (clr->header) {
		PE_DWord metadata_directory = PE_(bin_pe_rva_to_paddr)(bin, clr->header->MetaDataDirectoryAddress);
		bin_pe_dotnet_init_metadata(clr, bin->big_endian, bin->b, metadata_directory);
	}

	bin->clr = clr;
	return 0;
}
